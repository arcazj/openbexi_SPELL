from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.data_domain import DataAuthorizationError, DataValidationError
from backend.data_models import DataContainer, DataContainerRevision, activate_data_schema
from backend.data_repository import DataRepository
from backend.ir_v08 import (
    V08ValidationError,
    data_request_for_step,
    file_handle_reference,
)
from backend.tests.migration_support import run_migrations
from backend.models import Event, Execution
from backend.procedure_parser import ProcedureCatalog
from backend.supervisor import ConflictError, Supervisor, WorkerHandle


class _Hub:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, _execution_id: str, event: dict) -> None:
        self.events.append(event)


class _Runtime:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def resolve(self, request: dict) -> dict:
        self.requests.append(request)
        return {
            "outcome": "OK",
            "value": "spell-data-handle-v1.test",
            "revision": "1",
        }


class _BlockingRuntime(_Runtime):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def resolve(self, request: dict) -> dict:
        self.requests.append(request)
        self.started.set()
        self.release.wait(timeout=2)
        return {
            "outcome": "OK",
            "value": "spell-data-handle-v1.test",
            "revision": "1",
        }


class _RecoveringRuntime(_BlockingRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.recoveries: list[tuple[dict, object]] = []

    def recover(self, request: dict, *, original_binding) -> dict:
        self.recoveries.append((request, original_binding))
        return {
            "outcome": "OK",
            "value": "spell-data-handle-v1.recovered",
            "revision": "1",
        }


def _fixture(runtime=None):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "ARGS(mode='str')\n"
        "DataContainer('CONTAINER.A', schema_revision=1)\n",
        "supervisor-v08.spell.py",
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    execution = Execution(
        id="execution-v08",
        procedure_id="supervisor-v08",
        procedure_name="Supervisor V08",
        procedure_hash="a" * 64,
        procedure_source="",
        steps=list(procedure.steps),
        ir_version="0.8",
        variables={},
        context_id="simulator",
        created_by="operator",
        creation_idempotency_key="create-v08",
        state="waiting",
        revision=1,
        current_step=0,
        total_steps=1,
        worker_generation=7,
        next_sequence=1,
    )
    with sessions() as session:
        session.add(execution)
        session.commit()

    runtime = runtime or _Runtime()
    supervisor = Supervisor.__new__(Supervisor)
    supervisor.session_factory = sessions
    supervisor.hub = _Hub()
    supervisor._lock = threading.RLock()
    supervisor._data_requests = set()
    supervisor.data_runtime = runtime
    supervisor._closed = False
    handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 7)
    supervisor._workers = {execution.id: handle}
    request = data_request_for_step(execution.id, procedure.steps[0])
    return supervisor, sessions, runtime, handle, request


def _result(control: queue.Queue, timeout: float = 2) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = control.get(timeout=0.05)
        except queue.Empty:
            continue
        if message.get("type") == "data_result":
            return message
    raise AssertionError("data result was not delivered")


def test_supervisor_commits_data_result_before_delivery_and_replays() -> None:
    supervisor, sessions, runtime, handle, request = _fixture()
    supervisor._handle_data_request(
        request["execution_id"],
        handle,
        {"kind": "data_requested", "generation": 7, **request},
    )
    first = _result(handle.control)
    with sessions() as session:
        events = session.scalars(
            select(Event)
            .where(Event.execution_id == request["execution_id"])
            .order_by(Event.sequence)
        ).all()
        assert [event.event_type for event in events] == [
            "procedure.data_requested",
            "procedure.data_result",
        ]
        assert events[-1].payload == {
            key: value for key, value in first.items() if key != "type"
        }

    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()
    replay = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = replay
    supervisor._handle_data_request(
        request["execution_id"],
        replay,
        {"kind": "data_requested", "generation": 8, **request},
    )
    assert _result(replay.control) == first
    assert len(runtime.requests) == 1
    assert runtime.requests[0]["service_principal_id"] == "procedure-runtime"
    assert runtime.requests[0]["worker_generation"] == 7


def test_stale_runtime_completion_cannot_cross_generation_fence() -> None:
    runtime = _BlockingRuntime()
    supervisor, sessions, _runtime, handle, request = _fixture(runtime)
    supervisor._handle_data_request(
        request["execution_id"],
        handle,
        {"kind": "data_requested", "generation": 7, **request},
    )
    assert runtime.started.wait(timeout=1)
    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()
    replacement = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = replacement
    runtime.release.set()
    time.sleep(0.1)

    with sessions() as session:
        result = session.scalar(
            select(Event).where(
                Event.execution_id == request["execution_id"],
                Event.event_type == "procedure.data_result",
            )
        )
    assert result is None
    assert handle.control.empty()


def test_new_generation_uses_recovery_only_after_commit_delivery_crash() -> None:
    runtime = _RecoveringRuntime()
    supervisor, sessions, _runtime, handle, request = _fixture(runtime)
    supervisor._handle_data_request(
        request["execution_id"],
        handle,
        {"kind": "data_requested", "generation": 7, **request},
    )
    assert runtime.started.wait(timeout=1)
    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()
    replacement = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = replacement
    runtime.release.set()
    time.sleep(0.1)

    supervisor._handle_data_request(
        request["execution_id"],
        replacement,
        {"kind": "data_requested", "generation": 8, **request},
    )
    recovered = _result(replacement.control)
    assert recovered["outcome"] == "OK"
    assert len(runtime.requests) == 1
    assert len(runtime.recoveries) == 1
    recovery_request, original_binding = runtime.recoveries[0]
    assert recovery_request["worker_generation"] == 8
    assert original_binding.worker_generation == 7
    with sessions() as session:
        requested = session.scalar(
            select(Event).where(Event.event_type == "procedure.data_requested")
        )
        assert requested.payload["_runtime_binding"] == {
            "deterministic_request_id": request["request_id"],
            "execution_id": request["execution_id"],
            "service_principal_id": "procedure-runtime",
            "worker_generation": 7,
        }


def _projection_supervisor(tmp_path: Path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'projection.db').as_posix()}")
    run_migrations(engine)
    activate_data_schema(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)

    def authorize(session, binding) -> None:
        execution = session.get(Execution, binding.execution_id)
        if (
            execution is None
            or execution.ir_version != "0.8"
            or execution.worker_generation != binding.worker_generation
        ):
            raise DataAuthorizationError("procedure generation is not admitted")

    repository = DataRepository(
        sessions,
        cursor_secret=b"v08-supervisor-projection-test-secret",
        procedure_binding_check=authorize,
    )
    supervisor = Supervisor(
        sessions,
        ProcedureCatalog.__new__(ProcedureCatalog),
        _Hub(),
        data_repository=repository,
    )
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "ARGS(mode='str')\n"
        "DataContainer('CONTAINER.A', schema_revision=1)\n",
        "supervisor-projection-v08.spell.py",
    )
    return supervisor, sessions, procedure


@pytest.mark.parametrize(
    "arguments",
    [[], {}, {"mode": 1}, {"mode": "safe", "extra": True}],
)
def test_v08_argument_contract_rejects_before_execution_creation(
    tmp_path: Path,
    arguments,
) -> None:
    supervisor, sessions, procedure = _projection_supervisor(tmp_path)

    with pytest.raises(ConflictError):
        supervisor.create_execution(
            procedure,
            actor="operator-v08",
            role="operator",
            reason="argument contract regression",
            idempotency_key=f"invalid-v08-{type(arguments).__name__}-{len(arguments)}",
            automatic=False,
            initial_variables=arguments,
        )

    with sessions() as session:
        assert session.scalar(select(Execution)) is None


def test_v08_admission_and_checkpoint_share_execution_transactions(
    tmp_path: Path,
) -> None:
    supervisor, sessions, procedure = _projection_supervisor(tmp_path)
    created = supervisor.create_execution(
        procedure,
        actor="operator-v08",
        role="operator",
        reason="projection transaction regression",
        idempotency_key="create-v08-projection",
        automatic=False,
        initial_variables={"mode": "safe"},
    )
    with sessions() as session:
        execution = session.get(Execution, created.id)
        assert execution.variables == {"ARGS": {"mode": "safe"}}
        heads = session.scalars(
            select(DataContainer)
            .where(DataContainer.execution_id == created.id)
            .order_by(DataContainer.kind)
        ).all()
        assert {head.kind: head.current_revision for head in heads} == {
            "ARGS": 1,
            "IVARS": 1,
            "LOCAL": 1,
        }
        created_event = session.scalar(
            select(Event).where(
                Event.execution_id == created.id,
                Event.event_type == "execution.created",
            )
        )
        assert set(created_event.payload["data_projections"]) == {
            "ARGS",
            "IVARS",
            "LOCAL",
        }
        execution.worker_generation = 4
        execution.state = "running"
        session.commit()

    replay = supervisor.create_execution(
        procedure,
        actor="operator-v08",
        role="operator",
        reason="projection transaction regression",
        idempotency_key="create-v08-projection",
        automatic=False,
        initial_variables={"mode": "safe"},
    )
    assert replay.id == created.id

    invalid_checkpoint = {
        "step_index": 0,
        "next_step": 1,
        "variables": {
            "ARGS": {"mode": "safe"},
            "IVARS": {},
            "GLOBALS": {},
            "SHARED_DATA": {},
            "invalid": {"nested": "value"},
        },
        "effects": [],
    }
    with pytest.raises(DataValidationError):
        supervisor._commit_step(created.id, 4, invalid_checkpoint)
    with sessions() as session:
        execution = session.get(Execution, created.id)
        assert execution.current_step == 0
        assert {
            head.kind: head.current_revision
            for head in session.scalars(
                select(DataContainer).where(DataContainer.execution_id == created.id)
            )
        } == {"ARGS": 1, "IVARS": 1, "LOCAL": 1}

    assert supervisor._commit_step(
        created.id,
        4,
        {
            "step_index": 0,
            "next_step": 1,
            "variables": {
                "ARGS": {"mode": "safe"},
                "IVARS": {"counter": 2},
                "GLOBALS": {},
                "SHARED_DATA": {},
                "status": "complete",
            },
            "effects": [],
        },
    )
    with sessions() as session:
        execution = session.get(Execution, created.id)
        assert execution.current_step == 1
        assert {
            head.kind: head.current_revision
            for head in session.scalars(
                select(DataContainer).where(DataContainer.execution_id == created.id)
            )
        } == {"ARGS": 1, "IVARS": 2, "LOCAL": 2}
        checkpoint = session.scalar(
            select(Event).where(
                Event.execution_id == created.id,
                Event.event_type == "execution.checkpointed",
            )
        )
        assert set(checkpoint.payload["data_projections"]) == {"IVARS", "LOCAL"}


def test_file_handle_token_is_transient_and_never_persisted_or_projected(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "opaque-file-handle.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    run_migrations(engine)
    activate_data_schema(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)

    def authorize(session, binding) -> None:
        execution = session.get(Execution, binding.execution_id)
        if execution is None or execution.worker_generation != binding.worker_generation:
            raise DataAuthorizationError("procedure generation is not admitted")

    repository = DataRepository(
        sessions,
        cursor_secret=b"v08-opaque-file-handle-test-secret",
        procedure_binding_check=authorize,
    )
    token = "raw-file-handle-token-that-must-never-be-durable"

    class Runtime:
        def resolve(self, request: dict) -> dict:
            assert request["operation"] == "OPEN_FILE"
            return {"outcome": "OK", "value": token, "revision": "0"}

    supervisor = Supervisor(
        sessions,
        ProcedureCatalog.__new__(ProcedureCatalog),
        _Hub(),
        data_runtime=Runtime(),
        data_repository=repository,
    )
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "handle: str = ''\n"
        "OpenFile('PROJECT_DATA', 'opaque.txt', mode='WRITE', revision=0, target=handle)\n",
        "opaque-file-handle.spell.py",
    )
    created = supervisor.create_execution(
        procedure,
        actor="operator-v08",
        role="operator",
        reason="opaque FileHandle persistence regression",
        idempotency_key="create-opaque-file-handle",
        automatic=False,
        initial_variables={},
    )
    prior_variables = {
        "ARGS": {},
        "GLOBALS": {},
        "IVARS": {},
        "SHARED_DATA": {},
        "handle": "",
    }
    with sessions() as session:
        execution = session.get(Execution, created.id)
        execution.current_step = 1
        execution.worker_generation = 4
        execution.state = "waiting"
        execution.variables = prior_variables
        session.commit()

    handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 4)
    supervisor._workers[created.id] = handle
    request = data_request_for_step(created.id, procedure.steps[1])
    supervisor._handle_data_request(
        created.id,
        handle,
        {"kind": "data_requested", "generation": 4, **request},
    )
    transient = _result(handle.control)
    assert transient["value"] == token
    deadline = time.monotonic() + 1
    while supervisor._data_requests and time.monotonic() < deadline:
        time.sleep(0.01)
    supervisor._handle_data_request(
        created.id,
        handle,
        {"kind": "data_requested", "generation": 4, **request},
    )
    replay = _result(handle.control)
    assert replay["outcome"] == "STALE_HANDLE"
    assert "value" not in replay

    marker = file_handle_reference(
        token,
        execution_id=created.id,
        worker_generation=4,
        creator_request_id=request["request_id"],
    )
    with pytest.raises(ConflictError, match="raw FileHandle"):
        supervisor._reject_raw_file_handle_worker_message(
            created.id,
            4,
            {"kind": "event", "payload": {"copied": token}},
        )
    supervisor._reject_raw_file_handle_worker_message(
        created.id,
        4,
        {"kind": "event", "payload": {"handle": marker}},
    )
    for leaked_variables, leaked_effects in (
        (
            {**prior_variables, "handle": marker, "copied": token},
            [],
        ),
        (
            {**prior_variables, "handle": marker},
            [
                {
                    "event_type": "procedure.test",
                    "source": "worker",
                    "payload": {"copied": token},
                }
            ],
        ),
    ):
        with pytest.raises(ConflictError, match="raw FileHandle"):
            supervisor._commit_step(
                created.id,
                4,
                {
                    "step_index": 1,
                    "next_step": 2,
                    "variables": leaked_variables,
                    "effects": leaked_effects,
                },
            )
    assert supervisor._commit_step(
        created.id,
        4,
        {
            "step_index": 1,
            "next_step": 2,
            "variables": {**prior_variables, "handle": marker},
            "effects": [],
        },
    )

    with sessions() as session:
        execution = session.get(Execution, created.id)
        assert execution.variables["handle"] == marker
        events = session.scalars(
            select(Event).where(Event.execution_id == created.id)
        ).all()
        durable_result = next(
            event for event in events if event.event_type == "procedure.data_result"
        )
        checkpoint = next(
            event for event in events if event.event_type == "execution.checkpointed"
        )
        assert durable_result.payload["value"] == marker
        assert checkpoint.payload["variables"]["handle"] == marker
        assert token not in json.dumps(
            [event.payload for event in events], sort_keys=True
        )
        local_revision = session.scalar(
            select(DataContainerRevision)
            .where(
                DataContainerRevision.kind == "LOCAL",
                DataContainerRevision.owner_id == created.id,
            )
            .order_by(DataContainerRevision.revision.desc())
            .limit(1)
        )
        assert local_revision is not None
        assert token.encode("ascii") not in local_revision.canonical_variables
        assert b'"handle"' not in local_revision.canonical_variables

    engine.dispose()
    database_bytes = db_path.read_bytes()
    for suffix in ("-wal", "-journal"):
        sidecar = Path(f"{db_path}{suffix}")
        if sidecar.exists():
            database_bytes += sidecar.read_bytes()
    assert token.encode("ascii") not in database_bytes


def test_supervisor_rejects_cross_handle_substitution_from_worker() -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "first: str = ''\n"
        "second: str = ''\n"
        "OpenFile('PROJECT_DATA', 'first.txt', target=first)\n"
        "OpenFile('PROJECT_DATA', 'second.txt', target=second)\n"
        "WriteFile(handle=first, content='pinned')\n",
        "cross-handle.spell.py",
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    execution_id = "execution-cross-handle"
    first = file_handle_reference(
        "first-live-token",
        execution_id=execution_id,
        worker_generation=6,
        creator_request_id=data_request_for_step(
            execution_id, procedure.steps[2]
        )["request_id"],
    )
    second = file_handle_reference(
        "second-live-token",
        execution_id=execution_id,
        worker_generation=6,
        creator_request_id=data_request_for_step(
            execution_id, procedure.steps[3]
        )["request_id"],
    )
    execution = Execution(
        id=execution_id,
        procedure_id="cross-handle",
        procedure_name="Cross handle",
        procedure_hash="b" * 64,
        procedure_source="",
        steps=list(procedure.steps),
        ir_version="0.8",
        variables={"first": first, "second": second},
        context_id="simulator",
        created_by="operator",
        creation_idempotency_key="create-cross-handle",
        state="waiting",
        revision=1,
        current_step=4,
        total_steps=len(procedure.steps),
        worker_generation=6,
        next_sequence=1,
    )
    with sessions() as session:
        session.add(execution)
        session.commit()

    runtime = _Runtime()
    supervisor = Supervisor(
        sessions,
        ProcedureCatalog.__new__(ProcedureCatalog),
        _Hub(),
        data_runtime=runtime,
    )
    handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 6)
    supervisor._workers[execution_id] = handle
    substituted = data_request_for_step(
        execution_id,
        procedure.steps[4],
        variables={"first": second},
        worker_generation=6,
    )
    with pytest.raises(V08ValidationError, match="authoritative variable"):
        supervisor._handle_data_request(
            execution_id,
            handle,
            {"kind": "data_requested", "generation": 6, **substituted},
        )
    assert runtime.requests == []
