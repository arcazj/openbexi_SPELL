from __future__ import annotations

import queue
import threading
import time

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.ir_v07 import observation_request_for_step
from backend.models import Event, Execution
from backend.procedure_parser import ProcedureCatalog
from backend.supervisor import Supervisor, WorkerHandle


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
            "value": 12,
            "evidence": {"sample_id": "b" * 64},
        }


class _AnchorProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def telemetry_anchor(self, context_id: str, item_id: str) -> dict:
        self.calls.append((context_id, item_id))
        return {
            "context_id": context_id,
            "context_generation_id": "context-generation-1",
            "stream_epoch": "stream-epoch-1",
            "projection_sequence": "17",
            "item_id": item_id,
            "source_id": "simulator",
            "source_epoch": "source-epoch-1",
            "source_sequence": "9",
            "sample_id": "c" * 64,
        }


class _RestartRuntime(_Runtime):
    def __init__(self) -> None:
        super().__init__()
        self.first_started = threading.Event()
        self.release_first = threading.Event()

    def resolve(self, request: dict) -> dict:
        self.requests.append(request)
        if len(self.requests) == 1:
            self.first_started.set()
            self.release_first.wait(timeout=2)
        return {"outcome": "OK", "value": 12}


def _fixture(*, mode: str = "CURRENT", runtime=None, anchor_provider=None):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "reading: int = 0\n"
        f"GetTM('TM.COUNT', target=reading, scalar_type='int', mode={mode!r})\n",
        "supervisor-v07.spell.py",
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    execution = Execution(
        id="execution-v07",
        procedure_id="supervisor-v07",
        procedure_name="Supervisor V07",
        procedure_hash="a" * 64,
        procedure_source="",
        steps=list(procedure.steps),
        ir_version="0.7",
        variables={"reading": 0},
        context_id="simulator",
        created_by="operator",
        creation_idempotency_key="create-v07",
        state="waiting",
        revision=1,
        current_step=1,
        total_steps=2,
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
    supervisor._observation_requests = set()
    supervisor.observation_runtime = runtime
    supervisor.observation_anchor_provider = anchor_provider
    supervisor._closed = False
    handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 7)
    supervisor._workers = {execution.id: handle}
    request = observation_request_for_step(execution.id, procedure.steps[1])
    return supervisor, sessions, runtime, handle, request


def _result(control: queue.Queue, timeout: float = 2) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = control.get(timeout=0.05)
        except queue.Empty:
            continue
        if message.get("type") == "observation_result":
            return message
    raise AssertionError("observation result was not delivered")


def test_supervisor_commits_result_before_delivery_and_replays_exact_bytes() -> None:
    supervisor, sessions, runtime, handle, request = _fixture()
    supervisor._handle_observation_request(
        request["execution_id"],
        handle,
        {"kind": "observation_requested", "generation": 7, **request},
    )
    first = _result(handle.control)
    with sessions() as session:
        events = session.scalars(
            select(Event)
            .where(Event.execution_id == request["execution_id"])
            .order_by(Event.sequence)
        ).all()
        assert [event.event_type for event in events] == [
            "procedure.observation_requested",
            "procedure.observation_result",
        ]
        assert events[-1].payload == {
            key: value for key, value in first.items() if key != "type"
        }

    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()
    replay_handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = replay_handle
    supervisor._handle_observation_request(
        request["execution_id"],
        replay_handle,
        {"kind": "observation_requested", "generation": 8, **request},
    )
    replayed = _result(replay_handle.control)
    assert replayed == first
    assert len(runtime.requests) == 1


def test_stale_runtime_completion_cannot_cross_a_worker_generation_fence() -> None:
    supervisor, sessions, _runtime, handle, request = _fixture()
    result = {
        "schema_version": "spell.v07.observation-result/1",
        "request_id": request["request_id"],
        "execution_id": request["execution_id"],
        "step_index": request["step_index"],
        "operation": request["operation"],
        "outcome": "OK",
        "value": 12,
    }
    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()

    assert not supervisor._settle_observation_result(
        request["execution_id"], handle, request, result
    )
    assert handle.control.empty()
    with sessions() as session:
        assert session.scalar(
            select(Event).where(Event.event_type == "procedure.observation_result")
        ) is None


def test_restart_between_next_request_and_result_reuses_the_durable_anchor() -> None:
    runtime = _RestartRuntime()
    anchors = _AnchorProvider()
    supervisor, sessions, _runtime, first_handle, request = _fixture(
        mode="NEXT", runtime=runtime, anchor_provider=anchors
    )
    supervisor._handle_observation_request(
        request["execution_id"],
        first_handle,
        {"kind": "observation_requested", "generation": 7, **request},
    )
    assert runtime.first_started.wait(timeout=1)
    with sessions() as session:
        requested = session.scalar(
            select(Event).where(Event.event_type == "procedure.observation_requested")
        )
        assert requested is not None
        first_anchor = requested.payload["anchor"]
        first_digest = requested.payload["request_digest"]
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()

    recovered = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = recovered
    supervisor._handle_observation_request(
        request["execution_id"],
        recovered,
        {"kind": "observation_requested", "generation": 8, **request},
    )
    delivered = _result(recovered.control)
    runtime.release_first.set()

    assert anchors.calls == [("simulator", "TM.COUNT")]
    assert len(runtime.requests) == 2
    assert runtime.requests[0]["anchor"] == first_anchor
    assert runtime.requests[1]["anchor"] == first_anchor
    assert runtime.requests[0]["requested_at_unix_ns"] == runtime.requests[1][
        "requested_at_unix_ns"
    ]
    assert runtime.requests[0]["deadline_at_unix_ns"] == runtime.requests[1][
        "deadline_at_unix_ns"
    ]
    assert runtime.requests[0]["request_digest"] == first_digest
    assert runtime.requests[1]["request_digest"] == first_digest
    assert delivered["request_digest"] == first_digest
