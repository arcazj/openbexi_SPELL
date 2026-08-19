from __future__ import annotations

import queue
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.supervisor as supervisor_module
from backend.database import Base
from backend.models import Event, Execution
from backend.operator_models import OperatorPrompt
from backend.procedure_parser import ProcedureCatalog
from backend.supervisor import ConflictError, Supervisor, WorkerHandle
from backend.ir_v11 import ordinary_prompt_id
from backend.telecommand_runtime_v11 import (
    TelecommandRuntimeError,
    confirmation_prompt_id,
    execute_preflight,
    failure_prompt_id,
    failure_prompt_question,
    prepare_send_request,
)
from backend.telecommand_v11 import (
    DeterministicScriptedProvider,
    ElementStage,
    ProviderStep,
)


class _Hub:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, _execution_id: str, event: dict) -> None:
        self.events.append(event)


def _fixture(source: str = "Send(command='CMDNAME')\n"):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "supervisor-v11.spell.py"
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    execution = Execution(
        id="execution-v11",
        procedure_id="supervisor-v11",
        procedure_name="Supervisor V11",
        procedure_hash="a" * 64,
        procedure_source="",
        steps=list(procedure.steps),
        ir_version="0.11",
        variables={},
        context_id="simulator",
        created_by="operator",
        creation_idempotency_key="create-v11",
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

    supervisor = Supervisor.__new__(Supervisor)
    supervisor.session_factory = sessions
    supervisor.hub = _Hub()
    supervisor._lock = threading.RLock()
    supervisor._telecommand_requests = set()
    supervisor.operator_service = None
    supervisor._closed = False
    handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 7)
    supervisor._workers = {execution.id: handle}
    request, _, _ = prepare_send_request(
        execution.id, 0, procedure.steps[0], {}
    )
    return supervisor, sessions, handle, request


def _ordinary_fixture(
    source: str,
    *,
    current_step: int,
    variables: dict | None = None,
):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "supervisor-v11-ordinary.spell.py"
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    execution = Execution(
        id="execution-v11-ordinary",
        procedure_id="supervisor-v11-ordinary",
        procedure_name="Supervisor V11 Ordinary",
        procedure_hash="b" * 64,
        procedure_source=source,
        steps=list(procedure.steps),
        ir_version="0.11",
        variables=variables or {},
        context_id="simulator",
        created_by="operator",
        creation_idempotency_key="create-v11-ordinary",
        state="prompting",
        revision=1,
        current_step=current_step,
        total_steps=len(procedure.steps),
        worker_generation=7,
        next_sequence=1,
    )
    with sessions() as session:
        session.add(execution)
        session.commit()

    supervisor = Supervisor.__new__(Supervisor)
    supervisor.session_factory = sessions
    supervisor.hub = _Hub()
    supervisor._lock = threading.RLock()
    supervisor._telecommand_requests = set()
    supervisor.operator_service = None
    supervisor._closed = False
    supervisor._workers = {
        execution.id: WorkerHandle(object(), queue.Queue(), queue.Queue(), 7)
    }
    return supervisor, sessions, procedure, execution.id


def _ordinary_step_commit(
    procedure,
    step_index: int,
    variables: dict,
    *,
    prompt_resolution: dict | None = None,
) -> dict:
    step = procedure.steps[step_index]
    return {
        "step_index": step_index,
        "next_step": step_index + 1,
        "effects": [
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {
                    "step_index": step_index,
                    "line": step["line"],
                    "step_type": step["type"],
                    "skipped": False,
                },
            }
        ],
        "prompt_resolution": prompt_resolution,
        "variables": variables,
    }


def _settled_yes_no_prompt(
    execution_id: str,
    step_index: int,
    question: str,
    *,
    prompt_id: str | None = None,
) -> tuple[OperatorPrompt, dict]:
    prompt_id = prompt_id or ordinary_prompt_id(execution_id, step_index)
    settlement_id = str(uuid.uuid4())
    prompt = OperatorPrompt(
        id=prompt_id,
        execution_id=execution_id,
        step_index=step_index,
        state="SETTLED",
        prompt_type="YES_NO",
        input_kind="FIXED_CHOICE",
        question=question,
        options=["YES", "NO"],
        default_value=None,
        settings_snapshot={},
        settlement_id=settlement_id,
        settlement_outcome="ANSWERED",
        settled_value="YES",
        settled_by="operator@example.test",
    )
    return prompt, {
        "prompt_id": prompt_id,
        "settlement_id": settlement_id,
        "outcome": "ANSWERED",
        "response": "YES",
        "command_id": None,
    }


def _result(control: queue.Queue, timeout: float = 2) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = control.get(timeout=0.05)
        except queue.Empty:
            continue
        if message.get("type") == "telecommand_result":
            return message
    raise AssertionError("telecommand result was not delivered")


_TWO_PROMPTS_SOURCE = (
    "Prompt('First?', type='YES_NO')\n"
    "Prompt('Second?', type='YES_NO')\n"
    "Send(command='CMDNAME')\n"
)


def test_v11_prompt_checkpoint_requires_exact_current_step_settlement() -> None:
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        _TWO_PROMPTS_SOURCE, current_step=1, variables={"ARGS": {}}
    )

    with pytest.raises(ConflictError, match="requires its exact settlement"):
        supervisor._commit_step(
            execution_id,
            7,
            _ordinary_step_commit(procedure, 1, {"ARGS": {}}),
        )

    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 1


def test_v11_prompt_checkpoint_rejects_prior_step_settlement() -> None:
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        _TWO_PROMPTS_SOURCE, current_step=1, variables={"ARGS": {}}
    )
    prompt, resolution = _settled_yes_no_prompt(
        execution_id, 0, "First?"
    )
    with sessions() as session:
        session.add(prompt)
        session.commit()

    with pytest.raises(ConflictError, match="requires its exact settlement"):
        supervisor._commit_step(
            execution_id,
            7,
            _ordinary_step_commit(
                procedure, 1, {"ARGS": {}}, prompt_resolution=resolution
            ),
        )

    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 1


def test_v11_prompt_checkpoint_rejects_same_step_forged_declaration() -> None:
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        _TWO_PROMPTS_SOURCE, current_step=1, variables={"ARGS": {}}
    )
    prompt, resolution = _settled_yes_no_prompt(
        execution_id, 1, "Approve an unrelated action?"
    )
    with sessions() as session:
        session.add(prompt)
        session.commit()

    with pytest.raises(ConflictError, match="does not match its declaration"):
        supervisor._commit_step(
            execution_id,
            7,
            _ordinary_step_commit(
                procedure, 1, {"ARGS": {}}, prompt_resolution=resolution
            ),
        )

    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 1


def test_v11_prompt_checkpoint_accepts_exact_deterministic_declaration() -> None:
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        _TWO_PROMPTS_SOURCE, current_step=1, variables={"ARGS": {}}
    )
    prompt, resolution = _settled_yes_no_prompt(
        execution_id, 1, "Second?"
    )
    with sessions() as session:
        session.add(prompt)
        session.commit()

    assert supervisor._commit_step(
        execution_id,
        7,
        _ordinary_step_commit(
            procedure, 1, {"ARGS": {}}, prompt_resolution=resolution
        ),
    )
    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 2


def test_v11_checkpoint_rejects_command_selector_substitution_on_ordinary_step() -> None:
    source = (
        "tc_name: str = 'CMDNAME'\n"
        "Log('benign')\n"
        "Send(command=tc_name)\n"
    )
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        source,
        current_step=1,
        variables={"ARGS": {}, "tc_name": "CMDNAME"},
    )

    with pytest.raises(ConflictError, match="dependency checkpoint"):
        supervisor._commit_step(
            execution_id,
            7,
            _ordinary_step_commit(
                procedure, 1, {"ARGS": {}, "tc_name": "CMD2"}
            ),
        )

    with sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution.current_step == 1
        assert execution.variables["tc_name"] == "CMDNAME"


def test_v11_checkpoint_accepts_authoritative_dependency_assignment() -> None:
    source = "tc_name: str = 'CMDNAME'\nSend(command=tc_name)\n"
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        source, current_step=0
    )

    assert supervisor._commit_step(
        execution_id,
        7,
        _ordinary_step_commit(
            procedure, 0, {"ARGS": {}, "tc_name": "CMDNAME"}
        ),
    )
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution.current_step == 1
        assert execution.variables["tc_name"] == "CMDNAME"


def _rejecting_execute(request, service, preflight, **kwargs):
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(
                ElementStage.TRANSPORT,
                "REJECTED",
                preflight.plan.elements[0].element_id,
            )
        ]
    )
    return execute_preflight(
        request,
        service,
        preflight,
        confirmation_actor=kwargs.get("confirmation_actor"),
        provider=provider,
    )


def _commit_for_result(result: dict, *, prompt_resolution=None) -> dict:
    return {
        "step_index": 0,
        "next_step": 1,
        "effects": [
            {
                "event_type": "procedure.telecommand_settled",
                "source": "telecommand-runtime",
                "severity": "info",
                "payload": {
                    **{key: value for key, value in result.items() if key != "type"},
                    "step_index": 0,
                },
            },
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {
                    "step_index": 0,
                    "line": 1,
                    "step_type": "send_tc",
                    "skipped": False,
                },
            },
        ],
        "prompt_resolution": prompt_resolution,
        "variables": {"ARGS": {}},
    }


def test_supervisor_persists_intent_before_dispatch_and_replays_exact_result() -> None:
    supervisor, sessions, handle, request = _fixture()
    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    first = _result(handle.control)
    with sessions() as session:
        events = session.scalars(
            select(Event)
            .where(Event.execution_id == request["execution_id"])
            .order_by(Event.sequence)
        ).all()
        assert [event.event_type for event in events] == [
            "procedure.telecommand_requested",
            "procedure.telecommand_result",
        ]
        assert events[-1].payload == {
            key: value for key, value in first.items() if key != "type"
        }

        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()
    replay_handle = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = replay_handle
    supervisor._handle_telecommand_request(
        request["execution_id"],
        replay_handle,
        {"kind": "telecommand_requested", "generation": 8, **request},
    )
    replayed = _result(replay_handle.control)

    assert replayed == first
    with sessions() as session:
        assert len(
            session.scalars(
                select(Event).where(Event.execution_id == request["execution_id"])
            ).all()
        ) == 2


def test_restart_after_durable_intent_never_redispatches(
    monkeypatch,
) -> None:
    supervisor, sessions, first_handle, request = _fixture()
    started = threading.Event()
    release = threading.Event()
    real_execute = supervisor_module.execute_preflight

    def delayed_execute(*args, **kwargs):
        started.set()
        release.wait(timeout=2)
        return real_execute(*args, **kwargs)

    monkeypatch.setattr(supervisor_module, "execute_preflight", delayed_execute)
    supervisor._handle_telecommand_request(
        request["execution_id"],
        first_handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    assert started.wait(timeout=1)
    with sessions() as session:
        events = session.scalars(select(Event).order_by(Event.sequence)).all()
        assert [event.event_type for event in events] == [
            "procedure.telecommand_requested"
        ]
        execution = session.get(Execution, request["execution_id"])
        execution.worker_generation = 8
        session.commit()

    recovered = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[request["execution_id"]] = recovered
    supervisor._handle_telecommand_request(
        request["execution_id"],
        recovered,
        {"kind": "telecommand_requested", "generation": 8, **request},
    )
    delivered = _result(recovered.control)
    release.set()

    assert delivered["outcome"] == "UNCERTAIN"
    assert delivered["checkpoint"]["provider_call_count"] == 0
    assert delivered["checkpoint"]["elements"][0][
        "effect_certainty"
    ] == "EFFECT_UNKNOWN"
    with sessions() as session:
        events = session.scalars(select(Event).order_by(Event.sequence)).all()
        assert [event.event_type for event in events] == [
            "procedure.telecommand_requested",
            "procedure.telecommand_result",
        ]
        assert events[-1].payload["outcome"] == "UNCERTAIN"


def test_send_checkpoint_requires_exact_durable_result_evidence() -> None:
    supervisor, sessions, handle, request = _fixture()
    forged = {
        "step_index": 0,
        "next_step": 1,
        "effects": [
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {
                    "step_index": 0,
                    "line": 1,
                    "step_type": "send_tc",
                    "skipped": False,
                },
            }
        ],
        "prompt_resolution": None,
        "variables": {"ARGS": {}},
    }
    with pytest.raises(ConflictError, match="durable telecommand intent"):
        supervisor._commit_step(request["execution_id"], 7, forged)

    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    delivered = _result(handle.control)
    exact = {
        **forged,
        "effects": [
            {
                "event_type": "procedure.telecommand_settled",
                "source": "telecommand-runtime",
                "severity": "info",
                "payload": {
                    **{key: value for key, value in delivered.items() if key != "type"},
                    "step_index": 0,
                },
            },
            forged["effects"][0],
        ],
    }

    assert supervisor._commit_step(request["execution_id"], 7, exact)
    with sessions() as session:
        execution = session.get(Execution, request["execution_id"])
        assert execution.current_step == 1
        assert execution.variables == {"ARGS": {}}


def test_supervisor_confirmation_is_bound_to_the_exact_plan_prompt() -> None:
    source = "Send(command='CMDNAME', Confirm=True)\n"
    supervisor, sessions, handle, unsigned = _fixture(source)
    prompt_id = confirmation_prompt_id(
        unsigned["execution_id"], 0, unsigned["plan"]["plan_digest"]
    )
    settlement_id = str(uuid.uuid4())
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "supervisor-v11.spell.py"
    )
    request, _, _ = prepare_send_request(
        unsigned["execution_id"],
        0,
        procedure.steps[0],
        {},
        confirmation={
            "prompt_id": prompt_id,
        },
    )
    with sessions() as session:
        session.add(
            OperatorPrompt(
                id=prompt_id,
                execution_id=unsigned["execution_id"],
                step_index=0,
                state="SETTLED",
                prompt_type="YES_NO",
                input_kind="FIXED_CHOICE",
                question=(
                    "Confirm deterministic simulator telecommand plan "
                    f"{request['plan']['plan_id']}"
                ),
                options=["YES", "NO"],
                default_value="YES",
                settings_snapshot={
                    "PROMPT_WARNING_DELAY": None,
                    "PROMPT_RESPONSE_TIMEOUT": None,
                    "NO_CONTROLLER_GRACE": None,
                },
                settlement_id=settlement_id,
                settlement_outcome="ANSWERED",
                settled_value="YES",
                settled_by="operator@example.test",
            )
        )
        session.commit()

    with pytest.raises(ConflictError, match="confirmation settlement is invalid"):
        supervisor._handle_telecommand_request(
            request["execution_id"],
            handle,
            {"kind": "telecommand_requested", "generation": 7, **request},
        )
    with sessions() as session:
        session.get(OperatorPrompt, prompt_id).default_value = "NO"
        session.commit()

    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    result = _result(handle.control)

    assert result["outcome"] == "SETTLED"
    assert result["checkpoint"]["confirmed_by"].startswith("operator-")

    with pytest.raises(TelecommandRuntimeError, match="does not bind"):
        prepare_send_request(
            request["execution_id"],
            0,
            procedure.steps[0],
            {},
            confirmation={
                "prompt_id": str(uuid.uuid4()),
            },
        )


def test_supervisor_allows_noninteractive_cancel_but_rejects_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "execute_preflight", _rejecting_execute)
    cancel_source = (
        "Send(command='CMDNAME', OnFailure=CANCEL, PromptUser=False)\n"
    )
    supervisor, _, handle, request = _fixture(cancel_source)
    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    cancel_result = _result(handle.control)
    assert cancel_result["successful"] is False
    assert supervisor._commit_step(
        request["execution_id"], 7, _commit_for_result(cancel_result)
    )

    abort_source = "Send(command='CMDNAME', OnFailure=ABORT, PromptUser=False)\n"
    supervisor, _, handle, request = _fixture(abort_source)
    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    abort_result = _result(handle.control)
    with pytest.raises(ConflictError, match="OnFailure=ABORT"):
        supervisor._commit_step(
            request["execution_id"], 7, _commit_for_result(abort_result)
        )


def test_supervisor_binds_failure_continuation_to_exact_result_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "execute_preflight", _rejecting_execute)
    source = "Send(command='CMDNAME', OnFailure=CANCEL)\n"
    supervisor, sessions, handle, request = _fixture(source)
    supervisor._handle_telecommand_request(
        request["execution_id"],
        handle,
        {"kind": "telecommand_requested", "generation": 7, **request},
    )
    result = _result(handle.control)
    result_digest = result["result_digest"]
    prompt_id = failure_prompt_id(request["execution_id"], 0, result_digest)
    settlement_id = str(uuid.uuid4())
    with sessions() as session:
        session.add(
            OperatorPrompt(
                id=prompt_id,
                execution_id=request["execution_id"],
                step_index=0,
                state="SETTLED",
                prompt_type="YES_NO",
                input_kind="FIXED_CHOICE",
                question=failure_prompt_question(result_digest),
                options=["YES", "NO"],
                default_value="NO",
                settings_snapshot={
                    "PROMPT_WARNING_DELAY": None,
                    "PROMPT_RESPONSE_TIMEOUT": None,
                    "NO_CONTROLLER_GRACE": None,
                },
                settlement_id=settlement_id,
                settlement_outcome="ANSWERED",
                settled_value="YES",
                settled_by="operator@example.test",
            )
        )
        session.commit()
    resolution = {
        "prompt_id": prompt_id,
        "settlement_id": settlement_id,
        "outcome": "ANSWERED",
        "response": "YES",
        "command_id": None,
    }
    forged = {**resolution, "prompt_id": str(uuid.uuid4())}
    with pytest.raises(ConflictError, match="approved continuation"):
        supervisor._commit_step(
            request["execution_id"],
            7,
            _commit_for_result(result, prompt_resolution=forged),
        )
    assert supervisor._commit_step(
        request["execution_id"],
        7,
        _commit_for_result(result, prompt_resolution=resolution),
    )
