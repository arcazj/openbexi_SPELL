from __future__ import annotations

import json
import queue
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

import backend.procedure_parser as procedure_parser
import backend.worker as worker_module
from backend.ir_v03 import validate_ir_v03
from backend.models import Command, Event, Execution, Prompt
from backend.procedure_parser import ProcedureCatalog


def _valid_log_step() -> dict[str, Any]:
    return {
        "index": 0,
        "line": 1,
        "column": 1,
        "type": "log",
        "message": "must not execute",
        "level": "info",
    }


def _stored_steps_bytes(client: TestClient, execution_id: str) -> bytes:
    with client.app.state.engine.connect() as connection:
        stored = connection.execute(
            text("SELECT CAST(steps AS TEXT) FROM executions WHERE id = :execution_id"),
            {"execution_id": execution_id},
        ).scalar_one()
    assert type(stored) is str
    return stored.encode("utf-8")


def _stored_ir_columns(client: TestClient, execution_id: str) -> dict[str, bytes]:
    with client.app.state.engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT CAST(steps AS TEXT) AS steps, ir_version, current_step, "
                "total_steps, CAST(variables AS TEXT) AS variables "
                "FROM executions WHERE id = :execution_id"
            ),
            {"execution_id": execution_id},
        ).mappings().one()
    return {
        key: str(row[key]).encode("utf-8")
        for key in ("steps", "ir_version", "current_step", "total_steps", "variables")
    }


def _insert_tampered_execution(client: TestClient, suffix: str) -> tuple[str, int, int]:
    procedure = client.app.state.catalog.get("recovery")
    steps = json.loads(json.dumps(list(procedure.steps)))
    steps[0]["unrecognized_persisted_field"] = "tampered"
    generation = 7
    revision = 11
    with client.app.state.session_factory() as session:
        execution = Execution(
            procedure_id=f"tampered-{suffix}",
            procedure_name="Tampered persisted IR",
            procedure_hash=procedure.sha256,
            procedure_source=procedure.source,
            steps=steps,
            ir_version="0.3",
            variables={},
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key=f"tampered-{suffix}",
            total_steps=len(steps),
            state="recovery_required",
            revision=revision,
            worker_generation=generation,
        )
        session.add(execution)
        session.commit()
        return execution.id, generation, revision


class _AllocationFence:
    def __init__(self) -> None:
        self.queue_calls = 0
        self.process_calls = 0

    def Queue(self) -> Any:
        self.queue_calls += 1
        raise AssertionError("IR rejection reached multiprocessing.Queue allocation")

    def Process(self, *_args: Any, **_kwargs: Any) -> Any:
        self.process_calls += 1
        raise AssertionError("IR rejection reached multiprocessing.Process creation")


def _insert_persisted_row_mutation(
    client: TestClient,
    *,
    suffix: str,
    command_type: str,
    mutation: str,
) -> tuple[str, int, int]:
    procedure = client.app.state.catalog.get("recovery")
    steps = json.loads(json.dumps(list(procedure.steps)))
    values: dict[str, Any] = {
        "steps": steps,
        "ir_version": "0.3",
        "variables": {},
        "current_step": 0,
        "total_steps": len(steps),
    }
    open_prompt_step: int | None = None
    if mutation == "steps":
        steps[0]["unrecognized_persisted_field"] = "tampered"
    elif mutation == "ir_version":
        values["ir_version"] = "0.4"
    elif mutation == "current_step":
        values["current_step"] = len(steps) + 1
    elif mutation == "total_steps":
        values["total_steps"] = len(steps) + 1
    elif mutation == "checkpoint_variables":
        values["current_step"] = 2
        values["variables"] = {"undeclared": "tampered"}
    elif mutation == "resume_prompt":
        open_prompt_step = 0
    else:
        raise AssertionError(f"unsupported test mutation: {mutation}")

    generation = 7
    revision = 11
    with client.app.state.session_factory() as session:
        execution = Execution(
            procedure_id=f"persisted-row-{suffix}",
            procedure_name="Persisted row mutation",
            procedure_hash=procedure.sha256,
            procedure_source=procedure.source,
            steps=values["steps"],
            ir_version=values["ir_version"],
            variables=values["variables"],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key=f"persisted-row-{suffix}",
            total_steps=values["total_steps"],
            current_step=values["current_step"],
            state="ready" if command_type == "start" else "recovery_required",
            revision=revision,
            worker_generation=generation,
        )
        session.add(execution)
        session.flush()
        if open_prompt_step is not None:
            session.add(
                Prompt(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    step_index=open_prompt_step,
                    status="open",
                    question="Tampered resume prompt",
                    choices=["continue"],
                    default_choice="continue",
                )
            )
        session.commit()
        return execution.id, generation, revision


def _assert_bounded_ir_rejection(event: Event, expected_path: str) -> None:
    assert event.event_type == "execution.ir_rejected"
    assert event.source == "supervisor"
    assert event.severity == "error"
    assert set(event.payload) == {"phase", "code", "path", "message"}
    assert event.payload["phase"] == "supervisor_preflight"
    assert event.payload["code"] == "IR_VALIDATION_FAILED"
    assert type(event.payload["path"]) is str
    assert event.payload["path"].startswith(expected_path)
    assert len(event.payload["path"]) <= 160
    assert type(event.payload["message"]) is str
    assert len(event.payload["message"]) <= 240


def _recover_tampered_execution(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    suffix: str,
) -> tuple[str, int, bytes, _AllocationFence]:
    supervisor = client.app.state.supervisor
    execution_id, generation, revision = _insert_tampered_execution(client, suffix)
    stored_before = _stored_steps_bytes(client, execution_id)
    fence = _AllocationFence()
    monkeypatch.setattr(supervisor, "_ctx", fence)

    supervisor.issue_command(
        execution_id=execution_id,
        command_type="recover",
        expected_revision=revision,
        idempotency_key=f"recover-{suffix}",
        actor="pytest-operator",
        role="operator",
        reason="verify persisted IR preflight rejection",
        correlation_id=None,
        payload={},
    )
    return execution_id, generation, stored_before, fence


def test_parser_postvalidation_rejects_invalid_compiler_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid_step = {**_valid_log_step(), "compiler_only_field": True}

    def compile_invalid_output(
        _compiler: Any, _tree: Any
    ) -> tuple[str, list[dict[str, Any]]]:
        return "", [invalid_step]

    monkeypatch.setattr(procedure_parser._Compiler, "compile", compile_invalid_output)
    catalog = ProcedureCatalog(tmp_path)

    with pytest.raises(procedure_parser.ProcedureValidationError) as rejected:
        catalog.validate_source('Log("source is valid")\n')

    diagnostic = rejected.value.diagnostics[0]
    assert diagnostic.code == "SPELL105"
    assert "$.steps[0]" in diagnostic.message


def test_initial_start_accepts_a_valid_first_prompt(
    client: TestClient,
) -> None:
    procedure = client.app.state.catalog.validate_source(
        "Prompt('Start here?', choices=['yes'], default='yes')\n",
        source_name="initial-prompt.spell.py",
    )
    execution = client.app.state.supervisor.create_execution(
        procedure=procedure,
        context_id="simulator",
        actor="pytest-operator",
        role="operator",
        reason="verify initial prompt startup",
        idempotency_key="initial-prompt-start",
    )

    assert execution.state in {"starting", "running", "prompting"}
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        assert stored is not None
        assert stored.worker_generation == 1


def test_supervisor_rejects_tampered_ir_before_generation_or_process_allocation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_id, generation, stored_before, fence = _recover_tampered_execution(
        client, monkeypatch, suffix="durable-rejection"
    )

    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.scalar(
            select(Command).where(
                Command.execution_id == execution_id,
                Command.idempotency_key == "recover-durable-rejection",
            )
        )
        events = session.scalars(
            select(Event)
            .where(Event.execution_id == execution_id)
            .order_by(Event.sequence)
        ).all()

        assert execution is not None
        assert execution.worker_generation == generation
        assert execution.state == "recovery_required"
        assert command is not None and command.status == "failed"
        event_types = [event.event_type for event in events]
        assert event_types == [
            "command.accepted",
            "execution.state_changed",
            "execution.ir_rejected",
            "execution.state_changed",
            "command.failed",
        ]
        rejected = events[2]
        assert rejected.source == "supervisor"
        assert rejected.severity == "error"
        assert set(rejected.payload) == {"phase", "code", "path", "message"}
        assert rejected.payload["phase"] == "supervisor_preflight"
        assert rejected.payload["code"] == "IR_VALIDATION_FAILED"
        assert type(rejected.payload["path"]) is str
        assert len(rejected.payload["path"]) <= 160
        assert type(rejected.payload["message"]) is str
        assert len(rejected.payload["message"]) <= 240
        assert event_types.index("execution.ir_rejected") < event_types.index("command.failed")

    assert _stored_steps_bytes(client, execution_id) == stored_before
    assert fence.queue_calls == 0
    assert fence.process_calls == 0


@pytest.mark.parametrize(
    ("suffix", "command_type", "mutation", "expected_path"),
    [
        pytest.param(
            "initial-start-steps",
            "start",
            "steps",
            "$.steps[0]",
            id="initial-start-step-tampering",
        ),
        pytest.param(
            "stored-version",
            "recover",
            "ir_version",
            "$.ir_version",
            id="stored-ir-version",
        ),
        pytest.param(
            "stored-current-step",
            "recover",
            "current_step",
            "$.start_step",
            id="stored-current-step",
        ),
        pytest.param(
            "stored-total-steps",
            "recover",
            "total_steps",
            "$.total_steps",
            id="stored-total-steps",
        ),
        pytest.param(
            "stored-checkpoint",
            "recover",
            "checkpoint_variables",
            "$.checkpoint_variables",
            id="stored-checkpoint-variables",
        ),
        pytest.param(
            "resume-prompt-mismatch",
            "recover",
            "resume_prompt",
            "$.resume_prompt_id",
            id="resume-prompt-mismatch",
        ),
    ],
)
def test_persisted_row_mutations_fail_closed_before_worker_allocation(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    command_type: str,
    mutation: str,
    expected_path: str,
) -> None:
    supervisor = client.app.state.supervisor
    execution_id, generation, revision = _insert_persisted_row_mutation(
        client,
        suffix=suffix,
        command_type=command_type,
        mutation=mutation,
    )
    stored_before = _stored_ir_columns(client, execution_id)
    fence = _AllocationFence()
    monkeypatch.setattr(supervisor, "_ctx", fence)

    supervisor.issue_command(
        execution_id=execution_id,
        command_type=command_type,
        expected_revision=revision,
        idempotency_key=f"{command_type}-{suffix}",
        actor="pytest-operator",
        role="operator",
        reason="verify persisted row IR rejection boundary",
        correlation_id=None,
        payload={},
    )

    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.scalar(
            select(Command).where(
                Command.execution_id == execution_id,
                Command.idempotency_key == f"{command_type}-{suffix}",
            )
        )
        events = session.scalars(
            select(Event)
            .where(Event.execution_id == execution_id)
            .order_by(Event.sequence)
        ).all()

        assert execution is not None
        assert execution.worker_generation == generation
        assert execution.state == "recovery_required"
        assert command is not None and command.status == "failed"
        assert "persisted execution IR failed validation" in command.result_payload["error"]
        event_types = [event.event_type for event in events]
        assert event_types == [
            "command.accepted",
            "execution.state_changed",
            "execution.ir_rejected",
            "execution.state_changed",
            "command.failed",
        ]
        _assert_bounded_ir_rejection(events[2], expected_path)
        assert event_types.index("execution.ir_rejected") < event_types.index(
            "command.failed"
        )

    assert _stored_ir_columns(client, execution_id) == stored_before
    assert fence.queue_calls == 0
    assert fence.process_calls == 0


def test_rejection_audit_failure_still_prevents_worker_allocation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = client.app.state.supervisor
    original_add_event = supervisor._add_event

    def fail_rejection_audit(
        session: Any,
        execution: Execution,
        event_type: str,
        *args: Any,
        **kwargs: Any,
    ) -> Event:
        if event_type == "execution.ir_rejected":
            raise RuntimeError("forced rejection audit persistence failure")
        return original_add_event(session, execution, event_type, *args, **kwargs)

    monkeypatch.setattr(supervisor, "_add_event", fail_rejection_audit)
    execution_id, generation, stored_before, fence = _recover_tampered_execution(
        client, monkeypatch, suffix="audit-failure"
    )

    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.scalar(
            select(Command).where(
                Command.execution_id == execution_id,
                Command.idempotency_key == "recover-audit-failure",
            )
        )
        event_types = session.scalars(
            select(Event.event_type)
            .where(Event.execution_id == execution_id)
            .order_by(Event.sequence)
        ).all()

        assert execution is not None
        assert execution.worker_generation == generation
        assert execution.state == "recovery_required"
        assert command is not None and command.status == "failed"
        assert "execution.ir_rejected" not in event_types
        assert "command.failed" in event_types
        assert "forced rejection audit persistence failure" in command.result_payload["error"]

    assert _stored_steps_bytes(client, execution_id) == stored_before
    assert fence.queue_calls == 0
    assert fence.process_calls == 0


@pytest.mark.parametrize(
    ("ir_version", "steps"),
    [
        pytest.param("0.4", [_valid_log_step()], id="wrong-version"),
        pytest.param("0.3", None, id="unsized-payload"),
        pytest.param(
            "0.3",
            [{**_valid_log_step(), "unrecognized_worker_field": True}],
            id="malformed-payload",
        ),
    ],
)
def test_worker_rejects_ir_before_started_ack_checkpoint_prompt_or_effect(
    ir_version: str,
    steps: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validate_ir_v03("0.3", [_valid_log_step()])
    control: queue.Queue[dict[str, Any]] = queue.Queue()
    output: queue.Queue[dict[str, Any]] = queue.Queue()
    monkeypatch.setattr(worker_module, "_replace_worker_environment", lambda: None)

    worker_module.worker_main(
        "rejected-execution",
        3,
        ir_version,
        steps,
        0,
        "start-command",
        None,
        {},
        control,
        output,
    )
    messages: list[dict[str, Any]] = []
    while not output.empty():
        messages.append(output.get_nowait())

    assert [message["kind"] for message in messages] == ["event", "state", "terminal"]
    rejected = messages[0]
    assert rejected["event_type"] == "worker.ir_rejected"
    assert rejected["source"] == "worker"
    assert rejected["severity"] == "error"
    assert set(rejected["payload"]) == {"phase", "code", "path", "message"}
    assert rejected["payload"]["phase"] == "worker_preflight"
    assert rejected["payload"]["code"] == "IR_VALIDATION_FAILED"
    assert len(rejected["payload"]["path"]) <= 160
    assert len(rejected["payload"]["message"]) <= 240

    assert not any(
        message.get("event_type")
        in {
            "worker.started",
            "step.started",
            "procedure.log",
            "telemetry.sample",
            "step.completed",
        }
        for message in messages
    )
    assert not any(message["kind"] in {"step_commit", "prompt_opened"} for message in messages)
    assert not any(
        message["kind"] == "state" and "command_id" in message for message in messages
    )
