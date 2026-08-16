from __future__ import annotations

import queue
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from backend.procedure_parser import ProcedureCatalog
from backend.operator_serialization import command_dict as operator_command_dict
from backend.supervisor import Supervisor, WorkerHandle


DIGEST = "a" * 64


class Control:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def put(self, value: dict[str, Any]) -> None:
        self.items.append(value)


def _fake_live_worker_handle() -> WorkerHandle:
    def worker_queue() -> SimpleNamespace:
        return SimpleNamespace(close=lambda: None, cancel_join_thread=lambda: None)

    return WorkerHandle(
        process=SimpleNamespace(
            is_alive=lambda: True,
            kill=lambda: None,
            join=lambda timeout=None: None,
        ),
        control=worker_queue(),
        output=worker_queue(),
        generation=1,
    )


class Session:
    def __init__(self, objects: dict[tuple[type, str], Any]) -> None:
        self.objects = objects

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, model, identity, **_kwargs):
        return self.objects.get((model, identity))

    def scalar(self, _statement):
        return None

    def execute(self, _statement):
        return SimpleNamespace(rowcount=1)

    def commit(self):
        return None


class SessionFactory:
    def __init__(self, objects: dict[tuple[type, str], Any]) -> None:
        self.objects = objects

    def __call__(self):
        return Session(self.objects)


def _supervisor(service: Any = None) -> Supervisor:
    supervisor = Supervisor.__new__(Supervisor)
    supervisor.operator_service = service
    supervisor._lock = threading.RLock()
    supervisor._workers = {}
    supervisor._startproc_watchers = set()
    supervisor._abort_cleanup_barriers = set()
    supervisor._recovery_pause_pending = set()
    supervisor._prompt_settlement_attempts = {}
    supervisor._durable_delivery_attempts = {}
    supervisor._closed = False
    supervisor.command_ack_timeout_seconds = 0.1
    return supervisor


def _persist_applying_command(
    client,
    command_type: str,
    *,
    execution_state: str,
    projection_state: str,
) -> tuple[Supervisor, Any, dict[str, Any]]:
    from backend.models import Execution
    from backend.operator_models import ExecutionOperatorState, OperatorCommand

    supervisor = client.app.state.supervisor
    service = client.app.state.operator_service
    procedure = client.app.state.catalog.validate_source(
        'Log("one")\nLog("two")\nPrompt("done", type="OK")\n',
        f"runtime-{command_type.lower()}.spell.py",
    )
    execution = supervisor.create_execution(
        procedure,
        "runtime-test",
        "admin",
        "runtime recovery test",
        f"runtime-recovery-{command_type.lower()}",
        automatic=False,
    )
    command_id = f"operator-{command_type.lower()}"
    with supervisor.session_factory() as session:
        stored = session.get(Execution, execution.id)
        projection = session.get(ExecutionOperatorState, execution.id)
        assert stored is not None and projection is not None
        stored.state = execution_state
        stored.current_step = 0
        stored.revision += 1
        projection.state = projection_state
        projection.current_step = 0
        projection.revision += 1
        command = OperatorCommand(
            id=command_id,
            execution_id=execution.id,
            command_type=command_type,
            state="APPLYING",
            idempotency_key=f"applying-{command_type.lower()}",
            request_digest="a" * 64,
            expected_execution_revision=stored.revision,
            accepted_execution_revision=stored.revision,
            safe_point="REQUIRED",
            actor="runtime-test",
            role="admin",
            reason="runtime recovery test",
            correlation_id=f"correlation-{command_type.lower()}",
            target={"target_step": 2} if command_type == "GOTO" else {},
            request_payload={},
            result_payload={"application_step": 0},
            application_safe_point_id="safe-point",
            effect_certainty_before="NO_EFFECT",
            effect_certainty_after="NO_EFFECT",
            revision=1,
        )
        session.add(command)
        session.commit()
        result = operator_command_dict(command)
    return supervisor, service, result


def test_startproc_worker_message_uses_exact_admission_key() -> None:
    class Service:
        def __init__(self) -> None:
            self.declaration = None

        def admit_startproc(
            self,
            parent,
            operation,
            step,
            declaration,
            *,
            worker_generation=None,
        ):
            self.declaration = declaration
            return {
                "id": operation,
                "state": "SETTLED",
                "child_execution_id": "child",
                "result": {"outcome": "CHILD_ADMITTED"},
                "rejection_code": None,
            }

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    handle = SimpleNamespace(control=control)
    supervisor._handle_startproc_request(
        "parent",
        handle,
        {
            "startproc_id": "operation",
            "step_index": 2,
            "child_reference": "ops/child",
            "arguments": {"value": 1},
            "arguments_digest": DIGEST,
            "blocking": False,
            "visible": True,
            "automatic": True,
        },
    )
    assert service.declaration["child_reference"] == "ops/child"
    assert control.items == [
        {
            "type": "startproc_result",
            "startproc_id": "operation",
            "delivery_revision": 0,
            "outcome": "SETTLED",
            "child_execution_id": "child",
            "rejection_code": None,
            "result": {"outcome": "CHILD_ADMITTED"},
        }
    ]


def test_immutable_bundle_actions_register_before_worker_admission() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    procedure = catalog.validate_source(
        'ready: bool = False\n'
        'UserAction("ready", "Mark ready", handler=['
        '{"op": "SET_LITERAL", "name": "ready", '
        '"declared_type": "bool", "value": True}])\n'
        'Prompt("Hold", type="OK")\n',
        "actions.spell.py",
    )

    class Service:
        def __init__(self) -> None:
            self.projections = []
            self.registrations = []

        def ensure_execution_projection(self, execution_id, **kwargs):
            self.projections.append((execution_id, kwargs))

        def register_user_action(self, execution_id, definition, **kwargs):
            self.registrations.append((execution_id, definition, kwargs))

    service = Service()
    supervisor = _supervisor(service)
    supervisor.catalog = catalog

    supervisor._admit_operator_bundle("execution", procedure, automatic=True)
    supervisor._admit_operator_bundle("execution", procedure, automatic=True)

    assert service.projections[0] == (
        "execution",
        {
            "actor": "operator-bootstrap",
            "automatic": True,
            "background_allowed": False,
            "visible": True,
            "catalog_revision_id": None,
            "predecessor_execution_id": None,
            "depth": 0,
            "ownership_mode": "CONTROL_LOST",
            "settings": {},
            "authoritative": True,
        },
    )
    first = service.registrations[0]
    second = service.registrations[1]
    assert first[1] == second[1]
    assert first[2]["idempotency_key"] == second[2]["idempotency_key"]
    assert first[1]["source_digest"] == procedure.sha256
    assert first[1]["handler"] == [
        {
            "op": "SET_LITERAL",
            "name": "ready",
            "declared_type": "bool",
            "value": True,
        }
    ]


def test_background_application_uses_atomic_service_hook() -> None:
    class Service:
        def __init__(self) -> None:
            self.applied = None

        def get_execution_projection(self, execution_id):
            return {"current_safe_point_id": "safe-point"}

        def apply_background_command(self, command_id, safe_point_id):
            self.applied = (command_id, safe_point_id)

    service = Service()
    supervisor = _supervisor(service)
    supervisor._settle_operator_command(
        "execution",
        {"command_id": "command", "command_type": "BACKGROUND"},
        settled=True,
    )
    assert service.applied == ("command", "safe-point")


def test_safe_point_ack_precedes_atomic_breakpoint_pause() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=4,
        procedure_hash=DIGEST,
        revision=9,
    )

    class Service:
        def __init__(self) -> None:
            self.recorded = None

        def record_safe_point(self, execution_id, **values):
            self.recorded = (execution_id, values)

        def consume_breakpoint(
            self, execution_id, line, source_digest, **_kwargs
        ):
            return {"id": "breakpoint", "one_shot": True}

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    handle = SimpleNamespace(control=control, generation=4)
    supervisor._workers["execution"] = handle
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})
    supervisor._record_worker_safe_point(
        "execution",
        4,
        {
            "safe_point_token": "token",
            "safe_point_kind": "BEFORE_STATEMENT",
            "step_index": 1,
            "line": 7,
            "lexical_frame_id": "frame:root",
            "reachability_id": "reach:1",
            "effect_certainty": "NO_EFFECT",
        },
    )
    recorded_execution, recorded_point = service.recorded
    assert recorded_execution == "execution"
    assert recorded_point["safe_point_type"] == "BEFORE_STATEMENT"
    assert recorded_point["lexical_frame_id"] == "frame:root"
    assert recorded_point["reachability_id"] == "reach:1"
    assert control.items[0] == {"type": "safe_point_ack", "safe_point_token": "token"}
    assert control.items[1]["type"] == "pause"
    assert control.items[1]["command_id"].startswith("breakpoint:breakpoint:")


def test_recovery_safe_point_does_not_consume_one_shot_breakpoint() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=4,
        procedure_hash=DIGEST,
        revision=9,
    )

    class Service:
        def __init__(self) -> None:
            self.breakpoint_calls = 0

        @staticmethod
        def record_safe_point(*_args, **_kwargs):
            return None

        def consume_breakpoint(self, *_args):
            self.breakpoint_calls += 1
            return {"id": "one-shot", "one_shot": True}

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(control=control, generation=4)
    supervisor._recovery_pause_pending.add("execution")
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})

    supervisor._record_worker_safe_point(
        "execution",
        4,
        {
            "safe_point_token": "recovery-token",
            "safe_point_kind": "BEFORE_STATEMENT",
            "step_index": 1,
            "line": 7,
            "effect_certainty": "NO_EFFECT",
        },
    )

    assert service.breakpoint_calls == 0
    assert "execution" not in supervisor._recovery_pause_pending
    assert control.items == [
        {"type": "safe_point_ack", "safe_point_token": "recovery-token"}
    ]


def test_paused_operator_command_is_refenced_before_worker_delivery() -> None:
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "STEP_OVER",
        "state": "ACCEPTED",
        "request": {},
        "target": {},
    }

    class Service:
        def __init__(self) -> None:
            self.begin_calls = []

        @staticmethod
        def transition_operator_command(_command_id, state, **_fields):
            return {**command, "state": state}

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        def begin_operator_command_application(
            self, command_id, safe_point_id=None, **_kwargs
        ):
            self.begin_calls.append((command_id, safe_point_id))
            return {
                **command,
                "state": "APPLYING",
                "application_safe_point_id": safe_point_id,
            }

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )

    result = supervisor.dispatch_operator_command(command)

    assert result["state"] == "APPLYING"
    assert service.begin_calls == [("command", "safe-point")]
    assert control.items == [
        {
            "type": "step_over",
            "command_id": "command",
            "operator_application_safe_point_id": "safe-point",
        }
    ]


def test_stale_operator_command_is_superseded_without_worker_delivery() -> None:
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "RUN",
        "state": "ACCEPTED",
        "request": {},
        "target": {},
    }

    class Service:
        @staticmethod
        def transition_operator_command(_command_id, state, **_fields):
            return {**command, "state": state}

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        @staticmethod
        def begin_operator_command_application(
            _command_id, _safe_point_id=None, **_kwargs
        ):
            return {
                **command,
                "state": "SUPERSEDED",
                "rejection_code": "CONTROL_FENCE_STALE",
                "effect_certainty_after": "NO_EFFECT",
                "result": {"target_mutation": "NONE"},
            }

    supervisor = _supervisor(Service())
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )

    result = supervisor.dispatch_operator_command(command)

    assert result["state"] == "SUPERSEDED"
    assert result["rejection_code"] == "CONTROL_FENCE_STALE"
    assert result["effect_certainty_after"] == "NO_EFFECT"
    assert result["result"] == {"target_mutation": "NONE"}
    assert control.items == []


def test_operator_command_message_does_not_trust_request_or_target_envelopes() -> None:
    malicious = {
        "type": "abort",
        "command_id": "attacker-command",
        "operator_application_safe_point_id": "attacker-safe-point",
        "target_step": 99,
        "value": "untrusted",
    }
    step = Supervisor._operator_command_message(
        {
            "id": "accepted-command",
            "type": "STEP",
            "application_safe_point_id": "accepted-safe-point",
            "request": malicious,
            "target": malicious,
        }
    )
    assert step == {
        "type": "step",
        "command_id": "accepted-command",
        "operator_application_safe_point_id": "accepted-safe-point",
    }

    goto = Supervisor._operator_command_message(
        {
            "id": "goto-command",
            "type": "GOTO",
            "application_safe_point_id": "goto-safe-point",
            "request": malicious,
            "target": {**malicious, "target_step": 4},
        }
    )
    assert goto == {
        "type": "goto",
        "command_id": "goto-command",
        "operator_application_safe_point_id": "goto-safe-point",
        "target_step": 4,
    }


def test_applying_operator_command_replays_at_fresh_worker_safe_point() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=8,
        procedure_hash=DIGEST,
        revision=12,
    )
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "PAUSE",
        "state": "APPLYING",
        "request": {},
        "target": {},
        "application_safe_point_id": "previous-safe-point",
    }

    class Service:
        def __init__(self) -> None:
            self.begin_calls = []

        @staticmethod
        def record_safe_point(*_args, **_kwargs):
            return None

        def begin_operator_command_application(
            self, command_id, safe_point_id=None, **_kwargs
        ):
            self.begin_calls.append((command_id, safe_point_id))
            return command

    service = Service()
    supervisor = _supervisor(service)
    supervisor._waiting_operator_command = lambda _execution_id: command
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(control=control, generation=8)

    supervisor._record_worker_safe_point(
        "execution",
        8,
        {
            "safe_point_token": "token",
            "safe_point_kind": "BEFORE_STATEMENT",
            "step_index": 3,
            "line": 9,
            "effect_certainty": "NO_EFFECT",
        },
    )

    assert len(service.begin_calls) == 1
    assert service.begin_calls[0][0] == "command"
    assert service.begin_calls[0][1] != "previous-safe-point"
    assert control.items[0]["type"] == "pause"
    assert control.items[0]["command_id"] == "command"
    assert control.items[1] == {"type": "safe_point_ack", "safe_point_token": "token"}


def test_worker_command_ack_uses_fenced_application_settlement() -> None:
    class Service:
        def __init__(self) -> None:
            self.settlement = None

        @staticmethod
        def transition_operator_command(command_id, state, **fields):
            return {"id": command_id, "state": state, **fields}

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

        def settle_operator_command_application(self, command_id, **fields):
            self.settlement = (command_id, fields)
            return {"id": command_id, "state": "SETTLED", **fields}

    service = Service()
    supervisor = _supervisor(service)

    supervisor._settle_operator_command(
        "execution",
        {
            "command_id": "command",
            "command_type": "GOTO",
            "result": {"target_step": 4},
            "checkpoint_step": 4,
            "effect_certainty": "EFFECT_CONFIRMED",
        },
        settled=True,
    )

    assert service.settlement == (
        "command",
        {
            "result": {"target_step": 4},
            "application_safe_point_id": "safe-point",
            "effect_certainty": "EFFECT_CONFIRMED",
            "current_step": 4,
        },
    )


def test_concurrent_command_delivery_queues_one_application_revision() -> None:
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "STEP",
        "state": "WAITING_SAFE_POINT",
        "revision": 2,
        "request": {},
        "target": {},
    }
    barrier = threading.Barrier(2)

    class Service:
        @staticmethod
        def begin_operator_command_application(
            _command_id, safe_point_id=None, **_kwargs
        ):
            barrier.wait(timeout=1)
            return {
                **command,
                "state": "APPLYING",
                "revision": 3,
                "application_safe_point_id": safe_point_id,
            }

    supervisor = _supervisor(Service())
    control = Control()
    handle = SimpleNamespace(control=control)
    failures: list[BaseException] = []

    def deliver() -> None:
        try:
            supervisor._queue_operator_command_at_safe_point(
                command, handle, "safe-point"
            )
        except BaseException as exc:  # pragma: no cover - assertion reports it
            failures.append(exc)

    threads = [threading.Thread(target=deliver) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)

    assert failures == []
    assert all(not thread.is_alive() for thread in threads)
    assert control.items == [
        {
            "type": "step",
            "command_id": "command",
            "operator_application_safe_point_id": "safe-point",
        }
    ]


def test_step_checkpoint_evidence_settles_without_replaying_effect() -> None:
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "STEP",
        "state": "APPLYING",
        "revision": 3,
        "request": {},
        "target": {},
        "result": {"application_step": 2},
    }

    class Service:
        @staticmethod
        def reconcile_operator_command_application(command_id):
            assert command_id == "command"
            return {
                **command,
                "state": "SETTLED",
                "result": {
                    "application_step": 2,
                    "target_step": 3,
                    "checkpoint_evidence": True,
                },
            }

        @staticmethod
        def begin_operator_command_application(*_args, **_kwargs):
            raise AssertionError("settled checkpoint evidence must not be replayed")

    supervisor = _supervisor(Service())
    control = Control()
    result = supervisor._queue_operator_command_at_safe_point(
        command, SimpleNamespace(control=control), "safe-point"
    )

    assert result["state"] == "SETTLED"
    assert result["result"]["checkpoint_evidence"] is True
    assert control.items == []


@pytest.mark.parametrize("command_type", ["STEP", "SKIP", "GOTO"])
def test_restart_replays_applying_worker_command_at_original_checkpoint(
    client,
    monkeypatch: pytest.MonkeyPatch,
    command_type: str,
) -> None:
    supervisor, _service, command = _persist_applying_command(
        client,
        command_type,
        execution_state="paused",
        projection_state="PAUSED",
    )
    resumed: list[tuple[str, dict[str, Any], str]] = []
    monkeypatch.setattr(
        supervisor,
        "_resume_operator_worker_application",
        lambda execution_id, application, state: resumed.append(
            (execution_id, application, state)
        ),
    )

    supervisor.reconcile_orphaned_executions()

    assert len(resumed) == 1
    assert resumed[0][0] == command["execution_id"]
    assert resumed[0][1]["id"] == command["id"]
    assert resumed[0][1]["state"] == "APPLYING"
    assert resumed[0][2] == "paused"


@pytest.mark.parametrize(
    ("command_type", "terminal_state", "projection_state"),
    [
        ("RELOAD", "completed", "FINISHED"),
        ("RECOVER", "failed", "ERROR"),
    ],
)
def test_successor_creation_is_reused_after_crash_before_command_settlement(
    client,
    monkeypatch: pytest.MonkeyPatch,
    command_type: str,
    terminal_state: str,
    projection_state: str,
) -> None:
    from backend.models import Execution

    supervisor, _service, command = _persist_applying_command(
        client,
        command_type,
        execution_state=terminal_state,
        projection_state=projection_state,
    )
    spawned: list[str] = []

    def spawn(execution_id, _command_id, **_kwargs):
        spawned.append(execution_id)
        handle = _fake_live_worker_handle()
        supervisor._workers[execution_id] = handle
        return handle

    monkeypatch.setattr(supervisor, "_spawn_worker", spawn)
    monkeypatch.setattr(supervisor, "_arm_command_watchdog", lambda *_args: None)
    created = supervisor._create_successor_execution(
        command["execution_id"],
        command_id=command["id"],
        actor=command["actor"],
        reason=command["reason"],
        recover=command_type == "RECOVER",
    )

    settled = supervisor._apply_successor_operator_command(
        command, asynchronous_prepare=False
    )
    replayed = supervisor._apply_successor_operator_command(
        command, asynchronous_prepare=False
    )

    assert settled["state"] == replayed["state"] == "SETTLED"
    assert settled["result"]["execution_id"] == created.id
    with supervisor.session_factory() as session:
        successors = session.query(Execution).filter(
            Execution.creation_idempotency_key == f"v06-successor:{command['id']}"
        ).all()
        assert len(successors) == 1
        assert successors[0].state == (
            "recovering" if command_type == "RECOVER" else "ready"
        )
    assert len(spawned) == (1 if command_type == "RECOVER" else 0)


@pytest.mark.parametrize(
    ("command_type", "terminal_state", "projection_state"),
    [
        ("RELOAD", "completed", "FINISHED"),
        ("RECOVER", "failed", "ERROR"),
    ],
)
def test_restart_prepares_settled_successor_exactly_once(
    client,
    monkeypatch: pytest.MonkeyPatch,
    command_type: str,
    terminal_state: str,
    projection_state: str,
) -> None:
    from backend.models import Execution

    supervisor, service, command = _persist_applying_command(
        client,
        command_type,
        execution_state=terminal_state,
        projection_state=projection_state,
    )
    successor = supervisor._create_successor_execution(
        command["execution_id"],
        command_id=command["id"],
        actor=command["actor"],
        reason=command["reason"],
        recover=command_type == "RECOVER",
    )
    service.settle_operator_command_application(
        command["id"],
        result={
            "predecessor_execution_id": command["execution_id"],
            "execution_id": successor.id,
            "state": "REQUESTED",
        },
        application_safe_point_id=command["application_safe_point_id"],
        effect_certainty="NO_EFFECT",
    )
    spawned: list[str] = []

    def spawn(execution_id, _command_id, **_kwargs):
        spawned.append(execution_id)
        handle = _fake_live_worker_handle()
        supervisor._workers[execution_id] = handle
        return handle

    monkeypatch.setattr(supervisor, "_spawn_worker", spawn)
    monkeypatch.setattr(supervisor, "_arm_command_watchdog", lambda *_args: None)

    supervisor.reconcile_orphaned_executions()
    supervisor.reconcile_orphaned_executions()

    with supervisor.session_factory() as session:
        stored = session.get(Execution, successor.id)
        assert stored is not None
        assert stored.state == (
            "recovering" if command_type == "RECOVER" else "ready"
        )
    assert len(spawned) == (1 if command_type == "RECOVER" else 0)


def test_successor_failure_does_not_persist_exception_details() -> None:
    secret = "postgresql://operator:plaintext@example.invalid/app"

    class Service:
        @staticmethod
        def transition_operator_command(command_id, state, **fields):
            return {"id": command_id, "state": state, **fields}

    supervisor = _supervisor(Service())
    supervisor._create_successor_execution = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError(secret)
    )
    result = supervisor._apply_successor_operator_command(
        {
            "id": "reload",
            "execution_id": "predecessor",
            "type": "RELOAD",
            "state": "APPLYING",
            "actor": "operator",
            "reason": "reload",
        },
        asynchronous_prepare=False,
    )
    assert result["rejection_code"] == "SUCCESSOR_CREATION_FAILED"
    assert result["result"]["target_mutation"] == "UNKNOWN"
    assert secret not in repr(result)


def test_safe_point_reserves_command_then_action_then_inspection() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=5,
        procedure_hash=DIGEST,
        revision=10,
    )
    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "PAUSE",
        "state": "WAITING_SAFE_POINT",
        "revision": 0,
        "request": {},
        "target": {},
    }

    class Service:
        def __init__(self) -> None:
            self.command_pending = True
            self.action_pending = True
            self.calls: list[str] = []

        @staticmethod
        def record_safe_point(*_args, **_kwargs):
            return None

        def begin_operator_command_application(
            self, _command_id, safe_point_id=None, **_kwargs
        ):
            self.calls.append("command")
            return {
                **command,
                "state": "APPLYING",
                "revision": 1,
                "application_safe_point_id": safe_point_id,
            }

        def list_replayable_user_action_invocations(self, _execution_id=None):
            if not self.action_pending:
                return []
            return [
                {
                    "id": "action",
                    "execution_id": "execution",
                    "delivery_revision": 0,
                    "pinned_handler": [
                        {"op": "LOG", "message": "action", "severity": "info"}
                    ],
                }
            ]

        def begin_user_action_application(
            self, invocation_id, safe_point_id=None, **_kwargs
        ):
            self.calls.append(invocation_id)
            return {
                "id": invocation_id,
                "execution_id": "execution",
                "state": "APPLYING",
                "delivery_revision": 0,
                "application_safe_point_id": safe_point_id,
                "pinned_handler": [
                    {"op": "LOG", "message": "action", "severity": "info"}
                ],
            }

        @staticmethod
        def mark_user_action_delivery_attempt(_invocation_id, **_kwargs):
            return None

        @staticmethod
        def list_unacked_inspection_edits(_execution_id=None):
            return [
                {
                    "id": "edit",
                    "execution_id": "execution",
                    "revision": 1,
                    "variables": {"value": 2},
                }
            ]

        def begin_inspection_edit_application(
            self, edit_id, revision, safe_point_id=None, **_kwargs
        ):
            self.calls.append(edit_id)
            return {
                "id": edit_id,
                "execution_id": "execution",
                "state": "APPLYING",
                "revision": revision,
                "application_safe_point_id": safe_point_id,
                "variables": {"value": 2},
            }

        @staticmethod
        def mark_inspection_edit_delivery_attempt(
            _edit_id, _revision, **_kwargs
        ):
            return None

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})
    supervisor._waiting_operator_command = lambda _execution_id: (
        command if service.command_pending else None
    )
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(control=control, generation=5)

    def record(step_index: int) -> None:
        supervisor._record_worker_safe_point(
            "execution",
            5,
            {
                "safe_point_token": f"token-{step_index}",
                "safe_point_kind": "BEFORE_STATEMENT",
                "step_index": step_index,
                "line": step_index + 1,
                "effect_certainty": "NO_EFFECT",
            },
        )

    record(0)
    service.command_pending = False
    record(1)
    service.action_pending = False
    record(2)

    assert service.calls == ["command", "action", "edit"]
    assert [item["type"] for item in control.items] == [
        "pause",
        "safe_point_ack",
        "user_action",
        "safe_point_ack",
        "inspection_edit",
        "safe_point_ack",
    ]


def test_paused_bridge_delivers_next_mutation_without_another_worker_safe_point(
    monkeypatch,
) -> None:
    import backend.supervisor as supervisor_module

    command = {
        "id": "command",
        "execution_id": "execution",
        "type": "PAUSE",
        "state": "WAITING_SAFE_POINT",
        "revision": 0,
        "request": {},
        "target": {},
    }

    class Rows:
        def __init__(self, values):
            self.values = values

        def all(self):
            return list(self.values)

    class PendingSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def scalars(self, _statement):
            return Rows([command] if service.command_pending else [])

    class Service:
        def __init__(self) -> None:
            self.command_pending = True
            self.action_pending = True

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        @staticmethod
        def begin_operator_command_application(
            _command_id, safe_point_id=None, **_kwargs
        ):
            return {
                **command,
                "state": "APPLYING",
                "revision": 1,
                "application_safe_point_id": safe_point_id,
            }

        def list_replayable_user_action_invocations(self, _execution_id=None):
            return (
                [
                    {
                        "id": "action",
                        "execution_id": "execution",
                        "delivery_revision": 0,
                        "pinned_handler": [
                            {
                                "op": "LOG",
                                "message": "action",
                                "severity": "info",
                            }
                        ],
                    }
                ]
                if self.action_pending
                else []
            )

        @staticmethod
        def begin_user_action_application(
            invocation_id, safe_point_id=None, **_kwargs
        ):
            return {
                "id": invocation_id,
                "execution_id": "execution",
                "state": "APPLYING",
                "delivery_revision": 0,
                "application_safe_point_id": safe_point_id,
                "pinned_handler": [
                    {"op": "LOG", "message": "action", "severity": "info"}
                ],
            }

        @staticmethod
        def mark_user_action_delivery_attempt(_invocation_id, **_kwargs):
            return None

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = PendingSession
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )
    monkeypatch.setattr(supervisor_module, "operator_command_dict", lambda item: item)

    reserved = supervisor._replay_operator_command_deliveries()
    supervisor._replay_user_action_deliveries(skip_execution_ids=reserved)
    assert [item["type"] for item in control.items] == ["pause"]

    service.command_pending = False
    reserved = supervisor._replay_operator_command_deliveries()
    supervisor._replay_user_action_deliveries(skip_execution_ids=reserved)
    assert [item["type"] for item in control.items] == ["pause", "user_action"]


def test_blocking_child_terminal_is_settled_and_delivered_once() -> None:
    from backend.models import Execution

    child = SimpleNamespace(id="child", state="completed")

    class Service:
        def __init__(self) -> None:
            self.calls = 0

        def settle_startproc_child(self, operation, child_id, state):
            self.calls += 1
            assert (operation, child_id, state) == ("operation", "child", "FINISHED")
            return {
                "id": "operation",
                "revision": 2,
                "state": "SETTLED",
                "parent_execution_id": "parent",
                "child_execution_id": "child",
                "result": {
                    "outcome": "CHILD_FINISHED",
                    "child_state": "FINISHED",
                }
            }

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    handle = SimpleNamespace(
        control=control,
        generation=1,
        intentional_stop=False,
    )
    supervisor._workers["parent"] = handle
    supervisor.session_factory = SessionFactory({(Execution, "child"): child})
    supervisor._watch_startproc_child(
        "parent",
        handle,
        {"id": "operation", "child_execution_id": "child"},
    )
    assert service.calls == 1
    assert control.items[0]["result"]["outcome"] == "CHILD_FINISHED"


def test_no_worker_abort_reaches_aborted_without_claiming_clean_external_state() -> None:
    class Service:
        def __init__(self) -> None:
            self.transitions = []

        def transition_operator_command(self, command_id, state, **fields):
            self.transitions.append((state, fields))
            return {"id": command_id, "state": state, **fields}

        def begin_operator_command_application(
            self, command_id, safe_point_id=None, **_kwargs
        ):
            return {
                "id": command_id,
                "state": "APPLYING",
                "application_safe_point_id": safe_point_id,
                "effect_certainty_before": "EFFECT_POSSIBLE",
            }

        @staticmethod
        def list_reconcilable_startprocs(_execution_id):
            return []

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({})
    supervisor._set_state = lambda *args, **kwargs: None
    result = supervisor.dispatch_operator_command(
        {
            "id": "command",
            "execution_id": "execution",
            "type": "ABORT",
            "state": "ACCEPTED",
            "request": {},
            "target": {},
            "effect_certainty_before": "EFFECT_POSSIBLE",
        }
    )
    assert [state for state, _ in service.transitions] == [
        "WAITING_SAFE_POINT",
        "APPLYING",
        "SETTLED",
    ]
    assert result["result"]["clean_external_state"] is False
    assert result["effect_certainty"] == "EFFECT_POSSIBLE"


def test_parent_abort_is_propagated_to_a_live_blocking_child() -> None:
    from backend.models import Execution

    child = SimpleNamespace(id="child", state="running", revision=12)

    class Service:
        @staticmethod
        def list_reconcilable_startprocs(parent_execution_id):
            assert parent_execution_id == "parent"
            return [
                {
                    "id": "operation",
                    "blocking": True,
                    "state": "WAITING_CHILD",
                    "child_execution_id": "child",
                }
            ]

    supervisor = _supervisor(Service())
    supervisor.session_factory = SessionFactory({(Execution, "child"): child})
    supervisor._workers["child"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True)
    )
    issued: list[tuple[Any, ...]] = []
    supervisor.issue_command = lambda *args: issued.append(args)

    supervisor._abort_blocking_children("parent", "parent-abort")

    assert len(issued) == 1
    assert issued[0][:3] == ("child", "abort", 12)
    assert issued[0][3] == "parent-abort:parent-abort:operation"
    assert issued[0][4:7] == (
        "operator-runtime",
        "admin",
        "Propagate parent abort to blocking child",
    )


def test_no_worker_abort_waits_for_blocking_child_cleanup() -> None:
    class Service:
        def __init__(self) -> None:
            self.active = True
            self.transitions: list[tuple[str, dict[str, Any]]] = []
            self.settled = threading.Event()

        def transition_operator_command(self, command_id, state, **fields):
            self.transitions.append((state, fields))
            if state == "SETTLED":
                self.settled.set()
            return {
                "id": command_id,
                "execution_id": "parent",
                "state": state,
                **fields,
            }

        def begin_operator_command_application(
            self, command_id, safe_point_id=None, **_kwargs
        ):
            return {
                "id": command_id,
                "execution_id": "parent",
                "state": "APPLYING",
                "application_safe_point_id": safe_point_id,
                "effect_certainty_before": "EFFECT_POSSIBLE",
            }

        def list_reconcilable_startprocs(self, _execution_id):
            if not self.active:
                return []
            return [
                {
                    "id": "operation",
                    "blocking": True,
                    "state": "WAITING_CHILD",
                    "child_execution_id": "missing-child",
                }
            ]

        @staticmethod
        def reconcile_startproc_children():
            return []

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({})
    states: list[str] = []
    supervisor._set_state = lambda _execution_id, state, **_kwargs: states.append(state)

    result = supervisor.dispatch_operator_command(
        {
            "id": "command",
            "execution_id": "parent",
            "type": "ABORT",
            "state": "ACCEPTED",
            "request": {},
            "target": {},
            "effect_certainty_before": "EFFECT_POSSIBLE",
        }
    )

    assert result["state"] == "APPLYING"
    assert states == ["aborting"]
    assert not service.settled.is_set()
    service.active = False
    assert service.settled.wait(timeout=1)
    assert states == ["aborting", "aborted"]
    assert service.transitions[-1][1]["effect_certainty"] == "EFFECT_POSSIBLE"


def test_worker_abort_message_uses_the_same_blocking_child_barrier() -> None:
    from backend.operator_models import OperatorCommand

    class Service:
        def __init__(self) -> None:
            self.active = True
            self.settled = threading.Event()

        def transition_operator_command(self, command_id, state, **fields):
            if state == "SETTLED":
                self.settled.set()
            return {"id": command_id, "state": state, **fields}

        def list_reconcilable_startprocs(self, _execution_id):
            return (
                [
                    {
                        "id": "operation",
                        "blocking": True,
                        "state": "WAITING_CHILD",
                        "child_execution_id": "missing-child",
                    }
                ]
                if self.active
                else []
            )

        @staticmethod
        def reconcile_startproc_children():
            return []

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

    command = SimpleNamespace(
        id="command",
        command_type="STOP",
        effect_certainty_before="EFFECT_CONFIRMED",
    )
    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({(OperatorCommand, "command"): command})
    states: list[str] = []
    supervisor._set_state = lambda _execution_id, state, **_kwargs: states.append(state)

    supervisor._set_worker_state("parent", "aborted", command_id="command")

    assert states == ["aborting"]
    assert not service.settled.is_set()
    service.active = False
    assert service.settled.wait(timeout=1)
    assert states == ["aborting", "aborted"]


def test_prompt_delivery_is_retried_until_durable_application_ack() -> None:
    supervisor = _supervisor()
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )
    delivery = {
        "prompt": {
            "id": "prompt",
            "execution_id": "execution",
            "settlement": {
                "id": "settlement",
                "outcome": "ANSWERED",
                "value": "YES",
            },
        },
        "attempt": {"id": "attempt"},
    }

    supervisor.dispatch_prompt_settlement(delivery)
    supervisor._prompt_settlement_attempts["settlement"] -= 1
    supervisor.dispatch_prompt_settlement(delivery)

    assert len(control.items) == 2
    assert control.items[0] == control.items[1]
    assert control.items[0]["settlement_id"] == "settlement"


def test_user_action_replay_uses_pinned_handler_and_exact_attempt_hook() -> None:
    class Service:
        def __init__(self) -> None:
            self.attempted = []

        @staticmethod
        def list_replayable_user_action_invocations():
            return [
                {
                    "id": "invocation",
                    "execution_id": "execution",
                    "pinned_handler": [
                        {"op": "LOG", "message": "pinned", "severity": "info"}
                    ],
                }
            ]

        def mark_user_action_delivery_attempt(
            self, invocation_id, **_kwargs
        ):
            self.attempted.append(invocation_id)

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        @staticmethod
        def begin_user_action_application(
            invocation_id, safe_point_id=None, **_kwargs
        ):
            assert (invocation_id, safe_point_id) == ("invocation", "safe-point")
            return {
                "id": invocation_id,
                "state": "APPLYING",
                "delivery_revision": 0,
                "pinned_handler": [
                    {"op": "LOG", "message": "pinned", "severity": "info"}
                ],
            }

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )

    supervisor._replay_user_action_deliveries()

    assert control.items == [
        {
            "type": "user_action",
            "invocation_id": "invocation",
            "handler": [
                {"op": "LOG", "message": "pinned", "severity": "info"}
            ],
            "delivery_revision": 0,
        }
    ]
    assert service.attempted == ["invocation"]


def test_user_action_settlement_delegates_variables_and_effects_atomically() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=2,
        variables={"accepted": False},
    )

    class Service:
        def __init__(self) -> None:
            self.settlement = None

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

        def settle_user_action_invocation(self, *args, **kwargs):
            self.settlement = (args, kwargs)

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})
    effect = {
        "event_type": "procedure.user_action_log",
        "source": "procedure",
        "severity": "info",
        "payload": {"message": "applied"},
    }

    supervisor._settle_user_action(
        "execution",
        2,
        {
            "invocation_id": "invocation",
            "outcome": "EXECUTED",
            "application_id": "application",
            "safe_point_step": 4,
            "variables": {"accepted": True},
            "effects": [effect],
        },
    )

    assert execution.variables == {"accepted": False}
    assert service.settlement[0] == ("invocation", "EXECUTED")
    assert service.settlement[1]["variables"] == {"accepted": True}
    assert service.settlement[1]["effects"] == [effect]
    assert service.settlement[1]["application_safe_point_id"] is None


def test_startproc_terminal_result_replays_by_operation_revision() -> None:
    operation = {
        "id": "operation",
        "revision": 4,
        "state": "SETTLED",
        "parent_execution_id": "parent",
        "child_execution_id": "child",
        "result": {"outcome": "CHILD_FINISHED"},
        "rejection_code": None,
    }

    class Service:
        attempts = []

        @staticmethod
        def list_unacked_startproc_results():
            return [operation]

        @classmethod
        def mark_startproc_result_delivery_attempt(cls, startproc_id, revision):
            cls.attempts.append((startproc_id, revision))

    supervisor = _supervisor(Service())
    control = Control()
    supervisor._workers["parent"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )

    supervisor._replay_startproc_deliveries()

    assert control.items == [
        {
            "type": "startproc_result",
            "startproc_id": "operation",
            "delivery_revision": 4,
            "outcome": "SETTLED",
            "child_execution_id": "child",
            "rejection_code": None,
            "result": {"outcome": "CHILD_FINISHED"},
        }
    ]
    assert Service.attempts == [("operation", 4)]


def test_inspection_edit_replay_and_ack_use_durable_application_identity() -> None:
    class Service:
        def __init__(self) -> None:
            self.attempts = []
            self.ack = None

        @staticmethod
        def list_unacked_inspection_edits():
            return [
                {
                    "id": "edit",
                    "execution_id": "execution",
                        "revision": 1,
                        "execution_revision": 9,
                        "scope": "LOCAL_VARIABLE",
                        "path": "variables.accepted",
                        "type": "BOOLEAN",
                        "variables": {"accepted": True},
                }
            ]

        def mark_inspection_edit_delivery_attempt(
            self, edit_id, revision, **_kwargs
        ):
            self.attempts.append((edit_id, revision))

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        @staticmethod
        def begin_inspection_edit_application(
            edit_id, revision, safe_point_id=None, **_kwargs
        ):
            assert (edit_id, revision, safe_point_id) == (
                "edit",
                1,
                "safe-point",
            )
            return {
                "id": edit_id,
                "state": "APPLYING",
                "revision": revision,
                "execution_revision": 9,
                "scope": "LOCAL_VARIABLE",
                "path": "variables.accepted",
                "type": "BOOLEAN",
                "variables": {"accepted": True},
            }

        def ack_inspection_edit_application(self, *args, **kwargs):
            self.ack = (args, kwargs)

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )
    supervisor._replay_inspection_edit_deliveries()
    assert service.attempts == [("edit", 1)]
    assert control.items == [
        {
            "type": "inspection_edit",
            "edit_id": "edit",
                "delivery_revision": 1,
                "execution_revision": 9,
                "scope": "LOCAL_VARIABLE",
                "path": "variables.accepted",
                "declared_type": "BOOLEAN",
                "variables": {"accepted": True},
        }
    ]

    supervisor._settle_inspection_edit(
        "execution",
        {
            "edit_id": "edit",
            "application_id": "application",
            "outcome": "APPLIED",
            "variables": {"accepted": True},
        },
    )
    assert service.ack == (
        ("edit", "application"),
        {
            "outcome": "APPLIED",
            "rejection_code": None,
            "application_safe_point_id": None,
            "variables": {"accepted": True},
        },
    )


def test_running_action_waits_for_recorded_safe_point_before_refence() -> None:
    from backend.models import Execution

    execution = SimpleNamespace(
        id="execution",
        worker_generation=3,
        procedure_hash=DIGEST,
        revision=7,
    )
    invocation = {
        "id": "invocation",
        "execution_id": "execution",
        "state": "PENDING_SAFE_POINT",
        "delivery_revision": 0,
        "pinned_handler": [
            {"op": "LOG", "message": "pinned", "severity": "info"}
        ],
    }

    class Service:
        def __init__(self) -> None:
            self.begin_calls = []
            self.attempts = []

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "RUNNING", "current_safe_point_id": "old-point"}

        @staticmethod
        def list_replayable_user_action_invocations(execution_id=None):
            assert execution_id in {None, "execution"}
            return [invocation]

        def begin_user_action_application(
            self, invocation_id, safe_point_id=None, **_kwargs
        ):
            self.begin_calls.append((invocation_id, safe_point_id))
            return {**invocation, "state": "APPLYING"}

        def mark_user_action_delivery_attempt(
            self, invocation_id, **_kwargs
        ):
            self.attempts.append(invocation_id)

        @staticmethod
        def record_safe_point(*_args, **_kwargs):
            return None

    service = Service()
    supervisor = _supervisor(service)
    supervisor.session_factory = SessionFactory({(Execution, "execution"): execution})
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(control=control, generation=3)

    supervisor._replay_user_action_deliveries()
    assert service.begin_calls == []
    assert control.items == []

    supervisor._record_worker_safe_point(
        "execution",
        3,
        {
            "safe_point_token": "token",
            "safe_point_kind": "BEFORE_STATEMENT",
            "step_index": 2,
            "line": 8,
            "effect_certainty": "NO_EFFECT",
        },
    )

    assert len(service.begin_calls) == 1
    assert service.begin_calls[0][0] == "invocation"
    assert service.begin_calls[0][1] != "old-point"
    assert service.attempts == ["invocation"]
    assert control.items[0]["type"] == "user_action"
    assert control.items[1] == {"type": "safe_point_ack", "safe_point_token": "token"}


def test_stale_action_and_inspection_are_not_delivered() -> None:
    class Service:
        @staticmethod
        def get_execution_projection(_execution_id):
            return {"state": "PAUSED", "current_safe_point_id": "safe-point"}

        @staticmethod
        def begin_user_action_application(
            _invocation_id, _safe_point_id=None, **_kwargs
        ):
            return {
                "id": "invocation",
                "state": "SUPERSEDED",
                "rejection_code": "CONTROL_FENCE_STALE",
                "result": {"target_mutation": "NONE"},
            }

        @staticmethod
        def begin_inspection_edit_application(
            _edit_id, _revision, _safe_point_id=None, **_kwargs
        ):
            return {
                "id": "edit",
                "state": "REJECTED",
                "rejection_code": "CONTROL_FENCE_STALE",
                "result": {"target_mutation": "NONE"},
            }

    supervisor = _supervisor(Service())
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )

    action_queued = supervisor.dispatch_user_action(
        "execution",
        "invocation",
        [{"op": "LOG", "message": "must-not-run", "severity": "info"}],
    )
    edit_queued = supervisor.dispatch_inspection_edit(
        {
            "id": "edit",
            "execution_id": "execution",
            "revision": 1,
            "variables": {"accepted": True},
        }
    )

    assert action_queued["state"] == "SUPERSEDED"
    assert edit_queued["state"] == "REJECTED"
    assert action_queued["result"] == edit_queued["result"] == {
        "target_mutation": "NONE"
    }
    assert control.items == []


def test_control_loss_delivery_pauses_by_fencing_token_and_acks_safe_point() -> None:
    class Service:
        def __init__(self) -> None:
            self.ack = None

        @staticmethod
        def get_execution_projection(_execution_id):
            return {"current_safe_point_id": "safe-point"}

        def ack_control_loss_application(self, execution_id, fencing_token, safe_point_id):
            self.ack = (execution_id, fencing_token, safe_point_id)

    service = Service()
    supervisor = _supervisor(service)
    control = Control()
    supervisor._workers["execution"] = SimpleNamespace(
        process=SimpleNamespace(is_alive=lambda: True),
        control=control,
    )
    supervisor.dispatch_control_loss(
        {"execution_id": "execution", "fencing_token": 9}
    )
    assert control.items[0] == {
        "type": "control_loss",
        "delivery_id": "control-loss:execution:9",
        "lease_id": None,
        "fencing_token": 9,
        "delivery_revision": 9,
    }

    supervisor._settle_control_loss(
        "execution",
        {
            "delivery_id": "control-loss:execution:9",
            "fencing_token": 9,
        },
    )
    assert service.ack == ("execution", 9, "safe-point")


def test_control_loss_requested_event_publishes_before_worker_ack() -> None:
    event = {
        "id": "event",
        "execution_id": "execution",
        "sequence": 14,
        "event_type": "operator.control_loss_requested",
        "payload": {"control_fencing_token": 9, "worker_pause_applied": False},
    }

    class Service:
        def __init__(self) -> None:
            self.published = False

        def list_unpublished_control_loss_events(self):
            return [] if self.published else [event]

        def mark_control_loss_event_published(self, event_id):
            assert event_id == "event"
            self.published = True

    class Hub:
        def __init__(self) -> None:
            self.events = []

        def publish(self, execution_id, value):
            self.events.append((execution_id, value))

    service = Service()
    supervisor = _supervisor(service)
    supervisor.hub = Hub()

    supervisor._replay_control_loss_events()
    supervisor._replay_control_loss_events()

    assert supervisor.hub.events == [("execution", event)]
    assert event["payload"]["worker_pause_applied"] is False
