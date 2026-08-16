from __future__ import annotations

import queue
import threading
import uuid
from typing import Any, Callable

import pytest
from sqlalchemy import select

from backend.models import Command, Event, Execution
from backend.supervisor import ConflictError, Supervisor, WorkerHandle


class _FakeQueue:
    def __init__(self) -> None:
        self.closed = False
        self._closed = threading.Event()
        self.items: list[dict[str, Any]] = []

    def put(self, item: dict[str, Any]) -> None:
        self.items.append(item)

    def close(self) -> None:
        self.closed = True
        self._closed.set()

    def cancel_join_thread(self) -> None:
        return None


class _BlockingFirstOutput(_FakeQueue):
    def __init__(self, message: dict[str, Any]) -> None:
        super().__init__()
        self.message = message
        self.get_started = threading.Event()
        self.release_message = threading.Event()
        self._delivered = False
        self._guard = threading.Lock()

    def get(self, timeout: float | None = None) -> dict[str, Any]:
        with self._guard:
            first = not self._delivered
            if first:
                self._delivered = True
        if first:
            self.get_started.set()
            if not self.release_message.wait(timeout=2):
                raise queue.Empty
            return self.message
        if self._closed.wait(timeout=timeout):
            raise ValueError("worker output was closed")
        raise queue.Empty


class _SingleMessageOutput(_FakeQueue):
    def __init__(self, message: dict[str, Any]) -> None:
        super().__init__()
        self.message = message
        self._delivered = False
        self._guard = threading.Lock()

    def get(self, timeout: float | None = None) -> dict[str, Any]:
        with self._guard:
            if not self._delivered:
                self._delivered = True
                return self.message
        if self._closed.wait(timeout=timeout):
            raise ValueError("worker output was closed")
        raise queue.Empty


class _FakeProcess:
    def __init__(self, *, alive: bool = True) -> None:
        self.alive = alive
        self.exitcode: int | None = None
        self.terminated = False
        self.killed = False
        self.closed = False
        self.join_timeouts: list[float | None] = []

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.terminated = True
        self.alive = False
        self.exitcode = -15

    def kill(self) -> None:
        self.killed = True
        self.alive = False
        self.exitcode = -9

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)

    def close(self) -> None:
        self.closed = True


class _StartFailureProcess(_FakeProcess):
    def __init__(self) -> None:
        super().__init__(alive=False)
        self.start_called = False

    def start(self) -> None:
        self.start_called = True
        raise RuntimeError("forced process.start failure")


def _persist_execution(client, *, generation: int) -> str:
    identity = uuid.uuid4().hex
    with client.app.state.session_factory() as session:
        execution = Execution(
            procedure_id=f"worker-fence-{identity}",
            procedure_name="Worker fencing",
            procedure_hash="f" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="worker-fence-test",
            creation_idempotency_key=f"worker-fence-{identity}",
            total_steps=1,
            state="running",
            revision=3,
            worker_generation=generation,
        )
        session.add(execution)
        session.commit()
        return execution.id


def _handle(
    generation: int,
    *,
    output: _FakeQueue | None = None,
) -> WorkerHandle:
    return WorkerHandle(
        process=_FakeProcess(),
        control=_FakeQueue(),
        output=output or _FakeQueue(),
        generation=generation,
    )


def _run_thread(
    target: Callable[[], None],
    errors: list[BaseException],
) -> None:
    try:
        target()
    except BaseException as exc:  # pragma: no cover - surfaced by the caller
        errors.append(exc)


_DISPATCH_HANDLERS = (
    "append_event",
    "_set_worker_state",
    "_commit_step",
    "_open_prompt",
    "_record_worker_safe_point",
    "_settle_operator_command",
    "_settle_user_action",
    "_settle_inspection_edit",
    "_settle_control_loss",
    "_handle_startproc_request",
)


@pytest.mark.parametrize(
    "kind",
    (
        "event",
        "state",
        "step_commit",
        "prompt_opened",
        "safe_point",
        "command_applied",
        "command_rejected",
        "user_action_settled",
        "inspection_edit_applied",
        "control_loss_applied",
        "startproc_requested",
    ),
)
def test_retirement_wins_rejects_queued_message_and_preserves_successor(
    client,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    generation = 7
    execution_id = _persist_execution(client, generation=generation)
    output = _BlockingFirstOutput({"kind": kind, "generation": generation})
    retired = _handle(generation, output=output)
    successor = _handle(generation + 1)
    with supervisor._lock:
        supervisor._workers[execution_id] = retired

    handler_calls: list[str] = []

    def unexpected_handler(*_args: Any, **_kwargs: Any) -> None:
        handler_calls.append(kind)

    for name in _DISPATCH_HANDLERS:
        monkeypatch.setattr(supervisor, name, unexpected_handler)

    retirement_reserved = threading.Event()
    finish_retirement = threading.Event()
    original_terminate = supervisor._terminate_worker
    original_cleanup = supervisor._cleanup_worker

    def gated_terminate(candidate: WorkerHandle) -> bool:
        assert candidate is retired
        retirement_reserved.set()
        assert finish_retirement.wait(timeout=2)
        return original_terminate(candidate)

    def cleanup_then_claim_successor(
        candidate_execution_id: str,
        candidate: WorkerHandle,
    ) -> None:
        original_cleanup(candidate_execution_id, candidate)
        if candidate is retired:
            with supervisor._lock:
                assert candidate_execution_id not in supervisor._workers
                supervisor._workers[candidate_execution_id] = successor

    monkeypatch.setattr(supervisor, "_terminate_worker", gated_terminate)
    monkeypatch.setattr(supervisor, "_cleanup_worker", cleanup_then_claim_successor)

    errors: list[BaseException] = []
    consumer = threading.Thread(
        target=_run_thread,
        args=(lambda: supervisor._consume_worker(execution_id, retired), errors),
        daemon=True,
    )
    invalidator = threading.Thread(
        target=_run_thread,
        args=(lambda: supervisor._invalidate_worker(execution_id), errors),
        daemon=True,
    )
    consumer.start()
    assert output.get_started.wait(timeout=2)
    invalidator.start()
    assert retirement_reserved.wait(timeout=2)

    output.release_message.set()
    assert consumer.is_alive()
    finish_retirement.set()
    invalidator.join(timeout=3)
    consumer.join(timeout=3)

    assert not invalidator.is_alive()
    assert not consumer.is_alive()
    assert errors == []
    assert handler_calls == []
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is successor
        supervisor._workers.pop(execution_id, None)


def test_handler_wins_commits_before_retirement_without_holding_global_lock(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    generation = 13
    execution_id = _persist_execution(client, generation=generation)
    output = _SingleMessageOutput(
        {
            "kind": "event",
            "generation": generation,
            "event_type": "worker.handler_won",
            "payload": {"winner": "handler"},
        }
    )
    handle = _handle(generation, output=output)
    with supervisor._lock:
        supervisor._workers[execution_id] = handle

    handler_entered = threading.Event()
    finish_handler = threading.Event()
    invalidator_started = threading.Event()
    mutation_committed = threading.Event()
    ordering: list[str] = []
    original_append_event = supervisor.append_event
    original_terminate = supervisor._terminate_worker

    def blocked_append_event(*args: Any, **kwargs: Any) -> dict[str, Any]:
        handler_entered.set()
        assert finish_handler.wait(timeout=2)
        result = original_append_event(*args, **kwargs)
        ordering.append("mutation")
        mutation_committed.set()
        return result

    def observed_terminate(candidate: WorkerHandle) -> bool:
        assert mutation_committed.is_set()
        ordering.append("retirement")
        return original_terminate(candidate)

    monkeypatch.setattr(supervisor, "append_event", blocked_append_event)
    monkeypatch.setattr(supervisor, "_terminate_worker", observed_terminate)

    errors: list[BaseException] = []
    consumer = threading.Thread(
        target=_run_thread,
        args=(lambda: supervisor._consume_worker(execution_id, handle), errors),
        daemon=True,
    )

    def invalidate() -> None:
        invalidator_started.set()
        supervisor._invalidate_worker(execution_id)

    invalidator = threading.Thread(
        target=_run_thread,
        args=(invalidate, errors),
        daemon=True,
    )
    consumer.start()
    assert handler_entered.wait(timeout=2)
    invalidator.start()
    assert invalidator_started.wait(timeout=2)

    # The invalidator waits for this handle's dispatch reservation, not the
    # supervisor-wide lock needed by unrelated executions.
    assert supervisor._lock.acquire(timeout=0.5)
    supervisor._lock.release()
    assert invalidator.is_alive()

    finish_handler.set()
    consumer.join(timeout=3)
    invalidator.join(timeout=3)

    assert not consumer.is_alive()
    assert not invalidator.is_alive()
    assert errors == []
    assert ordering == ["mutation", "retirement"]
    with supervisor.session_factory() as session:
        stored = session.get(Execution, execution_id)
        events = session.scalars(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "worker.handler_won",
            )
        ).all()
        assert stored is not None
        assert stored.worker_generation == generation + 1
        assert len(events) == 1
        assert events[0].payload == {"winner": "handler"}
    with supervisor._lock:
        assert execution_id not in supervisor._workers


def test_abnormal_worker_invalidation_durably_advances_epoch(client) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    generation = 21
    execution_id = _persist_execution(client, generation=generation)
    handle = _handle(generation)
    with supervisor._lock:
        supervisor._workers[execution_id] = handle

    supervisor._invalidate_worker(execution_id)
    supervisor._invalidate_worker(execution_id)

    with supervisor.session_factory() as session:
        stored = session.get(Execution, execution_id)
        assert stored is not None
        assert stored.worker_generation == generation + 1
    with supervisor._lock:
        assert execution_id not in supervisor._workers
    assert handle.intentional_stop
    assert handle.process.terminated
    assert handle.process.closed


def test_stale_dispatch_failure_cannot_retire_replacement_worker(client) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    successor_generation = 32
    execution_id = _persist_execution(client, generation=successor_generation)
    retired = _handle(successor_generation - 1)
    successor = _handle(successor_generation)
    recovery_started = threading.Event()
    errors: list[BaseException] = []

    with retired.dispatch_lock:
        with supervisor._lock:
            supervisor._workers[execution_id] = retired

        def recover_stale_dispatch() -> None:
            recovery_started.set()
            supervisor._recover_dispatch_failure(
                execution_id,
                "stale dispatch failed",
                expected_handle=retired,
            )

        recovery = threading.Thread(
            target=_run_thread,
            args=(recover_stale_dispatch, errors),
            daemon=True,
        )
        recovery.start()
        assert recovery_started.wait(timeout=2)

        # Force retirement/replacement to linearize before stale recovery can
        # acquire the old handle's reservation.
        with supervisor._lock:
            supervisor._workers[execution_id] = successor

    recovery.join(timeout=3)

    assert not recovery.is_alive()
    assert errors == []
    assert not retired.intentional_stop
    assert not retired.process.terminated
    assert not successor.intentional_stop
    assert not successor.process.terminated
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is successor
        supervisor._workers.pop(execution_id, None)
    with supervisor.session_factory() as session:
        stored = session.get(Execution, execution_id)
        assert stored is not None
        assert stored.state == "running"
        assert stored.worker_generation == successor_generation


def test_stale_simulated_crash_cannot_fence_replacement_worker(client) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    successor_generation = 91
    execution_id = _persist_execution(client, generation=successor_generation)
    retired = _handle(successor_generation - 1)
    successor = _handle(successor_generation)
    with supervisor.session_factory() as session:
        command = Command(
            execution_id=execution_id,
            command_type="simulate_crash",
            idempotency_key=f"stale-simulated-crash-{execution_id}",
            expected_revision=3,
            actor="worker-fence-test",
            role="admin",
            reason="prove replacement identity fencing",
            correlation_id=str(uuid.uuid4()),
            request_payload={},
            status="accepted",
        )
        session.add(command)
        session.commit()
        command_id = command.id
    with supervisor._lock:
        supervisor._workers[execution_id] = successor

    supervisor._simulate_crash(
        execution_id, command_id, expected_handle=retired
    )

    assert not retired.intentional_stop and not retired.process.terminated
    assert not successor.intentional_stop and not successor.process.terminated
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is successor
        supervisor._workers.pop(execution_id, None)
    with supervisor.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.get(Command, command_id)
        assert execution is not None
        assert execution.state == "running"
        assert execution.worker_generation == successor_generation
        assert command is not None and command.status == "failed"
        assert command.result_payload == {
            "error": "worker was replaced before simulated crash"
        }


def test_simulated_crash_pinned_to_no_handle_cannot_relookup_replacement(client) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    successor_generation = 101
    execution_id = _persist_execution(client, generation=successor_generation)
    successor = _handle(successor_generation)
    with supervisor.session_factory() as session:
        command = Command(
            execution_id=execution_id,
            command_type="simulate_crash",
            idempotency_key=f"no-handle-simulated-crash-{execution_id}",
            expected_revision=3,
            actor="worker-fence-test",
            role="admin",
            reason="pin the no-handle acceptance snapshot",
            correlation_id=str(uuid.uuid4()),
            request_payload={},
            status="accepted",
        )
        session.add(command)
        session.commit()
        command_id = command.id
    with supervisor._lock:
        supervisor._workers[execution_id] = successor

    supervisor._simulate_crash(
        execution_id, command_id, expected_handle=None
    )

    assert not successor.intentional_stop and not successor.process.terminated
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is successor
        supervisor._workers.pop(execution_id, None)
    with supervisor.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.get(Command, command_id)
        assert execution is not None
        assert execution.state == "running"
        assert execution.worker_generation == successor_generation
        assert command is not None and command.status == "failed"
        assert command.result_payload == {
            "error": "worker was replaced before simulated crash"
        }


def test_control_loss_no_worker_decision_excludes_concurrent_spawn(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    execution_id = _persist_execution(client, generation=41)
    original_service = supervisor.operator_service
    state_entered = threading.Event()
    finish_state = threading.Event()
    spawn_called = threading.Event()
    errors: list[BaseException] = []

    class Service:
        acknowledged: tuple[str, int, str] | None = None

        @staticmethod
        def get_execution_projection(candidate_execution_id: str) -> dict[str, str]:
            assert candidate_execution_id == execution_id
            return {"current_safe_point_id": "safe-point-41"}

        def ack_control_loss_application(
            self,
            candidate_execution_id: str,
            fencing_token: int,
            safe_point_id: str,
        ) -> None:
            self.acknowledged = (
                candidate_execution_id,
                fencing_token,
                safe_point_id,
            )

    service = Service()
    supervisor.operator_service = service

    def blocked_set_state(*_args: Any, **_kwargs: Any) -> None:
        state_entered.set()
        assert finish_state.wait(timeout=2)

    def unexpected_spawn(*_args: Any, **_kwargs: Any) -> WorkerHandle:
        spawn_called.set()
        return _handle(42)

    monkeypatch.setattr(supervisor, "_set_state", blocked_set_state)
    monkeypatch.setattr(supervisor, "_spawn_worker_claimed", unexpected_spawn)

    delivery = threading.Thread(
        target=_run_thread,
        args=(
            lambda: supervisor.dispatch_control_loss(
                {"execution_id": execution_id, "fencing_token": 9}
            ),
            errors,
        ),
        daemon=True,
    )
    delivery.start()
    assert state_entered.wait(timeout=2)
    with pytest.raises(ConflictError, match="spawn is already in progress"):
        supervisor._spawn_worker(execution_id, str(uuid.uuid4()))
    assert not spawn_called.is_set()

    finish_state.set()
    delivery.join(timeout=3)
    supervisor.operator_service = original_service

    assert not delivery.is_alive()
    assert errors == []
    assert service.acknowledged == (execution_id, 9, "safe-point-41")
    with supervisor._lock:
        assert execution_id not in supervisor._spawning
        assert execution_id not in supervisor._workers


@pytest.mark.parametrize(
    ("state", "command_type"), (("starting", "start"), ("recovering", "recover"))
)
def test_partial_process_start_failure_is_fenced_removed_and_settled(
    client,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    command_type: str,
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    initial_generation = 51
    procedure = client.app.state.catalog.get("pause")
    created = supervisor.create_execution(
        procedure,
        actor="worker-fence-test",
        role="operator",
        reason="prepare a partial process start",
        idempotency_key=f"partial-start-execution-{command_type}-{uuid.uuid4().hex}",
        automatic=False,
    )
    execution_id = created.id
    with supervisor.session_factory() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        execution.state = state
        execution.worker_generation = initial_generation
        command = Command(
            execution_id=execution_id,
            command_type=command_type,
            idempotency_key=f"partial-start-{command_type}-{execution_id}",
            expected_revision=execution.revision,
            actor="worker-fence-test",
            role="admin",
            reason="force a partial process start",
            correlation_id=str(uuid.uuid4()),
            request_payload={},
            status="accepted",
        )
        session.add(command)
        session.commit()
        command_id = command.id

    process = _StartFailureProcess()
    queues: list[_FakeQueue] = []

    class Context:
        @staticmethod
        def Queue() -> _FakeQueue:
            worker_queue = _FakeQueue()
            queues.append(worker_queue)
            return worker_queue

        @staticmethod
        def Process(**_kwargs: Any) -> _StartFailureProcess:
            return process

    monkeypatch.setattr(supervisor, "_ctx", Context())
    with pytest.raises(RuntimeError, match="forced process.start failure"):
        supervisor._spawn_worker(execution_id, command_id)

    assert process.start_called
    assert process.closed
    assert len(queues) == 2 and all(worker_queue.closed for worker_queue in queues)
    with supervisor._lock:
        assert execution_id not in supervisor._workers
        assert execution_id not in supervisor._spawning
    with supervisor.session_factory() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        assert execution.worker_generation == initial_generation + 2

    supervisor._recover_dispatch_failure(
        execution_id, "worker startup failed: forced process.start failure"
    )
    with supervisor.session_factory() as session:
        execution = session.get(Execution, execution_id)
        command = session.get(Command, command_id)
        assert execution is not None and execution.state == "recovery_required"
        assert command is not None and command.status == "failed"
        assert "forced process.start failure" in command.result_payload["error"]


def test_operator_abort_defers_while_worker_spawn_owns_lifecycle_slot(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    execution_id = str(uuid.uuid4())
    successor = _handle(61)
    transition_entered = threading.Event()
    spawn_claimed = threading.Event()
    finish_transition = threading.Event()
    finish_spawn = threading.Event()
    errors: list[BaseException] = []
    dispatch_results: list[dict[str, Any]] = []
    spawn_results: list[WorkerHandle] = []
    begin_calls: list[str] = []
    original_service = supervisor.operator_service

    command = {
        "id": str(uuid.uuid4()),
        "execution_id": execution_id,
        "type": "ABORT",
        "state": "ACCEPTED",
    }

    class Service:
        @staticmethod
        def transition_operator_command(
            command_id: str, state: str, **_kwargs: Any
        ) -> dict[str, Any]:
            assert command_id == command["id"]
            assert state == "WAITING_SAFE_POINT"
            transition_entered.set()
            assert finish_transition.wait(timeout=2)
            return {**command, "state": state}

    def claimed_spawn(
        candidate_execution_id: str,
        _command_id: str,
        *,
        initial_controls: list[dict[str, Any]] | None = None,
    ) -> WorkerHandle:
        assert candidate_execution_id == execution_id
        assert initial_controls is None
        spawn_claimed.set()
        assert finish_spawn.wait(timeout=2)
        with supervisor._lock:
            supervisor._workers[execution_id] = successor
        return successor

    supervisor.operator_service = Service()
    monkeypatch.setattr(supervisor, "_spawn_worker_claimed", claimed_spawn)
    monkeypatch.setattr(
        supervisor,
        "_begin_operator_command_application",
        lambda *_args, **_kwargs: begin_calls.append("begin"),
    )

    dispatch = threading.Thread(
        target=_run_thread,
        args=(
            lambda: dispatch_results.append(
                supervisor.dispatch_operator_command(command)
            ),
            errors,
        ),
        daemon=True,
    )
    spawn = threading.Thread(
        target=_run_thread,
        args=(
            lambda: spawn_results.append(
                supervisor._spawn_worker(execution_id, str(uuid.uuid4()))
            ),
            errors,
        ),
        daemon=True,
    )
    dispatch.start()
    assert transition_entered.wait(timeout=2)
    spawn.start()
    assert spawn_claimed.wait(timeout=2)
    finish_transition.set()
    dispatch.join(timeout=3)

    assert not dispatch.is_alive()
    assert dispatch_results == [{**command, "state": "WAITING_SAFE_POINT"}]
    assert begin_calls == []
    finish_spawn.set()
    spawn.join(timeout=3)
    supervisor.operator_service = original_service

    assert not spawn.is_alive()
    assert errors == []
    assert spawn_results == [successor]
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is successor
        supervisor._workers.pop(execution_id, None)


def test_operator_abort_fences_dead_handle_before_terminal_mutation(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    generation = 66
    execution_id = _persist_execution(client, generation=generation)
    output = _SingleMessageOutput(
        {
            "kind": "event",
            "generation": generation,
            "event_type": "worker.buffered_after_abort",
            "payload": {"must_commit": False},
        }
    )
    dead = _handle(generation, output=output)
    dead.process.alive = False
    original_service = supervisor.operator_service
    command = {
        "id": str(uuid.uuid4()),
        "execution_id": execution_id,
        "type": "ABORT",
        "state": "ACCEPTED",
        "effect_certainty_before": "NO_EFFECT",
    }
    state_observations: list[tuple[bool, int]] = []

    class Service:
        @staticmethod
        def transition_operator_command(
            command_id: str, state: str, **_kwargs: Any
        ) -> dict[str, Any]:
            assert command_id == command["id"]
            return {**command, "state": state}

        @staticmethod
        def get_execution_projection(_execution_id: str) -> dict[str, str]:
            return {"current_safe_point_id": "dead-safe-point"}

    def observe_set_state(*_args: Any, **_kwargs: Any) -> None:
        with supervisor._lock:
            mapped = execution_id in supervisor._workers
        with supervisor.session_factory() as session:
            execution = session.get(Execution, execution_id)
            assert execution is not None
            state_observations.append((mapped, execution.worker_generation))

    supervisor.operator_service = Service()
    with supervisor._lock:
        supervisor._workers[execution_id] = dead
    monkeypatch.setattr(
        supervisor,
        "_begin_operator_command_application",
        lambda *_args, **_kwargs: {**command, "state": "APPLYING"},
    )
    monkeypatch.setattr(supervisor, "_set_state", observe_set_state)
    monkeypatch.setattr(
        supervisor,
        "_start_abort_cleanup_barrier",
        lambda *_args, **_kwargs: {**command, "state": "SETTLED"},
    )

    result = supervisor.dispatch_operator_command(command)
    supervisor.operator_service = original_service

    assert result["state"] == "SETTLED"
    assert state_observations == [(False, generation + 1)]
    assert dead.intentional_stop and dead.process.closed
    with supervisor._lock:
        assert execution_id not in supervisor._workers
        assert execution_id not in supervisor._spawning
    supervisor._consume_worker(execution_id, dead)
    with supervisor.session_factory() as session:
        assert session.scalar(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "worker.buffered_after_abort",
            )
        ) is None


def test_parent_abort_defers_child_terminalization_during_child_spawn(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    child_id = _persist_execution(client, generation=71)
    parent_id = str(uuid.uuid4())
    successor = _handle(72)
    spawn_claimed = threading.Event()
    finish_spawn = threading.Event()
    errors: list[BaseException] = []
    with supervisor.session_factory() as session:
        child = session.get(Execution, child_id)
        assert child is not None
        child.state = "starting"
        session.commit()

    monkeypatch.setattr(
        supervisor,
        "_blocking_startproc_operations",
        lambda candidate_parent_id: [
            {
                "id": "startproc-operation",
                "state": "WAITING_CHILD",
                "blocking": True,
                "child_execution_id": child_id,
            }
        ]
        if candidate_parent_id == parent_id
        else [],
    )

    def claimed_spawn(
        candidate_execution_id: str,
        _command_id: str,
        *,
        initial_controls: list[dict[str, Any]] | None = None,
    ) -> WorkerHandle:
        assert candidate_execution_id == child_id
        assert initial_controls is None
        spawn_claimed.set()
        assert finish_spawn.wait(timeout=2)
        with supervisor._lock:
            supervisor._workers[child_id] = successor
        return successor

    monkeypatch.setattr(supervisor, "_spawn_worker_claimed", claimed_spawn)
    spawn_results: list[WorkerHandle] = []
    spawn = threading.Thread(
        target=_run_thread,
        args=(
            lambda: spawn_results.append(
                supervisor._spawn_worker(child_id, str(uuid.uuid4()))
            ),
            errors,
        ),
        daemon=True,
    )
    spawn.start()
    assert spawn_claimed.wait(timeout=2)

    supervisor._abort_blocking_children(parent_id, "parent-command")
    with supervisor.session_factory() as session:
        child = session.get(Execution, child_id)
        assert child is not None and child.state == "starting"

    finish_spawn.set()
    spawn.join(timeout=3)

    assert not spawn.is_alive()
    assert errors == []
    assert spawn_results == [successor]
    with supervisor._lock:
        assert supervisor._workers.get(child_id) is successor
        supervisor._workers.pop(child_id, None)


def test_parent_abort_queues_abort_to_mapped_recovering_child(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    child_id = _persist_execution(client, generation=81)
    parent_id = str(uuid.uuid4())
    child_handle = _handle(81)
    with supervisor.session_factory() as session:
        child = session.get(Execution, child_id)
        assert child is not None
        child.state = "recovering"
        session.commit()

    monkeypatch.setattr(
        supervisor,
        "_blocking_startproc_operations",
        lambda candidate_parent_id: [
            {
                "id": "recovering-child-operation",
                "state": "WAITING_CHILD",
                "blocking": True,
                "child_execution_id": child_id,
            }
        ]
        if candidate_parent_id == parent_id
        else [],
    )
    monkeypatch.setattr(supervisor, "_arm_command_watchdog", lambda *_args: None)
    with supervisor._lock:
        supervisor._workers[child_id] = child_handle

    supervisor._abort_blocking_children(parent_id, "parent-command")

    with supervisor.session_factory() as session:
        child = session.get(Execution, child_id)
        command = session.scalar(
            select(Command).where(
                Command.execution_id == child_id,
                Command.command_type == "abort",
            )
        )
        assert child is not None and child.state == "aborting"
        assert command is not None and command.status == "accepted"
    assert child_handle.process.is_alive()
    assert not child_handle.intentional_stop
    assert child_handle.control.items == [
        {"type": "abort", "command_id": command.id}
    ]
    with supervisor._lock:
        assert supervisor._workers.get(child_id) is child_handle
        supervisor._workers.pop(child_id, None)


def test_concurrent_spawn_slot_claim_does_not_overwrite_winner(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor: Supervisor = client.app.state.supervisor
    execution_id = str(uuid.uuid4())
    winner = _handle(1)
    claimed_entered = threading.Event()
    finish_claim = threading.Event()
    claimed_commands: list[str] = []
    results: list[WorkerHandle] = []
    first_errors: list[BaseException] = []
    second_errors: list[BaseException] = []

    def claimed_spawn(
        candidate_execution_id: str,
        command_id: str,
        *,
        initial_controls: list[dict[str, Any]] | None = None,
    ) -> WorkerHandle:
        assert candidate_execution_id == execution_id
        assert initial_controls is None
        claimed_commands.append(command_id)
        claimed_entered.set()
        assert finish_claim.wait(timeout=2)
        with supervisor._lock:
            assert candidate_execution_id not in supervisor._workers
            supervisor._workers[candidate_execution_id] = winner
        return winner

    monkeypatch.setattr(supervisor, "_spawn_worker_claimed", claimed_spawn)

    first = threading.Thread(
        target=_run_thread,
        args=(
            lambda: results.append(supervisor._spawn_worker(execution_id, "first")),
            first_errors,
        ),
        daemon=True,
    )
    second = threading.Thread(
        target=_run_thread,
        args=(lambda: supervisor._spawn_worker(execution_id, "second"), second_errors),
        daemon=True,
    )
    first.start()
    assert claimed_entered.wait(timeout=2)
    second.start()
    second.join(timeout=2)

    assert not second.is_alive()
    assert len(second_errors) == 1
    assert isinstance(second_errors[0], ConflictError)
    assert "spawn is already in progress" in str(second_errors[0])
    assert claimed_commands == ["first"]

    finish_claim.set()
    first.join(timeout=3)

    assert not first.is_alive()
    assert first_errors == []
    assert results == [winner]
    with supervisor._lock:
        assert supervisor._workers.get(execution_id) is winner
        assert execution_id not in supervisor._spawning
        supervisor._workers.pop(execution_id, None)
