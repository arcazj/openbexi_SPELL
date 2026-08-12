from __future__ import annotations

import os
import multiprocessing
import hashlib
import json
import math
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .events import EventHub
from .models import Command, Event, Execution, Prompt
from .procedure_parser import IR_VERSION, Procedure, ProcedureCatalog
from .serialization import command_dict, event_dict, execution_dict, prompt_dict
from .worker import sanitized_worker_environment, worker_main


TERMINAL_STATES = {"completed", "aborted", "failed"}
ACTIVE_STATES = {
    "starting",
    "running",
    "pausing",
    "paused",
    "resuming",
    "prompting",
    "aborting",
    "recovering",
}
PROCEDURE_SUBSET_VERSION = f"spell-restricted-ast/{IR_VERSION}"
_WORKER_SPAWN_ENVIRONMENT_LOCK = threading.Lock()


def canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def configuration_hash(procedure: Procedure, context_id: str) -> str:
    return canonical_hash(
        {
            "context_id": context_id,
            "procedure_hash": procedure.sha256,
            "procedure_subset_version": f"spell-restricted-ast/{procedure.ir_version}",
            "steps": list(procedure.steps),
        }
    )


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


class AuthorizationError(PermissionError):
    pass


@dataclass
class WorkerHandle:
    process: multiprocessing.Process
    control: Any
    output: Any
    generation: int
    normal_exit: bool = False
    intentional_stop: bool = False
    failure_signal: threading.Event = field(default_factory=threading.Event)
    failure_detail: str | None = None


class Supervisor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        catalog: ProcedureCatalog,
        hub: EventHub,
        command_ack_timeout_seconds: float = 5.0,
    ):
        self.session_factory = session_factory
        self.catalog = catalog
        self.hub = hub
        self._ctx = multiprocessing.get_context("spawn")
        self._lock = threading.RLock()
        self._workers: dict[str, WorkerHandle] = {}
        self._closed = False
        if (
            not math.isfinite(command_ack_timeout_seconds)
            or command_ack_timeout_seconds <= 0
        ):
            raise ValueError("command ACK timeout must be a positive finite number")
        self.command_ack_timeout_seconds = command_ack_timeout_seconds

    def create_execution(
        self,
        procedure: Procedure,
        actor: str,
        role: str,
        reason: str,
        idempotency_key: str,
        context_id: str = "simulator",
    ) -> Execution:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError(
                "idempotency key is required and must not exceed 200 characters"
            )
        creation_request_hash = canonical_hash(
            {
                "procedure_id": procedure.id,
                "context_id": context_id,
                "reason": reason,
                "actor": actor,
            }
        )
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            existing = session.scalar(
                select(Execution).where(
                    Execution.created_by == actor,
                    Execution.creation_idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                created_event = session.scalar(
                    select(Event).where(
                        Event.execution_id == existing.id,
                        Event.event_type == "execution.created",
                    )
                )
                stored_hash = created_event.payload.get("request_hash") if created_event else None
                if stored_hash != creation_request_hash:
                    raise ConflictError("creation idempotency key was used for another request")
                session.expunge(existing)
                return existing
            execution = Execution(
                procedure_id=procedure.id,
                procedure_name=procedure.name,
                procedure_hash=procedure.sha256,
                procedure_source=procedure.source,
                steps=list(procedure.steps),
                ir_version=procedure.ir_version,
                variables={},
                total_steps=len(procedure.steps),
                context_id=context_id,
                created_by=actor,
                creation_idempotency_key=idempotency_key,
            )
            session.add(execution)
            session.flush()
            config_hash = configuration_hash(procedure, context_id)
            self._add_event(
                session,
                execution,
                "execution.created",
                {
                    "procedure_id": procedure.id,
                    "procedure_hash": procedure.sha256,
                    "procedure_subset_version": f"spell-restricted-ast/{procedure.ir_version}",
                    "configuration_hash": config_hash,
                    "request_hash": creation_request_hash,
                },
                source="api",
            )
            execution.state = "validated"
            execution.revision = 1
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "created", "state": "validated", "revision": 1},
                source="supervisor",
            )
            execution.state = "ready"
            execution.revision = 2
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "validated", "state": "ready", "revision": 2},
                source="supervisor",
            )
            start_payload = {"creation_request_hash": creation_request_hash}
            start_correlation_id = str(uuid.uuid4())
            start_request_hash = canonical_hash(
                {
                    "command_type": "start",
                    "expected_revision": 2,
                    "actor": actor,
                    "reason": reason or "Start newly created simulator execution",
                    "correlation_id": start_correlation_id,
                    "payload": start_payload,
                }
            )
            start_command = Command(
                execution_id=execution.id,
                command_type="start",
                idempotency_key=f"auto-start:{execution.id}",
                expected_revision=2,
                actor=actor,
                role=role,
                reason=reason or "Start newly created simulator execution",
                correlation_id=start_correlation_id,
                request_payload={"request": start_payload, "_request_hash": start_request_hash},
            )
            session.add(start_command)
            execution.state = "starting"
            execution.revision = 3
            session.flush()
            self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(start_command)},
                source="api",
                correlation_id=start_command.correlation_id,
                causation_id=start_command.id,
            )
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "ready", "state": "starting", "revision": 3},
                source="api",
                correlation_id=start_command.correlation_id,
                causation_id=start_command.id,
            )
            session.commit()
            session.refresh(execution)
            events = session.scalars(
                select(Event).where(Event.execution_id == execution.id).order_by(Event.sequence)
            ).all()
            published = [event_dict(event) for event in events]
            execution_id = execution.id
            start_command_id = start_command.id
            self._publish(execution_id, published)
        try:
            handle = self._spawn_worker(execution_id, start_command_id)
            self._arm_command_watchdog(execution_id, start_command_id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"worker startup failed: {exc}",
            )
        return self.get_execution(execution_id)

    def get_execution(self, execution_id: str) -> Execution:
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            session.expunge(execution)
            return execution

    def list_executions(self, limit: int = 100) -> list[Execution]:
        with self.session_factory() as session:
            items = session.scalars(
                select(Execution).order_by(Execution.created_at.desc()).limit(limit)
            ).all()
            for item in items:
                session.expunge(item)
            return list(items)

    def reconcile_orphaned_executions(self) -> None:
        """Mark persisted active executions recoverable after a control-plane restart."""
        with self.session_factory() as session:
            execution_ids = list(
                session.scalars(
                    select(Execution.id).where(Execution.state.in_(ACTIVE_STATES))
                ).all()
            )
        for execution_id in execution_ids:
            self.append_event(
                execution_id,
                "supervisor.restart_detected",
                {"action": "recovery_required"},
                source="supervisor",
                severity="warning",
            )
            self._set_state(
                execution_id,
                "recovery_required",
                source="supervisor",
                preserve_open_prompts=True,
                pending_command_error="supervisor restarted before command completion",
            )
        with self.session_factory() as session:
            settled_execution_ids = list(
                session.scalars(
                    select(Execution.id)
                    .join(Command, Command.execution_id == Execution.id)
                    .where(
                        Execution.state.in_(TERMINAL_STATES | {"recovery_required"}),
                        Command.status == "accepted",
                    )
                    .distinct()
                ).all()
            )
            settled_states = {
                execution_id: session.get(Execution, execution_id).state
                for execution_id in settled_execution_ids
            }
        for execution_id, state in settled_states.items():
            self._set_state(
                execution_id,
                state,
                source="supervisor",
                preserve_open_prompts=state == "recovery_required",
                pending_command_error="supervisor restarted before command completion",
            )

    def snapshot(self, execution_id: str) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            events = session.scalars(
                select(Event)
                .where(Event.execution_id == execution_id)
                .order_by(Event.sequence.desc())
                .limit(200)
            ).all()
            events.reverse()
            prompts = session.scalars(
                select(Prompt)
                .where(Prompt.execution_id == execution_id)
                .order_by(Prompt.created_at.desc())
            ).all()
            commands = session.scalars(
                select(Command)
                .where(Command.execution_id == execution_id)
                .order_by(Command.created_at.desc())
                .limit(50)
            ).all()
            serialized_events = [event_dict(item) for item in events]
            data = execution_dict(execution)
            data.update(
                {
                    "current_step_id": execution.current_step,
                    "current_line": (
                        execution.steps[execution.current_step]["line"]
                        if execution.current_step < execution.total_steps
                        else None
                    ),
                    "steps": execution.steps,
                    "source": execution.procedure_source,
                }
            )
            return {
                "execution": data,
                "telemetry": [
                    item for item in serialized_events if item["event_type"] == "telemetry.sample"
                ],
                "events": serialized_events,
                "logs": [
                    item for item in serialized_events if item["event_type"] == "procedure.log"
                ],
                "commands": [command_dict(item) for item in commands],
                "active_prompt": next(
                    (prompt_dict(item) for item in prompts if item.status == "open"), None
                ),
                "last_sequence": execution.next_sequence - 1,
            }

    def issue_command(
        self,
        execution_id: str,
        command_type: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        role: str,
        reason: str,
        correlation_id: str | None,
        payload: dict[str, Any],
    ) -> Command:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if command_type == "simulate_crash" and role != "admin":
            raise AuthorizationError("admin role required for simulated crash")
        if command_type not in {"start", "pause", "resume", "abort", "recover", "simulate_crash"}:
            raise ConflictError(f"unsupported command: {command_type}")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError("idempotency key is required and must not exceed 200 characters")
        if not reason.strip():
            raise ConflictError("a command reason is required")

        request_hash = canonical_hash(
            {
                "command_type": command_type,
                "expected_revision": expected_revision,
                "actor": actor,
                "reason": reason,
                "correlation_id": correlation_id,
                "payload": payload,
            }
        )
        published: list[dict[str, Any]] = []

        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            existing = session.scalar(
                select(Command).where(
                    Command.execution_id == execution_id,
                    Command.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_payload.get("_request_hash") != request_hash:
                    raise ConflictError("idempotency key was used for another command request")
                session.expunge(existing)
                return existing
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            if execution.revision != expected_revision:
                raise ConflictError(
                    f"revision mismatch: expected {expected_revision}, current {execution.revision}"
                )
            self._validate_transition(execution.state, command_type)
            state_before = execution.state
            command = Command(
                execution_id=execution_id,
                command_type=command_type,
                idempotency_key=idempotency_key,
                expected_revision=expected_revision,
                actor=actor,
                role=role,
                reason=reason,
                correlation_id=correlation_id or str(uuid.uuid4()),
                request_payload={"request": payload, "_request_hash": request_hash},
            )
            session.add(command)
            execution.revision += 1
            intermediate = {
                "start": "starting",
                "pause": "pausing",
                "resume": "resuming",
                "abort": "aborting",
                "recover": "recovering",
                "simulate_crash": execution.state,
            }[command_type]
            execution.state = intermediate
            session.flush()
            accepted = self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(command)},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            state_event = None
            if state_before != intermediate:
                state_event = self._add_event(
                    session,
                    execution,
                    "execution.state_changed",
                    {
                        "previous": state_before,
                        "state": intermediate,
                        "revision": execution.revision,
                    },
                    source="api",
                    correlation_id=command.correlation_id,
                    causation_id=command.id,
                )
            session.commit()
            session.refresh(command)
            published = [event_dict(accepted)]
            if state_event is not None:
                published.append(event_dict(state_event))
            session.expunge(command)
            self._publish(execution_id, published)
        try:
            if command_type in {"start", "recover"}:
                handle = self._spawn_worker(execution_id, command.id)
                self._arm_command_watchdog(execution_id, command.id, handle)
            elif command_type == "simulate_crash":
                self._simulate_crash(execution_id, command.id)
            elif command_type == "abort" and state_before == "recovery_required":
                self._set_state(
                    execution_id, "aborted", source="supervisor", command_id=command.id
                )
            else:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("supervisor is closed")
                    handle = self._workers.get(execution_id)
                if handle is None or not handle.process.is_alive():
                    raise RuntimeError("worker is unavailable")
                handle.control.put({"type": command_type, "command_id": command.id, **payload})
                self._arm_command_watchdog(execution_id, command.id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"command dispatch failed: {exc}",
            )
        return command

    def respond_to_prompt(
        self,
        prompt_id: str,
        response: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        role: str,
        reason: str,
        correlation_id: str | None,
    ) -> Command:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError(
                "idempotency key is required and must not exceed 200 characters"
            )
        request_hash = canonical_hash(
            {
                "prompt_id": prompt_id,
                "response": response,
                "expected_revision": expected_revision,
                "actor": actor,
                "reason": reason,
                "correlation_id": correlation_id,
            }
        )
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            prompt = session.get(Prompt, prompt_id)
            if prompt is None:
                raise NotFoundError("prompt not found")
            existing = session.scalar(
                select(Command).where(
                    Command.execution_id == prompt.execution_id,
                    Command.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_payload.get("_request_hash") != request_hash:
                    raise ConflictError("idempotency key was used for another prompt response")
                session.expunge(existing)
                return existing
            execution = session.get(Execution, prompt.execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            if execution.revision != expected_revision:
                raise ConflictError(
                    f"revision mismatch: expected {expected_revision}, current {execution.revision}"
                )
            if execution.state != "prompting" or prompt.status != "open":
                raise ConflictError("prompt is not open")
            if response not in prompt.choices:
                raise ConflictError("response must be one of the prompt choices")
            if not reason.strip():
                raise ConflictError("a response reason is required")
            command = Command(
                execution_id=execution.id,
                command_type="prompt_response",
                idempotency_key=idempotency_key,
                expected_revision=expected_revision,
                actor=actor,
                role=role,
                reason=reason,
                correlation_id=correlation_id or str(uuid.uuid4()),
                request_payload={
                    "prompt_id": prompt_id,
                    "response": response,
                    "_request_hash": request_hash,
                },
            )
            session.add(command)
            execution.revision += 1
            prompt.status = "responding"
            prompt.response = response
            prompt.responded_by = actor
            prompt.responded_at = datetime.now(timezone.utc)
            session.flush()
            accepted = self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(command)},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            reserved = self._add_event(
                session,
                execution,
                "prompt.response_reserved",
                {"prompt_id": prompt.id, "response": response, "revision": execution.revision},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            session.commit()
            session.refresh(command)
            published = [event_dict(accepted), event_dict(reserved)]
            session.expunge(command)
            execution_id = command.execution_id
            self._publish(execution_id, published)
        try:
            with self._lock:
                if self._closed:
                    raise RuntimeError("supervisor is closed")
                handle = self._workers.get(execution_id)
            if handle is None or not handle.process.is_alive():
                raise RuntimeError("worker is unavailable")
            handle.control.put(
                {
                    "type": "prompt_response",
                    "command_id": command.id,
                    "prompt_id": prompt_id,
                    "response": response,
                }
            )
            self._arm_command_watchdog(execution_id, command.id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"prompt dispatch failed: {exc}",
            )
        return command

    @staticmethod
    def _validate_transition(state: str, command_type: str) -> None:
        allowed = {
            "start": {"ready"},
            "pause": {"running"},
            "resume": {"paused"},
            "abort": {"starting", "running", "paused", "prompting", "recovery_required"},
            "recover": {"recovery_required"},
            "simulate_crash": {"running", "paused", "prompting"},
        }
        if state not in allowed[command_type]:
            raise ConflictError(f"cannot {command_type} while execution is {state}")

    def _spawn_worker(self, execution_id: str, command_id: str) -> WorkerHandle:
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            command = session.get(Command, command_id)
            expected_state = {
                "start": "starting",
                "recover": "recovering",
            }.get(command.command_type if command is not None else "")
            if (
                command is None
                or command.status != "accepted"
                or expected_state is None
                or execution.state != expected_state
            ):
                raise ConflictError("execution is no longer eligible to spawn a worker")
            previous = self._workers.get(execution_id)
            if previous is not None and previous.process.is_alive():
                raise ConflictError("execution already has a live worker")
            execution.worker_generation += 1
            generation = execution.worker_generation
            start_step = execution.current_step
            steps = execution.steps
            checkpoint_variables = dict(execution.variables)
            resume_prompt = session.scalar(
                select(Prompt).where(
                    Prompt.execution_id == execution_id,
                    Prompt.step_index == start_step,
                    Prompt.status == "open",
                )
            )
            resume_prompt_id = resume_prompt.id if resume_prompt is not None else None
            session.commit()
            control = self._ctx.Queue()
            output = self._ctx.Queue()
            process = self._ctx.Process(
                target=worker_main,
                name=f"spell-{execution_id[:8]}-g{generation}",
                args=(
                    execution_id,
                    generation,
                    steps,
                    start_step,
                    command_id,
                    resume_prompt_id,
                    checkpoint_variables,
                    control,
                    output,
                ),
                daemon=True,
            )
            handle = WorkerHandle(
                process=process,
                control=control,
                output=output,
                generation=generation,
            )
            self._workers[execution_id] = handle
            # ``spawn`` otherwise copies every backend service secret into the
            # child process environment. Serialize the short environment swap so
            # the child starts with only inert runtime keys, then restore the API.
            with _WORKER_SPAWN_ENVIRONMENT_LOCK:
                service_environment = dict(os.environ)
                try:
                    worker_environment = sanitized_worker_environment()
                    os.environ.clear()
                    os.environ.update(worker_environment)
                    process.start()
                finally:
                    os.environ.clear()
                    os.environ.update(service_environment)
        threading.Thread(
            target=self._consume_worker, args=(execution_id, handle), daemon=True
        ).start()
        threading.Thread(
            target=self._monitor_worker, args=(execution_id, handle), daemon=True
        ).start()
        return handle

    def _arm_command_watchdog(
        self, execution_id: str, command_id: str, handle: WorkerHandle
    ) -> threading.Thread:
        timeout_seconds = self.command_ack_timeout_seconds
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("command ACK timeout must be a positive finite number")
        watchdog = threading.Thread(
            target=self._watch_command_ack,
            args=(execution_id, command_id, handle, timeout_seconds),
            daemon=True,
        )
        watchdog.start()
        return watchdog

    def _watch_command_ack(
        self,
        execution_id: str,
        command_id: str,
        handle: WorkerHandle,
        timeout_seconds: float,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        retry_delay = 0.05
        while not self._closed:
            try:
                with self.session_factory() as session:
                    command = session.get(Command, command_id)
                    if (
                        command is None
                        or command.execution_id != execution_id
                        or command.status != "accepted"
                    ):
                        return
                    command_type = command.command_type
            except Exception:
                if self._closed:
                    return
                remaining = deadline - time.monotonic()
                time.sleep(min(retry_delay, remaining) if remaining > 0 else retry_delay)
                retry_delay = min(retry_delay * 2, 1.0)
                continue

            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))
                continue
            self._recover_worker_loss(
                execution_id,
                handle,
                "worker.command_ack_timeout",
                {
                    "command_id": command_id,
                    "command_type": command_type,
                    "timeout_seconds": timeout_seconds,
                },
                f"worker did not acknowledge {command_type} command within "
                f"{timeout_seconds:g} seconds",
                pending_command_id=command_id,
            )
            return

    def _consume_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        dead_since: float | None = None
        while not self._closed and not handle.intentional_stop:
            try:
                message = handle.output.get(timeout=0.2)
            except queue.Empty:
                try:
                    alive = handle.process.is_alive()
                except (AssertionError, OSError, ValueError) as exc:
                    if not handle.intentional_stop:
                        self._signal_worker_failure(
                            handle,
                            f"worker liveness check failed: {type(exc).__name__}: {exc}",
                        )
                    return
                if alive:
                    dead_since = None
                    continue
                dead_since = dead_since or time.monotonic()
                if time.monotonic() - dead_since >= 2.0:
                    return
                continue
            except (EOFError, OSError, ValueError) as exc:
                if not handle.intentional_stop:
                    self._signal_worker_failure(
                        handle,
                        f"worker output consumer failed: {type(exc).__name__}: {exc}",
                    )
                return
            try:
                kind = message["kind"]
                if kind == "terminal":
                    if not self._worker_message_is_current(execution_id, handle, message):
                        continue
                    handle.process.join(timeout=2)
                    if handle.process.is_alive():
                        self._signal_worker_failure(
                            handle, "worker remained alive after its terminal message"
                        )
                        return
                    handle.normal_exit = True
                    self._cleanup_worker(execution_id, handle)
                    return
                with self._lock:
                    if not self._worker_message_is_current(execution_id, handle, message):
                        continue
                    if kind == "event":
                        self.append_event(
                            execution_id,
                            message["event_type"],
                            message.get("payload", {}),
                            source=message.get("source", "worker"),
                            severity=message.get("severity", "info"),
                        )
                    elif kind == "state":
                        self._set_worker_state(
                            execution_id,
                            message["state"],
                            command_id=message.get("command_id"),
                        )
                    elif kind == "step_commit":
                        self._commit_step(execution_id, handle.generation, message)
                    elif kind == "prompt_opened":
                        self._open_prompt(execution_id, message)
                    else:
                        raise ValueError(f"unsupported worker message kind: {kind!r}")
            except Exception as exc:
                self._signal_worker_failure(
                    handle,
                    f"worker consumer failed while handling a message: "
                    f"{type(exc).__name__}: {exc}",
                )
                return

    def _monitor_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        while not self._closed and not handle.intentional_stop:
            if handle.failure_signal.wait(timeout=0.05):
                self._recover_worker_loss(
                    execution_id,
                    handle,
                    "worker.consumer_failed",
                    {"error": handle.failure_detail or "worker consumer failed"},
                    handle.failure_detail or "worker consumer failed",
                )
                return
            try:
                handle.process.join(timeout=0.05)
                if not handle.process.is_alive():
                    break
            except (AssertionError, OSError, ValueError) as exc:
                if not self._closed and not handle.intentional_stop:
                    self._recover_worker_loss(
                        execution_id,
                        handle,
                        "worker.monitor_failed",
                        {"error": f"{type(exc).__name__}: {exc}"},
                        f"worker monitor failed: {type(exc).__name__}: {exc}",
                    )
                return
        if self._closed or handle.intentional_stop:
            return
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if self._closed or handle.normal_exit or handle.intentional_stop:
                return
            if handle.failure_signal.wait(timeout=0.05):
                self._recover_worker_loss(
                    execution_id,
                    handle,
                    "worker.consumer_failed",
                    {"error": handle.failure_detail or "worker consumer failed"},
                    handle.failure_detail or "worker consumer failed",
                )
                return
        if self._closed or handle.normal_exit or handle.intentional_stop:
            return
        with self._lock:
            if self._workers.get(execution_id) is not handle:
                return
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                if execution is not None and execution.state in TERMINAL_STATES:
                    handle.normal_exit = True
                    self._cleanup_worker(execution_id, handle)
                    return
            exit_code = handle.process.exitcode
        self._recover_worker_loss(
            execution_id,
            handle,
            "worker.crashed",
            {"exit_code": exit_code},
            f"worker exited unexpectedly with code {exit_code}",
        )

    @staticmethod
    def _signal_worker_failure(handle: WorkerHandle, detail: str) -> None:
        if handle.failure_signal.is_set():
            return
        handle.failure_detail = detail
        handle.failure_signal.set()

    def _recover_worker_loss(
        self,
        execution_id: str,
        handle: WorkerHandle,
        event_type: str,
        payload: dict[str, Any],
        command_error: str,
        pending_command_id: str | None = None,
    ) -> None:
        with self._lock:
            if (
                self._closed
                or handle.intentional_stop
                or self._workers.get(execution_id) is not handle
            ):
                return
            if pending_command_id is not None:
                with self.session_factory() as session:
                    command = session.get(Command, pending_command_id)
                    if (
                        command is None
                        or command.execution_id != execution_id
                        or command.status != "accepted"
                    ):
                        return
            handle.intentional_stop = True
        terminated = self._terminate_worker(handle)
        if terminated:
            self._cleanup_worker(execution_id, handle)
        try:
            self.append_event(
                execution_id,
                event_type,
                payload,
                source="supervisor",
                severity="error",
            )
        except Exception:
            # The recovery transition below remains the durable source of truth if
            # recording the supplementary worker-loss event also fails.
            pass
        retry_delay = 0.05
        while not self._closed:
            try:
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="supervisor",
                    preserve_open_prompts=True,
                    pending_command_error=command_error,
                )
                return
            except Exception:
                if self._closed:
                    return
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 1.0)

    def _recover_dispatch_failure(self, execution_id: str, command_error: str) -> None:
        try:
            self._invalidate_worker(execution_id)
        except RuntimeError as exc:
            command_error = f"{command_error}; {exc}"
        retry_delay = 0.05
        while True:
            try:
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="supervisor",
                    preserve_open_prompts=True,
                    pending_command_error=command_error,
                )
                return
            except Exception:
                if self._closed:
                    return
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 1.0)

    def _simulate_crash(self, execution_id: str, command_id: str) -> None:
        with self._lock:
            handle = self._workers.get(execution_id)
            if handle is not None:
                handle.intentional_stop = True
        if handle is None or not handle.process.is_alive():
            self._fail_command(command_id, "worker is unavailable")
            self._set_state(
                execution_id,
                "recovery_required",
                source="supervisor",
                preserve_open_prompts=True,
            )
            return
        if not self._terminate_worker(handle):
            raise RuntimeError("simulated crash could not terminate worker")
        exit_code = handle.process.exitcode
        self._cleanup_worker(execution_id, handle)
        self.append_event(
            execution_id,
            "worker.crash_simulated",
            {"exit_code": exit_code},
            source="supervisor",
            severity="warning",
            causation_id=command_id,
        )
        self._complete_command(command_id, {"state": "recovery_required"})
        self._set_state(
            execution_id,
            "recovery_required",
            source="supervisor",
            preserve_open_prompts=True,
        )

    def _worker_message_is_current(
        self, execution_id: str, handle: WorkerHandle, message: dict[str, Any]
    ) -> bool:
        if message.get("generation") != handle.generation:
            return False
        with self._lock:
            if (
                handle.intentional_stop
                or self._workers.get(execution_id) is not handle
            ):
                return False
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                return execution is not None and execution.worker_generation == handle.generation

    def _commit_step(
        self, execution_id: str, generation: int, message: dict[str, Any]
    ) -> bool:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None or execution.worker_generation != generation:
                return False
            if execution.state not in {
                "running",
                "pausing",
                "paused",
                "resuming",
                "prompting",
                "aborting",
            }:
                return False
            step_index = message["step_index"]
            next_step = message["next_step"]
            if next_step <= execution.current_step:
                return False
            if step_index != execution.current_step or next_step != step_index + 1:
                raise ConflictError("worker checkpoint is not contiguous")

            prompt_resolution = message.get("prompt_resolution")
            checkpoint_variables = message.get("variables")
            if not isinstance(checkpoint_variables, dict):
                raise ConflictError("worker checkpoint variables are missing or invalid")
            if prompt_resolution is not None:
                prompt = session.get(Prompt, prompt_resolution["prompt_id"])
                command = session.get(Command, prompt_resolution["command_id"])
                if prompt is None or command is None or prompt.status != "responding":
                    raise ConflictError("prompt checkpoint references an unreserved prompt")
                if (
                    prompt.response != prompt_resolution["response"]
                    or command.request_payload.get("prompt_id") != prompt.id
                ):
                    raise ConflictError("prompt checkpoint does not match the reserved response")
                prompt.status = "answered"
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "prompt.answered",
                            {
                                "prompt_id": prompt.id,
                                "response": prompt_resolution["response"],
                            },
                            source="worker",
                            causation_id=command.id,
                        )
                    )
                )
                completed = self._complete_command_in_session(
                    session, execution, command, {"response": prompt_resolution["response"]}
                )
                if completed is not None:
                    published.append(event_dict(completed))

            for effect in message["effects"]:
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            effect["event_type"],
                            effect.get("payload", {}),
                            source=effect.get("source", "worker"),
                            severity=effect.get("severity", "info"),
                        )
                    )
                )
            execution.current_step = next_step
            execution.variables = checkpoint_variables
            published.append(
                event_dict(
                    self._add_event(
                        session,
                        execution,
                        "execution.checkpointed",
                        {
                            "next_step": next_step,
                            "generation": generation,
                            "variables": checkpoint_variables,
                        },
                        source="supervisor",
                    )
                )
            )
            session.commit()
            self._publish(execution_id, published)
        return True

    def _open_prompt(self, execution_id: str, message: dict[str, Any]) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None or execution.state not in {
                "running",
                "pausing",
                "prompting",
                "aborting",
            }:
                return
            prompt = session.get(Prompt, message["prompt_id"])
            if prompt is None:
                prompt = Prompt(
                    id=message["prompt_id"],
                    execution_id=execution_id,
                    step_index=message["step_index"],
                    question=message["question"],
                    choices=message["choices"],
                    default_choice=message["default"],
                )
                session.add(prompt)
                event_type = "prompt.opened"
            else:
                event_type = "prompt.reopened"

            previous = execution.state
            transition_to_prompting = previous not in {"pausing", "aborting"}
            if transition_to_prompting and previous != "prompting":
                execution.state = "prompting"
                execution.revision += 1
            prompt_event = self._add_event(
                session,
                execution,
                event_type,
                {
                    "prompt_id": prompt.id,
                    "step_index": prompt.step_index,
                    "question": prompt.question,
                    "choices": prompt.choices,
                    "default": prompt.default_choice,
                    "revision": execution.revision,
                },
                source="worker",
            )
            published.append(event_dict(prompt_event))
            if transition_to_prompting and previous != "prompting":
                state_event = self._add_event(
                    session,
                    execution,
                    "execution.state_changed",
                    {"previous": previous, "state": "prompting", "revision": execution.revision},
                    source="worker",
                )
                published.append(event_dict(state_event))
            session.commit()
            self._publish(execution_id, published)

    def _set_worker_state(
        self, execution_id: str, state: str, command_id: str | None = None
    ) -> None:
        allowed_previous = {
            "running": {"starting", "recovering", "resuming", "prompting", "running"},
            "paused": {"pausing", "paused"},
            "prompting": {"running", "prompting"},
            "aborted": {"aborting", "aborted"},
            "completed": {"running", "completed"},
            "failed": {"starting", "running", "recovering", "failed"},
        }
        pending_command_error: str | None = None
        with self._lock:
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                if execution is None or execution.state in TERMINAL_STATES:
                    return
                previous = execution.state
                if previous not in allowed_previous.get(state, set()):
                    if state not in TERMINAL_STATES or previous not in {
                        "pausing",
                        "resuming",
                        "aborting",
                    }:
                        return
                    pending_command_error = (
                        f"worker reached {state} before command dispatch"
                    )
            self._set_state(
                execution_id,
                state,
                source="worker",
                command_id=command_id,
                pending_command_error=pending_command_error,
            )

    def _set_state(
        self,
        execution_id: str,
        state: str,
        source: str,
        command_id: str | None = None,
        preserve_open_prompts: bool = False,
        pending_command_error: str | None = None,
    ) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                return
            previous = execution.state
            if previous in TERMINAL_STATES and previous != state:
                return
            if previous != state:
                execution.state = state
                execution.revision += 1
                state_payload: dict[str, Any] = {
                    "previous": previous,
                    "state": state,
                    "revision": execution.revision,
                }
                if pending_command_error is not None:
                    state_payload["reason"] = pending_command_error
                state_event = self._add_event(
                    session,
                    execution,
                    "execution.state_changed",
                    state_payload,
                    source=source,
                    causation_id=command_id,
                )
                published.append(event_dict(state_event))
                if state in TERMINAL_STATES | {"recovery_required"}:
                    active_prompts = session.scalars(
                        select(Prompt).where(
                            Prompt.execution_id == execution_id,
                            Prompt.status.in_(["open", "responding"]),
                        )
                    ).all()
                    for prompt in active_prompts:
                        if (
                            state == "recovery_required"
                            and preserve_open_prompts
                            and prompt.status == "open"
                        ):
                            continue
                        was_responding = prompt.status == "responding"
                        if state == "aborted":
                            prompt.status = "cancelled"
                            event_type = "prompt.cancelled"
                            reason = "execution_aborted"
                        elif state == "completed":
                            prompt.status = "closed"
                            event_type = "prompt.closed"
                            reason = "execution_completed"
                        else:
                            prompt.status = "interrupted"
                            event_type = "prompt.interrupted"
                            reason = (
                                "worker_recovery_required"
                                if state == "recovery_required"
                                else "execution_failed"
                            )
                        prompt.responded_at = datetime.now(timezone.utc)
                        prompt_event = self._add_event(
                            session,
                            execution,
                            event_type,
                            {"prompt_id": prompt.id, "reason": reason},
                            source="supervisor",
                            severity="warning" if state != "completed" else "info",
                            causation_id=command_id,
                        )
                        published.append(event_dict(prompt_event))
                        if was_responding and state != "completed":
                            pending_responses = session.scalars(
                                select(Command).where(
                                    Command.execution_id == execution_id,
                                    Command.command_type == "prompt_response",
                                    Command.status == "accepted",
                                )
                            ).all()
                            for pending in pending_responses:
                                if pending.request_payload.get("prompt_id") != prompt.id:
                                    continue
                                pending.status = "failed"
                                pending.result_payload = {
                                    "error": f"prompt response interrupted by {state}"
                                }
                                pending.completed_at = datetime.now(timezone.utc)
                                failed_event = self._add_event(
                                    session,
                                    execution,
                                    "command.failed",
                                    {
                                        "command_id": pending.id,
                                        "error": pending.result_payload["error"],
                                    },
                                    source="supervisor",
                                    severity="error",
                                    correlation_id=pending.correlation_id,
                                    causation_id=pending.id,
                                )
                                published.append(event_dict(failed_event))
            if state in TERMINAL_STATES | {"recovery_required"}:
                pending_commands = session.scalars(
                    select(Command).where(
                        Command.execution_id == execution_id,
                        Command.status == "accepted",
                    )
                ).all()
                error = pending_command_error or (
                    f"execution entered {state} before command completion"
                )
                for pending in pending_commands:
                    if command_id is not None and pending.id == command_id:
                        continue
                    failed_event = self._fail_command_in_session(
                        session, execution, pending, error
                    )
                    if failed_event is not None:
                        published.append(event_dict(failed_event))
            revision = execution.revision
            if command_id is not None:
                command = session.get(Command, command_id)
                if command is not None and command.execution_id == execution_id:
                    completed = self._complete_command_in_session(
                        session, execution, command, {"state": state, "revision": revision}
                    )
                    if completed is not None:
                        published.append(event_dict(completed))
            session.commit()
            self._publish(execution_id, published)

    def _complete_command(self, command_id: str, result: dict[str, Any]) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            command = session.get(Command, command_id)
            if command is None or command.status != "accepted":
                return
            execution_id = command.execution_id
            execution = session.get(Execution, execution_id)
            if execution is None:
                return
            event = self._complete_command_in_session(session, execution, command, result)
            session.commit()
            if event is not None:
                published = [event_dict(event)]
            self._publish(execution_id, published)

    def _complete_command_in_session(
        self,
        session: Session,
        execution: Execution,
        command: Command,
        result: dict[str, Any],
    ) -> Event | None:
        if command.status != "accepted":
            return None
        command.status = "completed"
        command.result_payload = result
        command.completed_at = datetime.now(timezone.utc)
        return self._add_event(
            session,
            execution,
            "command.completed",
            {"command_id": command.id, "result": result},
            source="supervisor",
            correlation_id=command.correlation_id,
            causation_id=command.id,
        )

    def _fail_command(self, command_id: str, message: str) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            command = session.get(Command, command_id)
            if command is None or command.status != "accepted":
                return
            execution_id = command.execution_id
            execution = session.get(Execution, execution_id)
            if execution is None:
                return
            event = self._fail_command_in_session(session, execution, command, message)
            session.commit()
            if event is not None:
                published = [event_dict(event)]
            self._publish(execution_id, published)

    def _fail_command_in_session(
        self,
        session: Session,
        execution: Execution,
        command: Command,
        message: str,
    ) -> Event | None:
        if command.status != "accepted":
            return None
        command.status = "failed"
        command.result_payload = {"error": message}
        command.completed_at = datetime.now(timezone.utc)
        return self._add_event(
            session,
            execution,
            "command.failed",
            {"command_id": command.id, "error": message},
            source="supervisor",
            severity="error",
            correlation_id=command.correlation_id,
            causation_id=command.id,
        )

    def append_event(
        self,
        execution_id: str,
        event_type: str,
        payload: dict[str, Any],
        source: str,
        severity: str = "info",
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            event = self._add_event(
                session,
                execution,
                event_type,
                payload,
                source,
                severity,
                correlation_id,
                causation_id,
            )
            session.commit()
            serialized = event_dict(event)
            # Commit and publication share the supervisor lock so live subscribers
            # observe the same per-execution order as the durable event log.
            self.hub.publish(execution_id, serialized)
        return serialized

    @staticmethod
    def _add_event(
        session: Session,
        execution: Execution,
        event_type: str,
        payload: dict[str, Any],
        source: str,
        severity: str = "info",
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> Event:
        event = Event(
            execution_id=execution.id,
            sequence=execution.next_sequence,
            event_type=event_type,
            source=source,
            severity=severity,
            correlation_id=correlation_id,
            causation_id=causation_id,
            payload=payload,
        )
        execution.next_sequence += 1
        session.add(event)
        session.flush()
        return event

    def _publish(self, execution_id: str, events: list[dict[str, Any]]) -> None:
        for event in events:
            self.hub.publish(execution_id, event)

    def _invalidate_worker(self, execution_id: str) -> None:
        with self._lock:
            handle = self._workers.get(execution_id)
            if handle is None:
                return
            handle.intentional_stop = True
        if not self._terminate_worker(handle):
            raise RuntimeError("worker termination failed; generation remains fenced")
        self._cleanup_worker(execution_id, handle)

    @staticmethod
    def _terminate_worker(handle: WorkerHandle) -> bool:
        try:
            if not handle.process.is_alive():
                return True
        except (AssertionError, AttributeError, OSError, ValueError):
            return False
        try:
            handle.process.terminate()
            handle.process.join(timeout=2)
        except (AssertionError, AttributeError, OSError, ValueError):
            pass
        try:
            if handle.process.is_alive():
                handle.process.kill()
                handle.process.join(timeout=2)
        except (AssertionError, AttributeError, OSError, ValueError):
            pass
        try:
            return not handle.process.is_alive()
        except (AssertionError, AttributeError, OSError, ValueError):
            return False

    def _cleanup_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        with self._lock:
            if self._workers.get(execution_id) is not handle:
                return
            self._workers.pop(execution_id, None)
        for worker_queue in (handle.control, handle.output):
            try:
                worker_queue.close()
                worker_queue.cancel_join_thread()
            except (OSError, ValueError):
                pass
        try:
            if not handle.process.is_alive():
                handle.process.close()
        except (AssertionError, AttributeError, ValueError):
            pass

    def events_after(self, execution_id: str, after: int, limit: int) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            if session.get(Execution, execution_id) is None:
                raise NotFoundError("execution not found")
            events = session.scalars(
                select(Event)
                .where(Event.execution_id == execution_id, Event.sequence > after)
                .order_by(Event.sequence)
                .limit(limit)
            ).all()
            return [event_dict(event) for event in events]

    def close(self) -> None:
        with self._lock:
            self._closed = True
            handles = tuple(self._workers.items())
            for _, handle in handles:
                handle.intentional_stop = True
        for execution_id, handle in handles:
            self._terminate_worker(handle)
            self._cleanup_worker(execution_id, handle)

        with self.session_factory() as session:
            execution_ids = set(
                session.scalars(
                    select(Execution.id).where(Execution.state.in_(ACTIVE_STATES))
                ).all()
            )
            execution_ids.update(
                session.scalars(
                    select(Command.execution_id)
                    .where(Command.status == "accepted")
                    .distinct()
                ).all()
            )
            states = {
                execution_id: session.get(Execution, execution_id).state
                for execution_id in execution_ids
                if session.get(Execution, execution_id) is not None
            }
        for execution_id, state in states.items():
            target_state = (
                state
                if state in TERMINAL_STATES | {"recovery_required"}
                else "recovery_required"
            )
            self._set_state(
                execution_id,
                target_state,
                source="supervisor",
                preserve_open_prompts=target_state == "recovery_required",
                pending_command_error="supervisor stopped before command completion",
            )
