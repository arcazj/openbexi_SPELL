"""Deterministic Candidate A host/context/attachment lifecycle state machine."""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Callable, Optional, Sequence, Tuple

from spell.driver.configuration import (
    context_binding_digest,
    execution_attachment_digest,
)

from .config import HostConfig
from .domain import (
    AttachmentState,
    AttemptRecord,
    Certainty,
    ContextState,
    ErrorCode,
    GenerationIdentity,
    HookAction,
    HookLayer,
    HookOutcome,
    HookTraceRecord,
    HostState,
    Method,
    OperationCommand,
    OperationRecord,
    Result,
    SafeFailure,
    Stage,
)
from .hooks import DeterministicHooks, HookSpec
from .journal import (
    JournalCapacityError,
    JournalConflictError,
    JournalError,
    JournalIntegrityError,
    OperationJournal,
)


@dataclass(frozen=True)
class ContextSnapshot:
    context_id: str
    context_generation: str
    context_binding_digest: str
    state: ContextState
    ready: bool
    last_observed_unix_ms: int


@dataclass(frozen=True)
class AttachmentSnapshot:
    execution_id: str
    execution_attachment_generation: str
    execution_attachment_digest: str
    driver_binding_id: str
    state: AttachmentState
    last_observed_unix_ms: int


@dataclass(frozen=True)
class HostSnapshot:
    state: HostState
    ready: bool
    contexts: Tuple[ContextSnapshot, ...]
    attachments: Tuple[AttachmentSnapshot, ...]
    in_flight_host: int
    in_flight_context: int
    last_observed_unix_ms: int


class SimulatorLifecycleHost:
    """Owns lifecycle effects; it has no procedure or data-plane API."""

    def __init__(
        self,
        config: HostConfig,
        journal: OperationJournal,
        *,
        hooks: DeterministicHooks | None = None,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if journal.generation != config.driver_host_generation:
            raise ValueError("journal and host generation differ")
        self.config = config
        self.journal = journal
        self.hooks = hooks or DeterministicHooks(delay_ms=config.hooks.delay_ms)
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._state_lock = asyncio.Lock()
        self._host_state = HostState.STARTING
        self._context: Optional[ContextSnapshot] = None
        self._attachment: Optional[AttachmentSnapshot] = None
        self._active: dict[str, asyncio.Event] = {}
        self._replay_projection()
        if self._host_state is HostState.STARTING:
            self._host_state = HostState.READY

    def _replay_projection(self) -> None:
        for attempt in self.journal.list_attempts_chronologically():
            if (
                attempt.identity.driver_host_generation
                != self.config.driver_host_generation
            ):
                continue
            if attempt.stage is Stage.ACCEPTED:
                attempt = self.journal.settle(
                    attempt.attempt_id,
                    Certainty.NO_EFFECT,
                    Result.INTERNAL,
                    SafeFailure(
                        ErrorCode.JOURNAL,
                        "restart occurred before lifecycle dispatch",
                    ),
                )
            if attempt.stage in {Stage.DISPATCHED, Stage.RECONCILING}:
                self._host_state = HostState.DEGRADED
                if attempt.method is Method.OPEN_CONTEXT:
                    self._attachment = None
                    self._context = None
                elif attempt.method is Method.ATTACH_EXECUTION:
                    self._attachment = None
                elif attempt.method is Method.DETACH_EXECUTION:
                    self._attachment = None
                elif attempt.method in {Method.CLOSE_CONTEXT, Method.DRAIN_HOST}:
                    self._attachment = None
                    self._context = None
                continue
            if (
                attempt.stage is not Stage.SETTLED
                or attempt.certainty is not Certainty.EFFECT_CONFIRMED
            ):
                continue
            now = attempt.settled_unix_ms
            identity = attempt.identity
            if attempt.method is Method.OPEN_CONTEXT:
                self._context = ContextSnapshot(
                    identity.context_id,
                    identity.context_generation,
                    identity.context_binding_digest,
                    ContextState.ACTIVE,
                    True,
                    now,
                )
            elif attempt.method is Method.CLOSE_CONTEXT:
                self._attachment = None
                self._context = None
            elif attempt.method is Method.ATTACH_EXECUTION:
                if (
                    attempt.lifecycle_reason == "RELOAD"
                    and attempt.result is not Result.OK
                ):
                    self._attachment = None
                else:
                    self._attachment = AttachmentSnapshot(
                        identity.execution_id,
                        identity.execution_attachment_generation,
                        identity.execution_attachment_digest,
                        identity.driver_binding_id,
                        AttachmentState.ATTACHED,
                        now,
                    )
            elif attempt.method is Method.DETACH_EXECUTION:
                self._attachment = None
            elif attempt.method is Method.DRAIN_HOST:
                self._attachment = None
                self._context = None
                self._host_state = HostState.CLOSED

    def snapshot(self) -> HostSnapshot:
        now = self._clock_ms()
        context_active = sum(
            1
            for attempt_id in self._active
            if self._attempt_has_context(attempt_id)
        )
        return HostSnapshot(
            state=self._host_state,
            ready=self._host_state is HostState.READY,
            contexts=(self._context,) if self._context is not None else (),
            attachments=(self._attachment,) if self._attachment is not None else (),
            in_flight_host=len(self._active),
            in_flight_context=context_active,
            last_observed_unix_ms=now,
        )

    def _attempt_has_context(self, attempt_id: str) -> bool:
        try:
            operation = next(
                item
                for item in self.journal.list_operations()
                if item.current_attempt_id == attempt_id
            )
        except StopIteration:
            return False
        return bool(operation.identity.context_id)

    def _failure_record(
        self,
        command: OperationCommand,
        result: Result,
        code: ErrorCode,
        message: str,
    ) -> OperationRecord:
        now = self._clock_ms()
        attempt = AttemptRecord(
            operation_id=command.operation_id,
            method=command.method,
            identity=command.identity,
            attempt_id=command.attempt_id,
            attempt_number=command.attempt_number,
            request_digest=command.request_digest,
            effect=command.effect,
            stage=Stage.SETTLED,
            certainty=Certainty.NO_EFFECT,
            result=result,
            error=SafeFailure(code, message),
            requested_unix_ms=now,
            accepted_unix_ms=now,
            settled_unix_ms=now,
            lifecycle_reason=command.lifecycle_reason,
            replaced_driver_binding_id=command.replaced_driver_binding_id,
        )
        return OperationRecord(
            operation_id=command.operation_id,
            method=command.method,
            identity=command.identity,
            current_attempt_id=command.attempt_id,
            attempts=(attempt,),
        )

    def _validate_generation(self, command: OperationCommand) -> Optional[OperationRecord]:
        identity = command.identity
        if identity.server_profile_id != self.config.server_profile_id:
            return self._failure_record(
                command, Result.STALE_GENERATION, ErrorCode.IDENTITY_MISMATCH, "server profile differs"
            )
        if identity.driver_host_generation != self.config.driver_host_generation:
            return self._failure_record(
                command,
                Result.STALE_GENERATION,
                ErrorCode.GENERATION_MISMATCH,
                "driver host generation differs",
            )
        if identity.host_profile_digest != self.config.host_profile_digest:
            return self._failure_record(
                command, Result.STALE_GENERATION, ErrorCode.DIGEST_MISMATCH, "host profile digest differs"
            )
        if command.credential_epoch != self.config.credential_epoch:
            return self._failure_record(
                command,
                Result.STALE_GENERATION,
                ErrorCode.IDENTITY_MISMATCH,
                "credential epoch differs",
            )
        return None

    def _validate_method(self, command: OperationCommand) -> Optional[OperationRecord]:
        identity = command.identity
        if self._host_state in {HostState.CLOSED, HostState.FAILED} or (
            self._host_state is HostState.DEGRADED
            and command.method is not Method.DRAIN_HOST
        ):
            return self._failure_record(
                command,
                Result.INVALID_ARGUMENT,
                ErrorCode.VALIDATION,
                "driver host generation is terminal",
            )
        if command.method is Method.OPEN_CONTEXT:
            resolved_digest = context_binding_digest(
                server_profile_id=identity.server_profile_id,
                driver_host_generation=identity.driver_host_generation,
                host_profile_digest=identity.host_profile_digest,
                schema_version=command.context_schema_version,
                context_profile_id=command.context_profile_id,
                synthetic_context_label=command.synthetic_context_label,
            )
            valid = (
                bool(identity.context_id and identity.context_generation and identity.context_binding_digest)
                and not identity.execution_id
                and command.expected_context_digest == identity.context_binding_digest
                and identity.context_binding_digest == resolved_digest
                and bool(command.context_schema_version and command.context_profile_id and command.synthetic_context_label)
                and self._context is None
                and self._host_state is HostState.READY
            )
        elif command.method is Method.CLOSE_CONTEXT:
            valid = self._matches_context(identity) and (
                self._attachment is None or command.detach_settled_attachments
            )
        elif command.method is Method.ATTACH_EXECUTION:
            resolved_digest = execution_attachment_digest(
                server_profile_id=identity.server_profile_id,
                driver_host_generation=identity.driver_host_generation,
                host_profile_digest=identity.host_profile_digest,
                context_id=identity.context_id,
                context_generation=identity.context_generation,
                context_binding_digest=identity.context_binding_digest,
                execution_id=identity.execution_id,
                schema_version=command.attachment_schema_version,
                attachment_profile_id=command.attachment_profile_id,
                synthetic_execution_label=command.synthetic_execution_label,
            )
            valid = (
                self._matches_context(identity)
                and bool(
                    identity.execution_id
                    and identity.execution_attachment_generation
                    and identity.execution_attachment_digest
                    and identity.driver_binding_id
                )
                and command.expected_attachment_digest == identity.execution_attachment_digest
                and identity.execution_attachment_digest == resolved_digest
                and bool(
                    command.attachment_schema_version
                    and command.attachment_profile_id
                    and command.synthetic_execution_label
                )
                and command.lifecycle_reason in {"INITIAL_LOAD", "RELOAD"}
                and (
                    (
                        self._attachment is None
                        and command.lifecycle_reason == "INITIAL_LOAD"
                        and not command.replaced_driver_binding_id
                    )
                    or (
                        self._attachment is not None
                        and command.lifecycle_reason == "RELOAD"
                        and command.replaced_driver_binding_id
                        == self._attachment.driver_binding_id
                    )
                )
            )
        elif command.method is Method.DETACH_EXECUTION:
            valid = self._matches_context(identity) and self._matches_attachment(identity)
        elif command.method is Method.CANCEL_LIFECYCLE_OPERATION:
            valid = bool(command.target_operation_id and command.target_attempt_id)
        elif command.method is Method.DRAIN_HOST:
            valid = self._host_state in {HostState.READY, HostState.DEGRADED}
        else:
            valid = False
        if valid:
            return None
        return self._failure_record(
            command, Result.INVALID_ARGUMENT, ErrorCode.VALIDATION, "lifecycle request is not valid for current state"
        )

    def _matches_context(self, identity: GenerationIdentity) -> bool:
        return self._context is not None and (
            identity.context_id,
            identity.context_generation,
            identity.context_binding_digest,
        ) == (
            self._context.context_id,
            self._context.context_generation,
            self._context.context_binding_digest,
        )

    def _matches_attachment(self, identity: GenerationIdentity) -> bool:
        return self._attachment is not None and (
            identity.execution_id,
            identity.execution_attachment_generation,
            identity.execution_attachment_digest,
            identity.driver_binding_id,
        ) == (
            self._attachment.execution_id,
            self._attachment.execution_attachment_generation,
            self._attachment.execution_attachment_digest,
            self._attachment.driver_binding_id,
        )

    async def execute(self, command: OperationCommand) -> OperationRecord:
        if command.deadline_unix_ms <= self._clock_ms():
            return self._failure_record(
                command, Result.DEADLINE_EXCEEDED, ErrorCode.DEADLINE, "deadline expired before dispatch"
            )
        generation_error = self._validate_generation(command)
        if generation_error is not None:
            return generation_error
        async with self._state_lock:
            existing = self.journal.get_attempt(command.attempt_id)
            if existing is not None:
                try:
                    accepted, _ = self.journal.accept(command)
                except (JournalConflictError, JournalIntegrityError):
                    return self._failure_record(
                        command,
                        Result.CONFLICT,
                        ErrorCode.CONFLICT,
                        "operation identity conflicts with durable evidence",
                    )
                if accepted.stage is Stage.ACCEPTED:
                    self.journal.settle(
                        command.attempt_id,
                        Certainty.NO_EFFECT,
                        Result.INTERNAL,
                        SafeFailure(ErrorCode.JOURNAL, "restart occurred before dispatch"),
                    )
                elif accepted.stage is Stage.DISPATCHED:
                    self.journal.reconcile(
                        command.attempt_id,
                        Certainty.EFFECT_POSSIBLE,
                        SafeFailure(ErrorCode.JOURNAL, "accepted operation requires reconciliation"),
                    )
                    self._host_state = HostState.DEGRADED
                return self.journal.get_operation(command.operation_id)
            validation_error = self._validate_method(command)
            if validation_error is not None:
                return validation_error
            host_limit = self.config.capacity.max_lifecycle_operations_per_host
            context_limit = self.config.capacity.max_lifecycle_operations_per_context
            context_active = sum(
                1 for attempt_id in self._active if self._attempt_has_context(attempt_id)
            )
            if len(self._active) >= host_limit or (
                command.identity.context_id and context_active >= context_limit
            ):
                return self._failure_record(
                    command,
                    Result.CAPACITY_EXHAUSTED,
                    ErrorCode.CAPACITY,
                    "lifecycle operation capacity is exhausted",
                )
            try:
                accepted, duplicate = self.journal.accept(command)
            except JournalCapacityError:
                self._host_state = HostState.DEGRADED
                return self._failure_record(
                    command,
                    Result.JOURNAL_UNAVAILABLE,
                    ErrorCode.JOURNAL,
                    "journal capacity is exhausted",
                )
            except (JournalConflictError, JournalIntegrityError):
                self._host_state = HostState.DEGRADED
                return self._failure_record(
                    command,
                    Result.CONFLICT,
                    ErrorCode.CONFLICT,
                    "operation identity conflicts with durable evidence",
                )
            if duplicate:
                raise RuntimeError("new journal acceptance unexpectedly reported a duplicate")
            cancellation = asyncio.Event()
            self._active[command.attempt_id] = cancellation
        deadline_task = asyncio.create_task(
            self._signal_deadline(command.deadline_unix_ms, cancellation)
        )
        dispatch_recorded = False
        try:
            self.journal.mark_dispatched(command.attempt_id)
            dispatch_recorded = True
            if command.method is Method.OPEN_CONTEXT:
                await self._open_context(command, cancellation)
            elif command.method is Method.CLOSE_CONTEXT:
                await self._close_context(command, cancellation)
            elif command.method is Method.ATTACH_EXECUTION:
                await self._attach_execution(command, cancellation)
            elif command.method is Method.DETACH_EXECUTION:
                await self._detach_execution(command, cancellation)
            elif command.method is Method.CANCEL_LIFECYCLE_OPERATION:
                await self._cancel_operation(command)
            elif command.method is Method.DRAIN_HOST:
                await self._drain_host(command, cancellation)
        except JournalError as exc:
            self._host_state = HostState.FAILED
            try:
                if dispatch_recorded:
                    self.journal.reconcile(
                        command.attempt_id,
                        Certainty.EFFECT_UNKNOWN,
                        SafeFailure(ErrorCode.JOURNAL, "journal failed after dispatch"),
                    )
                else:
                    self.journal.settle(
                        command.attempt_id,
                        Certainty.NO_EFFECT,
                        Result.JOURNAL_UNAVAILABLE,
                        SafeFailure(
                            ErrorCode.JOURNAL,
                            "journal rejected dispatch before lifecycle effect",
                        ),
                    )
            except JournalError as latch_error:
                raise JournalIntegrityError(
                    "journal failure could not be durably latched"
                ) from latch_error
            if dispatch_recorded:
                raise JournalIntegrityError(
                    "journal failed after lifecycle dispatch"
                ) from exc
        finally:
            deadline_task.cancel()
            with suppress(asyncio.CancelledError):
                await deadline_task
            async with self._state_lock:
                self._active.pop(command.attempt_id, None)
        return self.journal.get_operation(command.operation_id)

    async def _signal_deadline(
        self, deadline_unix_ms: int, cancellation: asyncio.Event
    ) -> None:
        remaining = max(0, deadline_unix_ms - self._clock_ms())
        if remaining:
            await asyncio.sleep(remaining / 1000)
        cancellation.set()

    def _cancellation_disposition(
        self, command: OperationCommand
    ) -> tuple[Result, SafeFailure]:
        if self._clock_ms() >= command.deadline_unix_ms:
            return (
                Result.DEADLINE_EXCEEDED,
                SafeFailure(ErrorCode.DEADLINE, "lifecycle deadline elapsed during setup"),
            )
        return (
            Result.CANCELLED,
            SafeFailure(ErrorCode.CANCELLED, "lifecycle cancellation was observed"),
        )

    def _completed_disposition(
        self, command: OperationCommand, cleanup_failed: bool
    ) -> tuple[Result, Optional[SafeFailure]]:
        if cleanup_failed:
            return (
                Result.INTERNAL,
                SafeFailure(ErrorCode.HOOK, "one or more lifecycle cleanup hooks failed"),
            )
        if self._clock_ms() >= command.deadline_unix_ms:
            return (
                Result.DEADLINE_EXCEEDED,
                SafeFailure(
                    ErrorCode.DEADLINE,
                    "lifecycle deadline elapsed after the effect completed",
                ),
            )
        return Result.OK, None

    def get_operation(self, operation_id: str, attempt_id: str = "") -> OperationRecord:
        operation = self.journal.get_operation(operation_id)
        if attempt_id and all(item.attempt_id != attempt_id for item in operation.attempts):
            raise KeyError("operation attempt not found")
        return operation

    async def _run_setup(
        self,
        attempt_id: str,
        specs: Sequence[HookSpec],
        cancellation: asyncio.Event,
    ) -> tuple[bool, list[HookSpec], bool]:
        completed: list[HookSpec] = []
        failed = False
        cancelled = False
        for spec in specs:
            current = self.journal.get_attempt(attempt_id)
            if current is None:
                raise JournalIntegrityError("operation attempt disappeared before hook")
            trace = await self.hooks.run(
                spec, HookAction.SETUP, len(current.hook_traces) + 1, cancellation
            )
            trace = replace(
                trace,
                identity=current.identity,
                operation_id=current.operation_id,
                attempt_id=current.attempt_id,
                stage=current.stage,
                certainty=current.certainty,
            )
            self.journal.append_trace(attempt_id, trace)
            if trace.outcome is HookOutcome.COMPLETED:
                completed.append(spec)
                continue
            failed = trace.outcome is HookOutcome.FAILED
            cancelled = trace.outcome is HookOutcome.CANCELLED
            break
        return failed, completed, cancelled

    async def _run_cleanup(
        self,
        attempt_id: str,
        specs: Sequence[HookSpec],
        action: HookAction,
        cancellation: asyncio.Event,
    ) -> bool:
        failed = False
        never_cancel = asyncio.Event()
        event = cancellation if action is HookAction.SETUP else never_cancel
        for spec in specs:
            current = self.journal.get_attempt(attempt_id)
            trace = await self.hooks.run(spec, action, len(current.hook_traces) + 1, event)
            trace = replace(
                trace,
                identity=current.identity,
                operation_id=current.operation_id,
                attempt_id=current.attempt_id,
                stage=current.stage,
                certainty=current.certainty,
            )
            self.journal.append_trace(attempt_id, trace)
            failed = failed or trace.outcome is HookOutcome.FAILED
        return failed

    def _context_specs(self) -> Tuple[HookSpec, ...]:
        return (
            HookSpec("context-configuration", HookLayer.CONTEXT_CONFIGURATION),
            *(HookSpec(value, HookLayer.CONTEXT_FIXTURE) for value in self.config.hooks.context_hooks),
        )

    def _attachment_specs(self) -> Tuple[HookSpec, ...]:
        return (
            HookSpec("attachment-configuration", HookLayer.ATTACHMENT_CONFIGURATION),
            *(
                HookSpec(value, HookLayer.ATTACHMENT_FIXTURE)
                for value in self.config.hooks.attachment_hooks
            ),
        )

    async def _open_context(self, command: OperationCommand, cancellation: asyncio.Event) -> None:
        identity = command.identity
        self._context = ContextSnapshot(
            identity.context_id,
            identity.context_generation,
            identity.context_binding_digest,
            ContextState.OPENING,
            False,
            self._clock_ms(),
        )
        failed, completed, cancelled = await self._run_setup(
            command.attempt_id, self._context_specs(), cancellation
        )
        if failed or cancelled:
            compensation_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(completed)),
                HookAction.COMPENSATE,
                cancellation,
            )
            self._context = None
            if compensation_failed:
                self.journal.reconcile(
                    command.attempt_id,
                    Certainty.EFFECT_UNKNOWN,
                    SafeFailure(ErrorCode.HOOK, "context compensation was incomplete"),
                )
                self._host_state = HostState.FAILED
            else:
                result, error = (
                    self._cancellation_disposition(command)
                    if cancelled
                    else (
                        Result.INTERNAL,
                        SafeFailure(ErrorCode.HOOK, "context setup did not complete"),
                    )
                )
                self.journal.settle(
                    command.attempt_id,
                    Certainty.NO_EFFECT,
                    result,
                    error,
                )
            return
        self._context = ContextSnapshot(
            identity.context_id,
            identity.context_generation,
            identity.context_binding_digest,
            ContextState.ACTIVE,
            True,
            self._clock_ms(),
        )
        self.journal.settle(command.attempt_id, Certainty.EFFECT_CONFIRMED, Result.OK)

    async def _close_context(self, command: OperationCommand, cancellation: asyncio.Event) -> None:
        cleanup_failed = False
        if self._attachment is not None:
            cleanup_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(self._attachment_specs())),
                HookAction.CLEANUP,
                cancellation,
            )
            self._attachment = None
        assert self._context is not None
        self._context = ContextSnapshot(
            self._context.context_id,
            self._context.context_generation,
            self._context.context_binding_digest,
            ContextState.CLOSING,
            False,
            self._clock_ms(),
        )
        context_cleanup_failed = await self._run_cleanup(
            command.attempt_id,
            tuple(reversed(self._context_specs())),
            HookAction.CLEANUP,
            cancellation,
        )
        cleanup_failed = cleanup_failed or context_cleanup_failed
        self._context = None
        result, error = self._completed_disposition(command, cleanup_failed)
        self.journal.settle(
            command.attempt_id,
            Certainty.EFFECT_CONFIRMED,
            result,
            error,
        )

    async def _attach_execution(self, command: OperationCommand, cancellation: asyncio.Event) -> None:
        identity = command.identity
        reload_removed = self._attachment is not None
        if reload_removed:
            cleanup_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(self._attachment_specs())),
                HookAction.CLEANUP,
                cancellation,
            )
            self._attachment = None
            if cleanup_failed:
                self.journal.settle(
                    command.attempt_id,
                    Certainty.EFFECT_CONFIRMED,
                    Result.INTERNAL,
                    SafeFailure(ErrorCode.HOOK, "reload cleanup did not complete cleanly"),
                )
                return
        self._attachment = AttachmentSnapshot(
            identity.execution_id,
            identity.execution_attachment_generation,
            identity.execution_attachment_digest,
            identity.driver_binding_id,
            AttachmentState.ATTACHING,
            self._clock_ms(),
        )
        failed, completed, cancelled = await self._run_setup(
            command.attempt_id, self._attachment_specs(), cancellation
        )
        if failed or cancelled:
            compensation_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(completed)),
                HookAction.COMPENSATE,
                cancellation,
            )
            self._attachment = None
            if compensation_failed:
                self.journal.reconcile(
                    command.attempt_id,
                    Certainty.EFFECT_UNKNOWN,
                    SafeFailure(ErrorCode.HOOK, "attachment compensation was incomplete"),
                )
                self._host_state = HostState.DEGRADED
            else:
                result, error = (
                    self._cancellation_disposition(command)
                    if cancelled
                    else (
                        Result.INTERNAL,
                        SafeFailure(ErrorCode.HOOK, "attachment setup did not complete"),
                    )
                )
                self.journal.settle(
                    command.attempt_id,
                    (
                        Certainty.EFFECT_CONFIRMED
                        if reload_removed
                        else Certainty.NO_EFFECT
                    ),
                    result,
                    error,
                )
            return
        self._attachment = AttachmentSnapshot(
            identity.execution_id,
            identity.execution_attachment_generation,
            identity.execution_attachment_digest,
            identity.driver_binding_id,
            AttachmentState.ATTACHED,
            self._clock_ms(),
        )
        self.journal.settle(command.attempt_id, Certainty.EFFECT_CONFIRMED, Result.OK)

    async def _detach_execution(self, command: OperationCommand, cancellation: asyncio.Event) -> None:
        assert self._attachment is not None
        self._attachment = AttachmentSnapshot(
            self._attachment.execution_id,
            self._attachment.execution_attachment_generation,
            self._attachment.execution_attachment_digest,
            self._attachment.driver_binding_id,
            AttachmentState.DETACHING,
            self._clock_ms(),
        )
        cleanup_failed = await self._run_cleanup(
            command.attempt_id,
            tuple(reversed(self._attachment_specs())),
            HookAction.CLEANUP,
            cancellation,
        )
        self._attachment = None
        result, error = self._completed_disposition(command, cleanup_failed)
        self.journal.settle(
            command.attempt_id,
            Certainty.EFFECT_CONFIRMED,
            result,
            error,
        )

    async def _cancel_operation(self, command: OperationCommand) -> None:
        try:
            target = self.journal.get_operation(command.target_operation_id)
        except KeyError:
            self.journal.settle(
                command.attempt_id,
                Certainty.NO_EFFECT,
                Result.INVALID_ARGUMENT,
                SafeFailure(ErrorCode.VALIDATION, "target lifecycle operation does not exist"),
            )
            return
        target_attempt = next(
            (item for item in target.attempts if item.attempt_id == command.target_attempt_id),
            None,
        )
        cancellation = self._active.get(command.target_attempt_id)
        if (
            target_attempt is None
            or target_attempt.stage not in {Stage.ACCEPTED, Stage.DISPATCHED}
            or cancellation is None
        ):
            self.journal.settle(
                command.attempt_id,
                Certainty.NO_EFFECT,
                Result.ALREADY_SETTLED,
                SafeFailure(ErrorCode.CONFLICT, "target lifecycle operation is already settled"),
            )
            return
        cancellation.set()
        self.journal.settle(command.attempt_id, Certainty.EFFECT_CONFIRMED, Result.OK)

    async def _drain_host(self, command: OperationCommand, cancellation: asyncio.Event) -> None:
        self._host_state = HostState.DRAINING
        for attempt_id, event in tuple(self._active.items()):
            if attempt_id != command.attempt_id:
                event.set()
        if command.grace_period_ms:
            await asyncio.sleep(command.grace_period_ms / 1000)
        if any(attempt_id != command.attempt_id for attempt_id in self._active):
            self._host_state = HostState.FAILED
            self.journal.reconcile(
                command.attempt_id,
                Certainty.EFFECT_UNKNOWN,
                SafeFailure(ErrorCode.HOOK, "host drain grace period expired"),
            )
            return
        cleanup_failed = False
        if self._attachment is not None:
            cleanup_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(self._attachment_specs())),
                HookAction.CLEANUP,
                cancellation,
            )
            self._attachment = None
        if self._context is not None:
            context_cleanup_failed = await self._run_cleanup(
                command.attempt_id,
                tuple(reversed(self._context_specs())),
                HookAction.CLEANUP,
                cancellation,
            )
            cleanup_failed = cleanup_failed or context_cleanup_failed
            self._context = None
        self._host_state = HostState.CLOSED
        result, error = self._completed_disposition(command, cleanup_failed)
        self.journal.settle(
            command.attempt_id,
            Certainty.EFFECT_CONFIRMED,
            result,
            error,
        )

    def close(self) -> None:
        self.journal.close()
