from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from pathlib import Path
from typing import Callable

from driver_host.config import CapacityConfig, JournalConfig
from driver_host.domain import (
    AttachmentState,
    Certainty,
    ContextState,
    ErrorCode,
    HookAction,
    HookOutcome,
    HostState,
    Method,
    Result,
    Stage,
)
from driver_host.hooks import DeterministicHooks, HookSpec
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.tests.support import (
    make_command,
    make_config,
    make_identity,
)


LIMITS = JournalConfig(max_entries=100, max_bytes=1_048_576)


def _trace_signature(operation):
    return [
        (trace.hook_id, trace.action, trace.outcome)
        for trace in operation.attempts[-1].hook_traces
    ]


async def _wait_until(predicate: Callable[[], bool], timeout: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("condition was not observed before the test timeout")


class SelectiveBlockingHooks(DeterministicHooks):
    def __init__(self) -> None:
        super().__init__()
        self._block_key: str | None = None
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    def arm(self, hook_id: str, action: HookAction) -> None:
        self._block_key = f"{hook_id}:{action.value}"
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(
        self,
        spec: HookSpec,
        action: HookAction,
        sequence: int,
        cancelled: asyncio.Event,
    ):
        if f"{spec.hook_id}:{action.value}" == self._block_key:
            self.started.set()
            await self.release.wait()
        return await super().run(spec, action, sequence, cancelled)


def test_happy_path_reload_and_reverse_cleanup_order(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks()
        journal = OperationJournal(
            tmp_path / "happy.sqlite", config.driver_host_generation, LIMITS
        )
        host = SimulatorLifecycleHost(config, journal, hooks=hooks)
        context_identity = make_identity(config, context=True)
        first_attachment = make_identity(config, attachment=True)
        second_attachment = make_identity(
            config,
            attachment=True,
            execution_attachment_generation="attachment-generation-2",
            driver_binding_id="driver-binding-2",
        )
        try:
            opened = await host.execute(
                make_command(
                    config,
                    Method.OPEN_CONTEXT,
                    "happy-open",
                    identity=context_identity,
                )
            )
            assert _trace_signature(opened) == [
                ("context-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("context-fixture-a", HookAction.SETUP, HookOutcome.COMPLETED),
                ("context-fixture-b", HookAction.SETUP, HookOutcome.COMPLETED),
            ]
            assert opened.attempts[-1].result is Result.OK
            assert opened.attempts[-1].certainty is Certainty.EFFECT_CONFIRMED
            assert host.snapshot().contexts[0].state is ContextState.ACTIVE

            attached = await host.execute(
                make_command(
                    config,
                    Method.ATTACH_EXECUTION,
                    "happy-attach",
                    identity=first_attachment,
                )
            )
            assert _trace_signature(attached) == [
                ("attachment-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-a", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-b", HookAction.SETUP, HookOutcome.COMPLETED),
            ]
            assert host.snapshot().attachments[0].state is AttachmentState.ATTACHED

            reloaded = await host.execute(
                make_command(
                    config,
                    Method.ATTACH_EXECUTION,
                    "happy-reload",
                    identity=second_attachment,
                    lifecycle_reason="RELOAD",
                    replaced_driver_binding_id="driver-binding-1",
                )
            )
            assert _trace_signature(reloaded) == [
                ("attachment-fixture-b", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-fixture-a", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-configuration", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-a", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-b", HookAction.SETUP, HookOutcome.COMPLETED),
            ]
            assert (
                host.snapshot().attachments[0].execution_attachment_generation
                == "attachment-generation-2"
            )

            detached = await host.execute(
                make_command(
                    config,
                    Method.DETACH_EXECUTION,
                    "happy-detach",
                    identity=second_attachment,
                    lifecycle_reason="FINISHED",
                )
            )
            assert _trace_signature(detached) == [
                ("attachment-fixture-b", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-fixture-a", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-configuration", HookAction.CLEANUP, HookOutcome.COMPLETED),
            ]
            assert host.snapshot().attachments == ()

            closed = await host.execute(
                make_command(
                    config,
                    Method.CLOSE_CONTEXT,
                    "happy-close",
                    identity=context_identity,
                )
            )
            assert _trace_signature(closed) == [
                ("context-fixture-b", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("context-fixture-a", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("context-configuration", HookAction.CLEANUP, HookOutcome.COMPLETED),
            ]
            assert host.snapshot().contexts == ()

            drained = await host.execute(
                make_command(config, Method.DRAIN_HOST, "happy-drain")
            )
            assert drained.attempts[-1].result is Result.OK
            assert host.snapshot().state is HostState.CLOSED
            assert host.snapshot().ready is False
        finally:
            host.close()

    asyncio.run(scenario())


def test_setup_failure_compensates_completed_context_hooks_in_reverse(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks(
            fail_points=frozenset({"context-fixture-b:SETUP"})
        )
        journal = OperationJournal(
            tmp_path / "context-compensate.sqlite",
            config.driver_host_generation,
            LIMITS,
        )
        host = SimulatorLifecycleHost(config, journal, hooks=hooks)
        try:
            operation = await host.execute(
                make_command(config, Method.OPEN_CONTEXT, "context-compensate")
            )
            attempt = operation.attempts[-1]
            assert _trace_signature(operation) == [
                ("context-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("context-fixture-a", HookAction.SETUP, HookOutcome.COMPLETED),
                ("context-fixture-b", HookAction.SETUP, HookOutcome.FAILED),
                ("context-fixture-a", HookAction.COMPENSATE, HookOutcome.COMPLETED),
                ("context-configuration", HookAction.COMPENSATE, HookOutcome.COMPLETED),
            ]
            assert attempt.stage is Stage.SETTLED
            assert attempt.certainty is Certainty.NO_EFFECT
            assert attempt.result is Result.INTERNAL
            assert attempt.error is not None and attempt.error.code is ErrorCode.HOOK
            assert host.snapshot().contexts == ()
            assert host.snapshot().state is HostState.READY
        finally:
            host.close()

    asyncio.run(scenario())


def test_attachment_failure_compensates_and_cleanup_failure_does_not_short_circuit(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks()
        journal = OperationJournal(
            tmp_path / "attachment-failures.sqlite",
            config.driver_host_generation,
            LIMITS,
        )
        host = SimulatorLifecycleHost(config, journal, hooks=hooks)
        try:
            await host.execute(
                make_command(config, Method.OPEN_CONTEXT, "attachment-failure-open")
            )
            hooks.fail_points = frozenset({"attachment-fixture-b:SETUP"})
            failed_attach = await host.execute(
                make_command(
                    config, Method.ATTACH_EXECUTION, "attachment-compensate"
                )
            )
            assert _trace_signature(failed_attach) == [
                ("attachment-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-a", HookAction.SETUP, HookOutcome.COMPLETED),
                ("attachment-fixture-b", HookAction.SETUP, HookOutcome.FAILED),
                ("attachment-fixture-a", HookAction.COMPENSATE, HookOutcome.COMPLETED),
                ("attachment-configuration", HookAction.COMPENSATE, HookOutcome.COMPLETED),
            ]
            assert host.snapshot().attachments == ()

            hooks.fail_points = frozenset()
            await host.execute(
                make_command(config, Method.ATTACH_EXECUTION, "cleanup-attach")
            )
            hooks.fail_points = frozenset({"attachment-fixture-b:CLEANUP"})
            detached = await host.execute(
                make_command(config, Method.DETACH_EXECUTION, "cleanup-detach")
            )
            assert _trace_signature(detached) == [
                ("attachment-fixture-b", HookAction.CLEANUP, HookOutcome.FAILED),
                ("attachment-fixture-a", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("attachment-configuration", HookAction.CLEANUP, HookOutcome.COMPLETED),
            ]
            attempt = detached.attempts[-1]
            assert attempt.result is Result.INTERNAL
            assert attempt.certainty is Certainty.EFFECT_CONFIRMED
            assert attempt.error is not None and attempt.error.code is ErrorCode.HOOK
            assert host.snapshot().attachments == ()
        finally:
            host.close()

    asyncio.run(scenario())


def test_duplicate_replay_after_restart_has_no_second_effect_and_conflict_is_safe(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        path = tmp_path / "restart.sqlite"
        command = make_command(config, Method.OPEN_CONTEXT, "restart-open")
        first_hooks = DeterministicHooks()
        first_host = SimulatorLifecycleHost(
            config,
            OperationJournal(path, config.driver_host_generation, LIMITS),
            hooks=first_hooks,
        )
        first = await first_host.execute(command)
        assert sum(first_hooks.effect_count.values()) == 3
        first_host.close()

        replay_hooks = DeterministicHooks()
        restarted = SimulatorLifecycleHost(
            config,
            OperationJournal(
                path, config.driver_host_generation, LIMITS, create=False
            ),
            hooks=replay_hooks,
        )
        try:
            assert restarted.snapshot().contexts[0].state is ContextState.ACTIVE
            replayed = await restarted.execute(command)
            assert replayed == first
            assert replay_hooks.effect_count == {}

            conflict = replace(command, synthetic_context_label="conflicting-label")
            rejected = await restarted.execute(conflict)
            assert rejected.attempts[-1].result is Result.CONFLICT
            assert rejected.attempts[-1].certainty is Certainty.NO_EFFECT
            assert replay_hooks.effect_count == {}
            assert (
                restarted.get_operation(command.operation_id).attempts[-1].result
                is Result.OK
            )
        finally:
            restarted.close()

    asyncio.run(scenario())


def test_visible_intermediate_states_and_drain_transition(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = SelectiveBlockingHooks()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "states.sqlite", config.driver_host_generation, LIMITS
            ),
            hooks=hooks,
        )
        try:
            hooks.arm("context-configuration", HookAction.SETUP)
            opening = asyncio.create_task(
                host.execute(make_command(config, Method.OPEN_CONTEXT, "state-open"))
            )
            await asyncio.wait_for(hooks.started.wait(), 1)
            snapshot = host.snapshot()
            assert snapshot.contexts[0].state is ContextState.OPENING
            assert snapshot.contexts[0].ready is False
            hooks.release.set()
            await asyncio.wait_for(opening, 2)

            hooks.arm("attachment-configuration", HookAction.SETUP)
            attaching = asyncio.create_task(
                host.execute(
                    make_command(config, Method.ATTACH_EXECUTION, "state-attach")
                )
            )
            await asyncio.wait_for(hooks.started.wait(), 1)
            assert host.snapshot().attachments[0].state is AttachmentState.ATTACHING
            hooks.release.set()
            await asyncio.wait_for(attaching, 2)

            hooks.arm("attachment-fixture-b", HookAction.CLEANUP)
            detaching = asyncio.create_task(
                host.execute(
                    make_command(config, Method.DETACH_EXECUTION, "state-detach")
                )
            )
            await asyncio.wait_for(hooks.started.wait(), 1)
            assert host.snapshot().attachments[0].state is AttachmentState.DETACHING
            hooks.release.set()
            await asyncio.wait_for(detaching, 2)

            hooks.arm("context-fixture-b", HookAction.CLEANUP)
            closing = asyncio.create_task(
                host.execute(make_command(config, Method.CLOSE_CONTEXT, "state-close"))
            )
            await asyncio.wait_for(hooks.started.wait(), 1)
            assert host.snapshot().contexts[0].state is ContextState.CLOSING
            hooks.release.set()
            await asyncio.wait_for(closing, 2)

            draining = asyncio.create_task(
                host.execute(
                    make_command(
                        config, Method.DRAIN_HOST, "state-drain", grace_period_ms=50
                    )
                )
            )
            await _wait_until(lambda: host.snapshot().state is HostState.DRAINING)
            await asyncio.wait_for(draining, 2)
            assert host.snapshot().state is HostState.CLOSED
        finally:
            host.close()

    asyncio.run(scenario())


def test_deadline_cancellation_and_already_settled_race(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks(delay_ms=250)
        journal = OperationJournal(
            tmp_path / "cancel.sqlite", config.driver_host_generation, LIMITS
        )
        host = SimulatorLifecycleHost(config, journal, hooks=hooks)
        try:
            expired = await host.execute(
                make_command(
                    config,
                    Method.OPEN_CONTEXT,
                    "expired",
                    deadline_unix_ms=1,
                )
            )
            expired_attempt = expired.attempts[-1]
            assert expired_attempt.result is Result.DEADLINE_EXCEEDED
            assert expired_attempt.certainty is Certainty.NO_EFFECT
            assert journal.list_operations() == ()

            target_command = make_command(
                config, Method.OPEN_CONTEXT, "cancel-target"
            )
            target_task = asyncio.create_task(host.execute(target_command))
            await _wait_until(
                lambda: (
                    journal.get_attempt(target_command.attempt_id) is not None
                    and journal.get_attempt(target_command.attempt_id).stage
                    is Stage.DISPATCHED
                )
            )
            cancel = await host.execute(
                make_command(
                    config,
                    Method.CANCEL_LIFECYCLE_OPERATION,
                    "cancel-request",
                    target_operation_id=target_command.operation_id,
                    target_attempt_id=target_command.attempt_id,
                )
            )
            target = await asyncio.wait_for(target_task, 2)

            assert cancel.attempts[-1].result is Result.OK
            assert cancel.attempts[-1].certainty is Certainty.EFFECT_CONFIRMED
            assert target.attempts[-1].result is Result.CANCELLED
            assert target.attempts[-1].certainty is Certainty.NO_EFFECT
            assert target.attempts[-1].hook_traces[0].outcome is HookOutcome.CANCELLED
            assert host.snapshot().contexts == ()

            raced = await host.execute(
                make_command(
                    config,
                    Method.CANCEL_LIFECYCLE_OPERATION,
                    "cancel-race",
                    target_operation_id=target_command.operation_id,
                    target_attempt_id=target_command.attempt_id,
                )
            )
            assert raced.attempts[-1].result is Result.ALREADY_SETTLED
            assert raced.attempts[-1].certainty is Certainty.NO_EFFECT
            assert target.attempts[-1] == host.get_operation(
                target_command.operation_id
            ).attempts[-1]
        finally:
            host.close()

    asyncio.run(scenario())


def test_deadline_during_setup_compensates_completed_hooks_with_no_effect(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks(delay_ms=200)
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "setup-deadline.sqlite",
                config.driver_host_generation,
                LIMITS,
            ),
            hooks=hooks,
        )
        try:
            operation = await host.execute(
                make_command(
                    config,
                    Method.OPEN_CONTEXT,
                    "setup-deadline",
                    deadline_unix_ms=time.time_ns() // 1_000_000 + 300,
                )
            )
            attempt = operation.attempts[-1]
            assert _trace_signature(operation) == [
                ("context-configuration", HookAction.SETUP, HookOutcome.COMPLETED),
                ("context-fixture-a", HookAction.SETUP, HookOutcome.CANCELLED),
                (
                    "context-configuration",
                    HookAction.COMPENSATE,
                    HookOutcome.COMPLETED,
                ),
            ]
            assert attempt.stage is Stage.SETTLED
            assert attempt.result is Result.DEADLINE_EXCEEDED
            assert attempt.certainty is Certainty.NO_EFFECT
            assert attempt.error is not None and attempt.error.code is ErrorCode.DEADLINE
            assert host.snapshot().contexts == ()
            assert hooks.effect_count == {
                "context-configuration:SETUP": 1,
                "context-configuration:COMPENSATE": 1,
            }
        finally:
            host.close()

    asyncio.run(scenario())


def test_deadline_during_cleanup_completes_with_confirmed_effect(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "cleanup-deadline.sqlite",
                config.driver_host_generation,
                LIMITS,
            ),
            hooks=hooks,
        )
        context_identity = make_identity(config, context=True)
        try:
            await host.execute(
                make_command(
                    config,
                    Method.OPEN_CONTEXT,
                    "cleanup-deadline-open",
                    identity=context_identity,
                )
            )
            hooks.delay_ms = 150
            operation = await host.execute(
                make_command(
                    config,
                    Method.CLOSE_CONTEXT,
                    "cleanup-deadline-close",
                    identity=context_identity,
                    deadline_unix_ms=time.time_ns() // 1_000_000 + 100,
                )
            )
            attempt = operation.attempts[-1]
            assert _trace_signature(operation) == [
                ("context-fixture-b", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("context-fixture-a", HookAction.CLEANUP, HookOutcome.COMPLETED),
                ("context-configuration", HookAction.CLEANUP, HookOutcome.COMPLETED),
            ]
            assert attempt.stage is Stage.SETTLED
            assert attempt.result is Result.DEADLINE_EXCEEDED
            assert attempt.certainty is Certainty.EFFECT_CONFIRMED
            assert attempt.error is not None and attempt.error.code is ErrorCode.DEADLINE
            assert host.snapshot().contexts == ()
        finally:
            host.close()

    asyncio.run(scenario())


def test_in_flight_and_journal_capacity_fail_before_a_second_effect(tmp_path: Path) -> None:
    async def scenario() -> None:
        capacity = CapacityConfig(
            max_contexts_per_host=1,
            max_attachments_per_context=1,
            max_lifecycle_operations_per_host=1,
            max_lifecycle_operations_per_context=1,
        )
        config = make_config(capacity=capacity)
        hooks = DeterministicHooks(delay_ms=100)
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "operation-capacity.sqlite",
                config.driver_host_generation,
                LIMITS,
            ),
            hooks=hooks,
        )
        try:
            opening = asyncio.create_task(
                host.execute(make_command(config, Method.OPEN_CONTEXT, "capacity-open"))
            )
            await _wait_until(lambda: host.snapshot().in_flight_host == 1)
            rejected = await host.execute(
                make_command(config, Method.DRAIN_HOST, "capacity-drain")
            )
            assert rejected.attempts[-1].result is Result.CAPACITY_EXHAUSTED
            assert rejected.attempts[-1].certainty is Certainty.NO_EFFECT
            assert len(host.journal.list_operations()) == 1
            await asyncio.wait_for(opening, 2)
        finally:
            host.close()

        full_config = make_config(generation="host-generation-full")
        full_host = SimulatorLifecycleHost(
            full_config,
            OperationJournal(
                tmp_path / "journal-capacity.sqlite",
                full_config.driver_host_generation,
                JournalConfig(max_entries=1, max_bytes=1_048_576),
            ),
        )
        try:
            await full_host.execute(
                make_command(full_config, Method.OPEN_CONTEXT, "journal-full-open")
            )
            rejected = await full_host.execute(
                make_command(full_config, Method.DRAIN_HOST, "journal-full-drain")
            )
            assert rejected.attempts[-1].result is Result.JOURNAL_UNAVAILABLE
            assert rejected.attempts[-1].certainty is Certainty.NO_EFFECT
            assert full_host.snapshot().state is HostState.DEGRADED
            assert full_host.snapshot().ready is False
            assert len(full_host.journal.list_operations()) == 1
        finally:
            full_host.close()

    asyncio.run(scenario())


def test_drain_grace_expiry_leaves_uncertain_evidence_and_failed_host(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = SelectiveBlockingHooks()
        hooks.arm("context-configuration", HookAction.SETUP)
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "failed-drain.sqlite",
                config.driver_host_generation,
                LIMITS,
            ),
            hooks=hooks,
        )
        try:
            target_task = asyncio.create_task(
                host.execute(make_command(config, Method.OPEN_CONTEXT, "blocked-open"))
            )
            await asyncio.wait_for(hooks.started.wait(), 1)
            drain_task = asyncio.create_task(
                host.execute(
                    make_command(
                        config,
                        Method.DRAIN_HOST,
                        "failed-drain",
                        grace_period_ms=100,
                    )
                )
            )
            await _wait_until(lambda: host.snapshot().state is HostState.DRAINING)
            drain = await asyncio.wait_for(drain_task, 2)
            drain_attempt = drain.attempts[-1]
            assert drain_attempt.stage is Stage.RECONCILING
            assert drain_attempt.certainty is Certainty.EFFECT_UNKNOWN
            assert drain_attempt.result is Result.RECONCILIATION_REQUIRED
            assert host.snapshot().state is HostState.FAILED

            hooks.release.set()
            target = await asyncio.wait_for(target_task, 2)
            assert target.attempts[-1].result is Result.CANCELLED
            assert host.snapshot().state is HostState.FAILED
        finally:
            host.close()

    asyncio.run(scenario())
