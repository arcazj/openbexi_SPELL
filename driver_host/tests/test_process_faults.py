from __future__ import annotations

import asyncio
import multiprocessing
import os
import signal
import time
from pathlib import Path

import pytest

from driver_host.domain import Certainty, HookAction, Method, Result, Stage
from driver_host.hooks import DeterministicHooks
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost

from .support import make_command, make_config


class _CrashJournal(OperationJournal):
    def __init__(self, *args, crash_boundary: str, **kwargs) -> None:
        self.crash_boundary = crash_boundary
        super().__init__(*args, **kwargs)

    def accept(self, command):
        if self.crash_boundary == "before_intent":
            os._exit(71)
        result = super().accept(command)
        if self.crash_boundary == "after_intent":
            os._exit(72)
        return result

    def mark_dispatched(self, attempt_id):
        result = super().mark_dispatched(attempt_id)
        if self.crash_boundary == "after_dispatch_before_effect":
            os._exit(73)
        return result

    def settle(self, attempt_id, certainty, result, error=None):
        if self.crash_boundary == "after_effect_before_result":
            os._exit(74)
        settled = super().settle(attempt_id, certainty, result, error)
        if self.crash_boundary == "after_result_before_reply":
            os._exit(75)
        return settled


class _DurableMarkerHooks(DeterministicHooks):
    def __init__(self, marker_path: str) -> None:
        super().__init__()
        self.marker_path = Path(marker_path)

    async def run(self, spec, action, sequence, cancelled):
        result = await super().run(spec, action, sequence, cancelled)
        if action is HookAction.SETUP and result.outcome.value == "COMPLETED":
            with self.marker_path.open("ab") as stream:
                stream.write(f"{spec.hook_id}\n".encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
        return result


def _crash_lifecycle_process(
    journal_path: str,
    marker_path: str,
    boundary: str,
) -> None:
    config = make_config(generation="process-fault-generation")
    command = make_command(config, Method.OPEN_CONTEXT, "process-fault")
    journal = _CrashJournal(
        journal_path,
        config.driver_host_generation,
        config.journal,
        crash_boundary=boundary,
    )
    host = SimulatorLifecycleHost(
        config,
        journal,
        hooks=_DurableMarkerHooks(marker_path),
    )
    asyncio.run(host.execute(command))
    if boundary == "after_reply":
        os._exit(76)
    os._exit(77)


@pytest.mark.parametrize(
    ("boundary", "expected_stage", "expected_effect", "marker_expected"),
    (
        ("before_intent", None, None, False),
        ("after_intent", Stage.ACCEPTED, None, False),
        (
            "after_dispatch_before_effect",
            Stage.DISPATCHED,
            Certainty.EFFECT_POSSIBLE,
            False,
        ),
        (
            "after_effect_before_result",
            Stage.DISPATCHED,
            Certainty.EFFECT_POSSIBLE,
            True,
        ),
        (
            "after_result_before_reply",
            Stage.SETTLED,
            Certainty.EFFECT_CONFIRMED,
            True,
        ),
        ("after_reply", Stage.SETTLED, Certainty.EFFECT_CONFIRMED, True),
    ),
)
def test_process_crash_boundaries_preserve_persist_before_effect_and_no_resend(
    tmp_path: Path,
    boundary: str,
    expected_stage: Stage | None,
    expected_effect: Certainty | None,
    marker_expected: bool,
) -> None:
    journal_path = tmp_path / f"{boundary}.sqlite"
    marker_path = tmp_path / f"{boundary}.effects"
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_lifecycle_process,
        args=(str(journal_path), str(marker_path), boundary),
    )
    process.start()
    process.join(timeout=20)
    assert not process.is_alive()
    assert process.exitcode not in {None, 0}

    config = make_config(generation="process-fault-generation")
    journal = OperationJournal(
        journal_path, config.driver_host_generation, config.journal
    )
    try:
        command = make_command(config, Method.OPEN_CONTEXT, "process-fault")
        marker_count = (
            len(marker_path.read_text(encoding="ascii").splitlines())
            if marker_path.is_file()
            else 0
        )
        assert (marker_count > 0) is marker_expected
        if expected_stage is None:
            assert journal.list_operations() == ()
            return

        attempt = journal.get_attempt(command.attempt_id)
        assert attempt is not None
        assert attempt.stage is expected_stage
        assert attempt.certainty is expected_effect

        host = SimulatorLifecycleHost(config, journal)
        replayed = asyncio.run(host.execute(command)).attempts[-1]
        if expected_stage is Stage.ACCEPTED:
            assert replayed.stage is Stage.SETTLED
            assert replayed.certainty is Certainty.NO_EFFECT
            assert replayed.result is Result.INTERNAL
        elif expected_stage is Stage.DISPATCHED:
            assert replayed.stage is Stage.RECONCILING
            assert replayed.certainty is Certainty.EFFECT_POSSIBLE
        else:
            assert replayed.stage is Stage.SETTLED
            assert replayed.certainty is Certainty.EFFECT_CONFIRMED
        final_marker_count = (
            len(marker_path.read_text(encoding="ascii").splitlines())
            if marker_path.is_file()
            else 0
        )
        assert final_marker_count == marker_count
    finally:
        journal.close()


class _UnresponsiveHooks(DeterministicHooks):
    def __init__(self, marker_path: str) -> None:
        super().__init__()
        self.marker_path = Path(marker_path)

    async def run(self, spec, action, sequence, cancelled):
        self.marker_path.write_text("entered", encoding="ascii")
        while True:
            await asyncio.sleep(1)


def _unresponsive_lifecycle_process(journal_path: str, marker_path: str) -> None:
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    config = make_config(generation="unresponsive-host-generation")
    journal = OperationJournal(
        journal_path, config.driver_host_generation, config.journal
    )
    host = SimulatorLifecycleHost(
        config,
        journal,
        hooks=_UnresponsiveHooks(marker_path),
    )
    command = make_command(config, Method.OPEN_CONTEXT, "forced-termination")
    asyncio.run(host.execute(command))


def test_unresponsive_host_is_killed_after_grace_and_acceptance_stays_reconciling(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("bounded SIGTERM-to-SIGKILL grace is qualified in Linux")
    journal_path = tmp_path / "forced-termination.sqlite"
    marker_path = tmp_path / "forced-termination.marker"
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_unresponsive_lifecycle_process,
        args=(str(journal_path), str(marker_path)),
    )
    process.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not marker_path.is_file():
        time.sleep(0.02)
    assert marker_path.is_file()

    started = time.monotonic()
    process.terminate()
    process.join(timeout=0.25)
    assert process.is_alive()
    process.kill()
    process.join(timeout=5)
    elapsed = time.monotonic() - started
    assert not process.is_alive()
    assert 0.20 <= elapsed <= 2.0

    config = make_config(generation="unresponsive-host-generation")
    journal = OperationJournal(
        journal_path, config.driver_host_generation, config.journal
    )
    try:
        command = make_command(config, Method.OPEN_CONTEXT, "forced-termination")
        accepted = journal.get_attempt(command.attempt_id)
        assert accepted is not None and accepted.stage is Stage.DISPATCHED
        host = SimulatorLifecycleHost(config, journal)
        reconciled = asyncio.run(host.execute(command)).attempts[-1]
        assert reconciled.stage is Stage.RECONCILING
        assert reconciled.certainty is Certainty.EFFECT_POSSIBLE
    finally:
        journal.close()
