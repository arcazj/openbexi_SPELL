from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from driver_host.config import JournalConfig
from driver_host.domain import Certainty, ErrorCode, Method, Result, SafeFailure, Stage
from driver_host.journal import (
    JournalCapacityError,
    JournalConflictError,
    JournalIntegrityError,
    OperationJournal,
)
from driver_host.tests.support import make_command, make_config, make_identity


LIMITS = JournalConfig(max_entries=100, max_bytes=1_048_576)


def test_accept_is_idempotent_and_conflicting_digest_is_rejected(
    journal: OperationJournal, host_config
) -> None:
    command = make_command(host_config, Method.OPEN_CONTEXT, "open")

    accepted, duplicate = journal.accept(command)
    replayed, replay_duplicate = journal.accept(command)

    assert duplicate is False
    assert replay_duplicate is True
    assert replayed == accepted
    assert accepted.stage is Stage.ACCEPTED

    conflict = replace(command, synthetic_context_label="different-label")
    assert conflict.request_digest != command.request_digest
    with pytest.raises(JournalConflictError, match="conflicts"):
        journal.accept(conflict)


def test_transition_history_and_terminal_disposition_survive_reopen(
    tmp_path: Path, host_config
) -> None:
    path = tmp_path / "driver.sqlite"
    command = make_command(host_config, Method.OPEN_CONTEXT, "durable")
    journal = OperationJournal(path, host_config.driver_host_generation, LIMITS)
    journal.accept(command)
    journal.mark_dispatched(command.attempt_id)
    settled = journal.settle(
        command.attempt_id, Certainty.EFFECT_CONFIRMED, Result.OK
    )
    journal.verify()
    journal.close()

    reopened = OperationJournal(
        path, host_config.driver_host_generation, LIMITS, create=False
    )
    try:
        operation = reopened.get_operation(command.operation_id)
        assert operation.attempts == (settled,)
        assert operation.current_attempt_id == command.attempt_id
        replayed, duplicate = reopened.accept(command)
        assert duplicate is True
        assert replayed == settled
        with pytest.raises(JournalConflictError, match="immutable"):
            reopened.settle(
                command.attempt_id, Certainty.NO_EFFECT, Result.CANCELLED
            )
    finally:
        reopened.close()


def test_new_attempt_requires_durable_no_effect_proof(
    journal: OperationJournal, host_config
) -> None:
    identity = make_identity(host_config, context=True)
    first = make_command(
        host_config, Method.OPEN_CONTEXT, "retry-1", identity=identity
    )
    journal.accept(first)

    premature = make_command(
        host_config,
        Method.OPEN_CONTEXT,
        "retry-2",
        identity=identity,
        operation_id=first.operation_id,
        attempt_number=2,
    )
    with pytest.raises(JournalConflictError, match="not authorized"):
        journal.accept(premature)

    journal.settle(
        first.attempt_id,
        Certainty.NO_EFFECT,
        Result.CANCELLED,
        SafeFailure(ErrorCode.CANCELLED, "cancelled before dispatch"),
    )
    accepted, duplicate = journal.accept(premature)

    assert duplicate is False
    assert accepted.attempt_number == 2
    assert [item.attempt_id for item in journal.get_operation(first.operation_id).attempts] == [
        first.attempt_id,
        premature.attempt_id,
    ]


def test_entry_capacity_rejects_without_evicting_evidence(tmp_path: Path, host_config) -> None:
    limits = JournalConfig(max_entries=1, max_bytes=1_048_576)
    journal = OperationJournal(
        tmp_path / "bounded.sqlite", host_config.driver_host_generation, limits
    )
    first = make_command(host_config, Method.OPEN_CONTEXT, "capacity-1")
    second = make_command(host_config, Method.DRAIN_HOST, "capacity-2")
    try:
        journal.accept(first)
        with pytest.raises(JournalCapacityError, match="capacity"):
            journal.accept(second)
        assert journal.get_attempt(first.attempt_id) is not None
        assert [item.operation_id for item in journal.list_operations()] == [
            first.operation_id
        ]
    finally:
        journal.close()


def test_missing_symlinked_truncated_and_checksum_invalid_storage_fails_closed(
    tmp_path: Path, host_config
) -> None:
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(JournalIntegrityError, match="missing"):
        OperationJournal(
            missing, host_config.driver_host_generation, LIMITS, create=False
        )

    provisioned = tmp_path / "provisioned.sqlite"
    provisioned_journal = OperationJournal(
        provisioned, host_config.driver_host_generation, LIMITS
    )
    provisioned_journal.close()
    provisioned.unlink()
    with pytest.raises(JournalIntegrityError, match="required journal is missing"):
        OperationJournal(provisioned, host_config.driver_host_generation, LIMITS)

    target = tmp_path / "target.sqlite"
    target_journal = OperationJournal(
        target, host_config.driver_host_generation, LIMITS
    )
    target_journal.close()
    link = tmp_path / "linked.sqlite"
    try:
        link.symlink_to(target)
    except OSError:
        pass
    else:
        with pytest.raises(JournalIntegrityError, match="symlink"):
            OperationJournal(link, host_config.driver_host_generation, LIMITS)

    corrupt = tmp_path / "checksum.sqlite"
    corrupt_journal = OperationJournal(
        corrupt, host_config.driver_host_generation, LIMITS
    )
    command = make_command(host_config, Method.OPEN_CONTEXT, "corrupt")
    corrupt_journal.accept(command)
    corrupt_journal.close()
    connection = sqlite3.connect(corrupt)
    connection.execute(
        "UPDATE operation_attempts SET record_checksum = ? WHERE attempt_id = ?",
        ("0" * 64, command.attempt_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(JournalIntegrityError, match="checksum"):
        OperationJournal(corrupt, host_config.driver_host_generation, LIMITS)

    truncated = tmp_path / "truncated.sqlite"
    truncated_journal = OperationJournal(
        truncated, host_config.driver_host_generation, LIMITS
    )
    truncated_journal.accept(
        make_command(host_config, Method.OPEN_CONTEXT, "truncate")
    )
    truncated_journal.close()
    contents = truncated.read_bytes()
    truncated.write_bytes(contents[: len(contents) // 2])
    with pytest.raises((JournalIntegrityError, sqlite3.DatabaseError)):
        OperationJournal(truncated, host_config.driver_host_generation, LIMITS)


def test_one_ledger_retains_attempts_across_host_generations(tmp_path: Path) -> None:
    path = tmp_path / "generations.sqlite"
    old_config = make_config(generation="host-generation-old")
    old_command = make_command(old_config, Method.DRAIN_HOST, "old")
    old = OperationJournal(path, old_config.driver_host_generation, LIMITS)
    old.accept(old_command)
    old.settle(old_command.attempt_id, Certainty.NO_EFFECT, Result.CANCELLED)
    old.close()

    new_config = make_config(generation="host-generation-new")
    current = OperationJournal(path, new_config.driver_host_generation, LIMITS)
    try:
        retained = current.get_operation(old_command.operation_id)
        assert retained.attempts[0].identity.driver_host_generation == (
            old_config.driver_host_generation
        )

        new_command = make_command(new_config, Method.DRAIN_HOST, "new")
        current.accept(new_command)
        current.settle(new_command.attempt_id, Certainty.NO_EFFECT, Result.CANCELLED)
        current.verify()
        assert {item.operation_id for item in current.list_operations()} == {
            old_command.operation_id,
            new_command.operation_id,
        }
    finally:
        current.close()


def test_active_generation_witnesses_only_exact_covered_fenced_generation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retirement.sqlite"
    fenced_config = make_config(generation="host-generation-fenced")
    settled = make_command(fenced_config, Method.OPEN_CONTEXT, "retire-settled")
    uncertain = make_command(fenced_config, Method.DRAIN_HOST, "retire-latched")
    fenced = OperationJournal(
        path, fenced_config.driver_host_generation, LIMITS
    )
    try:
        fenced.accept(settled)
        fenced.settle(settled.attempt_id, Certainty.NO_EFFECT, Result.CANCELLED)
        fenced.accept(uncertain)
        fenced.mark_dispatched(uncertain.attempt_id)
        fenced.reconcile(
            uncertain.attempt_id,
            Certainty.EFFECT_UNKNOWN,
            SafeFailure(ErrorCode.JOURNAL, "effect evidence is unavailable"),
        )
    finally:
        fenced.close()

    active_config = make_config(generation="host-generation-active")
    active = OperationJournal(path, active_config.driver_host_generation, LIMITS)
    operation_ids = {settled.operation_id, uncertain.operation_id}
    try:
        witness = active.retirement_witness(
            fenced_generation=fenced_config.driver_host_generation,
            canonical_operation_ids=operation_ids,
        )
        assert len(witness) == 64
        assert witness == active.retirement_witness(
            fenced_generation=fenced_config.driver_host_generation,
            canonical_operation_ids=operation_ids,
        )

        with pytest.raises(JournalConflictError, match="active host generation"):
            active.retirement_witness(
                fenced_generation=active_config.driver_host_generation,
                canonical_operation_ids=set(),
            )
        with pytest.raises(JournalConflictError, match="does not cover"):
            active.retirement_witness(
                fenced_generation=fenced_config.driver_host_generation,
                canonical_operation_ids={settled.operation_id},
            )
        with pytest.raises(JournalConflictError, match="not registered"):
            active.retirement_witness(
                fenced_generation="host-generation-unknown",
                canonical_operation_ids=set(),
            )
    finally:
        active.close()


def test_retirement_rejects_fenced_generation_with_unlatched_acceptance(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unlatched-retirement.sqlite"
    fenced_config = make_config(generation="host-generation-unlatched")
    command = make_command(fenced_config, Method.DRAIN_HOST, "unlatched")
    fenced = OperationJournal(path, fenced_config.driver_host_generation, LIMITS)
    fenced.accept(command)
    fenced.close()

    active_config = make_config(generation="host-generation-after-unlatched")
    active = OperationJournal(path, active_config.driver_host_generation, LIMITS)
    try:
        with pytest.raises(JournalConflictError, match="not settled"):
            active.retirement_witness(
                fenced_generation=fenced_config.driver_host_generation,
                canonical_operation_ids={command.operation_id},
            )
    finally:
        active.close()


def test_retirement_witness_cryptographically_binds_the_fenced_generation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "generation-bound-witness.sqlite"
    first_config = make_config(generation="host-generation-retired-a")
    first = OperationJournal(path, first_config.driver_host_generation, LIMITS)
    first.close()

    second_config = make_config(generation="host-generation-retired-b")
    second = OperationJournal(path, second_config.driver_host_generation, LIMITS)
    second.close()

    active_config = make_config(generation="host-generation-witnessing")
    active = OperationJournal(path, active_config.driver_host_generation, LIMITS)
    try:
        first_witness = active.retirement_witness(
            fenced_generation=first_config.driver_host_generation,
            canonical_operation_ids=set(),
        )
        second_witness = active.retirement_witness(
            fenced_generation=second_config.driver_host_generation,
            canonical_operation_ids=set(),
        )
        assert first_witness != second_witness
    finally:
        active.close()
