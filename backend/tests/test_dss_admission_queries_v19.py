"""Bounded admission reads preserve authoritative state and complete history."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest
from sqlalchemy import event, select

from backend.driver_models import DriverContextGeneration, DriverHostGeneration, DriverProfile
from backend.observation_domain import GetTMMode
from backend.observation_models import ObservationOutboxEvent, TelemetrySample
from backend.observation_repository import ObservationConflictError, ObservationStaleGenerationError
from backend.tests.test_dss_cohort_ingest_v19 import (
    admissions, commits, configured, frame, history, packet_samples,
)
from backend.tests.test_observation_repository import observation_store
from driver_host.tests.test_dss_transport import engine


@contextmanager
def statements(factory):
    captured = []
    database = factory.kw["bind"]
    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        captured.append(" ".join(statement.split()))
    event.listen(database, "before_cursor_execute", capture)
    try:
        yield captured
    finally:
        event.remove(database, "before_cursor_execute", capture)


def reads(sql, table):
    return [statement for statement in sql if statement.upper().startswith("SELECT ")
        and f" FROM {table} " in statement + " "]


@pytest.mark.parametrize("size", [1, 21, 22])
def test_cohort_authority_queries_are_constant_with_exact_received_history(
    observation_store, engine, monkeypatch, record_property, size,
):
    repository, factory, generation, clock = configured(observation_store)
    original = packet_samples(generation, clock, engine)[:size]
    repository.ingest_samples(admissions(original))
    values = frame(original, 2)
    receipt_times = [clock[0] + 10_000 + index for index in range(size)]
    receipt_iterator = iter(receipt_times)
    monkeypatch.setattr(repository, "_receive_time_ns", lambda: next(receipt_iterator))
    with statements(factory) as sql, commits(factory) as actual_commits:
        assert repository.ingest_samples(admissions(values, GetTMMode.NEXT, False)) == size
    assert actual_commits == [True]
    tables = ("driver_host_generations", "driver_profiles", "driver_context_generations",
        "observation_streams", "observation_freshness_policies")
    counts = {table: len(reads(sql, table)) for table in tables}
    # These are actual SQL statements, not helper-call counts or cached mocks.
    assert counts == dict.fromkeys(tables, 1)
    epoch_reads = [statement for statement in reads(sql, "observation_outbox")
        if "'telemetry.source_epoch_changed'" in statement]
    assert len(epoch_reads) == 1
    record_property("admission_sql_counts", json.dumps({"members": size, "total": len(sql),
        "shared_reads": counts, "epoch_reads": len(epoch_reads)}, sort_keys=True))
    stored = history(factory)
    accepted = sorted((row for row in stored["telemetry_samples"] if row["source_sequence"] == 2),
        key=lambda row: row["item_id"])
    assert len(accepted) == size
    assert [(row["id"], row["observation_id"], row["received_at_unix_ns"],
        row["freshness"], row["source_epoch"], row["source_sequence"]) for row in accepted] == [
        (value.sample_identity.sample_id, value.observation_id, received, "FRESH",
            value.sample_identity.source_epoch, 2) for value, received in zip(values, receipt_times)]
    events = [row for row in stored["observation_outbox"]
        if row["event_type"] == "telemetry.sample_observed"
        and row["aggregate_id"] in {value.sample_identity.sample_id for value in values}]
    assert len(events) == size
    assert {row["payload"]["data"]["sample_id"] for row in events} == {row["id"] for row in accepted}
    assert not stored["telemetry_gaps"]


@pytest.mark.parametrize("authority", ["host", "profile", "context"])
def test_failed_cohort_cannot_reuse_authority_in_a_later_transaction(
    observation_store, engine, authority,
):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    repository.ingest_samples(admissions(values))
    before = history(factory)
    new_epoch = frame(values, 1, epoch="epoch-" + "f" * 64)
    # A real final-member conflict follows 21 flushed samples and epoch changes.
    conflicting = (*new_epoch[:-1], replace(new_epoch[-1], observation_id=values[-1].observation_id))
    with pytest.raises(ObservationConflictError, match="reused"):
        repository.ingest_samples(admissions(conflicting))
    assert history(factory) == before
    with factory() as session:
        host = session.get(DriverHostGeneration, generation.driver_host_generation)
        if authority == "host":
            host.state = "FAILED"
        elif authority == "profile":
            session.get(DriverProfile, host.profile_id).server_profile_id = "different-profile"
        else:
            context = session.get(DriverContextGeneration, generation.context_generation)
            context.state, context.ready = "FAILED", False
        session.commit()
    with statements(factory) as sql:
        with pytest.raises(ObservationStaleGenerationError):
            repository.ingest_samples(admissions(new_epoch))
    assert reads(sql, "driver_host_generations")
    assert not any(statement.upper().startswith(("INSERT ", "UPDATE ", "DELETE ")) for statement in sql)
    assert history(factory) == before


@pytest.mark.parametrize("size", [1, 22])
def test_stale_sweep_joins_samples_without_losing_any_ordered_event_or_history(
    observation_store, engine, monkeypatch, record_property, size,
):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)[:size]
    repository.ingest_samples(admissions(values))
    before = history(factory)
    clock[0] += 6_000_000_000
    evaluated_at = datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc)
    monkeypatch.setattr(repository, "_database_now", lambda _session: evaluated_at)
    with statements(factory) as sql, commits(factory) as actual_commits:
        assert repository.mark_stale(now_unix_ns=clock[0]) == size
    assert actual_commits == [True]
    # The original locked join already selects both relations. No per-head
    # sample PK fetch or changed predicate is required to evaluate each alarm.
    assert not reads(sql, "telemetry_samples")
    joined = [statement for statement in reads(sql, "telemetry_item_heads")
        if "JOIN telemetry_samples" in statement and "telemetry_samples.observation_id" in statement]
    assert len(joined) == 1
    record_property("stale_sql_counts", json.dumps({"members": size, "total": len(sql),
        "joined_samples": len(joined), "sample_pk_reads": len(reads(sql, "telemetry_samples"))}))
    after = history(factory)
    for table in ("telemetry_samples", "telemetry_source_cursors", "telemetry_gaps",
            "driver_time_observations", "driver_time_heads"):
        assert after[table] == before[table]
    for table in ("observation_outbox", "telemetry_alarm_observations"):
        actual_by_id = {row["id"]: row for row in after[table]}
        assert all(actual_by_id[row["id"]] == row for row in before[table])
    old_events = {row["id"] for row in before["observation_outbox"]}
    emitted = sorted((row for row in after["observation_outbox"] if row["id"] not in old_events),
        key=lambda row: row["projection_sequence"])
    assert [(row["event_type"], row["aggregate_id"]) for row in emitted] == [
        pair for value in values for pair in (("telemetry.freshness_changed", value.sample_identity.item_id),
            ("telemetry.alarm_indeterminate", value.sample_identity.item_id))]
    before_sequence = before["observation_streams"][0]["last_sequence"]
    assert [row["projection_sequence"] for row in emitted] == list(
        range(before_sequence + 1, before_sequence + 2 * size + 1))
    for value, freshness, alarm in zip(values, emitted[::2], emitted[1::2]):
        assert freshness["payload"]["data"] == {
            "context_generation_id": generation.context_generation,
            "item_id": value.sample_identity.item_id, "sample_id": value.sample_identity.sample_id,
            "freshness": "STALE", "freshness_policy_revision": before["telemetry_samples"][0]["freshness_policy_revision"],
            "evaluated_at_database_time": evaluated_at.isoformat(),
        }
        data = alarm["payload"]["data"]
        assert data["sample_id"] == value.sample_identity.sample_id
        assert (data["quality"], data["validity"], data["freshness"], data["state"], data["reason"]) == (
            "GOOD", "VALID", "STALE", "INDETERMINATE", "FRESHNESS_UNACCEPTABLE")
        assert data["evaluated_at_database_time"] == evaluated_at.isoformat()
    previous_heads = {row["id"]: row for row in before["telemetry_item_heads"]}
    for row in after["telemetry_item_heads"]:
        previous = previous_heads[row["id"]]
        assert row == {**previous, "freshness": "STALE", "revision": previous["revision"] + 1,
            "updated_at": evaluated_at.replace(tzinfo=None)}
    assert repository.mark_stale(now_unix_ns=clock[0]) == 0
    assert history(factory) == after


def test_late_stale_sweep_commit_failure_rolls_back_every_head_alarm_and_event(
    observation_store, engine,
):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    repository.ingest_samples(admissions(values))
    before, flushed = history(factory), []
    clock[0] += 6_000_000_000
    def fail_commit(session):
        session.flush()
        events = session.scalars(select(ObservationOutboxEvent).where(
            ObservationOutboxEvent.event_type == "telemetry.freshness_changed")).all()
        assert len(events) == 22
        assert len(session.scalars(select(TelemetrySample)).all()) == 22
        flushed.append(True)
        raise RuntimeError("fail after all stale events flushed")
    event.listen(factory.class_, "before_commit", fail_commit)
    try:
        with pytest.raises(RuntimeError, match="fail after all stale events flushed"):
            repository.mark_stale(now_unix_ns=clock[0])
    finally:
        event.remove(factory.class_, "before_commit", fail_commit)
    assert flushed == [True]
    assert history(factory) == before
    assert repository.mark_stale(now_unix_ns=clock[0]) == 22
