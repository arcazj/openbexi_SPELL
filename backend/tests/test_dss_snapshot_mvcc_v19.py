"""SQLite keeps its existing locked, durable observation projection contract."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import threading

import pytest
from sqlalchemy import select

from backend.observation_domain import GetTMMode
from backend.observation_models import TelemetryItemHead, TelemetrySample
from backend.observation_repository import ObservationRepository
from backend.tests.test_dss_cohort_ingest_v19 import admissions, frame, history, packet_samples
from backend.tests.test_dss_clock_epoch_v19 import clock_value
from backend.tests.test_observation_repository import observation_store, sample
from driver_host.tests.test_dss_transport import engine


def seeded_dss(store, simulator, *, age_seconds=0, freshness="FRESH"):
    """Commit real typed packet members at a declared historical receive time."""
    _, factory, generation, clock = store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    simulator.advance(1)
    values = packet_samples(generation, clock, simulator)
    age_ns = age_seconds * 1_000_000_000
    values = tuple(replace(value, acquired_at_unix_ns=value.acquired_at_unix_ns - age_ns,
        clock_uncertainty_ns=2_000_000_000 if freshness == "UNKNOWN" else value.clock_uncertainty_ns)
        for value in values)
    if freshness != "STALE":
        clock[0] -= age_ns
    repository.ingest_samples(admissions(values))
    observed_time = replace(clock_value(generation, clock[0], seconds=0,
        epoch=values[0].sample_identity.source_epoch),
        source_sequence=values[0].sample_identity.source_sequence)
    repository.record_time(observed_time, context_generation_id=generation.context_generation)
    return repository, factory, generation, clock, values, observed_time


def without_read_time(snapshot):
    # Only the database time of two separate reads differs. Every data,
    # provenance, cursor, clock, generation and alarm field remains compared.
    return {key: value for key, value in snapshot.items() if key != "snapshot_at_database_time"}


@pytest.mark.parametrize("dss", [False, True])
def test_sqlite_preserves_locked_projection_and_complete_durable_payload(
    observation_store, engine, monkeypatch, dss,
):
    if dss:
        repository, factory, generation, clock, values, _ = seeded_dss(observation_store, engine)
        next_values = frame(values, values[0].sample_identity.source_sequence + 1)
        def mutate():
            repository.ingest_samples(admissions(next_values, GetTMMode.NEXT, False))
    else:
        repository, factory, generation, clock = observation_store
        value = sample(generation, sequence=1, engineering=28.0, observation_number=91001)
        repository.ingest_sample(value, mode=GetTMMode.CURRENT, resynchronized=True)
        def mutate():
            repository.ingest_sample(sample(generation, sequence=2, engineering=29.0,
                observation_number=91002), mode=GetTMMode.NEXT)
    assert factory.kw["bind"].dialect.name == "sqlite"
    with factory() as session:
        heads = session.scalars(select(TelemetryItemHead).order_by(TelemetryItemHead.item_id)).all()
        expected = [repository._sample_projection(session, session.get(TelemetrySample, row.sample_id))
            for row in heads]
    before = history(factory)
    snapshot = repository.snapshot("simulator")
    assert snapshot["items"] == expected
    assert history(factory) == before
    assert len(snapshot["items"]) == (22 if dss else 1)

    entered, release, wrote = threading.Event(), threading.Event(), threading.Event()
    original = repository._sample_dict
    def hold_projection(value, head):
        if threading.current_thread().name.startswith("sqlite-snapshot"):
            entered.set()
            assert release.wait(5), "test did not release the SQLite reader"
        return original(value, head)
    monkeypatch.setattr(repository, "_sample_dict", hold_projection)
    def write():
        mutate()
        wrote.set()
    with ThreadPoolExecutor(1, thread_name_prefix="sqlite-snapshot") as reader, ThreadPoolExecutor(1) as writer:
        pending = reader.submit(repository.snapshot, "simulator")
        assert entered.wait(5)
        mutation = writer.submit(write)
        try:
            assert not wrote.wait(0.03), "SQLite writer escaped the existing snapshot fence"
        finally:
            release.set()
        assert pending.result(timeout=5)["items"] == expected
        mutation.result(timeout=5)
    assert wrote.is_set()
    assert {row["source_sequence"] for row in repository.snapshot("simulator")["items"]} == {
        str(values[0].sample_identity.source_sequence + 1) if dss else "2"}


def test_sqlite_expiration_remains_a_durable_sweep_not_a_new_read_overlay(observation_store, engine):
    repository, factory, _, clock, _, _ = seeded_dss(observation_store, engine, age_seconds=6)
    before = history(factory)
    assert {row["freshness"] for row in repository.snapshot("simulator")["items"]} == {"FRESH"}
    assert history(factory) == before
    clock[0] += 6_000_000_000
    assert repository.mark_stale() == 22
    assert {row["freshness"] for row in repository.snapshot("simulator")["items"]} == {"STALE"}


@pytest.mark.parametrize("after_expiry_microseconds,expected", [(0, "FRESH"), (1, "STALE")])
def test_read_overlay_exact_expiry_boundary_on_real_persisted_samples(
    observation_store, engine, after_expiry_microseconds, expected,
):
    """Boundary unit proof; actual PostgreSQL transaction semantics live separately."""
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    engine.advance(1)
    values = packet_samples(generation, clock, engine)
    # Align real packet acquisitions to the database's microsecond resolution;
    # admission still derives and persists the original five-second policy TTL.
    acquired_ns = (values[0].acquired_at_unix_ns // 1000) * 1000
    values = tuple(replace(value, acquired_at_unix_ns=acquired_ns) for value in values)
    clock[0] = acquired_ns + 1000
    repository.ingest_samples(admissions(values))
    stored = history(factory)
    expiry_ns = acquired_ns + 1000 + 5_000_000_000
    assert {row["fresh_until_unix_ns"] for row in stored["telemetry_samples"]} == {expiry_ns}
    baseline = repository.snapshot("simulator")
    read_time = (datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(microseconds=expiry_ns // 1000 + after_expiry_microseconds))
    with factory() as session:
        context = repository._active_context(session, "simulator")
        stream = repository._stream(session, context.id, create=False, lock=False)
        assert stream is not None
        actual = repository._snapshot_projection(session, context, stream, read_time,
            commit=False, read_time_freshness=True)
    expected_projection = without_read_time(baseline)
    expected_projection["items"] = [dict(item, freshness=expected) for item in baseline["items"]]
    assert without_read_time(actual) == expected_projection
    assert actual["snapshot_at_database_time"] == read_time.isoformat()
    assert {row["alarm"]["freshness"] for row in actual["items"]} == {"FRESH"}
    assert history(factory) == stored
