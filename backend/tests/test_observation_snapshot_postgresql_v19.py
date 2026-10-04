"""Actual PostgreSQL MVCC reads never wait for an uncommitted DSS writer."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
import os
import threading
import time

import pytest
from sqlalchemy import event, select
from sqlalchemy.engine import make_url

from backend.database import create_database
from backend.driver_models import DriverContextGeneration
from backend.observation_domain import GetTMMode
from backend.observation_models import TelemetryItemHead, TelemetrySample
from backend.observation_repository import ObservationNotFoundError, ObservationRepository
from backend.tests import test_observation_repository as fixture_module
from backend.tests.migration_support import reset_test_database
from backend.tests.test_dss_cohort_ingest_v19 import admissions, frame, history
from backend.tests.test_dss_snapshot_mvcc_v19 import seeded_dss, without_read_time
from backend.tests.test_observation_repository import observation_store
from driver_host.tests.test_dss_transport import engine


POSTGRES_URL = os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL,
    reason="dedicated PostgreSQL migration database not configured")


@pytest.fixture
def postgres_store(tmp_path, monkeypatch):
    assert POSTGRES_URL is not None
    assert make_url(POSTGRES_URL).database == "spell_migration_test"
    database, _ = create_database(POSTGRES_URL)
    reset_test_database(database)
    database.dispose()
    monkeypatch.setattr(fixture_module, "create_database", lambda _: create_database(POSTGRES_URL))
    fixture = observation_store.__wrapped__(tmp_path)
    store = next(fixture)
    assert store[1].kw["bind"].dialect.name == "postgresql"
    try:
        yield store
    finally:
        fixture.close()
        cleanup, _ = create_database(POSTGRES_URL)
        try:
            reset_test_database(cleanup)
        finally:
            cleanup.dispose()


class RollbackAfterFlush(RuntimeError):
    pass


@contextmanager
def held_writer(repository, factory, mutation, *, rollback=False):
    """Hold a real flushed transaction and the original repository RLock."""
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    failures, sql = [], []
    writer_ident = []
    database = factory.kw["bind"]
    def statement(_connection, _cursor, value, _parameters, _context, _many):
        if writer_ident and threading.get_ident() == writer_ident[0]:
            if value.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE ")):
                sql.append(value.split(None, 1)[0].upper())
    def before_commit(session):
        if writer_ident and threading.get_ident() == writer_ident[0]:
            session.flush()
            assert sql, "the writer must have executed real changes before the barrier"
            entered.set()
            assert release.wait(5), "test failed to release the actual writer"
            if rollback:
                raise RollbackAfterFlush("declared test rollback after actual SQL flush")
    def write():
        writer_ident.append(threading.get_ident())
        try:
            with repository._lock:
                mutation()
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()
    event.listen(database, "before_cursor_execute", statement)
    event.listen(factory.class_, "before_commit", before_commit)
    thread = threading.Thread(target=write, name="held-pg-observation-writer")
    thread.start()
    try:
        assert entered.wait(5), repr(failures)
        assert not finished.is_set()
        yield finished
    finally:
        release.set()
        thread.join(5)
        event.remove(factory.class_, "before_commit", before_commit)
        event.remove(database, "before_cursor_execute", statement)
        assert not thread.is_alive(), "owned writer did not join"
    if rollback:
        assert len(failures) == 1 and isinstance(failures[0], RollbackAfterFlush), repr(failures)
    else:
        assert not failures, repr(failures)


def read_before_release(reader):
    # A two-thread executor is unnecessary: the writer already exists. Always
    # release/join it in the outer context before joining a blocked failed reader.
    result, errors, done = [], [], threading.Event()
    def read():
        try:
            result.append(reader())
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()
    thread = threading.Thread(target=read, name="pg-mvcc-snapshot-reader")
    thread.start()
    return thread, done, result, errors


def while_writer_held(repository, factory, mutation, *, reader=None, rollback=False,
    minimum_hold_seconds=0):
    reader = reader or (lambda: repository.snapshot("simulator"))
    thread = None
    try:
        with held_writer(repository, factory, mutation, rollback=rollback) as finished:
            started = time.monotonic()
            thread, done, result, errors = read_before_release(reader)
            assert done.wait(1), "MVCC reader waited on the uncommitted writer beyond one second"
            assert not finished.is_set(), "writer must still be held when the snapshot returns"
            assert not errors, repr(errors)
            assert len(result) == 1
            elapsed = time.monotonic() - started
            # For the Verify regression the real writer remains uncommitted
            # beyond the entire original one-second request budget, even
            # though the reader has already returned its successful result.
            remaining = minimum_hold_seconds - (time.monotonic() - started)
            if remaining > 0:
                assert not finished.wait(remaining)
    finally:
        if thread is not None:
            thread.join(5)
            assert not thread.is_alive(), "owned reader did not join after writer release"
    return result[0], elapsed


@pytest.mark.parametrize("rollback", [False, True])
def test_postgresql_snapshot_reads_exact_old_22_item_cohort_before_writer_commit(
    postgres_store, engine, rollback, record_property,
):
    repository, factory, _, _, values, _ = seeded_dss(postgres_store, engine)
    before = repository.snapshot("simulator")
    with factory() as session:
        heads = session.scalars(select(TelemetryItemHead).order_by(TelemetryItemHead.item_id)).all()
        expected_items = [repository._sample_projection(session, session.get(TelemetrySample, row.sample_id))
            for row in heads]
    assert before["items"] == expected_items
    stored = history(factory)
    next_sequence = values[0].sample_identity.source_sequence + 1
    newer = frame(values, next_sequence)
    captured, elapsed = while_writer_held(repository, factory,
        lambda: repository.ingest_samples(admissions(newer, GetTMMode.NEXT, False)), rollback=rollback)
    assert without_read_time(captured) == without_read_time(before)
    assert len(captured["items"]) == 22
    assert {row["raw_value"]["type"] for row in captured["items"]} >= {"UINT64", "BOOLEAN", "STRING"}
    after = repository.snapshot("simulator")
    if rollback:
        assert without_read_time(after) == without_read_time(before)
        assert history(factory) == stored
    else:
        assert {row["source_sequence"] for row in after["items"]} == {str(next_sequence)}
        assert {row["sample_id"] for row in after["items"]} == {value.sample_identity.sample_id for value in newer}
        assert int(after["through_sequence"]) == int(before["through_sequence"]) + 44
        assert after["driver_time"] == before["driver_time"]
        assert {row["last_source_sequence"] for row in after["source_epochs"]} == {str(next_sequence)}
    record_property("reader_seconds_while_actual_writer_held", elapsed)


@pytest.mark.parametrize("mutation", ["clock", "epoch", "rotation", "context-retirement"])
def test_postgresql_snapshot_epoch_clock_and_generation_are_one_committed_view(
    postgres_store, engine, mutation,
):
    repository, factory, generation, clock, values, observed_time = seeded_dss(postgres_store, engine)
    before = repository.snapshot("simulator")
    new_epoch = "epoch-" + "b" * 64
    def write():
        if mutation == "clock":
            repository.record_time(replace(observed_time, observation_id="mvcc-clock-next",
                time_unix_ns=observed_time.time_unix_ns + 1000,
                source_sequence=observed_time.source_sequence + 1),
                context_generation_id=generation.context_generation)
        elif mutation == "epoch":
            repository.ingest_samples(admissions(frame(values, 1, epoch=new_epoch)))
        elif mutation == "rotation":
            repository.rotate_stream_epoch("simulator")
        else:
            with factory() as session:
                row = session.get(DriverContextGeneration, generation.context_generation, with_for_update=True)
                row.state, row.ready = "CLOSED", False
                row.revision += 1
                session.commit()
    captured, _ = while_writer_held(repository, factory, write)
    assert without_read_time(captured) == without_read_time(before)
    if mutation == "context-retirement":
        with pytest.raises(ObservationNotFoundError):
            repository.snapshot("simulator")
        return
    after = repository.snapshot("simulator")
    if mutation == "clock":
        assert after["driver_time"]["observation_id"] == "mvcc-clock-next"
        assert after["items"] == before["items"]
        assert int(after["through_sequence"]) == int(before["through_sequence"]) + 1
    elif mutation == "epoch":
        assert {row["source_epoch"] for row in after["items"]} == {new_epoch}
        assert {row["source_epoch"] for row in after["source_epochs"]} == {new_epoch}
        assert after["driver_time"] is None
        assert after["synchronization_state"] == "COMPLETE"
        repository.record_time(replace(observed_time, observation_id="mvcc-new-epoch-clock", source_epoch=new_epoch),
            context_generation_id=generation.context_generation)
        assert repository.snapshot("simulator")["driver_time"]["source_epoch"] == new_epoch
    else:
        assert after["stream_epoch"] != before["stream_epoch"]
        assert after["through_sequence"] == "1"
        assert after["items"] == before["items"]
        assert after["driver_time"] == before["driver_time"]


@pytest.mark.parametrize("freshness", ["FRESH", "UNKNOWN", "STALE"])
def test_postgresql_read_time_expiry_never_changes_durable_sample_alarm_or_events(
    postgres_store, engine, freshness,
):
    repository, factory, _, _, _, _ = seeded_dss(postgres_store, engine,
        age_seconds=6, freshness=freshness)
    stored = history(factory)
    assert {row["freshness"] for row in stored["telemetry_item_heads"]} == {freshness}
    actual = repository.snapshot("simulator")
    assert {row["freshness"] for row in actual["items"]} == {
        "STALE" if freshness == "FRESH" else freshness}
    assert {row["alarm"]["freshness"] for row in actual["items"]} == {freshness}
    assert history(factory) == stored
    from backend.condition_engine import ConditionPlan, QualityFreshnessPolicy, evaluate_condition
    from backend.condition_runtime import CommittedObservationSnapshotProvider
    from backend.language_observation_fixture_v19 import condition
    provider = CommittedObservationSnapshotProvider(repository, lambda *_: "simulator",
        expected_policy_revision="v07-r1")
    outcome = evaluate_condition(ConditionPlan.from_dict(condition()), provider.capture("simulator"),
        QualityFreshnessPolicy("simulator-default", "v07-r1"))
    assert outcome.composite_result.value == "INDETERMINATE"
    assert history(factory) == stored


def test_postgresql_missing_stream_initializes_once_then_reads_without_mutation(postgres_store):
    _, factory, _, clock = postgres_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    assert history(factory)["observation_streams"] == []
    first = repository.snapshot("simulator")
    stored = history(factory)
    assert len(stored["observation_streams"]) == 1
    assert first["items"] == [] and first["driver_time"] is None
    assert first["through_sequence"] == "0" and first["synchronization_state"] == "NO_SAMPLE"
    second = repository.snapshot("simulator")
    assert without_read_time(second) == without_read_time(first)
    assert history(factory) == stored


def test_postgresql_verify_keeps_original_one_second_deadline_during_held_clock_write(
    postgres_store, engine,
):
    repository, factory, generation, _, _, observed_time = seeded_dss(postgres_store, engine)
    from backend.condition_engine import ConditionPlan, QualityFreshnessPolicy
    from backend.condition_runtime import CommittedObservationSnapshotProvider
    from backend.condition_service import ConditionService
    from backend.language_observation_fixture_v19 import condition
    service = ConditionService(factory, snapshot_provider=CommittedObservationSnapshotProvider(
        repository, lambda *_: "simulator", expected_policy_revision="v07-r1"))
    def read():
        return service.verify(plan=ConditionPlan.from_dict(condition()),
            policy=QualityFreshnessPolicy("simulator-default", "v07-r1"), timeout_seconds=1,
            request_scope="mvcc-held-clock-proof", idempotency_key="one-original-request")
    result, _ = while_writer_held(repository, factory,
        lambda: repository.record_time(replace(observed_time, observation_id="mvcc-held-clock",
            time_unix_ns=observed_time.time_unix_ns + 1000),
            context_generation_id=generation.context_generation), reader=read, minimum_hold_seconds=1.05)
    assert result["state"] == "TRUE" and result["attempt_count"] == 1
    assert result["timeout_ns"] == 1_000_000_000
    assert (datetime.fromisoformat(result["deadline_at_database_time"])
        - datetime.fromisoformat(result["created_at_database_time"])).total_seconds() == 1
    assert result["final_result"]["evaluation"]["composite_result"] == "TRUE"


def test_postgresql_forged_fresh_head_without_pinned_expiry_is_unknown_without_write(
    postgres_store, engine,
):
    repository, factory, _, _, _, _ = seeded_dss(postgres_store, engine)
    with factory() as session:
        sample = session.scalar(select(TelemetrySample).where(TelemetrySample.item_id == "TM.POWER.BUS_VOLTAGE"))
        sample.fresh_until_unix_ns = None
        session.commit()
    stored = history(factory)
    actual = repository.snapshot("simulator")
    voltage = next(row for row in actual["items"] if row["item_id"] == "TM.POWER.BUS_VOLTAGE")
    assert voltage["freshness"] == "UNKNOWN"
    assert voltage["alarm"]["freshness"] == "FRESH"
    assert history(factory) == stored


@pytest.mark.parametrize("mutation", ["epoch", "rotation"])
def test_postgresql_snapshot_stays_coherent_when_writer_commits_between_projection_reads(
    postgres_store, engine, monkeypatch, mutation,
):
    repository, factory, _, _, values, _ = seeded_dss(postgres_store, engine)
    before = repository.snapshot("simulator")
    entered, committed = threading.Event(), threading.Event()
    original = repository._sample_dict
    def pause_after_head_reads(value, head):
        if threading.current_thread().name == "pg-mvcc-snapshot-reader" and not entered.is_set():
            entered.set()
            assert committed.wait(5), "writer did not commit during the existing snapshot"
        return original(value, head)
    monkeypatch.setattr(repository, "_sample_dict", pause_after_head_reads)
    thread, done, result, errors = read_before_release(lambda: repository.snapshot("simulator"))
    try:
        assert entered.wait(5)
        if mutation == "epoch":
            repository.ingest_samples(admissions(frame(values, 1, epoch="epoch-" + "d" * 64)))
        else:
            repository.rotate_stream_epoch("simulator")
        committed.set()
        assert done.wait(1), "reader did not finish after the actual concurrent commit"
    finally:
        committed.set()
        thread.join(5)
        assert not thread.is_alive()
    assert not errors, repr(errors)
    assert len(result) == 1
    assert without_read_time(result[0]) == without_read_time(before)
    after = repository.snapshot("simulator")
    if mutation == "epoch":
        assert {row["source_epoch"] for row in after["items"]} == {"epoch-" + "d" * 64}
        assert after["driver_time"] is None
    else:
        assert after["stream_epoch"] != before["stream_epoch"]
        assert after["through_sequence"] == "1"


def test_postgresql_readonly_snapshot_returns_same_pooled_connection_to_writer_defaults(
    postgres_store, engine,
):
    repository, factory, _, _, _, _ = seeded_dss(postgres_store, engine)
    database = factory.kw["bind"]
    def settings(connection):
        return (connection.exec_driver_sql("SELECT pg_backend_pid()").scalar_one(),
            connection.exec_driver_sql("SHOW transaction_isolation").scalar_one(),
            connection.exec_driver_sql("SHOW transaction_read_only").scalar_one())
    with database.connect() as connection:
        before = settings(connection)
    assert before[1:] == ("read committed", "off")
    stored = history(factory)
    repository.snapshot("simulator")
    with database.connect() as connection:
        after = settings(connection)
        assert after == before, "the same physical pooled connection must return to writer defaults"
        assert connection.exec_driver_sql(
            "UPDATE observation_streams SET revision = revision + 1").rowcount == 1
        connection.rollback()
    assert history(factory) == stored
