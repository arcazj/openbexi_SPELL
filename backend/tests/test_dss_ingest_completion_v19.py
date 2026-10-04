"""Collector completion omits an unused read model, never durable admission."""
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy import event, select

from backend import observation_repository as repository_module
from backend.driver_models import DriverContextGeneration
from backend.observation_domain import GetTMMode, GetTMResult, ObservationResultCode
from backend.observation_models import (
    ObservationOutboxEvent, ObservationStream, TelemetryAlarmHead,
    TelemetryAlarmObservation, TelemetryGap, TelemetryItemHead,
    TelemetrySample, TelemetrySourceCursor,
)
from backend.observation_repository import (
    ObservationConflictError, ObservationRepository,
    ObservationStaleGenerationError, ObservationValidationError,
)
from backend.observation_service import ObservationRuntime
from backend.tests.test_dss_observation_profile_v19 import dss_sample
from backend.tests.test_observation_repository import observation_store, sample


TABLES = (TelemetrySample, TelemetryItemHead, TelemetrySourceCursor,
    TelemetryAlarmObservation, TelemetryAlarmHead, TelemetryGap,
    ObservationOutboxEvent, ObservationStream)


def stored(factory):
    with factory() as session:
        return {model.__tablename__: [dict(row) for row in session.execute(
            select(model.__table__).order_by(*model.__table__.primary_key.columns)
        ).mappings()] for model in TABLES}


def configured(store):
    _, factory, generation, clock = store
    return ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True), factory, generation, clock


def test_default_and_completion_persist_identical_full_history(tmp_path, monkeypatch):
    histories, projections = [], []
    for include in (True, False):
        directory = tmp_path / str(include)
        directory.mkdir()
        fixture = observation_store.__wrapped__(directory)
        store = next(fixture)
        repository, factory, generation, clock = configured(store)
        ids = iter(range(29001, 29101))
        # Both paths receive identical externally generated identities and
        # times, including ORM defaults, so compare every stored field exactly.
        monkeypatch.setattr(repository_module.uuid, "uuid4", lambda: UUID(int=next(ids)))
        monkeypatch.setattr(repository, "_database_now", lambda _session:
            datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc))
        monkeypatch.setattr(ObservationStream.__table__.c.updated_at.onupdate, "arg",
            lambda _context: datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc))
        def fixed_defaults(session, _flush_context, _instances):
            for row in session.new:
                if type(row) in TABLES:
                    for name in ("created_at", "updated_at"):
                        if hasattr(row, name) and getattr(row, name) is None:
                            setattr(row, name, datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc))
        event.listen(factory.class_, "before_flush", fixed_defaults)
        try:
            first = dss_sample(generation, clock)
            skipped = dss_sample(generation, clock, sequence=3, number=29002)
            for value, mode, resync in (
                (first, GetTMMode.CURRENT, True),
                (first, GetTMMode.CURRENT, False),
                (skipped, GetTMMode.NEXT, False),
                (skipped, GetTMMode.CURRENT, True),
            ):
                kwargs = {} if include else {"include_projection": False}
                result = repository.ingest_sample(value, mode=mode, resynchronized=resync, **kwargs)
                assert (isinstance(result, dict) if include else result is None)
            histories.append(stored(factory))
            projections.append(repository.snapshot("simulator")["items"])
            assert projections[-1][0]["synchronization_state"] == "COMPLETE"
            assert histories[-1]["telemetry_gaps"][0]["state"] == "RESOLVED"
        finally:
            event.remove(factory.class_, "before_flush", fixed_defaults)
            fixture.close()
    assert histories[0] == histories[1]
    assert projections[0] == projections[1]


def test_completion_opens_no_post_commit_transaction_or_projection(observation_store, monkeypatch):
    repository, factory, generation, clock = configured(observation_store)
    database, order = factory.kw["bind"], []
    def begin(_connection): order.append("begin")
    def commit(_connection): order.append("commit")
    def sql(_c, _cu, statement, _p, _ctx, _many): order.append("sql")
    monkeypatch.setattr(repository, "_sample_projection", lambda *_:
        pytest.fail("collector must not construct its unused return projection"))
    for name, callback in (("begin", begin), ("commit", commit), ("before_cursor_execute", sql)):
        event.listen(database, name, callback)
    try:
        assert repository.ingest_sample(dss_sample(generation, clock),
            mode=GetTMMode.CURRENT, resynchronized=True, include_projection=False) is None
    finally:
        for name, callback in (("begin", begin), ("commit", commit), ("before_cursor_execute", sql)):
            event.remove(database, name, callback)
    assert order.count("begin") == order.count("commit") == 1
    assert order[-1] == "commit"
    assert len(stored(factory)["telemetry_samples"]) == 1


@pytest.mark.parametrize("invalid", [None, 0, 1, "false"])
def test_projection_option_is_strict_boolean_before_any_database_work(observation_store, invalid):
    repository, factory, generation, clock = configured(observation_store)
    before = stored(factory)
    statements = []
    def sql(*_): statements.append(True)
    database = factory.kw["bind"]
    event.listen(database, "before_cursor_execute", sql)
    try:
        with pytest.raises(ObservationValidationError, match="include_projection"):
            repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT,
                include_projection=invalid)
    finally:
        event.remove(database, "before_cursor_execute", sql)
    assert not statements
    assert stored(factory) == before


def test_completion_commit_failure_rolls_back_all_flushed_admission_rows(observation_store):
    repository, factory, generation, clock = configured(observation_store)
    before, flushed = stored(factory), []
    def fail(session):
        session.flush()
        assert session.scalar(select(TelemetrySample)) is not None
        assert session.scalar(select(TelemetryAlarmObservation)) is not None
        assert session.scalar(select(ObservationOutboxEvent)) is not None
        flushed.append(True)
        raise RuntimeError("deliberate failed admission commit")
    event.listen(factory.class_, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="deliberate failed admission commit"):
            repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT,
                resynchronized=True, include_projection=False)
    finally:
        event.remove(factory.class_, "before_commit", fail)
    assert flushed == [True]
    assert stored(factory) == before
    assert repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT,
        resynchronized=True, include_projection=False) is None
    assert len(stored(factory)["telemetry_samples"]) == 1


@pytest.mark.parametrize("mutation", ["reused_content", "old_current", "retired_epoch", "retired_context"])
def test_completion_keeps_duplicate_resync_and_generation_fences(observation_store, mutation):
    repository, factory, generation, clock = configured(observation_store)
    first = dss_sample(generation, clock)
    repository.ingest_sample(first, mode=GetTMMode.CURRENT, resynchronized=True, include_projection=False)
    candidate, error = first, ObservationConflictError
    if mutation == "reused_content":
        candidate = replace(first, quality_reason="changed-payload")
    elif mutation == "old_current":
        repository.ingest_sample(dss_sample(generation, clock, sequence=2, number=29004),
            mode=GetTMMode.NEXT, include_projection=False)
    elif mutation == "retired_epoch":
        repository.ingest_sample(dss_sample(generation, clock, epoch="epoch-"+"b"*64, number=29005),
            mode=GetTMMode.CURRENT, resynchronized=True, include_projection=False)
    else:
        with factory() as session:
            context = session.get(DriverContextGeneration, generation.context_generation)
            context.state, context.ready = "FAILED", False
            session.commit()
        error = ObservationStaleGenerationError
    before = stored(factory)
    with pytest.raises(error):
        repository.ingest_sample(candidate, mode=GetTMMode.CURRENT, resynchronized=True,
            include_projection=False)
    assert stored(factory) == before


@pytest.mark.parametrize("dss", [False, True])
def test_only_dss_collector_requests_completion_and_still_commits(observation_store, monkeypatch, dss):
    legacy, factory, generation, clock = observation_store
    repository = configured(observation_store)[0] if dss else legacy
    value = dss_sample(generation, clock) if dss else sample(generation,
        sequence=1, engineering=28.0, observation_number=29006)
    options, original = [], repository.ingest_sample
    def ingest(value, **kwargs):
        options.append(kwargs.copy())
        return original(value, **kwargs)
    monkeypatch.setattr(repository, "ingest_sample", ingest)
    async def get_tm(_query): return GetTMResult(ObservationResultCode.OK, sample=value)
    runtime = ObservationRuntime(repository, get_tm=get_tm)
    assert asyncio.run(runtime._collect_item(generation, value.sample_identity.item_id, 1, cursor=None)) == 1
    assert options == [{"mode": GetTMMode.CURRENT, "resynchronized": True,
        **({"include_projection": False} if dss else {})}]
    result = repository.snapshot("simulator")["items"][0]
    assert result["sample_id"] == value.sample_identity.sample_id
    assert result["freshness"] == "FRESH"
    assert result["synchronization_state"] == "COMPLETE"
