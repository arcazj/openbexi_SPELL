from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from backend.database import create_database
from backend.driver_domain import (
    CAPABILITY_MATRIX,
    GenerationTuple,
)
from backend.driver_repository import (
    CapabilitySpec,
    DEFAULT_PROFILE_DIGEST,
    DEFAULT_PROFILE_ID,
    DriverRepository,
)
from backend.migrations import run_migrations
from backend.observation_domain import (
    ClockSource,
    DriverTelemetrySample,
    DriverTimeObservation,
    GapBounds,
    GetTMMode,
    GetTMResult,
    GetTimeResult,
    ItemIdentity,
    ObservationResultCode,
    Quality,
    SampleIdentity,
    ScalarKind,
    ScalarValue,
    Validity,
    sample_id_for,
)
from backend.observation_models import (
    ObservationOutboxEvent,
    ObservationStream,
    TelemetryAlarmObservation,
    TelemetryGap,
    TelemetrySample,
)
from backend.observation_repository import (
    ObservationConflictError,
    ObservationNotFoundError,
    ObservationRepository,
)
from backend.observation_service import OBSERVATION_ITEM_IDS, ObservationRuntime
from driver_host.observation import source_epoch_for


CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"
SOURCE_ID = "bundled-deterministic-simulator"
BASE_NS = 1_735_689_600_000_000_000
HOST_ID = str(UUID(int=7001))
SOURCE_EPOCH = source_epoch_for(HOST_ID, "repository-test-source")
CONTEXT_GENERATION_ID = str(UUID(int=7002))
CONTEXT_DIGEST = "c" * 64


def capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(
        CapabilitySpec(
            service=item.service,
            method=item.method.value,
            mutability=item.mutability,
            modifiers=item.modifiers,
            formats=(item.format,),
            stream_support=item.stream_support,
        )
        for item in CAPABILITY_MATRIX
    )


@pytest.fixture
def observation_store(tmp_path: Path):
    engine, session_factory = create_database(
        f"sqlite:///{(tmp_path / 'observation.db').as_posix()}"
    )
    run_migrations(engine)
    drivers = DriverRepository(session_factory)
    drivers.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="pytest-observation",
        correlation_id=str(UUID(int=7100)),
    )
    drivers.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=HOST_ID,
        contract_version="1.0",
        implementation_version="0.7.0-test",
        capabilities=capabilities(),
        actor="pytest-observation",
        correlation_id=str(UUID(int=7101)),
    )
    drivers.record_host_state(
        HOST_ID,
        "READY",
        expected_revision=0,
        actor="pytest-observation",
        correlation_id=str(UUID(int=7102)),
        observed_at=datetime(2026, 8, 16, tzinfo=timezone.utc),
    )
    context = drivers.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=HOST_ID,
        context_id="simulator",
        context_generation_id=CONTEXT_GENERATION_ID,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest=CONTEXT_DIGEST,
        actor="pytest-observation",
        correlation_id=str(UUID(int=7103)),
    )
    drivers.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest-observation",
        correlation_id=str(UUID(int=7104)),
        observed_at=datetime(2026, 8, 16, tzinfo=timezone.utc),
    )
    clock = [BASE_NS + 1_000_000]
    repository = ObservationRepository(session_factory, clock_ns=lambda: clock[0])
    generations = GenerationTuple(
        server_profile_id="local-synthetic",
        driver_host_generation=HOST_ID,
        host_profile_digest=DEFAULT_PROFILE_DIGEST,
        context_id="simulator",
        context_generation=CONTEXT_GENERATION_ID,
        context_binding_digest=CONTEXT_DIGEST,
    )
    try:
        yield repository, session_factory, generations, clock
    finally:
        engine.dispose()


def sample(
    generations: GenerationTuple,
    *,
    item_id: str = "TM.POWER.BUS_VOLTAGE",
    sequence: int,
    engineering: float | bool | str,
    observation_number: int,
    epoch: str | None = None,
) -> DriverTelemetrySample:
    epoch = epoch or source_epoch_for(
        generations.driver_host_generation, "repository-test-source"
    )
    if item_id == "TM.POWER.BUS_VOLTAGE":
        metadata = (
            "SIM.POWER.BUS_VOLTAGE",
            ScalarValue(ScalarKind.UINT64, int(float(engineering) * 1000)),
            ScalarValue(ScalarKind.FINITE_DOUBLE, float(engineering)),
            "V",
            "Synthetic DC bus voltage",
        )
    elif item_id == "TM.POWER.SAFE_MODE":
        metadata = (
            "SIM.POWER.SAFE_MODE",
            ScalarValue(ScalarKind.BOOLEAN, bool(engineering)),
            ScalarValue(ScalarKind.BOOLEAN, bool(engineering)),
            "",
            "Synthetic safe-mode flag",
        )
    else:
        metadata = (
            "SIM.THERMAL.MODE",
            ScalarValue(ScalarKind.STRING, str(engineering)),
            ScalarValue(ScalarKind.STRING, str(engineering)),
            "",
            "Synthetic thermal control mode",
        )
    identity = SampleIdentity(
        sample_id_for(SOURCE_ID, epoch, item_id, sequence),
        item_id,
        SOURCE_ID,
        epoch,
        sequence,
    )
    return DriverTelemetrySample(
        observation_id=str(UUID(int=observation_number)),
        generations=generations,
        sample_identity=identity,
        item_identity=ItemIdentity(item_id, metadata[0], CATALOG_DIGEST),
        raw_value=metadata[1],
        engineering_value=metadata[2],
        description=metadata[4],
        unit=metadata[3],
        acquired_at_unix_ns=BASE_NS + (
            sequence if sequence < 10_000 else observation_number % 10_000
        ) * 50_000_000,
        source="SIMULATOR",
        clock_provenance="bundled-deterministic-simulator-clock",
        clock_uncertainty_ns=1_000_000,
        validity=Validity.VALID,
        quality=Quality.GOOD,
        quality_reason="deterministic-simulator",
    )


def test_atomic_sample_gap_resynchronization_alarm_and_idempotency(
    observation_store,
) -> None:
    repository, session_factory, generations, clock = observation_store
    first = sample(generations, sequence=1, engineering=28.0, observation_number=7201)
    projection = repository.ingest_sample(
        first, mode=GetTMMode.CURRENT, resynchronized=True
    )
    assert projection["freshness"] == "FRESH"
    assert projection["synchronization_state"] == "COMPLETE"
    assert projection["alarm"]["state"] == "NOT_ALARMED"
    assert projection["received_at_unix_ns"] == str(clock[0])
    assert repository.snapshot("simulator")["through_sequence"] == "2"
    assert repository.telemetry_anchor(
        "simulator", first.item_identity.item_id
    ) == {
        "context_id": "simulator",
        "context_generation_id": CONTEXT_GENERATION_ID,
        "stream_epoch": repository.stream_cursor("simulator")["stream_epoch"],
        "projection_sequence": "2",
        "item_id": first.item_identity.item_id,
        "source_id": SOURCE_ID,
        "source_epoch": SOURCE_EPOCH,
        "source_sequence": "1",
        "sample_id": first.sample_identity.sample_id,
    }

    # A byte-identical sample identity is idempotent and creates no cursor event.
    duplicate = sample(generations, sequence=1, engineering=28.0, observation_number=7202)
    repository.ingest_sample(duplicate, mode=GetTMMode.CURRENT)
    assert repository.snapshot("simulator")["through_sequence"] == "2"
    mutated = sample(generations, sequence=1, engineering=29.0, observation_number=7203)
    with pytest.raises(ObservationConflictError, match="different content"):
        repository.ingest_sample(mutated, mode=GetTMMode.CURRENT)

    gap = repository.record_gap(
        generations,
        source_id=SOURCE_ID,
        item_id=first.item_identity.item_id,
        bounds=GapBounds(SOURCE_EPOCH, 3, 3),
    )
    assert gap["expected_source_sequence"] == "2"
    assert repository.snapshot("simulator")["synchronization_state"] == "GAPPED"
    assert repository.is_alarmed("simulator", first.item_identity.item_id)["state"] == (
        "INDETERMINATE"
    )

    clock[0] += 100_000_000
    recovered = sample(
        generations, sequence=3, engineering=21.0, observation_number=7204
    )
    projection = repository.ingest_sample(
        recovered, mode=GetTMMode.CURRENT, resynchronized=True
    )
    assert projection["synchronization_state"] == "COMPLETE"
    assert projection["alarm"]["state"] == "CRITICAL_LOW"
    snapshot = repository.snapshot("simulator")
    assert snapshot["synchronization_state"] == "COMPLETE"
    assert [item["projection_sequence"] for item in repository.replay(
        "simulator",
        stream_epoch=snapshot["stream_epoch"],
        after_sequence=0,
        limit=100,
    )["items"]] == [
        str(value) for value in range(1, int(snapshot["through_sequence"]) + 1)
    ]
    with session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(TelemetrySample)
        ) == 2
        assert session.scalar(
            select(func.count()).select_from(TelemetryGap).where(
                TelemetryGap.state == "RESOLVED"
            )
        ) == 1


def test_no_sample_alarm_is_indeterminate_and_read_only(
    observation_store, monkeypatch
) -> None:
    repository, session_factory, _generations, _clock = observation_store
    with session_factory() as session:
        before = {
            "streams": session.scalar(select(func.count()).select_from(ObservationStream)),
            "alarms": session.scalar(
                select(func.count()).select_from(TelemetryAlarmObservation)
            ),
            "events": session.scalar(
                select(func.count()).select_from(ObservationOutboxEvent)
            ),
        }

    first_time = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
    times = [first_time, first_time + timedelta(microseconds=1)]
    monkeypatch.setattr(repository, "_database_now", lambda _session: times.pop(0))
    result = repository.is_alarmed("simulator", "TM.POWER.BUS_VOLTAGE")
    second = repository.is_alarmed("simulator", "TM.POWER.BUS_VOLTAGE")
    assert second["evaluated_at_database_time"] != result["evaluated_at_database_time"]
    assert second["alarm_observation_id"] != result["alarm_observation_id"]
    assert result == {
        "alarm_observation_id": result["alarm_observation_id"],
        "item_id": "TM.POWER.BUS_VOLTAGE",
        "sample_id": None,
        "limit_set_id": "LIMIT.TM.POWER.BUS_VOLTAGE",
        "limit_revision": "v07-r1",
        "state": "INDETERMINATE",
        "severity": "INDETERMINATE",
        "evaluated_engineering_value": None,
        "quality": "UNKNOWN",
        "validity": "UNKNOWN",
        "freshness": "UNKNOWN",
        "boolean_value": None,
        "snapshot_cursor": {
            "stream_epoch": "UNINITIALIZED",
            "projection_sequence": "0",
        },
        "evaluated_at_database_time": result["evaluated_at_database_time"],
        "reason": "NO_SAMPLE",
    }
    assert len(result["alarm_observation_id"]) == 64
    with pytest.raises(ObservationNotFoundError):
        repository.is_alarmed("simulator", "TM.SECRET.HIDDEN")

    with session_factory() as session:
        after = {
            "streams": session.scalar(select(func.count()).select_from(ObservationStream)),
            "alarms": session.scalar(
                select(func.count()).select_from(TelemetryAlarmObservation)
            ),
            "events": session.scalar(
                select(func.count()).select_from(ObservationOutboxEvent)
            ),
        }
    assert after == before


def test_bundled_catalog_mismatch_is_rejected_before_projection(observation_store) -> None:
    repository, session_factory, generations, _clock = observation_store
    valid = sample(generations, sequence=1, engineering=28.0, observation_number=7241)
    invalid = (
        replace(
            valid,
            item_identity=ItemIdentity(
                valid.item_identity.item_id,
                valid.item_identity.qualified_name,
                "d" * 64,
            ),
        ),
        replace(
            valid,
            item_identity=ItemIdentity(
                valid.item_identity.item_id,
                "SIM.POWER.WRONG_NAME",
                valid.item_identity.catalog_digest,
            ),
        ),
        replace(valid, raw_value=ScalarValue(ScalarKind.STRING, "28000")),
        replace(valid, source="unapproved-simulator-source"),
        replace(valid, clock_provenance="unapproved-clock-provenance"),
    )

    for candidate in invalid:
        with pytest.raises(ObservationConflictError, match="immutable bundled catalog"):
            repository.ingest_sample(
                candidate,
                mode=GetTMMode.CURRENT,
                resynchronized=True,
            )

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(TelemetrySample)) == 0
        assert session.scalar(select(func.count()).select_from(ObservationStream)) == 0
        assert session.scalar(select(func.count()).select_from(ObservationOutboxEvent)) == 0


def test_uint64_source_sequence_round_trips_without_sqlite_precision_loss(
    observation_store,
) -> None:
    repository, session_factory, generations, _clock = observation_store
    first_sequence = 2**64 - 2
    last_sequence = 2**64 - 1
    first = sample(
        generations,
        sequence=first_sequence,
        engineering=28.0,
        observation_number=7251,
    )
    repository.ingest_sample(first, mode=GetTMMode.CURRENT, resynchronized=True)
    final = sample(
        generations,
        sequence=last_sequence,
        engineering=28.1,
        observation_number=7252,
    )
    projection = repository.ingest_sample(final, mode=GetTMMode.NEXT)

    assert projection["source_sequence"] == str(last_sequence)
    assert repository.telemetry_anchor(
        "simulator", final.item_identity.item_id
    )["source_sequence"] == str(last_sequence)
    with session_factory() as session:
        stored = session.get(TelemetrySample, final.sample_identity.sample_id)
        assert stored is not None
        assert stored.source_sequence == last_sequence
        raw = session.connection().exec_driver_sql(
            "SELECT source_sequence FROM telemetry_samples WHERE id = ?",
            (final.sample_identity.sample_id,),
        ).scalar_one()
        assert raw == "18446744073709551615"


def test_source_restart_bootstraps_a_new_epoch_without_numeric_comparison(
    observation_store,
) -> None:
    repository, _session_factory, generations, clock = observation_store
    first = sample(generations, sequence=1, engineering=28.0, observation_number=7253)
    repository.ingest_sample(first, mode=GetTMMode.CURRENT, resynchronized=True)

    restarted_epoch = source_epoch_for(HOST_ID, "repository-restarted-source")
    assert restarted_epoch != first.sample_identity.source_epoch
    clock[0] += 100_000_000
    restarted = sample(
        generations,
        sequence=1,
        engineering=28.1,
        observation_number=7254,
        epoch=restarted_epoch,
    )
    projection = repository.ingest_sample(
        restarted, mode=GetTMMode.CURRENT, resynchronized=True
    )
    assert projection["source_epoch"] == restarted_epoch
    assert projection["source_sequence"] == "1"
    anchor = repository.telemetry_anchor("simulator", restarted.item_identity.item_id)
    assert anchor["source_epoch"] == restarted_epoch
    assert anchor["source_sequence"] == "1"


def test_uint64_clock_uncertainty_crosses_signed_database_boundary(
    observation_store,
) -> None:
    repository, session_factory, generations, _clock = observation_store
    uncertainty = 2**63 + 17
    host_generations = GenerationTuple(
        server_profile_id=generations.server_profile_id,
        driver_host_generation=generations.driver_host_generation,
        host_profile_digest=generations.host_profile_digest,
    )
    time_observation = DriverTimeObservation(
        observation_id=str(UUID(int=7255)),
        generations=host_generations,
        time_unix_ns=BASE_NS,
        acquired_at_unix_ns=BASE_NS,
        clock_source=ClockSource.SIMULATOR,
        provenance="bundled-deterministic-simulator-clock",
        uncertainty_ns=uncertainty,
        quality=Quality.GOOD,
        validity=Validity.VALID,
    )
    stored_time = repository.record_time(
        time_observation, context_generation_id=CONTEXT_GENERATION_ID
    )
    assert stored_time["uncertainty_ns"] == str(uncertainty)

    telemetry = replace(
        sample(generations, sequence=1, engineering=28.0, observation_number=7256),
        clock_uncertainty_ns=uncertainty,
    )
    projection = repository.ingest_sample(
        telemetry, mode=GetTMMode.CURRENT, resynchronized=True
    )
    assert projection["clock_uncertainty_ns"] == str(uncertainty)
    assert projection["freshness"] == "UNKNOWN"

    with session_factory() as session:
        raw_time = session.connection().exec_driver_sql(
            "SELECT uncertainty_ns FROM driver_time_observations WHERE id = ?",
            (time_observation.observation_id,),
        ).scalar_one()
        raw_sample = session.connection().exec_driver_sql(
            "SELECT clock_uncertainty_ns FROM telemetry_samples WHERE id = ?",
            (telemetry.sample_identity.sample_id,),
        ).scalar_one()
        expected = f"{uncertainty:020d}"
        assert raw_time == raw_sample == expected


def test_projection_cursor_uses_bigint_and_crosses_int32_boundary(
    observation_store,
) -> None:
    repository, session_factory, generations, clock = observation_store
    first = sample(generations, sequence=1, engineering=28.0, observation_number=7261)
    repository.ingest_sample(first, mode=GetTMMode.CURRENT, resynchronized=True)

    with session_factory() as session:
        stream = session.scalar(select(ObservationStream))
        assert stream is not None
        stream.last_sequence = 2**31 - 1
        session.commit()

    clock[0] += 100_000_000
    second = sample(generations, sequence=2, engineering=28.1, observation_number=7262)
    projection = repository.ingest_sample(second, mode=GetTMMode.NEXT)
    assert projection["alarm"]["sample_id"] == second.sample_identity.sample_id
    assert repository.stream_cursor("simulator")["last_sequence"] == str(2**31 + 1)

    with session_factory() as session:
        emitted = session.scalars(
            select(ObservationOutboxEvent)
            .where(ObservationOutboxEvent.projection_sequence >= 2**31)
            .order_by(ObservationOutboxEvent.projection_sequence)
        ).all()
        assert [row.projection_sequence for row in emitted] == [2**31, 2**31 + 1]
        assert emitted[1].payload["data"]["sample_id"] == second.sample_identity.sample_id

    ddl = "\n".join(
        str(CreateTable(table).compile(dialect=postgresql.dialect()))
        for table in (
            ObservationStream.__table__,
            TelemetryAlarmObservation.__table__,
            ObservationOutboxEvent.__table__,
        )
    )
    assert "last_sequence BIGINT" in ddl
    assert ddl.count("projection_sequence BIGINT") == 2


def test_alarm_transition_is_bound_to_each_new_sample_identity(
    observation_store,
) -> None:
    repository, session_factory, generations, clock = observation_store
    first = sample(generations, sequence=1, engineering=28.0, observation_number=7271)
    second = sample(generations, sequence=2, engineering=28.1, observation_number=7272)

    repository.ingest_sample(first, mode=GetTMMode.CURRENT, resynchronized=True)
    clock[0] += 100_000_000
    repository.ingest_sample(second, mode=GetTMMode.NEXT)
    snapshot = repository.snapshot("simulator")
    replay = repository.replay(
        "simulator",
        stream_epoch=snapshot["stream_epoch"],
        after_sequence=0,
        limit=100,
    )["items"]

    assert [item["projection_sequence"] for item in replay] == ["1", "2", "3", "4"]
    alarms = [item for item in replay if item["event_type"] == "telemetry.alarm_changed"]
    assert [item["data"]["sample_id"] for item in alarms] == [
        first.sample_identity.sample_id,
        second.sample_identity.sample_id,
    ]

    repository.ingest_sample(second, mode=GetTMMode.NEXT)
    assert repository.stream_cursor("simulator")["last_sequence"] == "4"
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(TelemetryAlarmObservation)) == 2


def test_time_and_freshness_transitions_are_durable(observation_store) -> None:
    repository, session_factory, generations, clock = observation_store
    host_generations = GenerationTuple(
        server_profile_id=generations.server_profile_id,
        driver_host_generation=generations.driver_host_generation,
        host_profile_digest=generations.host_profile_digest,
    )
    time_observation = DriverTimeObservation(
        observation_id=str(UUID(int=7301)),
        generations=host_generations,
        time_unix_ns=BASE_NS,
        acquired_at_unix_ns=BASE_NS,
        clock_source=ClockSource.SIMULATOR,
        provenance="bundled-deterministic-simulator-clock",
        uncertainty_ns=1_000_000,
        quality=Quality.GOOD,
        validity=Validity.VALID,
    )
    repository.record_time(
        time_observation, context_generation_id=CONTEXT_GENERATION_ID
    )
    projection = repository.ingest_sample(
        sample(generations, sequence=1, engineering=28.0, observation_number=7302),
        mode=GetTMMode.CURRENT,
        resynchronized=True,
    )
    snapshot_view = repository.snapshot("simulator")
    with session_factory() as session:
        database_now = session.execute(select(func.current_timestamp())).scalar_one()
    if isinstance(database_now, str):
        database_now = datetime.fromisoformat(database_now)
    if database_now.tzinfo is None:
        database_now = database_now.replace(tzinfo=timezone.utc)
    host_now = datetime.fromtimestamp(clock[0] / 1_000_000_000, tz=timezone.utc)
    alarm_time = datetime.fromisoformat(
        projection["alarm"]["evaluated_at_database_time"]
    )
    snapshot_time = datetime.fromisoformat(snapshot_view["snapshot_at_database_time"])
    assert abs((alarm_time - database_now).total_seconds()) < 5
    assert abs((snapshot_time - database_now).total_seconds()) < 5
    assert abs((alarm_time - host_now).total_seconds()) > 86_400
    assert abs((snapshot_time - host_now).total_seconds()) > 86_400
    assert repository.driver_time("simulator")["clock_source"] == "SIMULATOR"
    clock[0] += 6_000_000_000
    assert repository.mark_stale(now_unix_ns=clock[0]) == 1
    stale = repository.snapshot("simulator")["items"][0]
    assert stale["freshness"] == "STALE"
    assert stale["alarm"]["state"] == "INDETERMINATE"
    stale_alarm_time = datetime.fromisoformat(
        stale["alarm"]["evaluated_at_database_time"]
    )
    assert abs((stale_alarm_time - database_now).total_seconds()) < 5
    assert repository.mark_stale(now_unix_ns=clock[0]) == 0


def test_collector_uses_current_then_restart_cursor_next_without_duplicates(
    observation_store,
) -> None:
    repository, session_factory, generations, clock = observation_store
    host = GenerationTuple(
        server_profile_id=generations.server_profile_id,
        driver_host_generation=generations.driver_host_generation,
        host_profile_digest=generations.host_profile_digest,
    )
    generation_set = {
        "host": host,
        "contexts": (generations,),
        "credential_epoch": 1,
    }
    values = {
        "TM.POWER.BUS_VOLTAGE": (28.0, 23.0),
        "TM.POWER.SAFE_MODE": (False, False),
        "TM.THERMAL.MODE": ("NOMINAL", "NOMINAL"),
    }
    calls: list[tuple[str, GetTMMode, int]] = []

    async def get_time(query):
        return GetTimeResult(
            ObservationResultCode.OK,
            observation=DriverTimeObservation(
                query.observation_id,
                query.generations,
                BASE_NS + len(calls),
                BASE_NS + len(calls),
                ClockSource.SIMULATOR,
                "bundled-deterministic-simulator-clock",
                1_000_000,
                Quality.GOOD,
                Validity.VALID,
            ),
        )

    async def get_tm(query):
        sequence = 1 if query.mode is GetTMMode.CURRENT else 2
        calls.append((query.item_id, query.mode, query.after_source_sequence))
        return GetTMResult(
            ObservationResultCode.OK,
            sample=sample(
                generations,
                item_id=query.item_id,
                sequence=sequence,
                engineering=values[query.item_id][sequence - 1],
                observation_number=7400 + sequence * 10 + OBSERVATION_ITEM_IDS.index(query.item_id),
            ),
        )

    first_runtime = ObservationRuntime(
        repository,
        generation_provider=lambda: generation_set,
        get_time=get_time,
        get_tm=get_tm,
    )
    assert asyncio.run(first_runtime.collect_once()) == 4
    assert {mode for _, mode, _ in calls} == {GetTMMode.CURRENT}
    assert all(item["after_source_sequence"] == 1 for item in repository.restart_cursors(
        CONTEXT_GENERATION_ID
    ))

    calls.clear()
    clock[0] += 100_000_000
    restarted_runtime = ObservationRuntime(
        repository,
        generation_provider=lambda: generation_set,
        get_time=get_time,
        get_tm=get_tm,
    )
    assert asyncio.run(restarted_runtime.collect_once()) == 4
    assert {mode for _, mode, _ in calls} == {GetTMMode.NEXT}
    assert {after for _, _, after in calls} == {1}
    assert all(item["after_source_sequence"] == 2 for item in repository.restart_cursors(
        CONTEXT_GENERATION_ID
    ))
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(TelemetrySample)) == 6
        sequences = session.scalars(
            select(ObservationOutboxEvent.projection_sequence)
            .order_by(ObservationOutboxEvent.projection_sequence)
        ).all()
        assert sequences == list(range(1, len(sequences) + 1))
