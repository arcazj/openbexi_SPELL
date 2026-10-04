"""Physical epoch transitions fence simulator model time without relaxing monotonicity."""
import asyncio
from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import select

from backend.driver_domain import GenerationTuple
from backend.observation_domain import ClockSource, DriverTimeObservation, GapBounds, GetTMMode, GetTMResult, GetTimeResult, ObservationResultCode, Quality, Validity
from backend.observation_models import DriverTimeObservation as TimeRow, ObservationOutboxEvent
from backend.observation_repository import ObservationRepository, ObservationClockError, ObservationConflictError, ObservationStaleGenerationError, ObservationNotFoundError
from backend.observation_service import ObservationRuntime
from backend.tests.test_dss_observation_profile_v19 import dss_sample
from backend.tests.test_observation_repository import observation_store
from dss.catalog import DATABASE_DIGEST

EPOCH_A = "epoch-" + "a" * 64
EPOCH_B = "epoch-" + "b" * 64


def clock_value(generation, now, *, epoch=EPOCH_A, seconds=1800, number=19801):
    host = GenerationTuple(generation.server_profile_id, generation.driver_host_generation, generation.host_profile_digest)
    return DriverTimeObservation(str(UUID(int=number)), host, now + seconds * 1_000_000_000, now - 1000,
        ClockSource.SIMULATOR, "dss-dynamics-clock", 1000, Quality.GOOD, Validity.VALID,
        epoch, 1, "c" * 64, DATABASE_DIGEST)


def test_accelerated_clock_reset_retires_only_head_preserves_history_and_requires_new_epoch(observation_store):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    old = clock_value(generation, clock[0])
    with pytest.raises(ObservationStaleGenerationError):
        repository.record_time(old, context_generation_id=generation.context_generation)
    repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    first = repository.record_time(old, context_generation_id=generation.context_generation)
    assert first["source_epoch"] == EPOCH_A
    assert first["source_packet_sha256"] == "c" * 64
    assert repository.driver_time("simulator")["time_unix_ns"] == str(old.time_unix_ns)
    with factory() as session:
        old_digest = session.get(TimeRow, old.observation_id).payload_digest
        old_event = session.scalar(select(ObservationOutboxEvent).where(ObservationOutboxEvent.aggregate_id == old.observation_id)).payload
    repository.ingest_sample(dss_sample(generation, clock, epoch=EPOCH_B, number=19802), mode=GetTMMode.CURRENT, resynchronized=True)
    assert repository.snapshot("simulator")["driver_time"] is None
    with pytest.raises(ObservationNotFoundError):
        repository.driver_time("simulator")
    for replay in (old, replace(old, observation_id=str(UUID(int=19803)))):
        with pytest.raises(ObservationStaleGenerationError):
            repository.record_time(replay, context_generation_id=generation.context_generation)
    new = clock_value(generation, clock[0], epoch=EPOCH_B, seconds=0, number=19804)
    repository.record_time(new, context_generation_id=generation.context_generation)
    reopened = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    assert reopened.driver_time("simulator")["source_epoch"] == EPOCH_B
    assert reopened.driver_time("simulator")["time_unix_ns"] == str(new.time_unix_ns)
    with factory() as session:
        assert session.get(TimeRow, old.observation_id).payload_digest == old_digest
        assert session.scalar(select(ObservationOutboxEvent).where(ObservationOutboxEvent.aggregate_id == old.observation_id, ObservationOutboxEvent.event_type == "driver.time_observed")).payload == old_event
        assert len(session.scalars(select(TimeRow)).all()) == 2
    with pytest.raises(ObservationClockError):
        reopened.record_time(replace(new, observation_id=str(UUID(int=19805)), time_unix_ns=new.time_unix_ns - 1_000_000_000), context_generation_id=generation.context_generation)
    with pytest.raises(ObservationConflictError, match="retired"):
        reopened.ingest_sample(dss_sample(generation, clock, sequence=2, number=19806), mode=GetTMMode.CURRENT, resynchronized=True)


@pytest.mark.parametrize("mutation", ["unadmitted_epoch", "wrong_database", "missing_packet_binding", "no_context"])
def test_dss_clock_cannot_claim_an_unadmitted_or_unbound_epoch(observation_store, mutation):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    value = clock_value(generation, clock[0])
    context = generation.context_generation
    if mutation == "unadmitted_epoch": value = replace(value, source_epoch=EPOCH_B)
    elif mutation == "wrong_database": value = replace(value, database_digest="d" * 64)
    elif mutation == "missing_packet_binding": value = replace(value, source_epoch="", source_sequence=0, source_packet_sha256="", database_digest="")
    else: context = None
    with pytest.raises((ObservationConflictError, ObservationStaleGenerationError)):
        repository.record_time(value, context_generation_id=context)
    assert repository.snapshot("simulator")["driver_time"] is None


def test_collector_admits_reset_telemetry_before_clock_and_rejects_cross_reset_capture(observation_store):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    old = clock_value(generation, clock[0])
    repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    repository.record_time(old, context_generation_id=generation.context_generation)
    current = [replace(old, observation_id=str(UUID(int=19810)))]
    sequence = [0]
    async def get_time(query):
        return GetTimeResult(ObservationResultCode.OK, observation=replace(current[0], observation_id=query.observation_id))
    async def get_tm(query):
        if query.mode is GetTMMode.NEXT and query.source_epoch != EPOCH_B:
            return GetTMResult(ObservationResultCode.GAP, gap=GapBounds(EPOCH_B, 1, 1))
        sequence[0] += 1
        return GetTMResult(ObservationResultCode.OK, sample=dss_sample(generation, clock, epoch=EPOCH_B, sequence=sequence[0], number=19810 + sequence[0]))
    runtime = ObservationRuntime(repository, generation_provider=lambda: {"host": old.generations, "contexts": (generation,), "credential_epoch": 1}, get_time=get_time, get_tm=get_tm, item_ids=("TM.POWER.BUS_VOLTAGE",))
    # Actual driver NEXT reports the reset gap; the following CURRENT admits it.
    assert asyncio.run(runtime.collect_once()) == 1
    # Captured old time cannot poison the newly admitted epoch or block TM ingestion.
    assert asyncio.run(runtime.collect_once()) == 1
    assert repository.snapshot("simulator")["driver_time"] is None
    current[0] = clock_value(generation, clock[0], epoch=EPOCH_B, seconds=0)
    assert asyncio.run(runtime.collect_once()) == 2
    assert repository.driver_time("simulator")["source_epoch"] == EPOCH_B
    current[0] = replace(current[0], time_unix_ns=current[0].time_unix_ns - 1_000_000_000)
    with pytest.raises(ObservationClockError):
        asyncio.run(runtime.collect_once())


def test_stream_rotation_preserves_clock_authority_and_orders_new_physical_epoch(observation_store):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    old = clock_value(generation, clock[0])
    repository.record_time(old, context_generation_id=generation.context_generation)
    # Create an earlier physical-epoch event at a larger projection sequence.
    repository.ingest_sample(dss_sample(generation, clock, epoch=EPOCH_B, number=19830), mode=GetTMMode.CURRENT, resynchronized=True)
    high = clock_value(generation, clock[0], epoch=EPOCH_B, number=19831)
    repository.record_time(high, context_generation_id=generation.context_generation)
    prior_cursor = repository.stream_cursor("simulator")
    rotated = repository.rotate_stream_epoch("simulator")
    assert rotated["stream_epoch"] != prior_cursor["stream_epoch"]
    assert repository.driver_time("simulator")["source_epoch"] == EPOCH_B
    with pytest.raises(ObservationClockError):
        repository.record_time(replace(high, observation_id=str(UUID(int=19832)), time_unix_ns=clock[0]), context_generation_id=generation.context_generation)
    new_epoch = "epoch-" + "d" * 64
    repository.ingest_sample(dss_sample(generation, clock, epoch=new_epoch, number=19833), mode=GetTMMode.CURRENT, resynchronized=True)
    assert repository.snapshot("simulator")["driver_time"] is None
    new = clock_value(generation, clock[0], epoch=new_epoch, seconds=0, number=19834)
    repository.record_time(new, context_generation_id=generation.context_generation)
    assert repository.driver_time("simulator")["source_epoch"] == new_epoch
    with pytest.raises(ObservationStaleGenerationError):
        repository.record_time(high, context_generation_id=generation.context_generation)
    with pytest.raises(ObservationConflictError, match="retired"):
        repository.ingest_sample(dss_sample(generation, clock, epoch=EPOCH_B, sequence=2, number=19835), mode=GetTMMode.CURRENT, resynchronized=True)
