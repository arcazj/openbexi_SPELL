from dataclasses import replace

import pytest

from backend.observation_domain import GetTMMode, SampleIdentity, sample_id_for
from backend.observation_repository import ObservationRepository, ObservationConflictError
from backend.tests.test_observation_repository import observation_store, sample


def dss_sample(generations, clock, *, item_id="TM.POWER.BUS_VOLTAGE", sequence=1, epoch="epoch-" + "a" * 64, number=19001):
    result = sample(generations, item_id=item_id, sequence=sequence,
        engineering=28.0 if item_id == "TM.POWER.BUS_VOLTAGE" else False,
        observation_number=number, epoch=epoch)
    identity = SampleIdentity(sample_id_for("dss-GENERIC", epoch, item_id, sequence), item_id, "dss-GENERIC", epoch, sequence)
    return replace(result, sample_identity=identity, acquired_at_unix_ns=clock[0] - 1000,
        clock_provenance="dss-dynamics-clock", quality_reason="DSS_SCENARIO")


def test_dss_and_legacy_profiles_do_not_accept_each_others_source(observation_store):
    legacy, factory, generation, clock = observation_store
    dss = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    actual = dss_sample(generation, clock)
    with pytest.raises(ObservationConflictError):
        legacy.ingest_sample(actual, mode=GetTMMode.CURRENT, resynchronized=True)
    prior = sample(generation, sequence=1, engineering=28.0, observation_number=19002)
    with pytest.raises(ObservationConflictError):
        dss.ingest_sample(prior, mode=GetTMMode.CURRENT, resynchronized=True)
    result = dss.ingest_sample(actual, mode=GetTMMode.CURRENT, resynchronized=True)
    assert result["source_id"] == "dss-GENERIC"
    assert result["freshness"] == "FRESH"


def test_reset_invalidates_other_item_heads_and_retires_the_entire_previous_epoch(observation_store):
    _, factory, generation, clock = observation_store
    dss = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    bus = dss_sample(generation, clock)
    flag = dss_sample(generation, clock, item_id="TM.POWER.SAFE_MODE", number=19003)
    dss.ingest_sample(bus, mode=GetTMMode.CURRENT, resynchronized=True)
    dss.ingest_sample(flag, mode=GetTMMode.CURRENT, resynchronized=True)
    # Same receive timestamp deliberately proves ordering uses the durable stream,
    # not wall-clock precision or lexical sample hashes.
    new_bus = dss_sample(generation, clock, epoch="epoch-" + "b" * 64, number=19004)
    dss.ingest_sample(new_bus, mode=GetTMMode.CURRENT, resynchronized=True)
    heads = {item["item_id"]: item for item in dss.snapshot("simulator")["items"]}
    assert heads["TM.POWER.BUS_VOLTAGE"]["freshness"] == "FRESH"
    assert heads["TM.POWER.SAFE_MODE"]["freshness"] == "STALE"
    assert heads["TM.POWER.SAFE_MODE"]["synchronization_state"] == "GAPPED"
    late_old = dss_sample(generation, clock, sequence=2, number=19005)
    with pytest.raises(ObservationConflictError, match="retired"):
        dss.ingest_sample(late_old, mode=GetTMMode.CURRENT, resynchronized=True)


def test_dss_catalog_digest_cannot_be_substituted(observation_store):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, dss_enabled=True)
    actual = dss_sample(generation, clock)
    forged = replace(actual, item_identity=replace(actual.item_identity, catalog_digest="f" * 64))
    with pytest.raises(ObservationConflictError, match="shared immutable"):
        repository.ingest_sample(forged, mode=GetTMMode.CURRENT, resynchronized=True)
