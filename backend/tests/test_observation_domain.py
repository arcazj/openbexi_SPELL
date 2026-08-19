from __future__ import annotations

import math

import pytest

from backend.driver_domain import GenerationTuple
from backend.observation_domain import (
    ClockSource,
    DriverTelemetrySample,
    DriverTimeObservation,
    GetTMMode,
    GetTMQuery,
    ItemIdentity,
    Quality,
    SampleIdentity,
    ScalarKind,
    ScalarValue,
    Validity,
    sample_id_for,
)


HOST_DIGEST = "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"


def generations(*, context: bool = False) -> GenerationTuple:
    return GenerationTuple(
        server_profile_id="local-synthetic",
        driver_host_generation="host-generation-1",
        host_profile_digest=HOST_DIGEST,
        context_id="context-1" if context else "",
        context_generation="context-generation-1" if context else "",
        context_binding_digest="a" * 64 if context else "",
    )


def test_scalar_values_have_exact_types_and_canonical_json_encodings() -> None:
    values = (
        (ScalarValue(ScalarKind.BOOLEAN, False), False),
        (ScalarValue(ScalarKind.INT64, -(2**63)), str(-(2**63))),
        (ScalarValue(ScalarKind.UINT64, 2**64 - 1), str(2**64 - 1)),
        (ScalarValue(ScalarKind.FINITE_DOUBLE, 28.0), 28.0),
        (ScalarValue(ScalarKind.STRING, "NOMINAL"), "NOMINAL"),
        (ScalarValue(ScalarKind.BYTES, b"\x00\xff"), "AP8="),
    )
    assert [value.canonical_json_value() for value, _ in values] == [
        expected for _, expected in values
    ]
    assert len({value.digest for value, _ in values}) == len(values)

    for invalid in (
        lambda: ScalarValue(ScalarKind.BOOLEAN, 0),
        lambda: ScalarValue(ScalarKind.INT64, True),
        lambda: ScalarValue(ScalarKind.UINT64, -1),
        lambda: ScalarValue(ScalarKind.FINITE_DOUBLE, math.nan),
        lambda: ScalarValue(ScalarKind.FINITE_DOUBLE, math.inf),
        lambda: ScalarValue(ScalarKind.STRING, "x" * 4097),
        lambda: ScalarValue(ScalarKind.BYTES, b"x" * 4097),
    ):
        with pytest.raises(ValueError):
            invalid()


def test_sample_identity_and_driver_authored_objects_are_strict() -> None:
    source_id = "bundled-deterministic-simulator"
    source_epoch = "epoch-" + "b" * 64
    item_id = "TM.POWER.BUS_VOLTAGE"
    identity = SampleIdentity(
        sample_id_for(source_id, source_epoch, item_id, 1),
        item_id,
        source_id,
        source_epoch,
        1,
    )
    item = ItemIdentity(item_id, "SIM.POWER.BUS_VOLTAGE", CATALOG_DIGEST)
    sample = DriverTelemetrySample(
        observation_id="observation-1",
        generations=generations(context=True),
        sample_identity=identity,
        item_identity=item,
        raw_value=ScalarValue(ScalarKind.UINT64, 28_000),
        engineering_value=ScalarValue(ScalarKind.FINITE_DOUBLE, 28.0),
        description="Synthetic DC bus voltage",
        unit="V",
        acquired_at_unix_ns=1_735_689_600_000_000_000,
        source="SIMULATOR",
        clock_provenance="bundled-deterministic-simulator-clock",
        clock_uncertainty_ns=1_000_000,
        validity=Validity.VALID,
        quality=Quality.GOOD,
        quality_reason="deterministic-simulator",
    )
    assert sample.sample_identity.source_sequence == 1
    assert not hasattr(sample, "received_at_unix_ns")
    assert not hasattr(sample, "freshness")

    time_value = DriverTimeObservation(
        "time-1",
        generations(),
        1,
        1,
        ClockSource.SIMULATOR,
        "bundled-deterministic-simulator-clock",
        1,
        Quality.GOOD,
        Validity.VALID,
    )
    assert not hasattr(time_value, "received_at_unix_ns")
    with pytest.raises(ValueError, match="sample_id"):
        SampleIdentity("0" * 64, item_id, source_id, source_epoch, 1)


def test_get_tm_query_modes_are_not_coercible_or_ambiguous() -> None:
    common = {
        "observation_id": "observation-1",
        "generations": generations(context=True),
        "correlation_id": "correlation-1",
        "deadline_unix_ns": 2_000_000_000,
        "item_id": "TM.POWER.BUS_VOLTAGE",
    }
    assert GetTMQuery(**common, mode=GetTMMode.CURRENT).after_source_sequence == 0
    assert GetTMQuery(
        **common,
        mode=GetTMMode.NEXT,
        source_epoch="epoch-" + "b" * 64,
        after_source_sequence=1,
    ).mode is GetTMMode.NEXT
    with pytest.raises(ValueError, match="CURRENT"):
        GetTMQuery(
            **common,
            mode=GetTMMode.CURRENT,
            source_epoch="epoch-" + "b" * 64,
        )
    with pytest.raises(ValueError, match="mode"):
        GetTMQuery(**common, mode="NEXT")  # type: ignore[arg-type]
