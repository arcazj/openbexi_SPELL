from __future__ import annotations

from driver_host.observation import (
    CATALOG_DIGEST,
    CATALOG_ITEMS as DRIVER_CATALOG_ITEMS,
    SOURCE_ID,
)

from backend.bundled_observation_catalog import (
    CATALOG_ITEMS as BACKEND_CATALOG_ITEMS,
    build_bundled_observation_catalog,
    bundled_visibility,
)
from backend.condition_engine import (
    SampleEvidence,
    ScalarType,
    TypedScalar,
    sample_id_for,
)
from backend.observation_catalog import AlarmState, Direction, ReadOutcome


def test_bundled_catalog_is_deterministic_and_uses_the_driver_telemetry_digest() -> None:
    first = build_bundled_observation_catalog()
    second = build_bundled_observation_catalog()

    assert first.identity == second.identity
    assert [item.item_id for item in first.tmtc_items] == [
        "TM.POWER.BUS_VOLTAGE",
        "TM.POWER.SAFE_MODE",
        "TM.THERMAL.MODE",
        "TC.SIMULATOR.RESET",
    ]
    assert first.limit_sets[0].telemetry_catalog_digest == CATALOG_DIGEST
    assert [
        (
            item.item_id,
            item.qualified_name,
            item.engineering_type,
            item.unit,
            item.description,
        )
        for item in BACKEND_CATALOG_ITEMS
    ] == [
        (
            item.item_id,
            item.qualified_name,
            item.engineering_type.value,
            item.unit,
            item.description,
        )
        for item in DRIVER_CATALOG_ITEMS
    ]


def test_bundled_reads_are_exact_bounded_and_read_only() -> None:
    catalog = build_bundled_observation_catalog()
    identity = catalog.identity
    visibility = bundled_visibility()

    resource = catalog.get_resource(
        catalog_id=identity.catalog_id,
        catalog_digest=identity.catalog_digest,
        resource_type="CONFIGURATION",
        resource_id="SIMULATOR.MODE",
        visibility=visibility,
    )
    lookup = catalog.tmtc_lookup(
        catalog_id=identity.catalog_id,
        catalog_digest=identity.catalog_digest,
        direction=Direction.TM,
        item_id="TM.POWER.BUS_VOLTAGE",
        maximum_entries=1,
        visibility=visibility,
    )

    assert resource.outcome is ReadOutcome.OK
    assert resource.entries[0].typed_value == TypedScalar(
        ScalarType.STRING, "DETERMINISTIC_READ_ONLY"
    )
    assert lookup.outcome is ReadOutcome.OK
    assert lookup.entries[0].qualified_name == "SIM.POWER.BUS_VOLTAGE"
    assert not hasattr(catalog, "write")
    assert not hasattr(catalog, "dispatch")


def test_real_driver_sample_can_be_evaluated_against_bundled_limits() -> None:
    catalog = build_bundled_observation_catalog()
    source_epoch = "epoch-driver-v07"
    item_id = "TM.POWER.BUS_VOLTAGE"
    sample = SampleEvidence(
        sample_id=sample_id_for(SOURCE_ID, source_epoch, item_id, 1),
        item_id=item_id,
        catalog_digest=CATALOG_DIGEST,
        source_id=SOURCE_ID,
        source_epoch=source_epoch,
        source_sequence=1,
        snapshot_cursor=7,
        raw_value=TypedScalar(ScalarType.UINT64, 22000),
        engineering_value=TypedScalar(ScalarType.FINITE_DOUBLE, 28.0),
        unit="V",
        validity="VALID",
        quality="GOOD",
        freshness="FRESH",
    )

    result = catalog.is_alarmed(
        catalog_id=catalog.identity.catalog_id,
        catalog_digest=catalog.identity.catalog_digest,
        item_id=item_id,
        sample=sample,
        snapshot_cursor=7,
        evaluated_at_database_time_unix_ns=1_735_689_600_000_000_000,
        visibility=bundled_visibility(),
    )

    assert result.outcome is ReadOutcome.OK
    assert result.observation is not None
    assert result.observation.state is AlarmState.NOT_ALARMED
    assert result.observation.sample_id == sample.sample_id
