from __future__ import annotations

import pytest

from backend.condition_engine import (
    SampleEvidence,
    ScalarType,
    TypedScalar,
    ValueField,
    sample_id_for,
)
from backend.observation_catalog import (
    AlarmState,
    CatalogContractError,
    CatalogOperation,
    CatalogVisibility,
    Direction,
    LimitBand,
    LimitBandKind,
    LimitSet,
    MemoryRegionRecord,
    ObservationCatalog,
    ReadOutcome,
    ResourceRecord,
    TmTcRecord,
)
from driver_host.observation import CATALOG_DIGEST as DRIVER_TELEMETRY_CATALOG_DIGEST


def bands(*, inclusive: bool = False, hysteresis: float | None = None) -> tuple[LimitBand, ...]:
    def enabled(kind: LimitBandKind, threshold: float) -> LimitBand:
        return LimitBand(
            kind,
            True,
            TypedScalar(ScalarType.FINITE_DOUBLE, threshold),
            inclusive,
            (
                TypedScalar(ScalarType.FINITE_DOUBLE, hysteresis)
                if hysteresis is not None
                else None
            ),
        )

    return (
        enabled(LimitBandKind.HARD_LOW, 10.0),
        enabled(LimitBandKind.SOFT_LOW, 20.0),
        enabled(LimitBandKind.SOFT_HIGH, 80.0),
        enabled(LimitBandKind.HARD_HIGH, 90.0),
    )


def limit_set(**kwargs) -> LimitSet:
    return LimitSet(
        "limits.power",
        "TM.POWER",
        DRIVER_TELEMETRY_CATALOG_DIGEST,
        "revision-1",
        ValueField.ENGINEERING,
        ScalarType.FINITE_DOUBLE,
        "V",
        kwargs.pop("bands", bands()),
        **kwargs,
    )


def build_catalog(*, enabled_operations=tuple(CatalogOperation)) -> ObservationCatalog:
    return ObservationCatalog.build(
        catalog_id="bundled-simulator",
        catalog_kind="SIMULATOR",
        catalog_revision="revision-1",
        resources=(
            ResourceRecord(
                "RESOURCE.MODE",
                "CONFIGURATION",
                TypedScalar(ScalarType.STRING, "NOMINAL"),
                description="Simulator mode",
            ),
            ResourceRecord(
                "RESOURCE.COUNT",
                "CONFIGURATION",
                TypedScalar(ScalarType.UINT64, 3),
                "count",
                "Channel count",
            ),
        ),
        memory_regions=(
            MemoryRegionRecord("MEM.A", 0x1000, 0x100, ScalarType.UINT64, "Region A"),
            MemoryRegionRecord("MEM.B", 0x2000, 0x100, ScalarType.BYTES, "Region B"),
        ),
        tmtc_items=(
            TmTcRecord("TM.POWER", "SIM.POWER", Direction.TM, ScalarType.FINITE_DOUBLE, "V", "Power"),
            TmTcRecord("TC.RESET", "SIM.RESET", Direction.TC, ScalarType.BOOLEAN, "", "Reset metadata only"),
        ),
        limit_sets=(limit_set(),),
        enabled_operations=enabled_operations,
    )


def all_visible() -> CatalogVisibility:
    return CatalogVisibility(allow_all=True)


def pin(catalog: ObservationCatalog) -> dict[str, str]:
    return {
        "catalog_id": catalog.identity.catalog_id,
        "catalog_digest": catalog.identity.catalog_digest,
    }


def telemetry_sample(
    value: float,
    *,
    quality: str = "GOOD",
    validity: str = "VALID",
    freshness: str = "FRESH",
    synchronized: bool = True,
    has_gap: bool = False,
    catalog_digest: str,
) -> SampleEvidence:
    scalar = TypedScalar(ScalarType.FINITE_DOUBLE, value)
    return SampleEvidence(
        sample_id=sample_id_for("simulator", "epoch-1", "TM.POWER", 1),
        item_id="TM.POWER",
        catalog_digest=catalog_digest,
        source_id="simulator",
        source_epoch="epoch-1",
        source_sequence=1,
        snapshot_cursor=5,
        raw_value=scalar,
        engineering_value=scalar,
        unit="V",
        validity=validity,
        quality=quality,
        freshness=freshness,
        synchronized=synchronized,
        has_gap=has_gap,
    )


def test_catalog_digest_and_result_order_are_deterministic() -> None:
    first = build_catalog()
    second = ObservationCatalog.build(
        catalog_id=first.identity.catalog_id,
        catalog_kind=first.identity.catalog_kind,
        catalog_revision=first.identity.catalog_revision,
        resources=reversed(first.resources),
        memory_regions=reversed(first.memory_regions),
        tmtc_items=reversed(first.tmtc_items),
        limit_sets=first.limit_sets,
    )
    assert first.identity.catalog_digest == second.identity.catalog_digest
    assert len(first.identity.catalog_digest) == 64

    result = first.get_resource(
        **pin(first),
        resource_type="CONFIGURATION",
        resource_id="RESOURCE.COUNT",
        visibility=all_visible(),
    )
    assert result.outcome is ReadOutcome.OK
    assert result.as_dict()["entries"] == [
        {
            "resource_id": "RESOURCE.COUNT",
            "resource_type": "CONFIGURATION",
            "typed_value": {"type": "UINT64", "value": "3"},
            "unit": "count",
            "description": "Channel count",
            "catalog_revision": "revision-1",
            "catalog_digest": first.identity.catalog_digest,
        }
    ]


def test_resource_read_is_exact_digest_pinned_and_authorization_scoped() -> None:
    catalog = build_catalog()
    hidden = catalog.get_resource(
        **pin(catalog),
        resource_type="CONFIGURATION",
        resource_id="RESOURCE.MODE",
        visibility=CatalogVisibility(),
    )
    missing = catalog.get_resource(
        **pin(catalog),
        resource_type="CONFIGURATION",
        resource_id="RESOURCE.UNKNOWN",
        visibility=all_visible(),
    )
    wildcard = catalog.get_resource(
        **pin(catalog),
        resource_type="CONFIGURATION",
        resource_id="RESOURCE.*",
        visibility=all_visible(),
    )
    stale = catalog.get_resource(
        catalog_id=catalog.identity.catalog_id,
        catalog_digest="f" * 64,
        resource_type="CONFIGURATION",
        resource_id="RESOURCE.MODE",
        visibility=all_visible(),
    )
    assert hidden.outcome is missing.outcome is ReadOutcome.NOT_FOUND
    assert hidden.entries == missing.entries == ()
    assert wildcard.outcome is ReadOutcome.INVALID_ARGUMENT
    assert stale.outcome is ReadOutcome.STALE_CATALOG


def test_memory_reads_are_exact_checked_and_cannot_cross_regions() -> None:
    catalog = build_catalog()
    exact = catalog.memory_lookup_region(
        **pin(catalog),
        memory_region_id="MEM.A",
        maximum_entries=1,
        visibility=all_visible(),
    )
    bounded = catalog.memory_lookup_address(
        **pin(catalog),
        start_address=0x1080,
        length=0x10,
        maximum_entries=1,
        visibility=all_visible(),
    )
    crossing = catalog.memory_lookup_address(
        **pin(catalog),
        start_address=0x10F0,
        length=0x20,
        maximum_entries=1,
        visibility=all_visible(),
    )
    overflow = catalog.memory_lookup_address(
        **pin(catalog),
        start_address=2**64 - 1,
        length=2,
        maximum_entries=1,
        visibility=all_visible(),
    )
    assert exact.outcome is bounded.outcome is ReadOutcome.OK
    assert bounded.entries[0].memory_region_id == "MEM.A"
    assert crossing.outcome is ReadOutcome.INVALID_ARGUMENT
    assert crossing.reason == "CROSS_REGION_READ"
    assert overflow.outcome is ReadOutcome.INVALID_ARGUMENT
    assert overflow.reason == "ADDRESS_OVERFLOW"


def test_tmtc_lookup_has_no_wildcard_filter_or_direction_fallback() -> None:
    catalog = build_catalog()
    by_id = catalog.tmtc_lookup(
        **pin(catalog),
        direction=Direction.TM,
        item_id="TM.POWER",
        maximum_entries=1,
        visibility=all_visible(),
    )
    by_name = catalog.tmtc_lookup(
        **pin(catalog),
        direction="TC",
        qualified_name="SIM.RESET",
        maximum_entries=1,
        visibility=all_visible(),
    )
    wrong_direction = catalog.tmtc_lookup(
        **pin(catalog),
        direction="TC",
        item_id="TM.POWER",
        maximum_entries=1,
        visibility=all_visible(),
    )
    wildcard = catalog.tmtc_lookup(
        **pin(catalog),
        direction="TM",
        qualified_name="SIM.*",
        maximum_entries=128,
        visibility=all_visible(),
    )
    both = catalog.tmtc_lookup(
        **pin(catalog),
        direction="TM",
        item_id="TM.POWER",
        qualified_name="SIM.POWER",
        maximum_entries=1,
        visibility=all_visible(),
    )
    assert by_id.outcome is by_name.outcome is ReadOutcome.OK
    assert wrong_direction.outcome is ReadOutcome.NOT_FOUND
    assert wildcard.outcome is ReadOutcome.INVALID_ARGUMENT
    assert both.outcome is ReadOutcome.INVALID_ARGUMENT


def test_disabled_capability_is_typed_unsupported_and_has_no_partial_result() -> None:
    catalog = build_catalog(enabled_operations={CatalogOperation.GET_RESOURCE})
    result = catalog.memory_lookup_region(
        **pin(catalog),
        memory_region_id="MEM.A",
        maximum_entries=1,
        visibility=all_visible(),
    )
    assert result.outcome is ReadOutcome.UNSUPPORTED
    assert result.entries == ()


def test_limit_contract_requires_canonical_bands_types_and_order() -> None:
    disabled = LimitBand(LimitBandKind.HARD_LOW, False)
    assert disabled.canonical()["threshold"] is None
    with pytest.raises(CatalogContractError, match="disabled band cannot carry"):
        LimitBand(
            LimitBandKind.HARD_LOW,
            False,
            TypedScalar(ScalarType.FINITE_DOUBLE, 1.0),
        )
    unordered = list(bands())
    unordered[2] = LimitBand(
        LimitBandKind.SOFT_HIGH,
        True,
        TypedScalar(ScalarType.FINITE_DOUBLE, 15.0),
    )
    with pytest.raises(CatalogContractError, match="INVALID_LIMIT_ORDER"):
        limit_set(bands=tuple(unordered))
    with pytest.raises(CatalogContractError, match="canonical order"):
        limit_set(bands=tuple(reversed(bands())))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (5.0, AlarmState.CRITICAL_LOW),
        (15.0, AlarmState.WARNING_LOW),
        (50.0, AlarmState.NOT_ALARMED),
        (85.0, AlarmState.WARNING_HIGH),
        (95.0, AlarmState.CRITICAL_HIGH),
    ],
)
def test_is_alarmed_returns_deterministic_read_only_band_state(value, expected) -> None:
    catalog = build_catalog()
    result = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(value, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_000,
        visibility=all_visible(),
    )
    assert result.outcome is ReadOutcome.OK
    assert result.observation is not None
    assert result.observation.state is expected
    assert result.observation.boolean_projection is (expected is not AlarmState.NOT_ALARMED)
    assert result.observation.reason == "DETERMINISTIC_BAND_RESULT"


@pytest.mark.parametrize(
    ("sample_kwargs", "reason"),
    [
        ({"validity": "INVALID"}, "INVALID_OR_UNKNOWN_VALIDITY"),
        ({"quality": "BAD"}, "UNACCEPTABLE_QUALITY"),
        ({"freshness": "STALE"}, "STALE_OR_UNKNOWN_FRESHNESS"),
        ({"has_gap": True}, "GAPPED_OR_UNSYNCHRONIZED"),
        ({"synchronized": False}, "GAPPED_OR_UNSYNCHRONIZED"),
    ],
)
def test_alarm_quality_freshness_and_gap_matrix_is_indeterminate(sample_kwargs, reason) -> None:
    catalog = build_catalog()
    result = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(
            50.0,
            catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST,
            **sample_kwargs,
        ),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_000,
        visibility=all_visible(),
    )
    assert result.observation is not None
    assert result.observation.state is AlarmState.INDETERMINATE
    assert result.observation.boolean_projection is None
    assert result.observation.reason == reason
    assert result.observation.evaluated_value is None


def test_no_sample_disabled_limits_and_unit_mismatch_never_clear_an_alarm() -> None:
    catalog = build_catalog()
    no_sample = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=None,
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_000,
        visibility=all_visible(),
    )
    wrong_unit_sample = telemetry_sample(50.0, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST)
    wrong_unit_sample = SampleEvidence(**{**wrong_unit_sample.__dict__, "unit": "A"})
    wrong_unit = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=wrong_unit_sample,
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_001,
        visibility=all_visible(),
    )
    disabled_catalog = ObservationCatalog.build(
        catalog_id="bundled-simulator",
        catalog_kind="SIMULATOR",
        catalog_revision="revision-disabled",
        limit_sets=(limit_set(enabled=False),),
    )
    disabled = disabled_catalog.is_alarmed(
        **pin(disabled_catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(50.0, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_002,
        visibility=all_visible(),
    )
    assert no_sample.observation is not None
    assert no_sample.observation.state is AlarmState.INDETERMINATE
    assert no_sample.observation.reason == "NO_SAMPLE"
    assert wrong_unit.observation is not None
    assert wrong_unit.observation.reason == "UNIT_MISMATCH"
    assert disabled.observation is not None
    assert disabled.observation.reason == "LIMIT_SET_DISABLED"


def test_alarm_uses_the_limit_telemetry_digest_not_the_read_catalog_digest() -> None:
    catalog = build_catalog()
    assert catalog.identity.catalog_digest != DRIVER_TELEMETRY_CATALOG_DIGEST
    result = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(50.0, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=1_500,
        visibility=all_visible(),
    )
    assert result.outcome is ReadOutcome.OK
    assert result.observation is not None
    assert result.observation.state is AlarmState.NOT_ALARMED
    assert result.observation.reason == "DETERMINISTIC_BAND_RESULT"


def test_inclusive_boundary_and_hysteresis_are_revision_fields() -> None:
    catalog = ObservationCatalog.build(
        catalog_id="bounded-catalog",
        catalog_kind="SIMULATOR",
        catalog_revision="revision-inclusive",
        limit_sets=(limit_set(bands=bands(inclusive=True, hysteresis=2.0)),),
    )
    boundary = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(90.0, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=2_000,
        visibility=all_visible(),
    )
    retained = catalog.is_alarmed(
        **pin(catalog),
        item_id="TM.POWER",
        sample=telemetry_sample(89.0, catalog_digest=DRIVER_TELEMETRY_CATALOG_DIGEST),
        snapshot_cursor=5,
        evaluated_at_database_time_unix_ns=2_001,
        visibility=all_visible(),
        previous_state=AlarmState.CRITICAL_HIGH,
    )
    assert boundary.observation is not None
    assert boundary.observation.state is AlarmState.CRITICAL_HIGH
    assert retained.observation is not None
    assert retained.observation.state is AlarmState.CRITICAL_HIGH
    assert retained.observation.reason == "HYSTERESIS_RETAINED"
