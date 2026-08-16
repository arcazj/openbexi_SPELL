"""Immutable read-only metadata used by the v0.7 bundled simulator."""

from __future__ import annotations

from dataclasses import dataclass

from .condition_engine import ScalarType, TypedScalar, ValueField
from .observation_catalog import (
    CatalogVisibility,
    Direction,
    LimitBand,
    LimitBandKind,
    LimitSet,
    MemoryRegionRecord,
    ObservationCatalog,
    ResourceRecord,
    TmTcRecord,
)


POLICY_ID = "simulator-default"
POLICY_REVISION = "v07-r1"
CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"


@dataclass(frozen=True)
class _TelemetryItem:
    item_id: str
    qualified_name: str
    raw_type: str
    engineering_type: str
    unit: str
    description: str


CATALOG_ITEMS = (
    _TelemetryItem(
        "TM.POWER.BUS_VOLTAGE",
        "SIM.POWER.BUS_VOLTAGE",
        "UINT64",
        "FINITE_DOUBLE",
        "V",
        "Synthetic DC bus voltage",
    ),
    _TelemetryItem(
        "TM.POWER.SAFE_MODE",
        "SIM.POWER.SAFE_MODE",
        "BOOLEAN",
        "BOOLEAN",
        "",
        "Synthetic safe-mode flag",
    ),
    _TelemetryItem(
        "TM.THERMAL.MODE",
        "SIM.THERMAL.MODE",
        "STRING",
        "STRING",
        "",
        "Synthetic thermal control mode",
    ),
)

_SCALAR_TYPES = {
    "BOOLEAN": ScalarType.BOOLEAN,
    "INT64": ScalarType.INT64,
    "UINT64": ScalarType.UINT64,
    "FINITE_DOUBLE": ScalarType.FINITE_DOUBLE,
    "STRING": ScalarType.STRING,
    "BYTES": ScalarType.BYTES,
}


def _threshold(kind: LimitBandKind, value: float) -> LimitBand:
    return LimitBand(
        band=kind,
        enabled=True,
        threshold=TypedScalar(ScalarType.FINITE_DOUBLE, value),
        inclusive=False,
        hysteresis=TypedScalar(ScalarType.FINITE_DOUBLE, 0.0),
    )


def build_bundled_observation_catalog() -> ObservationCatalog:
    """Build the finite catalog from constants shipped in the product image."""

    telemetry = tuple(
        TmTcRecord(
            item_id=item.item_id,
            qualified_name=item.qualified_name,
            direction=Direction.TM,
            value_type=_SCALAR_TYPES[item.engineering_type],
            unit=item.unit,
            description=item.description,
        )
        for item in CATALOG_ITEMS
    )
    return ObservationCatalog.build(
        catalog_id="bundled-observation-reads",
        catalog_kind="SIMULATOR",
        catalog_revision="v07-r1",
        resources=(
            ResourceRecord(
                resource_id="SIMULATOR.MODE",
                resource_type="CONFIGURATION",
                typed_value=TypedScalar(ScalarType.STRING, "DETERMINISTIC_READ_ONLY"),
                description="Bundled simulator observation mode",
            ),
            ResourceRecord(
                resource_id="SIMULATOR.TELEMETRY_ITEM_COUNT",
                resource_type="CAPACITY",
                typed_value=TypedScalar(ScalarType.UINT64, len(CATALOG_ITEMS)),
                unit="items",
                description="Finite bundled telemetry item count",
            ),
        ),
        memory_regions=(
            MemoryRegionRecord(
                memory_region_id="SIMULATOR.CONFIGURATION",
                start_address=0x1000,
                length=0x100,
                value_type=ScalarType.UINT64,
                description="Synthetic configuration metadata region",
            ),
            MemoryRegionRecord(
                memory_region_id="SIMULATOR.TELEMETRY",
                start_address=0x2000,
                length=0x200,
                value_type=ScalarType.BYTES,
                description="Synthetic telemetry metadata region",
            ),
        ),
        tmtc_items=(
            *telemetry,
            TmTcRecord(
                item_id="TC.SIMULATOR.RESET",
                qualified_name="SIM.CONTROL.RESET",
                direction=Direction.TC,
                value_type=ScalarType.BOOLEAN,
                unit="",
                description="Read-only telecommand metadata; dispatch is unavailable",
            ),
        ),
        limit_sets=(
            LimitSet(
                limit_set_id="LIMIT.TM.POWER.BUS_VOLTAGE",
                item_id="TM.POWER.BUS_VOLTAGE",
                telemetry_catalog_digest=CATALOG_DIGEST,
                limit_revision="v07-r1",
                value_domain=ValueField.ENGINEERING,
                value_type=ScalarType.FINITE_DOUBLE,
                unit="V",
                bands=(
                    _threshold(LimitBandKind.HARD_LOW, 22.0),
                    _threshold(LimitBandKind.SOFT_LOW, 24.0),
                    _threshold(LimitBandKind.SOFT_HIGH, 30.0),
                    _threshold(LimitBandKind.HARD_HIGH, 32.0),
                ),
            ),
        ),
    )


def bundled_visibility() -> CatalogVisibility:
    """All authenticated local simulator roles share the explicit finite view."""

    return CatalogVisibility(allow_all=True)


__all__ = [
    "POLICY_ID",
    "POLICY_REVISION",
    "build_bundled_observation_catalog",
    "bundled_visibility",
]
