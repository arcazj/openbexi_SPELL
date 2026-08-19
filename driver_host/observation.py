"""Deterministic read-only time and telemetry source for the bundled simulator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Tuple


CATALOG_ID = "bundled-simulator-telemetry"
CATALOG_KIND = "TELEMETRY"
CATALOG_REVISION = "v07-r1"
CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"
SOURCE_ID = "bundled-deterministic-simulator"
DEFAULT_TICK_NS = 50_000_000
DEFAULT_SIMULATOR_EPOCH_NS = 1_735_689_600_000_000_000
DEFAULT_CLOCK_UNCERTAINTY_NS = 1_000_000
MAX_CLOCK_UNCERTAINTY_NS = 60_000_000_000
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
UINT64_MAX = 2**64 - 1


class ScalarKind(str, Enum):
    BOOLEAN = "BOOLEAN"
    INT64 = "INT64"
    UINT64 = "UINT64"
    FINITE_DOUBLE = "FINITE_DOUBLE"
    STRING = "STRING"
    BYTES = "BYTES"


class ClockSource(str, Enum):
    SIMULATOR_GCS_TIME = "SIMULATOR_GCS_TIME"
    SIMULATOR = "SIMULATOR"
    HOST_FALLBACK = "HOST_FALLBACK"


class Validity(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class Quality(str, Enum):
    GOOD = "GOOD"
    SUSPECT = "SUSPECT"
    BAD = "BAD"
    UNKNOWN = "UNKNOWN"


class ObservationCode(str, Enum):
    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    CANCELLED = "CANCELLED"
    GAP = "GAP"
    STALE_GENERATION = "STALE_GENERATION"
    CLOCK_UNCERTAIN = "CLOCK_UNCERTAIN"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    INTERNAL = "INTERNAL"


@dataclass(frozen=True)
class ScalarValue:
    kind: ScalarKind
    value: bool | int | float | str | bytes


@dataclass(frozen=True)
class CatalogItem:
    item_id: str
    qualified_name: str
    raw_type: ScalarKind
    engineering_type: ScalarKind
    unit: str
    description: str


CATALOG_ITEMS = (
    CatalogItem(
        "TM.POWER.BUS_VOLTAGE",
        "SIM.POWER.BUS_VOLTAGE",
        ScalarKind.UINT64,
        ScalarKind.FINITE_DOUBLE,
        "V",
        "Synthetic DC bus voltage",
    ),
    CatalogItem(
        "TM.POWER.SAFE_MODE",
        "SIM.POWER.SAFE_MODE",
        ScalarKind.BOOLEAN,
        ScalarKind.BOOLEAN,
        "",
        "Synthetic safe-mode flag",
    ),
    CatalogItem(
        "TM.THERMAL.MODE",
        "SIM.THERMAL.MODE",
        ScalarKind.STRING,
        ScalarKind.STRING,
        "",
        "Synthetic thermal control mode",
    ),
)


def _catalog_material() -> dict[str, object]:
    return {
        "catalog_id": CATALOG_ID,
        "catalog_kind": CATALOG_KIND,
        "catalog_revision": CATALOG_REVISION,
        "items": [
            {
                "description": item.description,
                "engineering_type": item.engineering_type.value,
                "item_id": item.item_id,
                "qualified_name": item.qualified_name,
                "raw_type": item.raw_type.value,
                "unit": item.unit,
            }
            for item in CATALOG_ITEMS
        ],
    }


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


if _canonical_digest(_catalog_material()) != CATALOG_DIGEST:
    raise RuntimeError("bundled simulator telemetry catalog digest differs")


def source_epoch_for(driver_host_generation: str, source_instance_id: str) -> str:
    if not driver_host_generation or not source_instance_id:
        raise ValueError("source epoch inputs must be nonempty")
    material = {
        "driver_host_generation": driver_host_generation,
        "source_id": SOURCE_ID,
        "source_instance_id": source_instance_id,
    }
    return f"epoch-{_canonical_digest(material)}"


def sample_id_for(item_id: str, source_epoch: str, source_sequence: int) -> str:
    return _canonical_digest(
        {
            "item_id": item_id,
            "source_epoch": source_epoch,
            "source_id": SOURCE_ID,
            "source_sequence": str(source_sequence),
        }
    )


@dataclass(frozen=True)
class ClockReading:
    time_unix_ns: int
    acquired_at_unix_ns: int
    source: ClockSource
    provenance: str
    uncertainty_ns: int
    quality: Quality = Quality.GOOD
    validity: Validity = Validity.VALID


@dataclass(frozen=True)
class TelemetrySample:
    sample_id: str
    item: CatalogItem
    source_epoch: str
    source_sequence: int
    raw_value: ScalarValue
    engineering_value: ScalarValue
    acquired_at_unix_ns: int
    clock_provenance: str
    clock_uncertainty_ns: int
    validity: Validity = Validity.VALID
    quality: Quality = Quality.GOOD
    quality_reason: str = "deterministic-simulator"


@dataclass(frozen=True)
class Gap:
    source_epoch: str
    first_available_sequence: int
    last_available_sequence: int


class ObservationFailure(RuntimeError):
    def __init__(
        self,
        code: ObservationCode,
        message: str,
        *,
        retryable: bool = False,
        gap: Optional[Gap] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = retryable
        self.gap = gap


class SimulatorClock:
    """Typed simulator time with explicit host fallback provenance."""

    def __init__(
        self,
        *,
        source: ClockSource = ClockSource.SIMULATOR,
        simulator_epoch_ns: int = DEFAULT_SIMULATOR_EPOCH_NS,
        simulator_skew_ns: int = 0,
        uncertainty_ns: int = DEFAULT_CLOCK_UNCERTAINTY_NS,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        host_clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if type(source) is not ClockSource:
            raise ValueError("clock source must be typed")
        if type(simulator_epoch_ns) is not int or type(simulator_skew_ns) is not int:
            raise ValueError("simulator clock fields must be integers")
        if type(uncertainty_ns) is not int or uncertainty_ns < 0:
            raise ValueError("clock uncertainty must be a nonnegative integer")
        self.source = source
        self.simulator_epoch_ns = simulator_epoch_ns
        self.simulator_skew_ns = simulator_skew_ns
        self.uncertainty_ns = uncertainty_ns
        self._monotonic_ns = monotonic_ns
        self._host_clock_ns = host_clock_ns
        self._started_monotonic_ns = monotonic_ns()
        self._last_time_unix_ns: Optional[int] = None

    def read(self) -> ClockReading:
        if self.uncertainty_ns > MAX_CLOCK_UNCERTAINTY_NS:
            raise ObservationFailure(
                ObservationCode.CLOCK_UNCERTAIN,
                "clock uncertainty exceeds the simulator policy",
            )
        if self.source is ClockSource.HOST_FALLBACK:
            value = self._host_clock_ns()
            provenance = "explicit-host-clock-fallback"
        else:
            elapsed = self._monotonic_ns() - self._started_monotonic_ns
            value = self.simulator_epoch_ns + self.simulator_skew_ns + elapsed
            provenance = (
                "simulator-emulated-gcs-clock"
                if self.source is ClockSource.SIMULATOR_GCS_TIME
                else "bundled-deterministic-simulator-clock"
            )
        if type(value) is not int or not INT64_MIN <= value <= INT64_MAX:
            raise ObservationFailure(
                ObservationCode.CONTRACT_MISMATCH,
                "clock value is outside signed Unix nanoseconds",
            )
        if self._last_time_unix_ns is not None and value < self._last_time_unix_ns:
            raise ObservationFailure(
                ObservationCode.CLOCK_UNCERTAIN,
                "clock regression was detected",
            )
        if not provenance:
            raise ObservationFailure(
                ObservationCode.CONTRACT_MISMATCH,
                "clock provenance is unavailable",
            )
        self._last_time_unix_ns = value
        return ClockReading(
            time_unix_ns=value,
            acquired_at_unix_ns=value,
            source=self.source,
            provenance=provenance,
            uncertainty_ns=self.uncertainty_ns,
        )


class DeterministicObservationEngine:
    """Owns a single locked source sequence for all bundled telemetry items."""

    def __init__(
        self,
        driver_host_generation: str,
        *,
        clock: Optional[SimulatorClock] = None,
        tick_ns: int = DEFAULT_TICK_NS,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        deadline_clock_ns: Callable[[], int] = time.time_ns,
        source_instance_id: str | None = None,
    ) -> None:
        if type(tick_ns) is not int or not 1_000_000 <= tick_ns <= 10_000_000_000:
            raise ValueError("simulator tick is outside the bounded range")
        self.clock = clock or SimulatorClock(monotonic_ns=monotonic_ns)
        self.tick_ns = tick_ns
        self._monotonic_ns = monotonic_ns
        self._deadline_clock_ns = deadline_clock_ns
        self.source_instance_id = source_instance_id or uuid.uuid4().hex
        self.source_epoch = source_epoch_for(
            driver_host_generation, self.source_instance_id
        )
        self._catalog = {item.item_id: item for item in CATALOG_ITEMS}
        self._lock = asyncio.Lock()
        self._sequence = 1
        reading = self.clock.read()
        self._samples = self._build_samples(self._sequence, reading)
        self._next_tick_monotonic_ns = monotonic_ns() + tick_ns

    def get_time(self) -> ClockReading:
        return self.clock.read()

    @property
    def sequence(self) -> int:
        return self._sequence

    def _values(self, item_id: str, sequence: int) -> tuple[ScalarValue, ScalarValue]:
        index = (sequence - 1) % 6
        if item_id == "TM.POWER.BUS_VOLTAGE":
            raw = (28_000, 23_000, 21_000, 31_000, 33_000, 28_000)[index]
            return (
                ScalarValue(ScalarKind.UINT64, raw),
                ScalarValue(ScalarKind.FINITE_DOUBLE, raw / 1000.0),
            )
        if item_id == "TM.POWER.SAFE_MODE":
            value = (False, False, True, True, False, False)[index]
            return ScalarValue(ScalarKind.BOOLEAN, value), ScalarValue(
                ScalarKind.BOOLEAN, value
            )
        value = ("NOMINAL", "NOMINAL", "WARM", "WARM", "SAFE", "NOMINAL")[index]
        return ScalarValue(ScalarKind.STRING, value), ScalarValue(
            ScalarKind.STRING, value
        )

    def _build_samples(
        self, sequence: int, reading: ClockReading
    ) -> dict[str, TelemetrySample]:
        samples = {}
        for item in CATALOG_ITEMS:
            raw, engineering = self._values(item.item_id, sequence)
            samples[item.item_id] = TelemetrySample(
                sample_id=sample_id_for(item.item_id, self.source_epoch, sequence),
                item=item,
                source_epoch=self.source_epoch,
                source_sequence=sequence,
                raw_value=raw,
                engineering_value=engineering,
                acquired_at_unix_ns=reading.acquired_at_unix_ns,
                clock_provenance=reading.provenance,
                clock_uncertainty_ns=reading.uncertainty_ns,
                validity=reading.validity,
                quality=reading.quality,
            )
        return samples

    def _item(self, item_id: str) -> CatalogItem:
        try:
            return self._catalog[item_id]
        except KeyError as exc:
            raise ObservationFailure(
                ObservationCode.NOT_FOUND, "telemetry item was not found"
            ) from exc

    async def current(self, item_id: str) -> TelemetrySample:
        self._item(item_id)
        async with self._lock:
            try:
                return self._samples[item_id]
            except KeyError as exc:
                raise ObservationFailure(
                    ObservationCode.NOT_AVAILABLE,
                    "telemetry sample is not available",
                    retryable=True,
                ) from exc

    def _gap(self) -> ObservationFailure:
        return ObservationFailure(
            ObservationCode.GAP,
            "telemetry cursor is outside retained history",
            gap=Gap(self.source_epoch, self._sequence, self._sequence),
        )

    async def next(
        self,
        item_id: str,
        source_epoch: str,
        after_source_sequence: int,
        deadline_unix_ns: int,
    ) -> TelemetrySample:
        self._item(item_id)
        while True:
            async with self._lock:
                if source_epoch != self.source_epoch:
                    raise self._gap()
                if after_source_sequence < self._sequence:
                    if after_source_sequence + 1 != self._sequence:
                        raise self._gap()
                    return self._samples[item_id]
                if after_source_sequence > self._sequence:
                    raise self._gap()
                due = self._next_tick_monotonic_ns

            remaining_ns = deadline_unix_ns - self._deadline_clock_ns()
            if remaining_ns <= 0:
                raise ObservationFailure(
                    ObservationCode.DEADLINE_EXCEEDED,
                    "telemetry NEXT deadline elapsed",
                )
            delay_ns = max(0, due - self._monotonic_ns())
            if delay_ns >= remaining_ns:
                await asyncio.sleep(remaining_ns / 1_000_000_000)
                raise ObservationFailure(
                    ObservationCode.DEADLINE_EXCEEDED,
                    "telemetry NEXT deadline elapsed",
                )
            await asyncio.sleep(delay_ns / 1_000_000_000)

            async with self._lock:
                if (
                    self._sequence == after_source_sequence
                    and self._monotonic_ns() >= self._next_tick_monotonic_ns
                ):
                    if self._sequence >= UINT64_MAX:
                        raise ObservationFailure(
                            ObservationCode.CONTRACT_MISMATCH,
                            "telemetry source sequence overflowed",
                        )
                    self._sequence += 1
                    reading = self.clock.read()
                    self._samples = self._build_samples(self._sequence, reading)
                    self._next_tick_monotonic_ns = self._monotonic_ns() + self.tick_ns


__all__ = [
    "CATALOG_DIGEST",
    "CATALOG_ID",
    "CATALOG_ITEMS",
    "CATALOG_KIND",
    "CATALOG_REVISION",
    "ClockReading",
    "ClockSource",
    "DeterministicObservationEngine",
    "Gap",
    "ObservationCode",
    "ObservationFailure",
    "Quality",
    "SOURCE_ID",
    "ScalarKind",
    "ScalarValue",
    "SimulatorClock",
    "TelemetrySample",
    "Validity",
    "sample_id_for",
    "source_epoch_for",
]
