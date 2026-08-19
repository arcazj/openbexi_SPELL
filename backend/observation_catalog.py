"""Immutable deterministic simulator catalogs and read-only alarm semantics."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Iterable, Mapping, TypeAlias

from .condition_engine import (
    NUMERIC_TYPES,
    SampleEvidence,
    ScalarType,
    TypedScalar,
    ValueField,
)


MAX_CATALOG_ENTRIES = 128
MAX_RESPONSE_BYTES = 65_536
MAX_DESCRIPTION_BYTES = 4_096
MAX_UNIT_BYTES = 256
UINT64_LIMIT = 2**64

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_QUALIFIED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CatalogContractError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class ReadOutcome(str, Enum):
    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    STALE_CATALOG = "STALE_CATALOG"
    BOUND_EXCEEDED = "BOUND_EXCEEDED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    INTERNAL = "INTERNAL"


class CatalogOperation(str, Enum):
    GET_RESOURCE = "GetResource"
    MEMORY_LOOKUP = "MemoryLookup"
    TMTC_LOOKUP = "TMTCLookup"
    GET_LIMITS = "GetLimits"
    IS_ALARMED = "IsAlarmed"


class Direction(str, Enum):
    TM = "TM"
    TC = "TC"


class LimitBandKind(str, Enum):
    HARD_LOW = "HARD_LOW"
    SOFT_LOW = "SOFT_LOW"
    SOFT_HIGH = "SOFT_HIGH"
    HARD_HIGH = "HARD_HIGH"


class AlarmState(str, Enum):
    NOT_ALARMED = "NOT_ALARMED"
    WARNING_LOW = "WARNING_LOW"
    WARNING_HIGH = "WARNING_HIGH"
    CRITICAL_LOW = "CRITICAL_LOW"
    CRITICAL_HIGH = "CRITICAL_HIGH"
    INDETERMINATE = "INDETERMINATE"


_ALARM_SEVERITY = {
    AlarmState.NOT_ALARMED: "NONE",
    AlarmState.WARNING_LOW: "WARNING",
    AlarmState.WARNING_HIGH: "WARNING",
    AlarmState.CRITICAL_LOW: "CRITICAL",
    AlarmState.CRITICAL_HIGH: "CRITICAL",
    AlarmState.INDETERMINATE: "INDETERMINATE",
}


def _raise(code: str, path: str, message: str) -> None:
    raise CatalogContractError(code, path, message)


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _raise("INVALID_IDENTIFIER", path, "must be a bounded ASCII identifier")
    return value


def _qualified_name(value: Any, path: str) -> str:
    if not isinstance(value, str) or _QUALIFIED_NAME.fullmatch(value) is None:
        _raise("INVALID_QUALIFIED_NAME", path, "must be an exact bounded qualified name")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _raise("INVALID_DIGEST", path, "must be a lowercase SHA-256 digest")
    return value


def _bounded_text(value: Any, path: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        _raise("BOUND_EXCEEDED", path, "must be bounded UTF-8 text")
    return value


def _nonnegative_int(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        _raise("INVALID_ARGUMENT", path, "must be a nonnegative integer")
    return value


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CatalogIdentity:
    catalog_id: str
    catalog_kind: str
    catalog_revision: str
    catalog_digest: str

    def __post_init__(self) -> None:
        _identifier(self.catalog_id, "catalog.catalog_id")
        _identifier(self.catalog_kind, "catalog.catalog_kind")
        _identifier(self.catalog_revision, "catalog.catalog_revision")
        _digest(self.catalog_digest, "catalog.catalog_digest")

    def as_dict(self) -> dict[str, str]:
        return {
            "catalog_id": self.catalog_id,
            "catalog_kind": self.catalog_kind,
            "catalog_revision": self.catalog_revision,
            "catalog_digest": self.catalog_digest,
        }


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    resource_type: str
    typed_value: TypedScalar
    unit: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "resource.resource_id")
        _identifier(self.resource_type, "resource.resource_type")
        _bounded_text(self.unit, "resource.unit", MAX_UNIT_BYTES)
        _bounded_text(self.description, "resource.description", MAX_DESCRIPTION_BYTES)

    def canonical(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "typed_value": self.typed_value.as_dict(),
            "unit": self.unit,
            "description": self.description,
        }

    def as_result(self, identity: CatalogIdentity) -> dict[str, Any]:
        return {**self.canonical(), "catalog_revision": identity.catalog_revision, "catalog_digest": identity.catalog_digest}


@dataclass(frozen=True)
class MemoryRegionRecord:
    memory_region_id: str
    start_address: int
    length: int
    value_type: ScalarType
    description: str = ""

    def __post_init__(self) -> None:
        _identifier(self.memory_region_id, "memory.memory_region_id")
        _nonnegative_int(self.start_address, "memory.start_address")
        _nonnegative_int(self.length, "memory.length")
        if self.length == 0:
            _raise("INVALID_ARGUMENT", "memory.length", "must be greater than zero")
        if self.start_address >= UINT64_LIMIT or self.length >= UINT64_LIMIT:
            _raise("ADDRESS_OVERFLOW", "memory", "address or length exceeds UINT64")
        if self.start_address + self.length > UINT64_LIMIT:
            _raise("ADDRESS_OVERFLOW", "memory", "address range wraps UINT64")
        _bounded_text(self.description, "memory.description", MAX_DESCRIPTION_BYTES)

    @property
    def end_address(self) -> int:
        return self.start_address + self.length

    def canonical(self) -> dict[str, Any]:
        return {
            "memory_region_id": self.memory_region_id,
            "start_address": str(self.start_address),
            "length": str(self.length),
            "value_type": self.value_type.value,
            "description": self.description,
        }

    def as_result(self, identity: CatalogIdentity) -> dict[str, Any]:
        return {**self.canonical(), "catalog_revision": identity.catalog_revision, "catalog_digest": identity.catalog_digest}


@dataclass(frozen=True)
class TmTcRecord:
    item_id: str
    qualified_name: str
    direction: Direction
    value_type: ScalarType
    unit: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        _identifier(self.item_id, "tmtc.item_id")
        _qualified_name(self.qualified_name, "tmtc.qualified_name")
        _bounded_text(self.unit, "tmtc.unit", MAX_UNIT_BYTES)
        _bounded_text(self.description, "tmtc.description", MAX_DESCRIPTION_BYTES)

    def canonical(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "qualified_name": self.qualified_name,
            "direction": self.direction.value,
            "value_type": self.value_type.value,
            "unit": self.unit,
            "description": self.description,
        }

    def as_result(self, identity: CatalogIdentity) -> dict[str, Any]:
        return {**self.canonical(), "catalog_revision": identity.catalog_revision, "catalog_digest": identity.catalog_digest}


@dataclass(frozen=True)
class LimitBand:
    band: LimitBandKind
    enabled: bool
    threshold: TypedScalar | None = None
    inclusive: bool = False
    hysteresis: TypedScalar | None = None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(self.inclusive) is not bool:
            _raise("TYPE_MISMATCH", "limit_band", "enabled and inclusive must be boolean")
        if self.enabled and self.threshold is None:
            _raise("MISSING_FIELD", self.band.value, "enabled band requires a threshold")
        if not self.enabled and (self.threshold is not None or self.hysteresis is not None):
            _raise("INVALID_ARGUMENT", self.band.value, "disabled band cannot carry threshold data")
        if self.threshold is not None and self.threshold.scalar_type not in NUMERIC_TYPES:
            _raise("TYPE_MISMATCH", self.band.value, "threshold must be numeric")
        if self.hysteresis is not None:
            if self.hysteresis.scalar_type not in NUMERIC_TYPES or self.hysteresis.numeric() < 0:
                _raise("INVALID_ARGUMENT", self.band.value, "hysteresis must be finite and nonnegative")

    def canonical(self) -> dict[str, Any]:
        return {
            "band": self.band.value,
            "enabled": self.enabled,
            "threshold": self.threshold.as_dict() if self.threshold else None,
            "inclusive": self.inclusive,
            "hysteresis": self.hysteresis.as_dict() if self.hysteresis else None,
        }


@dataclass(frozen=True)
class LimitSet:
    limit_set_id: str
    item_id: str
    telemetry_catalog_digest: str
    limit_revision: str
    value_domain: ValueField
    value_type: ScalarType
    unit: str
    bands: tuple[LimitBand, ...]
    enabled: bool = True

    def __post_init__(self) -> None:
        _identifier(self.limit_set_id, "limits.limit_set_id")
        _identifier(self.item_id, "limits.item_id")
        _digest(self.telemetry_catalog_digest, "limits.telemetry_catalog_digest")
        _identifier(self.limit_revision, "limits.limit_revision")
        _bounded_text(self.unit, "limits.unit", MAX_UNIT_BYTES)
        if type(self.enabled) is not bool:
            _raise("TYPE_MISMATCH", "limits.enabled", "must be boolean")
        if self.value_type not in NUMERIC_TYPES:
            _raise("TYPE_MISMATCH", "limits.value_type", "v0.7 alarm bands require numeric values")
        expected = tuple(LimitBandKind)
        actual = tuple(band.band for band in self.bands)
        if actual != expected:
            _raise("CONTRACT_MISMATCH", "limits.bands", "all four bands must appear in canonical order")
        enabled_values: list[Decimal] = []
        for band in self.bands:
            if not band.enabled:
                continue
            assert band.threshold is not None
            if band.threshold.scalar_type is not self.value_type:
                _raise("TYPE_MISMATCH", band.band.value, "threshold type must match the limit value type")
            if band.hysteresis and band.hysteresis.scalar_type is not self.value_type:
                _raise("TYPE_MISMATCH", band.band.value, "hysteresis type must match the limit value type")
            enabled_values.append(band.threshold.numeric())
        if any(left > right for left, right in zip(enabled_values, enabled_values[1:])):
            _raise("INVALID_LIMIT_ORDER", "limits.bands", "enabled thresholds are not ordered")

    def band(self, kind: LimitBandKind) -> LimitBand:
        return self.bands[tuple(LimitBandKind).index(kind)]

    def canonical(self) -> dict[str, Any]:
        return {
            "limit_set_id": self.limit_set_id,
            "item_id": self.item_id,
            "telemetry_catalog_digest": self.telemetry_catalog_digest,
            "limit_revision": self.limit_revision,
            "value_domain": self.value_domain.value,
            "value_type": self.value_type.value,
            "unit": self.unit,
            "enabled": self.enabled,
            "bands": [band.canonical() for band in self.bands],
        }

    def as_result(self, identity: CatalogIdentity) -> dict[str, Any]:
        return {**self.canonical(), "catalog_digest": identity.catalog_digest}


CatalogEntry: TypeAlias = ResourceRecord | MemoryRegionRecord | TmTcRecord | LimitSet


@dataclass(frozen=True)
class CatalogVisibility:
    resource_ids: frozenset[str] = frozenset()
    memory_region_ids: frozenset[str] = frozenset()
    tmtc_item_ids: frozenset[str] = frozenset()
    limit_item_ids: frozenset[str] = frozenset()
    allow_all: bool = False

    def __post_init__(self) -> None:
        for group_name in (
            "resource_ids",
            "memory_region_ids",
            "tmtc_item_ids",
            "limit_item_ids",
        ):
            for value in getattr(self, group_name):
                _identifier(value, f"visibility.{group_name}")
        if type(self.allow_all) is not bool:
            _raise("TYPE_MISMATCH", "visibility.allow_all", "must be boolean")

    def permits(self, group: str, item_id: str) -> bool:
        return self.allow_all or item_id in getattr(self, group)


@dataclass(frozen=True)
class CatalogReadResult:
    operation: CatalogOperation
    outcome: ReadOutcome
    catalog_identity: CatalogIdentity
    entries: tuple[CatalogEntry, ...] = ()
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation.value,
            "outcome": self.outcome.value,
            "catalog_identity": self.catalog_identity.as_dict(),
            "entries": [entry.as_result(self.catalog_identity) for entry in self.entries],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AlarmObservation:
    alarm_observation_id: str
    item_id: str
    sample_id: str | None
    limit_set_id: str
    limit_revision: str
    state: AlarmState
    severity: str
    evaluated_value: TypedScalar | None
    quality: str
    validity: str
    freshness: str
    snapshot_cursor: int
    evaluated_at_database_time_unix_ns: int
    reason: str

    @property
    def boolean_projection(self) -> bool | None:
        if self.state is AlarmState.INDETERMINATE:
            return None
        return self.state is not AlarmState.NOT_ALARMED

    def as_dict(self) -> dict[str, Any]:
        return {
            "alarm_observation_id": self.alarm_observation_id,
            "item_id": self.item_id,
            "sample_id": self.sample_id,
            "limit_set_id": self.limit_set_id,
            "limit_revision": self.limit_revision,
            "state": self.state.value,
            "severity": self.severity,
            "evaluated_engineering_value": (
                self.evaluated_value.as_dict() if self.evaluated_value else None
            ),
            "quality": self.quality,
            "validity": self.validity,
            "freshness": self.freshness,
            "snapshot_cursor": self.snapshot_cursor,
            "evaluated_at_database_time_unix_ns": self.evaluated_at_database_time_unix_ns,
            "reason": self.reason,
            "boolean_projection": self.boolean_projection,
        }


@dataclass(frozen=True)
class AlarmReadResult:
    outcome: ReadOutcome
    catalog_identity: CatalogIdentity
    observation: AlarmObservation | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": CatalogOperation.IS_ALARMED.value,
            "outcome": self.outcome.value,
            "catalog_identity": self.catalog_identity.as_dict(),
            "observation": self.observation.as_dict() if self.observation else None,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ObservationCatalog:
    identity: CatalogIdentity
    resources: tuple[ResourceRecord, ...] = ()
    memory_regions: tuple[MemoryRegionRecord, ...] = ()
    tmtc_items: tuple[TmTcRecord, ...] = ()
    limit_sets: tuple[LimitSet, ...] = ()
    enabled_operations: frozenset[CatalogOperation] = frozenset(CatalogOperation)
    _canonical_payload: Mapping[str, Any] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name, entries, key in (
            ("resources", self.resources, lambda item: (item.resource_type, item.resource_id)),
            ("memory_regions", self.memory_regions, lambda item: item.memory_region_id),
            ("tmtc_items", self.tmtc_items, lambda item: item.item_id),
            ("limit_sets", self.limit_sets, lambda item: item.item_id),
        ):
            if len(entries) > MAX_CATALOG_ENTRIES:
                _raise("BOUND_EXCEEDED", name, f"catalog section exceeds {MAX_CATALOG_ENTRIES} entries")
            identities = [key(item) for item in entries]
            if len(identities) != len(set(identities)):
                _raise("DUPLICATE_IDENTITY", name, "catalog identities must be unique")
        qualified_names = [item.qualified_name for item in self.tmtc_items]
        if len(qualified_names) != len(set(qualified_names)):
            _raise("DUPLICATE_IDENTITY", "tmtc_items", "qualified names must be unique")
        sorted_sections = {
            "resources": sorted((item.canonical() for item in self.resources), key=lambda item: (item["resource_type"], item["resource_id"])),
            "memory_regions": sorted((item.canonical() for item in self.memory_regions), key=lambda item: item["memory_region_id"]),
            "tmtc_items": sorted((item.canonical() for item in self.tmtc_items), key=lambda item: item["item_id"]),
            "limit_sets": sorted((item.canonical() for item in self.limit_sets), key=lambda item: item["item_id"]),
        }
        payload = {
            "schema_version": "spell.v07.observation-catalog/1",
            "catalog_id": self.identity.catalog_id,
            "catalog_kind": self.identity.catalog_kind,
            "catalog_revision": self.identity.catalog_revision,
            **sorted_sections,
        }
        if _canonical_digest(payload) != self.identity.catalog_digest:
            _raise("CONTRACT_MISMATCH", "catalog.catalog_digest", "catalog content does not match its digest")
        object.__setattr__(self, "_canonical_payload", payload)

    @classmethod
    def build(
        cls,
        *,
        catalog_id: str,
        catalog_kind: str,
        catalog_revision: str,
        resources: Iterable[ResourceRecord] = (),
        memory_regions: Iterable[MemoryRegionRecord] = (),
        tmtc_items: Iterable[TmTcRecord] = (),
        limit_sets: Iterable[LimitSet] = (),
        enabled_operations: Iterable[CatalogOperation] = tuple(CatalogOperation),
    ) -> "ObservationCatalog":
        catalog_id = _identifier(catalog_id, "catalog.catalog_id")
        catalog_kind = _identifier(catalog_kind, "catalog.catalog_kind")
        catalog_revision = _identifier(catalog_revision, "catalog.catalog_revision")
        resource_tuple = tuple(resources)
        memory_tuple = tuple(memory_regions)
        tmtc_tuple = tuple(tmtc_items)
        limit_tuple = tuple(limit_sets)
        payload = {
            "schema_version": "spell.v07.observation-catalog/1",
            "catalog_id": catalog_id,
            "catalog_kind": catalog_kind,
            "catalog_revision": catalog_revision,
            "resources": sorted((item.canonical() for item in resource_tuple), key=lambda item: (item["resource_type"], item["resource_id"])),
            "memory_regions": sorted((item.canonical() for item in memory_tuple), key=lambda item: item["memory_region_id"]),
            "tmtc_items": sorted((item.canonical() for item in tmtc_tuple), key=lambda item: item["item_id"]),
            "limit_sets": sorted((item.canonical() for item in limit_tuple), key=lambda item: item["item_id"]),
        }
        identity = CatalogIdentity(
            catalog_id=catalog_id,
            catalog_kind=catalog_kind,
            catalog_revision=catalog_revision,
            catalog_digest=_canonical_digest(payload),
        )
        return cls(
            identity=identity,
            resources=resource_tuple,
            memory_regions=memory_tuple,
            tmtc_items=tmtc_tuple,
            limit_sets=limit_tuple,
            enabled_operations=frozenset(enabled_operations),
        )

    def _result(
        self,
        operation: CatalogOperation,
        outcome: ReadOutcome,
        entries: tuple[CatalogEntry, ...] = (),
        reason: str = "",
    ) -> CatalogReadResult:
        result = CatalogReadResult(operation, outcome, self.identity, entries, reason)
        if outcome is ReadOutcome.OK:
            encoded = json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(encoded) > MAX_RESPONSE_BYTES:
                return CatalogReadResult(operation, ReadOutcome.BOUND_EXCEEDED, self.identity, (), "RESPONSE_BOUND_EXCEEDED")
        return result

    def _pin(self, operation: CatalogOperation, catalog_id: Any, catalog_digest: Any) -> CatalogReadResult | None:
        if operation not in self.enabled_operations:
            return self._result(operation, ReadOutcome.UNSUPPORTED, reason="CAPABILITY_DISABLED")
        try:
            supplied_id = _identifier(catalog_id, "query.catalog_id")
            supplied_digest = _digest(catalog_digest, "query.catalog_digest")
        except CatalogContractError:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_CATALOG_IDENTITY")
        if supplied_id != self.identity.catalog_id:
            return self._result(operation, ReadOutcome.CONTRACT_MISMATCH, reason="CATALOG_ID_MISMATCH")
        if supplied_digest != self.identity.catalog_digest:
            return self._result(operation, ReadOutcome.STALE_CATALOG, reason="CATALOG_DIGEST_MISMATCH")
        return None

    @staticmethod
    def _maximum(value: Any) -> bool:
        return type(value) is int and 1 <= value <= MAX_CATALOG_ENTRIES

    def get_resource(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        resource_type: str,
        resource_id: str,
        visibility: CatalogVisibility,
    ) -> CatalogReadResult:
        operation = CatalogOperation.GET_RESOURCE
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return failure
        try:
            resource_type = _identifier(resource_type, "query.resource_type")
            resource_id = _identifier(resource_id, "query.resource_id")
        except CatalogContractError:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_EXACT_IDENTITY")
        match = next((item for item in self.resources if item.resource_type == resource_type and item.resource_id == resource_id), None)
        if match is None or not visibility.permits("resource_ids", resource_id):
            return self._result(operation, ReadOutcome.NOT_FOUND, reason="NOT_FOUND")
        return self._result(operation, ReadOutcome.OK, (match,), "EXACT_MATCH")

    def memory_lookup_region(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        memory_region_id: str,
        maximum_entries: int,
        visibility: CatalogVisibility,
    ) -> CatalogReadResult:
        operation = CatalogOperation.MEMORY_LOOKUP
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return failure
        try:
            memory_region_id = _identifier(memory_region_id, "query.memory_region_id")
        except CatalogContractError:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_EXACT_IDENTITY")
        if not self._maximum(maximum_entries):
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_MAXIMUM_ENTRIES")
        match = next((item for item in self.memory_regions if item.memory_region_id == memory_region_id), None)
        if match is None or not visibility.permits("memory_region_ids", memory_region_id):
            return self._result(operation, ReadOutcome.NOT_FOUND, reason="NOT_FOUND")
        return self._result(operation, ReadOutcome.OK, (match,), "EXACT_MATCH")

    def memory_lookup_address(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        start_address: int,
        length: int,
        maximum_entries: int,
        visibility: CatalogVisibility,
    ) -> CatalogReadResult:
        operation = CatalogOperation.MEMORY_LOOKUP
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return failure
        if not self._maximum(maximum_entries):
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_MAXIMUM_ENTRIES")
        if type(start_address) is not int or type(length) is not int or start_address < 0 or length <= 0:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_ADDRESS_RANGE")
        if start_address >= UINT64_LIMIT or length >= UINT64_LIMIT or start_address + length > UINT64_LIMIT:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="ADDRESS_OVERFLOW")
        end_address = start_address + length
        containing = [item for item in self.memory_regions if item.start_address <= start_address and end_address <= item.end_address]
        if len(containing) != 1:
            overlaps = any(start_address < item.end_address and end_address > item.start_address for item in self.memory_regions)
            outcome = ReadOutcome.INVALID_ARGUMENT if overlaps else ReadOutcome.NOT_FOUND
            reason = "CROSS_REGION_READ" if overlaps else "NOT_FOUND"
            return self._result(operation, outcome, reason=reason)
        match = containing[0]
        if not visibility.permits("memory_region_ids", match.memory_region_id):
            return self._result(operation, ReadOutcome.NOT_FOUND, reason="NOT_FOUND")
        return self._result(operation, ReadOutcome.OK, (match,), "BOUNDED_ADDRESS_MATCH")

    def tmtc_lookup(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        direction: Direction | str,
        maximum_entries: int,
        visibility: CatalogVisibility,
        item_id: str | None = None,
        qualified_name: str | None = None,
    ) -> CatalogReadResult:
        operation = CatalogOperation.TMTC_LOOKUP
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return failure
        if not self._maximum(maximum_entries) or (item_id is None) == (qualified_name is None):
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_EXACT_QUERY")
        try:
            direction = Direction(direction)
            if item_id is not None:
                item_id = _identifier(item_id, "query.item_id")
            else:
                qualified_name = _qualified_name(qualified_name, "query.qualified_name")
        except (CatalogContractError, ValueError):
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_EXACT_QUERY")
        match = next(
            (
                item
                for item in self.tmtc_items
                if item.direction is direction
                and (item.item_id == item_id if item_id is not None else item.qualified_name == qualified_name)
            ),
            None,
        )
        if match is None or not visibility.permits("tmtc_item_ids", match.item_id):
            return self._result(operation, ReadOutcome.NOT_FOUND, reason="NOT_FOUND")
        return self._result(operation, ReadOutcome.OK, (match,), "EXACT_MATCH")

    def get_limits(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        item_id: str,
        visibility: CatalogVisibility,
    ) -> CatalogReadResult:
        operation = CatalogOperation.GET_LIMITS
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return failure
        try:
            item_id = _identifier(item_id, "query.item_id")
        except CatalogContractError:
            return self._result(operation, ReadOutcome.INVALID_ARGUMENT, reason="INVALID_EXACT_IDENTITY")
        match = next((item for item in self.limit_sets if item.item_id == item_id), None)
        if match is None or not visibility.permits("limit_item_ids", item_id):
            return self._result(operation, ReadOutcome.NOT_FOUND, reason="NOT_FOUND")
        return self._result(operation, ReadOutcome.OK, (match,), "EXACT_MATCH")

    def is_alarmed(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        item_id: str,
        sample: SampleEvidence | None,
        snapshot_cursor: int,
        evaluated_at_database_time_unix_ns: int,
        visibility: CatalogVisibility,
        previous_state: AlarmState | None = None,
    ) -> AlarmReadResult:
        operation = CatalogOperation.IS_ALARMED
        if failure := self._pin(operation, catalog_id, catalog_digest):
            return AlarmReadResult(failure.outcome, self.identity, reason=failure.reason)
        try:
            item_id = _identifier(item_id, "query.item_id")
            _nonnegative_int(snapshot_cursor, "query.snapshot_cursor")
            _nonnegative_int(evaluated_at_database_time_unix_ns, "query.evaluated_at")
        except CatalogContractError:
            return AlarmReadResult(ReadOutcome.INVALID_ARGUMENT, self.identity, reason="INVALID_ARGUMENT")
        limit_set = next((item for item in self.limit_sets if item.item_id == item_id), None)
        if limit_set is None or not visibility.permits("limit_item_ids", item_id):
            return AlarmReadResult(ReadOutcome.NOT_FOUND, self.identity, reason="NOT_FOUND")
        if sample is not None and sample.item_id != item_id:
            return AlarmReadResult(ReadOutcome.CONTRACT_MISMATCH, self.identity, reason="SAMPLE_ITEM_MISMATCH")
        observation = evaluate_alarm(
            limit_set=limit_set,
            catalog_digest=self.identity.catalog_digest,
            sample=sample,
            snapshot_cursor=snapshot_cursor,
            evaluated_at_database_time_unix_ns=evaluated_at_database_time_unix_ns,
            previous_state=previous_state,
        )
        return AlarmReadResult(ReadOutcome.OK, self.identity, observation, "READ_ONLY_EVALUATION")


def _threshold_matches(value: Decimal, band: LimitBand) -> bool:
    assert band.threshold is not None
    threshold = band.threshold.numeric()
    if band.band in {LimitBandKind.HARD_LOW, LimitBandKind.SOFT_LOW}:
        return value <= threshold if band.inclusive else value < threshold
    return value >= threshold if band.inclusive else value > threshold


def _state_for_value(value: Decimal, limit_set: LimitSet) -> AlarmState:
    checks = (
        (LimitBandKind.HARD_LOW, AlarmState.CRITICAL_LOW),
        (LimitBandKind.HARD_HIGH, AlarmState.CRITICAL_HIGH),
        (LimitBandKind.SOFT_LOW, AlarmState.WARNING_LOW),
        (LimitBandKind.SOFT_HIGH, AlarmState.WARNING_HIGH),
    )
    for kind, state in checks:
        band = limit_set.band(kind)
        if band.enabled and _threshold_matches(value, band):
            return state
    return AlarmState.NOT_ALARMED


def _retains_previous(value: Decimal, previous: AlarmState, limit_set: LimitSet) -> bool:
    mapping = {
        AlarmState.CRITICAL_LOW: LimitBandKind.HARD_LOW,
        AlarmState.WARNING_LOW: LimitBandKind.SOFT_LOW,
        AlarmState.WARNING_HIGH: LimitBandKind.SOFT_HIGH,
        AlarmState.CRITICAL_HIGH: LimitBandKind.HARD_HIGH,
    }
    kind = mapping.get(previous)
    if kind is None:
        return False
    band = limit_set.band(kind)
    if not band.enabled or band.hysteresis is None or band.hysteresis.numeric() == 0:
        return False
    assert band.threshold is not None
    threshold = band.threshold.numeric()
    hysteresis = band.hysteresis.numeric()
    if kind in {LimitBandKind.HARD_LOW, LimitBandKind.SOFT_LOW}:
        return value <= threshold + hysteresis
    return value >= threshold - hysteresis


def _can_retain_over(current: AlarmState, previous: AlarmState) -> bool:
    lower_states = {
        AlarmState.CRITICAL_LOW: {AlarmState.WARNING_LOW, AlarmState.NOT_ALARMED},
        AlarmState.WARNING_LOW: {AlarmState.NOT_ALARMED},
        AlarmState.WARNING_HIGH: {AlarmState.NOT_ALARMED},
        AlarmState.CRITICAL_HIGH: {AlarmState.WARNING_HIGH, AlarmState.NOT_ALARMED},
    }
    return current in lower_states.get(previous, set())


def evaluate_alarm(
    *,
    limit_set: LimitSet,
    catalog_digest: str,
    sample: SampleEvidence | None,
    snapshot_cursor: int,
    evaluated_at_database_time_unix_ns: int,
    previous_state: AlarmState | None = None,
) -> AlarmObservation:
    """Evaluate one sample and one immutable limit revision without side effects."""

    _digest(catalog_digest, "alarm.catalog_digest")
    _nonnegative_int(snapshot_cursor, "alarm.snapshot_cursor")
    _nonnegative_int(evaluated_at_database_time_unix_ns, "alarm.evaluated_at")
    state = AlarmState.INDETERMINATE
    reason = "NO_SAMPLE"
    selected: TypedScalar | None = None
    if sample is not None:
        gates = (
            (sample.snapshot_cursor != snapshot_cursor, "SNAPSHOT_CURSOR_MISMATCH"),
            (
                sample.catalog_digest != limit_set.telemetry_catalog_digest,
                "TELEMETRY_CATALOG_MISMATCH",
            ),
            (not limit_set.enabled, "LIMIT_SET_DISABLED"),
            (not any(band.enabled for band in limit_set.bands), "LIMIT_BANDS_MISSING_OR_DISABLED"),
            (sample.validity != "VALID", "INVALID_OR_UNKNOWN_VALIDITY"),
            (sample.quality != "GOOD", "UNACCEPTABLE_QUALITY"),
            (sample.freshness != "FRESH", "STALE_OR_UNKNOWN_FRESHNESS"),
            (not sample.synchronized or sample.has_gap, "GAPPED_OR_UNSYNCHRONIZED"),
            (not sample.clock_acceptable, "CLOCK_UNACCEPTABLE"),
        )
        failed_reason = next((message for failed, message in gates if failed), None)
        if failed_reason is not None:
            reason = failed_reason
        else:
            selected = sample.selected_value(limit_set.value_domain)
            if selected.scalar_type is not limit_set.value_type:
                reason = "VALUE_TYPE_MISMATCH"
            elif limit_set.value_domain is ValueField.ENGINEERING and sample.unit != limit_set.unit:
                reason = "UNIT_MISMATCH"
            else:
                value = selected.numeric()
                state = _state_for_value(value, limit_set)
                if (
                    previous_state is not None
                    and _can_retain_over(state, previous_state)
                    and _retains_previous(value, previous_state, limit_set)
                ):
                    state = previous_state
                    reason = "HYSTERESIS_RETAINED"
                else:
                    reason = "DETERMINISTIC_BAND_RESULT"
    payload = {
        "item_id": limit_set.item_id,
        "sample_id": sample.sample_id if sample else None,
        "limit_set_id": limit_set.limit_set_id,
        "limit_revision": limit_set.limit_revision,
        "state": state.value,
        "snapshot_cursor": snapshot_cursor,
        "evaluated_at_database_time_unix_ns": evaluated_at_database_time_unix_ns,
        "reason": reason,
    }
    return AlarmObservation(
        alarm_observation_id=_canonical_digest(payload),
        item_id=limit_set.item_id,
        sample_id=sample.sample_id if sample else None,
        limit_set_id=limit_set.limit_set_id,
        limit_revision=limit_set.limit_revision,
        state=state,
        severity=_ALARM_SEVERITY[state],
        evaluated_value=selected if state is not AlarmState.INDETERMINATE else None,
        quality=sample.quality if sample else "UNKNOWN",
        validity=sample.validity if sample else "UNKNOWN",
        freshness=sample.freshness if sample else "UNKNOWN",
        snapshot_cursor=snapshot_cursor,
        evaluated_at_database_time_unix_ns=evaluated_at_database_time_unix_ns,
        reason=reason,
    )


__all__ = [
    "AlarmObservation",
    "AlarmReadResult",
    "AlarmState",
    "CatalogContractError",
    "CatalogIdentity",
    "CatalogOperation",
    "CatalogReadResult",
    "CatalogVisibility",
    "Direction",
    "LimitBand",
    "LimitBandKind",
    "LimitSet",
    "MemoryRegionRecord",
    "ObservationCatalog",
    "ReadOutcome",
    "ResourceRecord",
    "TmTcRecord",
    "evaluate_alarm",
]
