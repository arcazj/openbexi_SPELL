"""Proto-independent typed driver observation boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .driver_domain import GenerationTuple


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_UINT64_MAX = 2**64 - 1
MAX_SCALAR_BYTES = 4096
MAX_TEXT_BYTES = 4096


def _identifier(value: str, label: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded identifier")


def _digest(value: str, label: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _text(value: str, label: str, *, allow_empty: bool = False) -> None:
    if type(value) is not str or (not value and not allow_empty):
        raise ValueError(f"{label} must be a string")
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError(f"{label} exceeds the bounded UTF-8 size")


def _signed_ns(value: int, label: str) -> None:
    if type(value) is not int or not _INT64_MIN <= value <= _INT64_MAX:
        raise ValueError(f"{label} is outside signed Unix nanoseconds")


def _uint64(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= _UINT64_MAX:
        raise ValueError(f"{label} is outside the unsigned 64-bit range")


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


class ObservationResultCode(str, Enum):
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


class GetTMMode(str, Enum):
    CURRENT = "CURRENT"
    NEXT = "NEXT"


@dataclass(frozen=True)
class ScalarValue:
    kind: ScalarKind
    value: bool | int | float | str | bytes

    def __post_init__(self) -> None:
        if type(self.kind) is not ScalarKind:
            raise ValueError("scalar kind must be a ScalarKind")
        if self.kind is ScalarKind.BOOLEAN:
            valid = type(self.value) is bool
        elif self.kind is ScalarKind.INT64:
            valid = type(self.value) is int and _INT64_MIN <= self.value <= _INT64_MAX
        elif self.kind is ScalarKind.UINT64:
            valid = type(self.value) is int and 0 <= self.value <= _UINT64_MAX
        elif self.kind is ScalarKind.FINITE_DOUBLE:
            valid = type(self.value) is float and math.isfinite(self.value)
        elif self.kind is ScalarKind.STRING:
            valid = (
                type(self.value) is str
                and len(self.value.encode("utf-8")) <= MAX_SCALAR_BYTES
            )
        else:
            valid = type(self.value) is bytes and len(self.value) <= MAX_SCALAR_BYTES
        if not valid:
            raise ValueError(f"invalid {self.kind.value} scalar value")

    def canonical_json_value(self) -> bool | str | float:
        if self.kind in {ScalarKind.INT64, ScalarKind.UINT64}:
            return str(self.value)
        if self.kind is ScalarKind.BYTES:
            return base64.b64encode(self.value).decode("ascii")  # type: ignore[arg-type]
        return self.value  # type: ignore[return-value]

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.kind.value, "value": self.canonical_json_value()}

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def sample_id_for(
    source_id: str, source_epoch: str, item_id: str, source_sequence: int
) -> str:
    _identifier(source_id, "source_id")
    _identifier(source_epoch, "source_epoch")
    _identifier(item_id, "item_id")
    _uint64(source_sequence, "source_sequence")
    encoded = json.dumps(
        {
            "item_id": item_id,
            "source_epoch": source_epoch,
            "source_id": source_id,
            "source_sequence": str(source_sequence),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ItemIdentity:
    item_id: str
    qualified_name: str
    catalog_digest: str

    def __post_init__(self) -> None:
        _identifier(self.item_id, "item_id")
        _identifier(self.qualified_name, "qualified_name")
        _digest(self.catalog_digest, "catalog_digest")


@dataclass(frozen=True)
class SampleIdentity:
    sample_id: str
    item_id: str
    source_id: str
    source_epoch: str
    source_sequence: int

    def __post_init__(self) -> None:
        _digest(self.sample_id, "sample_id")
        _identifier(self.item_id, "item_id")
        _identifier(self.source_id, "source_id")
        _identifier(self.source_epoch, "source_epoch")
        _uint64(self.source_sequence, "source_sequence")
        if self.source_sequence < 1:
            raise ValueError("source_sequence must be at least one")
        if self.sample_id != sample_id_for(
            self.source_id, self.source_epoch, self.item_id, self.source_sequence
        ):
            raise ValueError("sample_id does not bind the canonical sample identity")


@dataclass(frozen=True)
class DriverTimeObservation:
    observation_id: str
    generations: GenerationTuple
    time_unix_ns: int
    acquired_at_unix_ns: int
    clock_source: ClockSource
    provenance: str
    uncertainty_ns: int
    quality: Quality
    validity: Validity

    def __post_init__(self) -> None:
        _identifier(self.observation_id, "observation_id")
        if type(self.generations) is not GenerationTuple:
            raise ValueError("generations must be a GenerationTuple")
        _signed_ns(self.time_unix_ns, "time_unix_ns")
        _signed_ns(self.acquired_at_unix_ns, "acquired_at_unix_ns")
        if type(self.clock_source) is not ClockSource:
            raise ValueError("clock_source must be a ClockSource")
        _text(self.provenance, "provenance")
        _uint64(self.uncertainty_ns, "uncertainty_ns")
        if type(self.quality) is not Quality or type(self.validity) is not Validity:
            raise ValueError("quality and validity must be typed")


@dataclass(frozen=True)
class DriverTelemetrySample:
    observation_id: str
    generations: GenerationTuple
    sample_identity: SampleIdentity
    item_identity: ItemIdentity
    raw_value: ScalarValue
    engineering_value: ScalarValue
    description: str
    unit: str
    acquired_at_unix_ns: int
    source: str
    clock_provenance: str
    clock_uncertainty_ns: int
    validity: Validity
    quality: Quality
    quality_reason: str

    def __post_init__(self) -> None:
        _identifier(self.observation_id, "observation_id")
        if type(self.generations) is not GenerationTuple:
            raise ValueError("generations must be a GenerationTuple")
        if not self.generations.context_id or self.generations.execution_id:
            raise ValueError("telemetry sample requires a context-only generation tuple")
        if type(self.sample_identity) is not SampleIdentity:
            raise ValueError("sample_identity must be a SampleIdentity")
        if type(self.item_identity) is not ItemIdentity:
            raise ValueError("item_identity must be an ItemIdentity")
        if self.sample_identity.item_id != self.item_identity.item_id:
            raise ValueError("sample and item identities differ")
        if type(self.raw_value) is not ScalarValue or type(self.engineering_value) is not ScalarValue:
            raise ValueError("raw and engineering values must be typed scalars")
        _text(self.description, "description")
        _text(self.unit, "unit", allow_empty=True)
        _signed_ns(self.acquired_at_unix_ns, "acquired_at_unix_ns")
        _identifier(self.source, "source")
        _text(self.clock_provenance, "clock_provenance")
        _uint64(self.clock_uncertainty_ns, "clock_uncertainty_ns")
        if type(self.validity) is not Validity or type(self.quality) is not Quality:
            raise ValueError("validity and quality must be typed")
        _text(self.quality_reason, "quality_reason")


@dataclass(frozen=True)
class GapBounds:
    source_epoch: str
    first_available_sequence: int
    last_available_sequence: int

    def __post_init__(self) -> None:
        _identifier(self.source_epoch, "source_epoch")
        _uint64(self.first_available_sequence, "first_available_sequence")
        _uint64(self.last_available_sequence, "last_available_sequence")
        if self.first_available_sequence < 1 or self.last_available_sequence < self.first_available_sequence:
            raise ValueError("gap bounds are invalid")


def _query_common(
    observation_id: str,
    generations: GenerationTuple,
    correlation_id: str,
    deadline_unix_ns: int,
    credential_epoch: int,
) -> None:
    _identifier(observation_id, "observation_id")
    if type(generations) is not GenerationTuple:
        raise ValueError("generations must be a GenerationTuple")
    _identifier(correlation_id, "correlation_id")
    _signed_ns(deadline_unix_ns, "deadline_unix_ns")
    if deadline_unix_ns <= 0:
        raise ValueError("deadline_unix_ns must be positive")
    if type(credential_epoch) is not int or not 1 <= credential_epoch <= _UINT64_MAX:
        raise ValueError("credential_epoch is invalid")


@dataclass(frozen=True)
class GetTimeQuery:
    observation_id: str
    generations: GenerationTuple
    correlation_id: str
    deadline_unix_ns: int
    credential_epoch: int = 1

    def __post_init__(self) -> None:
        _query_common(**vars(self))
        if self.generations.context_id or self.generations.execution_id:
            raise ValueError("GetTime requires a host-only generation tuple")


@dataclass(frozen=True)
class GetTMQuery:
    observation_id: str
    generations: GenerationTuple
    correlation_id: str
    deadline_unix_ns: int
    item_id: str
    mode: GetTMMode
    source_epoch: str = ""
    after_source_sequence: int = 0
    credential_epoch: int = 1

    def __post_init__(self) -> None:
        _query_common(
            self.observation_id,
            self.generations,
            self.correlation_id,
            self.deadline_unix_ns,
            self.credential_epoch,
        )
        _identifier(self.item_id, "item_id")
        if not self.generations.context_id or self.generations.execution_id:
            raise ValueError("GetTM requires a context-only generation tuple")
        if type(self.mode) is not GetTMMode:
            raise ValueError("mode must be a GetTMMode")
        _uint64(self.after_source_sequence, "after_source_sequence")
        if self.mode is GetTMMode.CURRENT:
            if self.source_epoch or self.after_source_sequence:
                raise ValueError("CURRENT cannot include a source cursor")
        else:
            _identifier(self.source_epoch, "source_epoch")


@dataclass(frozen=True)
class ObservationError:
    code: ObservationResultCode
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if type(self.code) is not ObservationResultCode or self.code is ObservationResultCode.OK:
            raise ValueError("observation error requires a non-OK result code")
        _text(self.message, "observation error message")
        if type(self.retryable) is not bool:
            raise ValueError("retryable must be boolean")


@dataclass(frozen=True)
class GetTimeResult:
    code: ObservationResultCode
    observation: Optional[DriverTimeObservation] = None
    error: Optional[ObservationError] = None

    def __post_init__(self) -> None:
        if self.code is ObservationResultCode.OK:
            if type(self.observation) is not DriverTimeObservation or self.error is not None:
                raise ValueError("OK GetTime requires one observation and no error")
        elif self.observation is not None or type(self.error) is not ObservationError or self.error.code is not self.code:
            raise ValueError("failed GetTime requires one matching typed error")


@dataclass(frozen=True)
class GetTMResult:
    code: ObservationResultCode
    sample: Optional[DriverTelemetrySample] = None
    gap: Optional[GapBounds] = None
    error: Optional[ObservationError] = None

    def __post_init__(self) -> None:
        if self.code is ObservationResultCode.OK:
            valid = type(self.sample) is DriverTelemetrySample and self.gap is None and self.error is None
        elif self.code is ObservationResultCode.GAP:
            valid = self.sample is None and type(self.gap) is GapBounds and self.error is None
        else:
            valid = self.sample is None and self.gap is None and type(self.error) is ObservationError and self.error.code is self.code
        if not valid:
            raise ValueError("GetTM result payload does not match its typed outcome")


__all__ = [
    "ClockSource",
    "DriverTelemetrySample",
    "DriverTimeObservation",
    "GapBounds",
    "GetTMMode",
    "GetTMQuery",
    "GetTMResult",
    "GetTimeQuery",
    "GetTimeResult",
    "ItemIdentity",
    "ObservationError",
    "ObservationResultCode",
    "Quality",
    "SampleIdentity",
    "ScalarKind",
    "ScalarValue",
    "Validity",
    "sample_id_for",
]
