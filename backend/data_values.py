"""Canonical, bounded, non-executing SPELL v0.8 typed values."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "spell.data.value/1"
SUPPORTED_TYPES = frozenset(
    {
        "NULL",
        "BOOLEAN",
        "INT64",
        "UINT64",
        "DECIMAL",
        "FINITE_DOUBLE",
        "STRING",
        "BYTES",
        "UTC_DATETIME",
        "REL_DURATION",
        "LIST",
        "MAP",
    }
)
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
UINT64_MAX = 2**64 - 1
MAXIMUM_DEPTH = 8
MAXIMUM_TOTAL_NODES = 4096
MAXIMUM_LIST_ITEMS = 1024
MAXIMUM_MAP_ENTRIES = 1024
MAXIMUM_KEY_UTF8_BYTES = 256
MAXIMUM_STRING_UTF8_BYTES = 65_536
MAXIMUM_BYTES_DECODED = 1_048_576
MAXIMUM_SERIALIZED_UTF8_BYTES = 1_048_576

_INTEGER_PATTERN = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_UNSIGNED_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_DECIMAL_PATTERN = re.compile(
    r"(?:0|-?(?:0\.[0-9]*[1-9]|[1-9][0-9]*(?:\.[0-9]*[1-9])?))\Z"
)
_UTC_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z"
)


class TypedValueError(ValueError):
    """A fail-closed typed-value rejection with a stable safe outcome."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CorruptValueError(TypedValueError):
    def __init__(self, message: str = "stored typed value is corrupt") -> None:
        super().__init__("CORRUPT_VALUE", message)


def contract_integer_to_wire(
    value: int, *, allow_zero: bool = True, label: str = "integer"
) -> str:
    """Serialize a persisted nonnegative BIGINT without JSON precision loss."""

    minimum = 0 if allow_zero else 1
    if type(value) is not int or not minimum <= value <= INT64_MAX:
        qualifier = "nonnegative" if allow_zero else "positive"
        raise TypedValueError(
            "REJECTED", f"{label} must be a {qualifier} signed 64-bit integer"
        )
    return str(value)


def contract_integer_from_wire(
    value: str, *, allow_zero: bool = True, label: str = "integer"
) -> int:
    """Parse the canonical decimal-string form used for revisions and counters."""

    if type(value) is not str or _UNSIGNED_PATTERN.fullmatch(value) is None:
        raise TypedValueError("REJECTED", f"{label} is not canonical decimal")
    parsed = int(value, 10)
    minimum = 0 if allow_zero else 1
    if not minimum <= parsed <= INT64_MAX:
        qualifier = "nonnegative" if allow_zero else "positive"
        raise TypedValueError(
            "REJECTED", f"{label} must be a {qualifier} signed 64-bit integer"
        )
    return parsed


@dataclass
class _Budget:
    nodes: int = 0

    def consume(self, depth: int) -> None:
        if depth > MAXIMUM_DEPTH:
            raise TypedValueError("LIMIT_EXCEEDED", "typed value depth exceeds 8")
        self.nodes += 1
        if self.nodes > MAXIMUM_TOTAL_NODES:
            raise TypedValueError(
                "LIMIT_EXCEEDED", "typed value node count exceeds 4096"
            )


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TypedValueError("REJECTED", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _nonfinite_json(value: str) -> Any:
    raise TypedValueError("REJECTED", f"non-finite JSON number: {value}")


def strict_json_loads(payload: bytes | str, *, maximum_bytes: int) -> Any:
    """Decode one bounded strict UTF-8 JSON value without duplicate keys."""

    if isinstance(payload, str):
        try:
            raw = payload.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise TypedValueError("REJECTED", "JSON contains an unpaired surrogate") from exc
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise TypeError("JSON payload must be bytes or str")
    if len(raw) > maximum_bytes:
        raise TypedValueError("LIMIT_EXCEEDED", "JSON payload exceeds its byte limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise TypedValueError("REJECTED", "JSON byte-order mark is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TypedValueError("REJECTED", "JSON is not strict UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_object,
            parse_constant=_nonfinite_json,
        )
    except TypedValueError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise TypedValueError("REJECTED", "JSON is malformed or has trailing data") from exc


def _closed_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise TypedValueError("TYPE_MISMATCH", f"{label} must be an object")
    if not all(type(key) is str for key in value):
        raise TypedValueError("REJECTED", f"{label} keys must be strings")
    actual = set(value)
    if actual != fields:
        raise TypedValueError(
            "REJECTED",
            f"{label} fields differ: expected {sorted(fields)!r}, got {sorted(actual)!r}",
        )
    return value


def _nfc_string(value: Any, maximum_bytes: int, label: str) -> str:
    if type(value) is not str:
        raise TypedValueError("TYPE_MISMATCH", f"{label} must be a string")
    if unicodedata.normalize("NFC", value) != value:
        raise TypedValueError("NON_CANONICAL", f"{label} is not NFC")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise TypedValueError("REJECTED", f"{label} has an unpaired surrogate") from exc
    if len(raw) > maximum_bytes:
        raise TypedValueError("LIMIT_EXCEEDED", f"{label} exceeds its UTF-8 limit")
    return value


def _bounded_integer_string(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    unsigned: bool = False,
) -> str:
    if type(value) is not str:
        raise TypedValueError("TYPE_MISMATCH", "integer wire value must be a string")
    pattern = _UNSIGNED_PATTERN if unsigned else _INTEGER_PATTERN
    if pattern.fullmatch(value) is None:
        raise TypedValueError("NON_CANONICAL", "integer wire value is not canonical")
    number = int(value)
    if not minimum <= number <= maximum:
        raise TypedValueError("VALUE_OUT_OF_RANGE", "integer is outside its bound")
    return value


def _decimal_string(value: Any) -> str:
    if type(value) is not str:
        raise TypedValueError("TYPE_MISMATCH", "decimal wire value must be a string")
    if len(value) > MAXIMUM_STRING_UTF8_BYTES:
        raise TypedValueError("LIMIT_EXCEEDED", "decimal exceeds its byte limit")
    if _DECIMAL_PATTERN.fullmatch(value) is None:
        raise TypedValueError("NON_CANONICAL", "decimal wire value is not canonical")
    try:
        number = Decimal(value)
    except Exception as exc:
        raise TypedValueError("REJECTED", "decimal wire value is invalid") from exc
    if not number.is_finite():
        raise TypedValueError("VALUE_OUT_OF_RANGE", "decimal must be finite")
    if number.is_zero() and number.is_signed():
        raise TypedValueError("NON_CANONICAL", "negative decimal zero is forbidden")
    return value


def _finite_double(value: Any) -> float:
    if type(value) is not float:
        raise TypedValueError("TYPE_MISMATCH", "FINITE_DOUBLE must be a JSON number")
    if not math.isfinite(value):
        raise TypedValueError("VALUE_OUT_OF_RANGE", "FINITE_DOUBLE must be finite")
    if value == 0.0 and math.copysign(1.0, value) < 0:
        raise TypedValueError("NON_CANONICAL", "negative floating zero is forbidden")
    return value


def _utc_datetime(value: Any) -> str:
    if type(value) is not str:
        raise TypedValueError("TYPE_MISMATCH", "UTC_DATETIME must be a string")
    if _UTC_PATTERN.fullmatch(value) is None:
        raise TypedValueError(
            "NON_CANONICAL", "UTC_DATETIME must use UTC Z and six fractional digits"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise TypedValueError("VALUE_OUT_OF_RANGE", "UTC_DATETIME is invalid") from exc
    if parsed.second == 60:
        raise TypedValueError("VALUE_OUT_OF_RANGE", "leap seconds are forbidden")
    return value


def _bytes_value(value: Any) -> str:
    if type(value) is not str or not value.isascii():
        raise TypedValueError("TYPE_MISMATCH", "BYTES must be an ASCII base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TypedValueError("NON_CANONICAL", "BYTES is not canonical base64") from exc
    if len(decoded) > MAXIMUM_BYTES_DECODED:
        raise TypedValueError("LIMIT_EXCEEDED", "BYTES exceeds its decoded limit")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise TypedValueError("NON_CANONICAL", "BYTES padding is not canonical")
    return value


def _validate_envelope(value: Any, *, depth: int, budget: _Budget) -> dict[str, Any]:
    budget.consume(depth)
    envelope = _closed_object(
        value, {"schema_version", "type", "value"}, "typed value envelope"
    )
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise TypedValueError("REJECTED", "typed value schema version is unsupported")
    type_id = envelope["type"]
    if type(type_id) is not str or type_id not in SUPPORTED_TYPES:
        raise TypedValueError("TYPE_MISMATCH", "typed value type is unsupported")
    wire = envelope["value"]

    if type_id == "NULL":
        if wire is not None:
            raise TypedValueError("TYPE_MISMATCH", "NULL value must be null")
        canonical: Any = None
    elif type_id == "BOOLEAN":
        if type(wire) is not bool:
            raise TypedValueError("TYPE_MISMATCH", "BOOLEAN value must be a boolean")
        canonical = wire
    elif type_id == "INT64":
        canonical = _bounded_integer_string(
            wire, minimum=INT64_MIN, maximum=INT64_MAX
        )
    elif type_id == "UINT64":
        canonical = _bounded_integer_string(
            wire, minimum=0, maximum=UINT64_MAX, unsigned=True
        )
    elif type_id == "DECIMAL":
        canonical = _decimal_string(wire)
    elif type_id == "FINITE_DOUBLE":
        canonical = _finite_double(wire)
    elif type_id == "STRING":
        canonical = _nfc_string(wire, MAXIMUM_STRING_UTF8_BYTES, "STRING")
    elif type_id == "BYTES":
        canonical = _bytes_value(wire)
    elif type_id == "UTC_DATETIME":
        canonical = _utc_datetime(wire)
    elif type_id == "REL_DURATION":
        canonical = _bounded_integer_string(
            wire, minimum=INT64_MIN, maximum=INT64_MAX
        )
    elif type_id == "LIST":
        if type(wire) is not list:
            raise TypedValueError("TYPE_MISMATCH", "LIST value must be an array")
        if len(wire) > MAXIMUM_LIST_ITEMS:
            raise TypedValueError("LIMIT_EXCEEDED", "LIST exceeds its item limit")
        canonical = [
            _validate_envelope(item, depth=depth + 1, budget=budget) for item in wire
        ]
    else:
        if type(wire) is not list:
            raise TypedValueError("TYPE_MISMATCH", "MAP value must be an array")
        if len(wire) > MAXIMUM_MAP_ENTRIES:
            raise TypedValueError("LIMIT_EXCEEDED", "MAP exceeds its entry limit")
        canonical = []
        previous: bytes | None = None
        for raw_entry in wire:
            entry = _closed_object(raw_entry, {"key", "value"}, "MAP entry")
            key = _nfc_string(entry["key"], MAXIMUM_KEY_UTF8_BYTES, "MAP key")
            encoded_key = key.encode("utf-8")
            if previous is not None and encoded_key <= previous:
                outcome = "duplicate" if encoded_key == previous else "out of order"
                raise TypedValueError("NON_CANONICAL", f"MAP key is {outcome}")
            previous = encoded_key
            canonical.append(
                {
                    "key": key,
                    "value": _validate_envelope(
                        entry["value"], depth=depth + 1, budget=budget
                    ),
                }
            )
    return {"schema_version": SCHEMA_VERSION, "type": type_id, "value": canonical}


def validate_typed_value(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached canonical envelope."""

    canonical = _validate_envelope(value, depth=1, budget=_Budget())
    _canonical_bytes(canonical)
    return canonical


def _canonical_bytes(canonical: Mapping[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TypedValueError("REJECTED", "typed value cannot be serialized") from exc
    if len(raw) > MAXIMUM_SERIALIZED_UTF8_BYTES:
        raise TypedValueError(
            "LIMIT_EXCEEDED", "typed value exceeds its serialized byte limit"
        )
    return raw


def canonical_typed_value_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical_bytes(validate_typed_value(value))


def canonical_typed_value_json(value: Mapping[str, Any]) -> str:
    return canonical_typed_value_bytes(value).decode("utf-8")


def typed_value_digest(value: Mapping[str, Any] | bytes | str) -> str:
    if isinstance(value, Mapping):
        raw = canonical_typed_value_bytes(value)
    else:
        raw = canonical_typed_value_bytes(decode_typed_value(value))
    return hashlib.sha256(raw).hexdigest()


def decode_typed_value(
    payload: bytes | str, *, require_canonical: bool = True
) -> dict[str, Any]:
    """Decode a typed value and reject non-canonical bytes by default."""

    if isinstance(payload, str):
        try:
            raw = payload.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise TypedValueError("REJECTED", "typed value has an unpaired surrogate") from exc
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise TypeError("typed value payload must be bytes or str")
    decoded = strict_json_loads(raw, maximum_bytes=MAXIMUM_SERIALIZED_UTF8_BYTES)
    canonical = validate_typed_value(decoded)
    canonical_bytes = _canonical_bytes(canonical)
    if require_canonical and raw != canonical_bytes:
        raise TypedValueError("NON_CANONICAL", "typed value JSON bytes are not canonical")
    return canonical


def decode_stored_typed_value(
    payload: bytes | str, expected_digest: str
) -> dict[str, Any]:
    """Verify an exact stored digest before returning any decoded value."""

    if type(expected_digest) is not str or re.fullmatch(
        r"[0-9a-f]{64}", expected_digest
    ) is None:
        raise CorruptValueError("stored typed value digest is malformed")
    try:
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    except UnicodeEncodeError as exc:
        raise CorruptValueError("stored typed value is not UTF-8") from exc
    if not isinstance(raw, bytes):
        raise TypeError("stored typed value payload must be bytes or str")
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise CorruptValueError("stored typed value digest differs")
    try:
        return decode_typed_value(raw, require_canonical=True)
    except TypedValueError as exc:
        raise CorruptValueError("stored typed value bytes are invalid") from exc


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise TypedValueError("VALUE_OUT_OF_RANGE", "decimal must be finite")
    if value.is_zero():
        if value.is_signed():
            raise TypedValueError("NON_CANONICAL", "negative decimal zero is forbidden")
        return "0"
    digits = value.as_tuple().digits
    exponent = value.as_tuple().exponent
    if len(digits) + abs(exponent) > MAXIMUM_STRING_UTF8_BYTES:
        raise TypedValueError("LIMIT_EXCEEDED", "decimal exceeds its byte limit")
    wire = format(value, "f")
    if "." in wire:
        wire = wire.rstrip("0").rstrip(".")
    return _decimal_string(wire)


def make_typed_value(type_id: str, value: Any) -> dict[str, Any]:
    """Create a canonical envelope from an explicitly selected SPELL type."""

    if type_id == "INT64" or type_id == "UINT64" or type_id == "REL_DURATION":
        if type(value) is not int:
            raise TypedValueError("TYPE_MISMATCH", f"{type_id} requires an integer")
        wire: Any = str(value)
    elif type_id == "DECIMAL":
        if type(value) is not Decimal:
            raise TypedValueError("TYPE_MISMATCH", "DECIMAL requires Decimal")
        wire = _decimal_wire(value)
    elif type_id == "BYTES":
        if type(value) is not bytes:
            raise TypedValueError("TYPE_MISMATCH", "BYTES requires bytes")
        if len(value) > MAXIMUM_BYTES_DECODED:
            raise TypedValueError("LIMIT_EXCEEDED", "BYTES exceeds its decoded limit")
        wire = base64.b64encode(value).decode("ascii")
    elif type_id == "UTC_DATETIME":
        if type(value) is not datetime or value.tzinfo is None:
            raise TypedValueError(
                "TYPE_MISMATCH", "UTC_DATETIME requires an aware datetime"
            )
        wire = value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elif type_id == "STRING":
        if type(value) is not str:
            raise TypedValueError("TYPE_MISMATCH", "STRING requires str")
        wire = unicodedata.normalize("NFC", value)
    elif type_id == "LIST":
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise TypedValueError("TYPE_MISMATCH", "LIST requires typed envelopes")
        wire = list(value)
    elif type_id == "MAP":
        if not isinstance(value, Mapping):
            raise TypedValueError("TYPE_MISMATCH", "MAP requires a mapping")
        wire = [
            {"key": key, "value": item}
            for key, item in sorted(
                value.items(), key=lambda pair: str(pair[0]).encode("utf-8")
            )
        ]
    else:
        wire = value
    return validate_typed_value(
        {"schema_version": SCHEMA_VERSION, "type": type_id, "value": wire}
    )


def typed_value_to_python(value: Mapping[str, Any]) -> Any:
    """Return the inert Python representation of a validated envelope."""

    canonical = validate_typed_value(value)
    type_id = canonical["type"]
    wire = canonical["value"]
    if type_id in {"NULL", "BOOLEAN", "FINITE_DOUBLE", "STRING"}:
        return wire
    if type_id in {"INT64", "UINT64", "REL_DURATION"}:
        return int(wire)
    if type_id == "DECIMAL":
        return Decimal(wire)
    if type_id == "BYTES":
        return base64.b64decode(wire, validate=True)
    if type_id == "UTC_DATETIME":
        return datetime.strptime(wire, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    if type_id == "LIST":
        return [typed_value_to_python(item) for item in wire]
    return {entry["key"]: typed_value_to_python(entry["value"]) for entry in wire}


encode_typed_value = canonical_typed_value_bytes


__all__ = [
    "CorruptValueError",
    "INT64_MAX",
    "INT64_MIN",
    "MAXIMUM_BYTES_DECODED",
    "MAXIMUM_DEPTH",
    "MAXIMUM_LIST_ITEMS",
    "MAXIMUM_MAP_ENTRIES",
    "MAXIMUM_SERIALIZED_UTF8_BYTES",
    "MAXIMUM_TOTAL_NODES",
    "SCHEMA_VERSION",
    "SUPPORTED_TYPES",
    "TypedValueError",
    "UINT64_MAX",
    "canonical_typed_value_bytes",
    "canonical_typed_value_json",
    "contract_integer_from_wire",
    "contract_integer_to_wire",
    "decode_stored_typed_value",
    "decode_typed_value",
    "encode_typed_value",
    "make_typed_value",
    "strict_json_loads",
    "typed_value_digest",
    "typed_value_to_python",
    "validate_typed_value",
]
