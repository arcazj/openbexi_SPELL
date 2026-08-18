from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from backend.data_values import (
    CorruptValueError,
    SCHEMA_VERSION,
    TypedValueError,
    canonical_typed_value_bytes,
    contract_integer_from_wire,
    contract_integer_to_wire,
    decode_stored_typed_value,
    decode_typed_value,
    make_typed_value,
    typed_value_digest,
    typed_value_to_python,
    validate_typed_value,
)


def envelope(type_id: str, value: object) -> dict[str, object]:
    return {"schema_version": SCHEMA_VERSION, "type": type_id, "value": value}


@pytest.mark.parametrize(
    "value",
    [
        envelope("NULL", None),
        envelope("BOOLEAN", True),
        envelope("INT64", "-9223372036854775808"),
        envelope("INT64", "9223372036854775807"),
        envelope("UINT64", "18446744073709551615"),
        envelope("DECIMAL", "0.125"),
        envelope("DECIMAL", "-12.5"),
        envelope("FINITE_DOUBLE", 1.25),
        envelope("STRING", "caf\u00e9"),
        envelope("BYTES", "AAEC/w=="),
        envelope("UTC_DATETIME", "2026-08-17T20:30:45.123456Z"),
        envelope("REL_DURATION", "-500000000"),
        envelope("LIST", [envelope("BOOLEAN", False), envelope("INT64", "7")]),
        envelope(
            "MAP",
            [
                {"key": "alpha", "value": envelope("STRING", "one")},
                {"key": "beta", "value": envelope("UINT64", "2")},
            ],
        ),
    ],
)
def test_type_matrix_round_trips_exact_canonical_bytes(value) -> None:
    raw = canonical_typed_value_bytes(value)
    assert decode_typed_value(raw) == value
    assert canonical_typed_value_bytes(decode_typed_value(raw)) == raw
    assert typed_value_digest(value) == hashlib.sha256(raw).hexdigest()


def test_canonical_golden_is_stable_and_uses_no_ascii_escape_for_valid_text() -> None:
    value = envelope(
        "MAP",
        [
            {"key": "a", "value": envelope("INT64", "1")},
            {"key": "z", "value": envelope("STRING", "caf\u00e9")},
        ],
    )
    assert canonical_typed_value_bytes(value) == (
        b'{"schema_version":"spell.data.value/1","type":"MAP","value":['
        b'{"key":"a","value":{"schema_version":"spell.data.value/1",'
        b'"type":"INT64","value":"1"}},{"key":"z","value":'
        b'{"schema_version":"spell.data.value/1","type":"STRING",'
        b'"value":"caf\xc3\xa9"}}]}'
    )


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ({"schema_version": SCHEMA_VERSION, "type": "NULL"}, "REJECTED"),
        (
            {
                "schema_version": SCHEMA_VERSION,
                "type": "NULL",
                "value": None,
                "extra": False,
            },
            "REJECTED",
        ),
        (envelope("UNKNOWN", None), "TYPE_MISMATCH"),
        (envelope("NULL", False), "TYPE_MISMATCH"),
        (envelope("BOOLEAN", 1), "TYPE_MISMATCH"),
        (envelope("INT64", "+1"), "NON_CANONICAL"),
        (envelope("INT64", "01"), "NON_CANONICAL"),
        (envelope("INT64", "9223372036854775808"), "VALUE_OUT_OF_RANGE"),
        (envelope("UINT64", "-1"), "NON_CANONICAL"),
        (envelope("UINT64", "18446744073709551616"), "VALUE_OUT_OF_RANGE"),
        (envelope("DECIMAL", "1.0"), "NON_CANONICAL"),
        (envelope("DECIMAL", "1e2"), "NON_CANONICAL"),
        (envelope("DECIMAL", "-0"), "NON_CANONICAL"),
        (envelope("FINITE_DOUBLE", 1), "TYPE_MISMATCH"),
        (envelope("FINITE_DOUBLE", float("inf")), "VALUE_OUT_OF_RANGE"),
        (envelope("FINITE_DOUBLE", -0.0), "NON_CANONICAL"),
        (envelope("STRING", "e\u0301"), "NON_CANONICAL"),
        (envelope("BYTES", "AAE"), "NON_CANONICAL"),
        (envelope("UTC_DATETIME", "2026-08-17T20:30:45Z"), "NON_CANONICAL"),
        (envelope("UTC_DATETIME", "2026-08-17T20:30:60.000000Z"), "VALUE_OUT_OF_RANGE"),
        (envelope("REL_DURATION", "1ns"), "NON_CANONICAL"),
        (
            envelope(
                "MAP",
                [
                    {"key": "b", "value": envelope("NULL", None)},
                    {"key": "a", "value": envelope("NULL", None)},
                ],
            ),
            "NON_CANONICAL",
        ),
        (
            envelope(
                "MAP",
                [
                    {"key": "a", "value": envelope("NULL", None)},
                    {"key": "a", "value": envelope("NULL", None)},
                ],
            ),
            "NON_CANONICAL",
        ),
    ],
)
def test_invalid_values_fail_with_safe_outcome(value, code: str) -> None:
    with pytest.raises(TypedValueError) as raised:
        validate_typed_value(value)
    assert raised.value.code == code


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"spell.data.value/1","type":"NULL","value":null,"value":null}',
        b'\xef\xbb\xbf{"schema_version":"spell.data.value/1","type":"NULL","value":null}',
        b'{"schema_version":"spell.data.value/1","type":"FINITE_DOUBLE","value":NaN}',
        b'{"schema_version":"spell.data.value/1","type":"NULL","value":null} trailing',
        b' {"schema_version":"spell.data.value/1","type":"NULL","value":null}',
        b'{"type":"NULL","schema_version":"spell.data.value/1","value":null}',
    ],
)
def test_strict_decoder_rejects_duplicate_nonfinite_trailing_and_noncanonical_json(
    raw: bytes,
) -> None:
    with pytest.raises(TypedValueError):
        decode_typed_value(raw)


def test_depth_node_and_collection_limits_are_enforced_before_persistence() -> None:
    too_deep = envelope("NULL", None)
    for _ in range(8):
        too_deep = envelope("LIST", [too_deep])
    with pytest.raises(TypedValueError, match="depth") as depth_error:
        validate_typed_value(too_deep)
    assert depth_error.value.code == "LIMIT_EXCEEDED"

    with pytest.raises(TypedValueError, match="item limit"):
        validate_typed_value(
            envelope("LIST", [envelope("NULL", None)] * 1025)
        )

    branch = envelope("LIST", [envelope("NULL", None)] * 4)
    with pytest.raises(TypedValueError, match="node count"):
        validate_typed_value(envelope("LIST", [branch] * 1024))

    oversized = base64.b64encode(b"x" * 1_048_577).decode("ascii")
    with pytest.raises(TypedValueError, match="decoded limit"):
        validate_typed_value(envelope("BYTES", oversized))


def test_stored_digest_is_verified_before_decode_and_corruption_is_not_returned() -> None:
    raw = canonical_typed_value_bytes(envelope("STRING", "trusted"))
    digest = hashlib.sha256(raw).hexdigest()
    assert decode_stored_typed_value(raw, digest) == envelope("STRING", "trusted")
    with pytest.raises(CorruptValueError) as raised:
        decode_stored_typed_value(raw.replace(b"trusted", b"changed"), digest)
    assert raised.value.code == "CORRUPT_VALUE"
    with pytest.raises(CorruptValueError):
        decode_stored_typed_value(raw, "not-a-digest")


def test_explicit_native_construction_and_inert_decode_are_lossless() -> None:
    values = {
        "integer": make_typed_value("INT64", -7),
        "decimal": make_typed_value("DECIMAL", Decimal("12.5000")),
        "bytes": make_typed_value("BYTES", b"\x00\xff"),
        "time": make_typed_value(
            "UTC_DATETIME", datetime(2026, 8, 17, 20, 0, tzinfo=timezone.utc)
        ),
    }
    combined = make_typed_value("MAP", values)
    decoded = typed_value_to_python(combined)
    assert decoded == {
        "bytes": b"\x00\xff",
        "decimal": Decimal("12.5"),
        "integer": -7,
        "time": datetime(2026, 8, 17, 20, 0, tzinfo=timezone.utc),
    }


def test_native_decimal_construction_is_exact_beyond_context_precision() -> None:
    value = Decimal("123456789012345678901234567890123456789.12000")
    encoded = make_typed_value("DECIMAL", value)

    assert encoded["value"] == "123456789012345678901234567890123456789.12"
    assert typed_value_to_python(encoded) == value
    assert make_typed_value("DECIMAL", Decimal("1E+3"))["value"] == "1000"
    assert make_typed_value("DECIMAL", Decimal("1.2300E-3"))["value"] == "0.00123"


def test_contract_integer_wire_form_crosses_32_bit_without_json_number_loss() -> None:
    value = (1 << 31) + 17
    assert contract_integer_to_wire(value, allow_zero=False, label="revision") == (
        "2147483665"
    )
    assert contract_integer_from_wire(
        "2147483665", allow_zero=False, label="revision"
    ) == value
    assert contract_integer_to_wire((1 << 63) - 1) == "9223372036854775807"
    for invalid in ("", "00", "01", "+1", "-1", 1):
        with pytest.raises(TypedValueError, match="canonical decimal"):
            contract_integer_from_wire(invalid)  # type: ignore[arg-type]
    with pytest.raises(TypedValueError, match="signed 64-bit"):
        contract_integer_to_wire(1 << 63)
