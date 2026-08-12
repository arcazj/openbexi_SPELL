from __future__ import annotations

import asyncio
from types import SimpleNamespace

import grpc
import pytest
from google.protobuf.message import DecodeError

from spell.driver.v1 import driver_pb2

from driver_host.wire import (
    MAX_FIELD_OCCURRENCES,
    MAX_MESSAGE_BYTES,
    MAX_WIRE_DEPTH,
    StrictDriverWireInterceptor,
    validate_protobuf_wire,
)


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _length_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _varint_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def test_conflicting_duplicate_singular_field_is_rejected_before_normalization() -> None:
    invalid = driver_pb2.RequestIdentity(server_profile_id="invalid").SerializeToString()
    valid_override = _length_field(2, b"local-synthetic")
    ambiguous = invalid + valid_override

    assert driver_pb2.RequestIdentity.FromString(ambiguous).server_profile_id == (
        "local-synthetic"
    )
    with pytest.raises(DecodeError, match="conflicting duplicate"):
        validate_protobuf_wire(ambiguous, driver_pb2.RequestIdentity.DESCRIPTOR)

    exact = _length_field(2, b"local-synthetic")
    validate_protobuf_wire(exact + exact, driver_pb2.RequestIdentity.DESCRIPTOR)


def test_additive_unknown_fields_are_accepted_but_unknown_enums_are_rejected() -> None:
    request = driver_pb2.HealthRequest().SerializeToString()
    additive_unknown = request + _length_field(99, b"future-minor-field")
    validate_protobuf_wire(additive_unknown, driver_pb2.HealthRequest.DESCRIPTOR)
    decoded = driver_pb2.HealthRequest.FromString(additive_unknown)
    assert decoded.identity == driver_pb2.RequestIdentity()
    assert decoded.SerializeToString() == additive_unknown

    unknown_reason = _varint_field(2, 999)
    with pytest.raises(DecodeError, match="unknown enum"):
        validate_protobuf_wire(
            unknown_reason,
            driver_pb2.DetachExecutionRequest.DESCRIPTOR,
        )


def test_wire_size_depth_occurrence_and_truncation_limits_fail_closed() -> None:
    with pytest.raises(DecodeError, match="bounded size"):
        validate_protobuf_wire(
            b"x" * (MAX_MESSAGE_BYTES + 1), driver_pb2.HealthRequest.DESCRIPTOR
        )
    with pytest.raises(DecodeError, match="nesting"):
        validate_protobuf_wire(
            b"", driver_pb2.HealthRequest.DESCRIPTOR, depth=MAX_WIRE_DEPTH + 1
        )
    repeated_unknown = _varint_field(99, 0) * (MAX_FIELD_OCCURRENCES + 1)
    with pytest.raises(DecodeError, match="too many fields"):
        validate_protobuf_wire(repeated_unknown, driver_pb2.HealthRequest.DESCRIPTOR)
    with pytest.raises(DecodeError, match="truncated"):
        validate_protobuf_wire(b"\x0a\x08short", driver_pb2.HealthRequest.DESCRIPTOR)


def test_aio_interceptor_replaces_the_handler_raw_request_deserializer() -> None:
    calls: list[object] = []

    async def behavior(request, _context):
        calls.append(request)
        return driver_pb2.HealthResponse()

    original = grpc.unary_unary_rpc_method_handler(
        behavior,
        request_deserializer=driver_pb2.HealthRequest.FromString,
        response_serializer=driver_pb2.HealthResponse.SerializeToString,
    )

    async def continuation(_details):
        return original

    async def scenario() -> None:
        interceptor = StrictDriverWireInterceptor()
        wrapped = await interceptor.intercept_service(
            continuation,
            SimpleNamespace(
                method="/spell.driver.v1.DriverInfrastructureService/Health"
            ),
        )
        first = driver_pb2.RequestIdentity(
            server_profile_id="first"
        ).SerializeToString()
        second = driver_pb2.RequestIdentity(
            server_profile_id="second"
        ).SerializeToString()
        ambiguous = _length_field(1, first) + _length_field(1, second)

        invalid = wrapped.request_deserializer(ambiguous)
        assert type(invalid).__name__ == "_InvalidWireRequest"
        assert calls == []

        valid = driver_pb2.HealthRequest(
            identity=driver_pb2.RequestIdentity(server_profile_id="only")
        )
        parsed = wrapped.request_deserializer(valid.SerializeToString())
        assert parsed == valid
        await wrapped.unary_unary(parsed, None)
        assert calls == [valid]

    asyncio.run(scenario())
