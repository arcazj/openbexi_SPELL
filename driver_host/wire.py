"""Bounded raw-wire validation before protobuf request deserialization."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

import grpc
from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf.message import DecodeError

from spell.driver.v1 import driver_pb2


MAX_MESSAGE_BYTES = 64 * 1024
MAX_WIRE_DEPTH = 16
MAX_FIELD_OCCURRENCES = 4_096
LOGGER = logging.getLogger("spell.driver.wire")

_VARINT_TYPES = {
    FieldDescriptor.TYPE_INT64,
    FieldDescriptor.TYPE_UINT64,
    FieldDescriptor.TYPE_INT32,
    FieldDescriptor.TYPE_BOOL,
    FieldDescriptor.TYPE_UINT32,
    FieldDescriptor.TYPE_ENUM,
    FieldDescriptor.TYPE_SINT32,
    FieldDescriptor.TYPE_SINT64,
}
_FIXED64_TYPES = {FieldDescriptor.TYPE_DOUBLE, FieldDescriptor.TYPE_FIXED64, FieldDescriptor.TYPE_SFIXED64}
_LENGTH_TYPES = {
    FieldDescriptor.TYPE_STRING,
    FieldDescriptor.TYPE_MESSAGE,
    FieldDescriptor.TYPE_BYTES,
}
_FIXED32_TYPES = {FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_FIXED32, FieldDescriptor.TYPE_SFIXED32}
_PACKABLE_TYPES = _VARINT_TYPES | _FIXED64_TYPES | _FIXED32_TYPES


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise DecodeError("truncated varint")
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, offset
    raise DecodeError("varint exceeds 64 bits")


def _expected_wire_type(field: FieldDescriptor) -> int:
    if field.type in _VARINT_TYPES:
        return 0
    if field.type in _FIXED64_TYPES:
        return 1
    if field.type in _LENGTH_TYPES:
        return 2
    if field.type in _FIXED32_TYPES:
        return 5
    raise DecodeError("unsupported protobuf field type")


def _validate_packed(payload: bytes, field: FieldDescriptor) -> None:
    offset = 0
    wire_type = _expected_wire_type(field)
    while offset < len(payload):
        if wire_type == 0:
            value, offset = _varint(payload, offset)
            if field.type == FieldDescriptor.TYPE_ENUM and value not in field.enum_type.values_by_number:
                raise DecodeError("unknown enum value")
        elif wire_type == 1:
            offset += 8
        elif wire_type == 5:
            offset += 4
        else:
            raise DecodeError("invalid packed field type")
        if offset > len(payload):
            raise DecodeError("truncated packed field")


def validate_protobuf_wire(
    data: bytes,
    descriptor: Descriptor,
    *,
    depth: int = 0,
) -> None:
    """Reject ambiguous or unbounded encodings before protobuf normalizes them."""

    if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_BYTES:
        raise DecodeError("protobuf request exceeds the bounded size")
    if depth > MAX_WIRE_DEPTH:
        raise DecodeError("protobuf request exceeds the nesting limit")

    offset = 0
    occurrences = 0
    singular_values: dict[int, bytes] = {}
    oneof_fields: dict[str, int] = {}
    while offset < len(data):
        occurrences += 1
        if occurrences > MAX_FIELD_OCCURRENCES:
            raise DecodeError("protobuf request has too many fields")
        key, offset = _varint(data, offset)
        field_number = key >> 3
        wire_type = key & 7
        if field_number < 1 or wire_type not in {0, 1, 2, 5}:
            raise DecodeError("protobuf request has an invalid field key")

        value_start = offset
        numeric_value: int | None = None
        payload: bytes | None = None
        if wire_type == 0:
            numeric_value, offset = _varint(data, offset)
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            length, offset = _varint(data, offset)
            if length > MAX_MESSAGE_BYTES or offset + length > len(data):
                raise DecodeError("protobuf request has a truncated field")
            payload = data[offset : offset + length]
            offset += length
        else:
            offset += 4
        if offset > len(data):
            raise DecodeError("protobuf request has a truncated field")

        field = descriptor.fields_by_number.get(field_number)
        if field is None:
            # Unknown fields are retained for protobuf minor-version compatibility.
            continue
        expected_wire_type = _expected_wire_type(field)
        packed = (
            field.is_repeated
            and field.type in _PACKABLE_TYPES
            and wire_type == 2
        )
        if wire_type != expected_wire_type and not packed:
            raise DecodeError("protobuf field uses the wrong wire type")
        if packed:
            assert payload is not None
            _validate_packed(payload, field)
        elif field.type == FieldDescriptor.TYPE_ENUM:
            assert numeric_value is not None
            if numeric_value not in field.enum_type.values_by_number:
                raise DecodeError("unknown enum value")
        elif field.type == FieldDescriptor.TYPE_MESSAGE:
            assert payload is not None
            validate_protobuf_wire(payload, field.message_type, depth=depth + 1)

        encoded_value = data[value_start:offset]
        if not field.is_repeated:
            previous = singular_values.setdefault(field_number, encoded_value)
            if previous != encoded_value:
                raise DecodeError("conflicting duplicate singular field")
        if field.containing_oneof is not None:
            oneof_name = field.containing_oneof.full_name
            previous_number = oneof_fields.setdefault(oneof_name, field_number)
            if previous_number != field_number:
                raise DecodeError("conflicting oneof fields")


_REQUEST_DESCRIPTORS = {
    f"/{service.full_name}/{method.name}": method.input_type
    for service in driver_pb2.DESCRIPTOR.services_by_name.values()
    for method in service.methods
}


@dataclass(frozen=True)
class _InvalidWireRequest:
    pass


class StrictDriverWireInterceptor(grpc.aio.ServerInterceptor):
    """Turn raw-wire ambiguity into one bounded INVALID_ARGUMENT response."""

    def __init__(self) -> None:
        self.audit_counts: Counter[str] = Counter()

    async def intercept_service(self, continuation: Any, handler_call_details: Any) -> Any:
        handler = await continuation(handler_call_details)
        descriptor = _REQUEST_DESCRIPTORS.get(handler_call_details.method)
        if handler is None or descriptor is None or handler.unary_unary is None:
            return handler

        parser: Callable[[bytes], Any] = handler.request_deserializer

        def strict_deserializer(data: bytes) -> Any:
            try:
                validate_protobuf_wire(data, descriptor)
                return parser(data)
            except (DecodeError, TypeError, ValueError):
                return _InvalidWireRequest()

        async def bounded_unary_unary(request: Any, context: Any) -> Any:
            if isinstance(request, _InvalidWireRequest):
                self.audit_counts["wire_rejected"] += 1
                LOGGER.warning("driver RPC wire rejected reason=invalid_bounded_request")
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "invalid bounded driver request",
                )
            return await handler.unary_unary(request, context)

        return grpc.unary_unary_rpc_method_handler(
            bounded_unary_unary,
            request_deserializer=strict_deserializer,
            response_serializer=handler.response_serializer,
        )


__all__ = [
    "MAX_FIELD_OCCURRENCES",
    "MAX_MESSAGE_BYTES",
    "MAX_WIRE_DEPTH",
    "StrictDriverWireInterceptor",
    "validate_protobuf_wire",
]
