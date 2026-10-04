"""CCSDS 133.0-B-2 primary header with the declared DSS/1 binary payload.

Application CRC and tagged data are project conventions, not a claim about a
vendor Cortex, PUS, transfer frames, CLTUs, or a physical spacecraft link.
"""
from __future__ import annotations

import binascii
import math
import socket
import struct
import time
from dataclasses import dataclass

TC_APID, TM_APID, ACK_APID = 100, 101, 102
MAX_PACKET_BYTES = 65542
MAX_DEPTH, MAX_NODES = 12, 2048
PREFIX = b"DSS\x01"


class PacketError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    packet_type: int
    apid: int
    sequence: int
    body: dict


def _encode(value, depth=0, budget=None):
    budget = [MAX_NODES] if budget is None else budget
    budget[0] -= 1
    if depth > MAX_DEPTH or budget[0] < 0:
        raise PacketError("binary value exceeds nesting/node bounds")
    if value is None: return b"\x00"
    if type(value) is bool: return b"\x01" + bytes([value])
    if type(value) is int:
        if -(1 << 63) <= value < 0: return b"\x02" + struct.pack(">q", value)
        if 0 <= value < (1 << 64): return b"\x03" + struct.pack(">Q", value)
        raise PacketError("integer outside 64-bit bounds")
    if type(value) is float:
        if not math.isfinite(value): raise PacketError("nonfinite scalar")
        return b"\x04" + struct.pack(">d", value)
    if type(value) in {str, bytes}:
        raw = value.encode("utf-8") if type(value) is str else value
        if len(raw) > 8192: raise PacketError("string/bytes outside bounds")
        return bytes([5 if type(value) is str else 6]) + struct.pack(">H", len(raw)) + raw
    if type(value) is list:
        if len(value) > 256: raise PacketError("list outside bounds")
        return b"\x07" + struct.pack(">H", len(value)) + b"".join(_encode(v, depth+1, budget) for v in value)
    if type(value) is dict:
        if len(value) > 128 or any(type(k) is not str for k in value): raise PacketError("map outside bounds")
        return b"\x08" + struct.pack(">H", len(value)) + b"".join(
            _encode(k, depth+1, budget) + _encode(value[k], depth+1, budget) for k in sorted(value))
    raise PacketError("unsupported binary type")


class _Reader:
    def __init__(self, raw): self.raw, self.index, self.nodes = raw, 0, 0

    def take(self, length):
        if self.index + length > len(self.raw): raise PacketError("truncated binary value")
        value = self.raw[self.index:self.index+length]
        self.index += length
        return value

    def value(self, depth=0):
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes > MAX_NODES: raise PacketError("binary value exceeds bounds")
        tag = self.take(1)[0]
        if tag == 0: return None
        if tag == 1:
            value = self.take(1)[0]
            if value not in {0, 1}: raise PacketError("noncanonical boolean")
            return bool(value)
        if tag in {2, 3, 4}:
            value = struct.unpack({2:">q",3:">Q",4:">d"}[tag], self.take(8))[0]
            if tag == 2 and value >= 0: raise PacketError("noncanonical signed integer")
            if tag == 4 and not math.isfinite(value): raise PacketError("nonfinite scalar")
            return value
        if tag in {5, 6}:
            length = struct.unpack(">H", self.take(2))[0]
            if length > 8192: raise PacketError("string/bytes outside bounds")
            raw = self.take(length)
            if tag == 6: return raw
            try: return raw.decode("utf-8", "strict")
            except UnicodeError as exc: raise PacketError("invalid UTF-8 scalar") from exc
        if tag in {7, 8}:
            length = struct.unpack(">H", self.take(2))[0]
            if length > (256 if tag == 7 else 128): raise PacketError("container outside bounds")
            if tag == 7: return [self.value(depth+1) for _ in range(length)]
            result, previous = {}, None
            for _ in range(length):
                key = self.value(depth+1)
                if type(key) is not str or (previous is not None and key <= previous):
                    raise PacketError("unordered or duplicate binary map key")
                result[key], previous = self.value(depth+1), key
            return result
        raise PacketError("unknown binary type tag")


def encode_packet(packet_type: int, apid: int, sequence: int, body: dict) -> bytes:
    if (type(packet_type) is not int or packet_type not in {0,1} or type(apid) is not int
            or not 0 <= apid < 2047 or type(sequence) is not int or not 0 <= sequence < 16384
            or type(body) is not dict):
        raise PacketError("invalid packet header/body")
    payload = PREFIX + _encode(body)
    if len(payload) + 2 > 65536: raise PacketError("packet exceeds CCSDS length")
    header = struct.pack(">HHH", (packet_type << 12) | (1 << 11) | apid, 0xc000 | sequence, len(payload)+1)
    raw = header + payload
    return raw + struct.pack(">H", binascii.crc_hqx(raw, 0xffff))


def decode_packet(raw: bytes) -> Packet:
    if type(raw) is not bytes or not 13 <= len(raw) <= MAX_PACKET_BYTES: raise PacketError("packet length outside bounds")
    first, second, length = struct.unpack(">HHH", raw[:6])
    if first >> 13 != 0 or not first & 0x800 or second >> 14 != 3:
        raise PacketError("unsupported packet version/secondary header/segmentation")
    if len(raw) != length + 7: raise PacketError("CCSDS length differs from bytes")
    if binascii.crc_hqx(raw[:-2], 0xffff) != struct.unpack(">H", raw[-2:])[0]: raise PacketError("application CRC mismatch")
    if raw[6:10] != PREFIX: raise PacketError("DSS secondary-header profile differs")
    reader = _Reader(raw[10:-2])
    body = reader.value()
    if type(body) is not dict or reader.index != len(reader.raw): raise PacketError("trailing/nonobject packet payload")
    return Packet((first >> 12) & 1, first & 0x7ff, second & 0x3fff, body)


def encode_tc(body: dict, sequence: int = 0) -> bytes:
    return encode_packet(1, TC_APID, sequence, body)


def decode_tc(raw: bytes) -> dict:
    packet = decode_packet(raw)
    if packet.packet_type != 1 or packet.apid != TC_APID: raise PacketError("not a DSS TC packet")
    return packet.body


def encode_tm(body: dict, sequence: int = 0, ack: bool = False) -> bytes:
    return encode_packet(0, ACK_APID if ack else TM_APID, sequence, body)


def decode_tm(raw: bytes) -> dict:
    packet = decode_packet(raw)
    if packet.packet_type != 0 or packet.apid not in {TM_APID,ACK_APID}: raise PacketError("not a DSS telemetry/ack packet")
    return packet.body


def recv_packet(connection: socket.socket, timeout: float | None = None) -> bytes:
    original_timeout = connection.gettimeout()
    lifetime = timeout if timeout is not None else (original_timeout if original_timeout else 5.0)
    if type(lifetime) not in {int,float} or not math.isfinite(lifetime) or not 0 < lifetime <= 60:
        raise PacketError("aggregate packet deadline is invalid")
    deadline = time.monotonic() + lifetime
    def exact(length):
        result = bytearray()
        while len(result) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError("aggregate Space Packet receive deadline expired")
            connection.settimeout(remaining)
            part = connection.recv(length-len(result))
            if not part: raise PacketError("TCP closed before a complete Space Packet")
            result.extend(part)
        return bytes(result)
    try:
        header = exact(6)
        length = struct.unpack(">H", header[4:])[0] + 1
        return header + exact(length)
    finally:
        connection.settimeout(original_timeout)
