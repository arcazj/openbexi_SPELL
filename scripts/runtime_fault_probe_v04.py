#!/usr/bin/env python3
"""Bounded in-namespace probes used by the v0.4 fault collector."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import socket
import struct
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import grpc


MAX_CAPTURED_PACKETS = 4_096
MAX_ENDPOINT_TUPLES = 128
MAX_API_RESPONSE_BYTES = 64 * 1024
DRIVER_PROJECTION_URL = "http://spell-api:8000/api/v1/drivers"


def _resolve(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def _connect_code(host: str, port: int) -> int | str:
    addresses = _resolve(host)
    if not addresses:
        return "DNS_UNAVAILABLE"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        return sock.connect_ex((host, port))
    except OSError as exc:
        return f"OSERROR_{exc.errno or 0}"
    finally:
        sock.close()


def reachability() -> dict[str, Any]:
    targets = {
        "gateway_listener": ("spell-driver", 50051),
        "reverse_api": ("backend", 8000),
        "database": ("postgres", 5432),
        "proxy": ("proxy", 8080),
        "host_alias": ("host.docker.internal", 80),
        "loopback_api": ("127.0.0.1", 8000),
        "loopback_proxy": ("127.0.0.1", 8080),
    }
    observations = {
        name: {
            "addresses": _resolve(host),
            "connect_code": _connect_code(host, port),
            "port": port,
        }
        for name, (host, port) in targets.items()
    }
    return {
        "observations": observations,
        "gateway_listener_reachable": observations["gateway_listener"][
            "connect_code"
        ]
        == 0,
        "reverse_api_reachable": observations["reverse_api"]["connect_code"] == 0,
        "database_resolved": bool(observations["database"]["addresses"]),
        "proxy_resolved": bool(observations["proxy"]["addresses"]),
        "host_alias_resolved": bool(observations["host_alias"]["addresses"]),
    }


def _packet_tuple(frame: bytes) -> tuple[str, str, str, int, int] | None:
    if len(frame) < 14:
        return None
    offset = 14
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ether_type == 0x0800:
        if len(frame) < offset + 20:
            return None
        header_length = (frame[offset] & 0x0F) * 4
        protocol = frame[offset + 9]
        source = socket.inet_ntop(socket.AF_INET, frame[offset + 12 : offset + 16])
        destination = socket.inet_ntop(
            socket.AF_INET, frame[offset + 16 : offset + 20]
        )
        transport = offset + header_length
        family = "ipv4"
    elif ether_type == 0x86DD:
        if len(frame) < offset + 40:
            return None
        protocol = frame[offset + 6]
        source = socket.inet_ntop(socket.AF_INET6, frame[offset + 8 : offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, frame[offset + 24 : offset + 40])
        transport = offset + 40
        family = "ipv6"
    else:
        return None
    if protocol not in {6, 17} or len(frame) < transport + 4:
        return None
    source_port, destination_port = struct.unpack("!HH", frame[transport : transport + 4])
    return family, source, destination, source_port, destination_port


def packet_capture(seconds: float, phase: str) -> dict[str, Any]:
    if not 0.5 <= seconds <= 15:
        raise ValueError("capture duration is outside the bounded range")
    local_addresses = set(_resolve(socket.gethostname()))
    gateway_addresses = set(_resolve("backend"))
    approved_addresses = local_addresses | gateway_addresses | {
        "127.0.0.1",
        "127.0.0.11",
        "::1",
    }
    counts: Counter[tuple[str, str, str, int, int]] = Counter()
    captured = 0
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.settimeout(0.2)
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and captured < MAX_CAPTURED_PACKETS:
            try:
                frame = sock.recv(65_535)
            except socket.timeout:
                continue
            captured += 1
            observed = _packet_tuple(frame)
            if observed is not None and len(counts) < MAX_ENDPOINT_TUPLES:
                counts[observed] += 1
    finally:
        sock.close()

    endpoints = [
        {
            "family": item[0],
            "source": item[1],
            "destination": item[2],
            "source_port": item[3],
            "destination_port": item[4],
            "packet_count": count,
        }
        for item, count in sorted(counts.items())
    ]

    def approved(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return value in approved_addresses or address.is_loopback

    unapproved = {
        value
        for item in endpoints
        for value in (item["source"], item["destination"])
        if not approved(value)
    }
    return {
        "phase": phase,
        "capture_seconds": seconds,
        "captured_frame_count": captured,
        "endpoint_tuple_count": len(endpoints),
        "endpoint_tuples": endpoints,
        "approved_address_count": len(approved_addresses),
        "unapproved_endpoint_count": len(unapproved),
        "capture_truncated": captured >= MAX_CAPTURED_PACKETS
        or len(counts) >= MAX_ENDPOINT_TUPLES,
    }


def _credentials(directory: Path, *, include_client: bool) -> grpc.ChannelCredentials:
    root = (directory / "ca.crt").read_bytes()
    if not include_client:
        return grpc.ssl_channel_credentials(root_certificates=root)
    return grpc.ssl_channel_credentials(
        root_certificates=root,
        private_key=(directory / "client.key").read_bytes(),
        certificate_chain=(directory / "client.crt").read_bytes(),
    )


async def _raw_status(
    target: str,
    credentials: grpc.ChannelCredentials,
    path: str,
    *,
    metadata: tuple[tuple[str, str], ...] = (),
) -> str:
    channel = grpc.aio.secure_channel(
        target,
        credentials,
        options=(("grpc.ssl_target_name_override", "spell-driver"),),
    )
    call = channel.unary_unary(
        path,
        request_serializer=lambda value: value,
        response_deserializer=lambda value: value,
    )
    try:
        await call(b"", timeout=2, metadata=metadata)
        return "OK"
    except grpc.aio.AioRpcError as exc:
        return exc.code().name
    finally:
        await channel.close()


async def grpc_security(target: str, credential_directory: Path) -> dict[str, Any]:
    authenticated = _credentials(credential_directory, include_client=True)
    jwt_only = _credentials(credential_directory, include_client=False)
    bearer = "Bearer runtime-token-value-is-never-reported"
    return {
        "reflection_status": await _raw_status(
            target,
            authenticated,
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        ),
        "direct_administration_status": await _raw_status(
            target,
            authenticated,
            "/spell.driver.v1.DriverAdministration/RotateCredentials",
        ),
        "unauthorized_metadata_status": await _raw_status(
            target,
            authenticated,
            "/spell.driver.v1.DriverInfrastructureService/Health",
            metadata=(("authorization", bearer),),
        ),
        "jwt_without_mtls_status": await _raw_status(
            target,
            jwt_only,
            "/spell.driver.v1.DriverInfrastructureService/Health",
            metadata=(
                ("authorization", bearer),
                ("x-spell-contract-major", "1"),
                ("x-spell-credential-epoch", "1"),
            ),
        ),
    }


async def credential_status(target: str, credential_directory: Path) -> dict[str, Any]:
    status = await _raw_status(
        target,
        _credentials(credential_directory, include_client=True),
        "/spell.driver.v1.DriverAdministration/CredentialProbe",
    )
    return {"tls_authenticated_unknown_rpc_status": status}


def _projection_observation(token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        DRIVER_PROJECTION_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Host": "127.0.0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            data = response.read(MAX_API_RESPONSE_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_API_RESPONSE_BYTES + 1)
        return {"http_status": exc.code, "response_bytes": len(data)}
    if len(data) > MAX_API_RESPONSE_BYTES:
        raise ValueError("driver projection response exceeded the bounded size")
    payload = json.loads(data)
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError("driver projection response has an unexpected shape")
    driver = items[0]
    return {
        "http_status": status,
        "driver_count": 1,
        "driver_id": driver.get("id"),
        "driver_state": driver.get("state"),
        "credential_epoch": driver.get("credential_epoch"),
        "last_observed_at": driver.get("last_observed_at"),
        "stale": driver.get("stale"),
        "staleness": driver.get("staleness"),
    }


def api_projection(
    *,
    timeout_seconds: float,
    expected_status: int,
    must_advance_from: str | None,
) -> dict[str, Any]:
    if not 0.5 <= timeout_seconds <= 30:
        raise ValueError("API projection timeout is outside the bounded range")
    token = os.environ.get("SPELL_API_BEARER_TOKEN")
    if not token:
        raise ValueError("SPELL_API_BEARER_TOKEN is required")
    baseline: datetime | None = None
    if must_advance_from is not None:
        baseline = datetime.fromisoformat(must_advance_from.replace("Z", "+00:00"))
        if baseline.utcoffset() is None:
            raise ValueError("projection baseline timestamp must include an offset")

    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = _projection_observation(token)
        if latest["http_status"] == expected_status:
            if baseline is None:
                return latest
            observed_value = latest.get("last_observed_at")
            if isinstance(observed_value, str):
                observed = datetime.fromisoformat(
                    observed_value.replace("Z", "+00:00")
                )
                if observed.utcoffset() is not None and observed > baseline:
                    return {**latest, "observation_advanced": True}
        time.sleep(0.2)
    if must_advance_from is not None:
        raise RuntimeError("driver projection observation did not advance after recovery")
    raise RuntimeError(
        f"driver projection did not return expected HTTP status {expected_status}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("reachability")
    capture = subparsers.add_parser("packet-capture")
    capture.add_argument("--seconds", type=float, required=True)
    capture.add_argument("--phase", choices=("nominal", "fault"), required=True)
    security = subparsers.add_parser("grpc-security")
    security.add_argument("--target", default="spell-driver:50051")
    security.add_argument("--credential-dir", type=Path, required=True)
    credential = subparsers.add_parser("credential-status")
    credential.add_argument("--target", default="spell-driver:50051")
    credential.add_argument("--credential-dir", type=Path, required=True)
    projection = subparsers.add_parser("api-projection")
    projection.add_argument("--timeout-seconds", type=float, default=5.0)
    projection.add_argument("--expected-status", type=int, choices=(200, 500), required=True)
    projection.add_argument("--must-advance-from")
    args = parser.parse_args()

    if args.command == "reachability":
        result = reachability()
    elif args.command == "packet-capture":
        result = packet_capture(args.seconds, args.phase)
    elif args.command == "grpc-security":
        result = asyncio.run(grpc_security(args.target, args.credential_dir))
    elif args.command == "credential-status":
        result = asyncio.run(credential_status(args.target, args.credential_dir))
    else:
        result = api_projection(
            timeout_seconds=args.timeout_seconds,
            expected_status=args.expected_status,
            must_advance_from=args.must_advance_from,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
