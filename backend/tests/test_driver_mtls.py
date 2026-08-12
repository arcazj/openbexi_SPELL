from __future__ import annotations

import asyncio
import multiprocessing
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import AsyncIterator

import grpc
import pytest

from backend import driver_client as driver_client_module
from backend.driver_client import DriverClient
from backend.driver_domain import CONTRACT_MAJOR_METADATA, CREDENTIAL_EPOCH_METADATA
from driver_host.config import (
    DEFAULT_CLIENT_COMMON_NAME,
    DEFAULT_CLIENT_SAN,
    HostConfig,
)
from driver_host.pki import PkiBundle, generate_bundle
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.security import DriverAuthorizationInterceptor
from driver_host.server import build_server
from driver_host.domain import Method
from spell.driver.configuration import context_binding_digest
from spell.driver.v1 import driver_pb2, driver_pb2_grpc


_AUTHORITY_OPTIONS = (
    ("grpc.ssl_target_name_override", "spell-driver"),
    ("grpc.default_authority", "spell-driver"),
    ("grpc.enable_retries", 0),
)


class _RecordingHandshakeService(
    driver_pb2_grpc.DriverInfrastructureServiceServicer
):
    def __init__(self) -> None:
        self.dispatch_count = 0

    async def Handshake(  # noqa: N802 - generated gRPC method name
        self, request: driver_pb2.HandshakeRequest, context: grpc.aio.ServicerContext
    ) -> driver_pb2.HandshakeResponse:
        del request, context
        self.dispatch_count += 1
        return driver_pb2.HandshakeResponse()


@asynccontextmanager
async def _loopback_server(
    bundle: PkiBundle, config: HostConfig | None = None
) -> AsyncIterator[
    tuple[str, _RecordingHandshakeService, DriverAuthorizationInterceptor]
]:
    authorization = DriverAuthorizationInterceptor(config or HostConfig())
    service = _RecordingHandshakeService()
    server = grpc.aio.server(interceptors=(authorization,))
    driver_pb2_grpc.add_DriverInfrastructureServiceServicer_to_server(
        service, server
    )
    credentials = grpc.ssl_server_credentials(
        ((bundle.server_private_key, bundle.server_certificate),),
        root_certificates=bundle.ca_certificate,
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", credentials)
    assert port > 0
    await server.start()
    try:
        yield f"127.0.0.1:{port}", service, authorization
    finally:
        await server.stop(grace=0)


async def _handshake(
    target: str,
    *,
    root_certificates: bytes | None,
    private_key: bytes | None,
    certificate_chain: bytes | None,
    credential_epoch: str = "1",
) -> driver_pb2.HandshakeResponse:
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )
    channel = grpc.aio.secure_channel(
        target, credentials, options=_AUTHORITY_OPTIONS
    )
    try:
        return await driver_pb2_grpc.DriverInfrastructureServiceStub(
            channel
        ).Handshake(
            driver_pb2.HandshakeRequest(),
            timeout=2,
            metadata=(
                (CONTRACT_MAJOR_METADATA, "1"),
                (CREDENTIAL_EPOCH_METADATA, credential_epoch),
            ),
            wait_for_ready=False,
        )
    finally:
        await channel.close()


async def _assert_transport_rejected(
    target: str,
    service: _RecordingHandshakeService,
    **credentials: bytes | str | None,
) -> grpc.StatusCode:
    with pytest.raises(grpc.aio.AioRpcError) as caught:
        await _handshake(target, **credentials)
    assert service.dispatch_count == 0
    return caught.value.code()


def _write_client_bundle(directory: Path, bundle: PkiBundle) -> tuple[Path, Path, Path]:
    ca_path = directory / "ca.crt"
    cert_path = directory / "client.crt"
    key_path = directory / "client.key"
    ca_path.write_bytes(bundle.ca_certificate)
    cert_path.write_bytes(bundle.client_certificate)
    key_path.write_bytes(bundle.client_private_key)
    key_path.chmod(0o600)
    return ca_path, cert_path, key_path


def _spawn_worker_credential_probe(key_path: str, output: Connection) -> None:
    credential_environment = sorted(
        name
        for name in os.environ
        if name.startswith("SPELL_DRIVER_")
        and any(secret in name for secret in ("KEY", "CERT", "CA", "CREDENTIAL"))
    )
    try:
        output.send(
            {
                "key_exists": Path(key_path).exists(),
                "credential_environment": credential_environment,
            }
        )
    finally:
        output.close()


def _wire_varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _wire_message_field(number: int, value: bytes) -> bytes:
    return _wire_varint((number << 3) | 2) + _wire_varint(len(value)) + value


@asynccontextmanager
async def _strict_wire_loopback_server(
    bundle: PkiBundle, journal_path: Path
) -> AsyncIterator[tuple[str, object, OperationJournal]]:
    config = HostConfig()
    journal = OperationJournal(
        journal_path, config.driver_host_generation, config.journal
    )
    host = SimulatorLifecycleHost(config, journal)
    server, service = build_server(config, host)
    credentials = grpc.ssl_server_credentials(
        ((bundle.server_private_key, bundle.server_certificate),),
        root_certificates=bundle.ca_certificate,
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", credentials)
    assert port > 0
    await server.start()
    try:
        yield f"127.0.0.1:{port}", service, journal
    finally:
        await server.stop(grace=0)
        host.close()


def test_valid_current_gateway_identity_reaches_dispatch() -> None:
    async def run() -> None:
        bundle = generate_bundle()
        async with _loopback_server(bundle) as (target, service, authorization):
            response = await _handshake(
                target,
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            assert isinstance(response, driver_pb2.HandshakeResponse)
            assert service.dispatch_count == 1
            assert authorization.audit_counts == {"authorized": 1}

    asyncio.run(run())


def test_ambiguous_raw_wire_is_rejected_before_dispatch_or_journal_effect(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        bundle = generate_bundle()
        async with _strict_wire_loopback_server(
            bundle, tmp_path / "strict-wire.sqlite"
        ) as (target, service, journal):
            config = service.config
            context_digest = context_binding_digest(
                server_profile_id=config.server_profile_id,
                driver_host_generation=config.driver_host_generation,
                host_profile_digest=config.host_profile_digest,
                schema_version="spell.driver.context-binding/1",
                context_profile_id="synthetic-context",
                synthetic_context_label="strict-wire-context",
            )
            valid_identity = driver_pb2.RequestIdentity(
                contract_version=driver_pb2.ContractVersion(major=1, minor=0),
                server_profile_id=config.server_profile_id,
                driver_host_generation=config.driver_host_generation,
                host_profile_digest=config.host_profile_digest,
                context_id="strict-wire-context",
                context_generation="strict-wire-generation",
                context_binding_digest=context_digest,
                operation_id=str(uuid.uuid4()),
                attempt_id=str(uuid.uuid4()),
                attempt_number=1,
                correlation_id=str(uuid.uuid4()),
                deadline_unix_ms=int(time.time() * 1000) + 10_000,
                credential_epoch=config.credential_epoch,
            )
            request = driver_pb2.OpenContextRequest(
                identity=valid_identity,
                configuration=driver_pb2.ContextBindingConfiguration(
                    schema_version="spell.driver.context-binding/1",
                    context_profile_id="synthetic-context",
                    synthetic_context_label="strict-wire-context",
                    expected_context_binding_digest=context_digest,
                ),
            )
            invalid_identity = driver_pb2.RequestIdentity(
                server_profile_id="invalid-first-value"
            )
            ambiguous = _wire_message_field(
                1, invalid_identity.SerializeToString()
            ) + request.SerializeToString()
            assert driver_pb2.OpenContextRequest.FromString(
                ambiguous
            ).identity == valid_identity

            credentials = grpc.ssl_channel_credentials(
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            channel = grpc.aio.secure_channel(
                target, credentials, options=_AUTHORITY_OPTIONS
            )
            raw_call = channel.unary_unary(
                "/spell.driver.v1.DriverInfrastructureService/OpenContext",
                request_serializer=lambda value: value,
                response_deserializer=driver_pb2.LifecycleOperationResponse.FromString,
            )
            try:
                with pytest.raises(grpc.aio.AioRpcError) as unauthorized:
                    await raw_call(b"\x0a\x08short", timeout=2)
                assert unauthorized.value.code() == grpc.StatusCode.FAILED_PRECONDITION
                assert service.authorization_audit == {"contract_major_rejected": 1}
                assert service.wire_audit == {}

                with pytest.raises(grpc.aio.AioRpcError) as rejected:
                    await raw_call(
                        ambiguous,
                        timeout=2,
                        metadata=(
                            (CONTRACT_MAJOR_METADATA, "1"),
                            (CREDENTIAL_EPOCH_METADATA, "1"),
                        ),
                    )
                assert rejected.value.code() == grpc.StatusCode.INVALID_ARGUMENT
                assert service.authorization_audit == {
                    "contract_major_rejected": 1,
                    "authorized": 1,
                }
                assert service.wire_audit == {"wire_rejected": 1}
                assert service.dispatch_counts[Method.OPEN_CONTEXT.value] == 0
                assert journal.list_operations() == ()
            finally:
                await channel.close()

    asyncio.run(run())


@pytest.mark.parametrize("trust_mode", ("missing-server-ca", "wrong-server-ca"))
def test_missing_or_wrong_server_ca_fails_before_dispatch(trust_mode: str) -> None:
    async def run() -> None:
        bundle = generate_bundle()
        wrong_bundle = generate_bundle()
        roots = (
            None
            if trust_mode == "missing-server-ca"
            else wrong_bundle.ca_certificate
        )
        async with _loopback_server(bundle) as (target, service, _):
            code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=roots,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            assert code == grpc.StatusCode.UNAVAILABLE

    asyncio.run(run())


def test_missing_client_identity_and_wrong_client_ca_fail_before_dispatch() -> None:
    async def run() -> None:
        bundle = generate_bundle()
        wrong_bundle = generate_bundle()
        async with _loopback_server(bundle) as (target, service, _):
            missing_code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=None,
                certificate_chain=None,
            )
            wrong_code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=wrong_bundle.client_private_key,
                certificate_chain=wrong_bundle.client_certificate,
            )
            assert missing_code == grpc.StatusCode.UNAVAILABLE
            assert wrong_code == grpc.StatusCode.UNAVAILABLE

    asyncio.run(run())


@pytest.mark.parametrize(
    ("client_common_name", "client_san"),
    (
        ("openbexi-spell-procedure-worker", DEFAULT_CLIENT_SAN),
        (DEFAULT_CLIENT_COMMON_NAME, "spiffe://openbexi-spell.local/service/other"),
        (
            "openbexi-spell-procedure-worker",
            "spiffe://openbexi-spell.local/service/procedure-worker",
        ),
    ),
    ids=("wrong-cn", "wrong-san", "wrong-role"),
)
def test_wrong_role_san_or_common_name_fails_before_dispatch(
    client_common_name: str, client_san: str
) -> None:
    async def run() -> None:
        bundle = generate_bundle(
            client_common_name=client_common_name, client_san=client_san
        )
        async with _loopback_server(bundle) as (target, service, authorization):
            code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            assert code == grpc.StatusCode.PERMISSION_DENIED
            assert authorization.audit_counts == {"peer_role_rejected": 1}

    asyncio.run(run())


def test_revoked_fingerprint_fails_before_dispatch() -> None:
    async def run() -> None:
        bundle = generate_bundle()
        config = HostConfig(revoked_client_fingerprints=(bundle.client_fingerprint,))
        async with _loopback_server(bundle, config) as (
            target,
            service,
            authorization,
        ):
            code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            assert code == grpc.StatusCode.PERMISSION_DENIED
            assert authorization.audit_counts == {"peer_certificate_revoked": 1}

    asyncio.run(run())


def test_stale_credential_epoch_fails_before_dispatch() -> None:
    async def run() -> None:
        bundle = generate_bundle()
        async with _loopback_server(bundle, HostConfig(credential_epoch=2)) as (
            target,
            service,
            authorization,
        ):
            code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
                credential_epoch="1",
            )
            assert code == grpc.StatusCode.UNAUTHENTICATED
            assert authorization.audit_counts == {"credential_epoch_rejected": 1}

    asyncio.run(run())


def test_expired_gateway_certificate_fails_before_dispatch() -> None:
    async def run() -> None:
        now = datetime.now(timezone.utc)
        bundle = generate_bundle(
            now=now,
            client_not_before=now - timedelta(days=2),
            client_not_after=now - timedelta(days=1),
        )
        async with _loopback_server(bundle) as (target, service, _):
            code = await _assert_transport_rejected(
                target,
                service,
                root_certificates=bundle.ca_certificate,
                private_key=bundle.client_private_key,
                certificate_chain=bundle.client_certificate,
            )
            assert code == grpc.StatusCode.UNAVAILABLE

    asyncio.run(run())


def test_driver_client_consumes_key_before_a_spawn_worker_can_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        bundle = generate_bundle()
        ca_path, cert_path, key_path = _write_client_bundle(tmp_path, bundle)
        async with _loopback_server(bundle) as (target, service, _):
            monkeypatch.setattr(driver_client_module, "DRIVER_TARGET", target)
            client = DriverClient.from_files(
                target,
                ca_path,
                cert_path,
                key_path,
                timeout_seconds=2,
            )
            try:
                assert not key_path.exists()
                assert ca_path.is_file()
                assert cert_path.is_file()

                context = multiprocessing.get_context("spawn")
                receiving, sending = context.Pipe(duplex=False)
                process = context.Process(
                    target=_spawn_worker_credential_probe,
                    args=(str(key_path), sending),
                )
                process.start()
                sending.close()
                try:
                    process.join(timeout=30)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)
                        pytest.fail("spawn worker credential probe did not terminate")
                    assert process.exitcode == 0
                    assert receiving.poll(5), "spawn worker returned no probe result"
                    assert receiving.recv() == {
                        "key_exists": False,
                        "credential_environment": [],
                    }
                finally:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)
                    receiving.close()

                await client.handshake()
                assert service.dispatch_count == 1
            finally:
                await client.close()

    asyncio.run(run())
