"""Process entry point for the isolated local simulator driver host."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Optional, Sequence

import grpc

from spell.driver.v1 import driver_pb2_grpc

from .config import HostConfig
from .journal import OperationJournal
from .lifecycle import SimulatorLifecycleHost
from .observation_service import DriverObservationService, MAX_ACTIVE_OBSERVATIONS
from .security import DriverAuthorizationInterceptor
from .service import DriverInfrastructureService
from .wire import StrictDriverWireInterceptor


PRODUCT_BIND_ADDRESS = "0.0.0.0:50051"
DEFAULT_CREDENTIAL_DIRECTORY = Path("/run/spell-driver-server")
DEFAULT_CONFIG_PATH = Path("/etc/spell-driver/host.json")
DEFAULT_JOURNAL_PATH = Path("/var/lib/spell-driver/driver.sqlite")
MAX_MESSAGE_BYTES = 64 * 1024
MAX_METADATA_BYTES = 8 * 1024


def _read_bounded_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    value = path.read_bytes()
    if not value or len(value) > MAX_MESSAGE_BYTES:
        raise ValueError(f"{label} has an invalid size")
    return value


def server_credentials(credential_directory: str | Path) -> grpc.ServerCredentials:
    directory = Path(credential_directory)
    ca_certificate = _read_bounded_file(directory / "ca.crt", "driver CA certificate")
    server_certificate = _read_bounded_file(
        directory / "server.crt", "driver server certificate"
    )
    server_private_key = _read_bounded_file(
        directory / "server.key", "driver server private key"
    )
    return grpc.ssl_server_credentials(
        ((server_private_key, server_certificate),),
        root_certificates=ca_certificate,
        require_client_auth=True,
    )


def build_server(
    config: HostConfig,
    host: SimulatorLifecycleHost,
) -> tuple[grpc.aio.Server, DriverInfrastructureService]:
    """Construct an unbound server so tests can inject a loopback-only port."""

    service = DriverInfrastructureService(config, host)
    observation_service = DriverObservationService(config, host)
    authorization = DriverAuthorizationInterceptor(config)
    wire = StrictDriverWireInterceptor()
    service.authorization_audit = authorization.audit_counts
    service.wire_audit = wire.audit_counts
    server = grpc.aio.server(
        # The wire interceptor returns a replacement RpcMethodHandler whose
        # request_deserializer validates raw bytes before protobuf parsing.
        interceptors=(authorization, wire),
        options=(
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_metadata_size", MAX_METADATA_BYTES),
            ("grpc.so_reuseport", 0),
        ),
        maximum_concurrent_rpcs=(
            config.capacity.max_lifecycle_operations_per_host
            + MAX_ACTIVE_OBSERVATIONS
            + 2
        ),
    )
    driver_pb2_grpc.add_DriverInfrastructureServiceServicer_to_server(service, server)
    driver_pb2_grpc.add_DriverObservationServiceServicer_to_server(
        observation_service, server
    )
    return server, service


async def serve(
    config_path: str | Path,
    journal_path: str | Path,
    credential_directory: str | Path,
) -> None:
    config = HostConfig.from_file(config_path)
    journal = OperationJournal(journal_path, config.driver_host_generation, config.journal)
    host = SimulatorLifecycleHost(config, journal)
    server, _ = build_server(config, host)
    bound_port = server.add_secure_port(
        PRODUCT_BIND_ADDRESS, server_credentials(credential_directory)
    )
    if bound_port != 50051:
        journal.close()
        raise RuntimeError("driver host failed to bind its fixed internal port")
    try:
        await server.start()
        await server.wait_for_termination()
    finally:
        await server.stop(grace=1)
        host.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="run the local-only deterministic v0.4 simulator driver"
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--journal", default=str(DEFAULT_JOURNAL_PATH))
    parser.add_argument(
        "--credential-dir", default=str(DEFAULT_CREDENTIAL_DIRECTORY)
    )
    args = parser.parse_args(argv)
    asyncio.run(serve(args.config, args.journal, args.credential_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
