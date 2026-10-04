from __future__ import annotations

import asyncio
import hashlib
import time

import grpc
import pytest

from driver_host.dss_config import DssConfig
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.pki import generate_bundle
from driver_host.server import build_server
from driver_host.tests.support import make_config
from driver_host.tests.test_observation import observation_identity
from driver_host.tests.test_dss_transport import engine, ingest_pending
from spell.driver.dss.v1 import dss_pb2, dss_pb2_grpc


def test_additive_dss_rpc_preserves_mtls_metadata_generation_and_context_authority(tmp_path, engine):
    async def scenario():
        config = make_config()
        host = SimulatorLifecycleHost(config, OperationJournal(tmp_path / "lifecycle.sqlite", config.driver_host_generation, config.journal))
        server, infrastructure = build_server(config, host, dss_config=DssConfig(enabled=True, journal_path=tmp_path / "dss.sqlite"))
        ingest_pending(infrastructure.dss_service.telemetry, engine)
        bundle = generate_bundle()
        credentials = grpc.ssl_server_credentials(((bundle.server_private_key, bundle.server_certificate),), root_certificates=bundle.ca_certificate, require_client_auth=True)
        port = server.add_secure_port("127.0.0.1:0", credentials)
        await server.start()
        channel = grpc.aio.secure_channel(f"127.0.0.1:{port}", grpc.ssl_channel_credentials(bundle.ca_certificate, bundle.client_private_key, bundle.client_certificate), options=(("grpc.ssl_target_name_override", "spell-driver"),))
        stub = dss_pb2_grpc.DssServiceStub(channel)
        metadata = (("x-spell-contract-major", "1"), ("x-spell-credential-epoch", "1"))
        try:
            request = dss_pb2.HealthRequest(identity=observation_identity(config))
            result = await stub.Health(request, metadata=metadata, timeout=2)
            assert result.ready
            assert result.satellite_id == "GENERIC"
            evidence = await stub.ClockEvidence(request, metadata=metadata, timeout=2)
            from dss.packets import decode_tm
            from backend.driver_client import DriverClient
            from backend.driver_domain import GenerationTuple
            from backend.observation_domain import GetTimeQuery, ObservationResultCode
            body = decode_tm(evidence.telemetry_packet)
            assert evidence.packet_sha256 == hashlib.sha256(evidence.telemetry_packet).hexdigest()
            assert body["satellite_epoch"] == result.satellite_epoch
            client = DriverClient(channel, 2.0, 1)
            value = await client.get_time(GetTimeQuery("dss-clock-real-rpc", GenerationTuple(config.server_profile_id,
                config.driver_host_generation, config.host_profile_digest), "clock-proof", time.time_ns() + 2_000_000_000), dss=True)
            assert value.code is ObservationResultCode.OK
            assert value.observation.source_epoch == body["satellite_epoch"]
            assert value.observation.source_packet_sha256 == evidence.packet_sha256
            assert value.observation.source_sequence == body["tm_sequence"]
            assert value.observation.time_unix_ns == body["clock_epoch_unix_ns"] + body["simulation_time_ns"]
            with pytest.raises(grpc.aio.AioRpcError) as failure:
                await stub.Health(request, metadata=(("x-spell-contract-major", "1"), ("x-spell-credential-epoch", "2")), timeout=2)
            assert failure.value.code() in {grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED}
            request.identity.driver_host_generation = "unadmitted-generation"
            with pytest.raises(grpc.aio.AioRpcError) as failure:
                await stub.Health(request, metadata=metadata, timeout=2)
            assert failure.value.code() is grpc.StatusCode.FAILED_PRECONDITION
            with pytest.raises(grpc.aio.AioRpcError) as failure:
                await stub.ClockEvidence(request, metadata=metadata, timeout=2)
            assert failure.value.code() is grpc.StatusCode.FAILED_PRECONDITION
            with pytest.raises(grpc.aio.AioRpcError) as failure:
                await stub.CommandStage(dss_pb2.CommandStageRequest(identity=observation_identity(config, context=True)), metadata=metadata, timeout=2)
            assert failure.value.code() is grpc.StatusCode.FAILED_PRECONDITION
            assert engine.evidence(engine.state()["scenario_id"])["operations"] == []
        finally:
            await channel.close()
            await server.stop(grace=0)
            infrastructure.dss_service.telemetry.close()
            infrastructure.dss_service.command.close()
            host.close()
    asyncio.run(scenario())
