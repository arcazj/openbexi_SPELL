"""The additive clock reply must agree with an independently decoded TM packet."""
import asyncio
import hashlib
import time
from dataclasses import replace

import pytest

from backend.driver_client import DriverClient
from backend.observation_domain import GetTimeQuery, ObservationResultCode
from backend.tests.test_driver_client_observation import FakeChannel, generations, wire_generation
from dss.packets import decode_tm, encode_tm
from driver_host.tests.test_dss_transport import engine
from spell.driver.dss.v1 import dss_pb2
from spell.driver.v1 import driver_pb2


@pytest.mark.parametrize("mutation", ["none", "raw_hash", "header_sequence", "database", "time_claim", "acquisition_claim", "uncertainty_claim", "boolean_sequence", "ack_apid"])
def test_dss_client_binds_clock_to_exact_packet_and_rejects_crc_valid_substitution(engine, mutation):
    raw = bytes.fromhex(engine.evidence(engine.state()["scenario_id"])["packets"][0]["packet_hex"])
    body = decode_tm(raw)
    channel = FakeChannel()
    client = DriverClient(channel, 2.0, 1)
    def reply(request):
        observation = driver_pb2.DriverTimeObservation(observation_id=request.identity.observation_id,
            generation=wire_generation(generations()), time_unix_ns=body["clock_epoch_unix_ns"] + body["simulation_time_ns"],
            acquired_at_unix_ns=body["acquired_at_unix_ns"], clock_source=driver_pb2.CLOCK_SOURCE_SIMULATOR,
            provenance="dss-dynamics-clock", uncertainty_ns=body.get("driver_time_uncertainty_ns", body["clock_uncertainty_ns"]),
            quality=driver_pb2.OBSERVATION_QUALITY_GOOD, validity=driver_pb2.OBSERVATION_VALIDITY_VALID)
        actual_body = dict(body)
        sequence = body["tm_sequence"] & 0x3fff
        if mutation == "database": actual_body["database_digest"] = "f" * 64
        if mutation == "boolean_sequence": actual_body["tm_sequence"] = True
        if mutation == "header_sequence": sequence += 1
        packet = encode_tm(actual_body, sequence=sequence, ack=mutation == "ack_apid")
        if mutation == "time_claim": observation.time_unix_ns += 1
        if mutation == "acquisition_claim": observation.acquired_at_unix_ns += 1
        if mutation == "uncertainty_claim": observation.uncertainty_ns += 1
        return dss_pb2.ClockEvidenceResponse(time_response=driver_pb2.GetTimeResponse(
            contract_version=driver_pb2.ContractVersion(major=1, minor=0), result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
            observation=observation), telemetry_packet=packet,
            packet_sha256="e" * 64 if mutation == "raw_hash" else hashlib.sha256(packet).hexdigest())
    channel.behaviors["/spell.driver.dss.v1.DssService/ClockEvidence"] = reply
    result = asyncio.run(client.get_time(GetTimeQuery("clock-client-test", generations(), "clock-proof", time.time_ns() + 2_000_000_000), dss=True))
    assert result.code is (ObservationResultCode.OK if mutation == "none" else ObservationResultCode.CONTRACT_MISMATCH)
    if mutation == "none":
        assert result.observation.source_epoch == body["satellite_epoch"]
        assert result.observation.source_sequence == body["tm_sequence"]
        assert result.observation.source_packet_sha256 == hashlib.sha256(raw).hexdigest()
        for bad in (False, 0.0):
            with pytest.raises(ValueError):
                replace(result.observation, source_epoch="", source_sequence=bad, source_packet_sha256="", database_digest="")
