from __future__ import annotations

import asyncio
import time
from typing import Any

from spell.driver.v1 import driver_pb2

from backend.driver_client import DriverClient
from backend.driver_domain import GenerationTuple
from backend.observation_domain import (
    GetTMMode,
    GetTMQuery,
    GetTimeQuery,
    ObservationResultCode,
    sample_id_for,
)


HOST_DIGEST = "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"
SOURCE_ID = "bundled-deterministic-simulator"
SOURCE_EPOCH = "epoch-" + "b" * 64


class FakeCall:
    def __init__(self, behavior):
        self.behavior = behavior

    async def __call__(self, request, **_kwargs):
        return self.behavior(request)


class FakeChannel:
    def __init__(self) -> None:
        self.behaviors: dict[str, Any] = {}

    def unary_unary(self, path: str, **_kwargs):
        return FakeCall(lambda request: self.behaviors[path](request))

    async def close(self) -> None:
        return None


def generations(*, context: bool = False) -> GenerationTuple:
    return GenerationTuple(
        "local-synthetic",
        "host-generation-1",
        HOST_DIGEST,
        context_id="context-1" if context else "",
        context_generation="context-generation-1" if context else "",
        context_binding_digest="a" * 64 if context else "",
    )


def wire_generation(value: GenerationTuple):
    return driver_pb2.ObservationGeneration(
        server_profile_id=value.server_profile_id,
        driver_host_generation=value.driver_host_generation,
        host_profile_digest=value.host_profile_digest,
        context_id=value.context_id,
        context_generation=value.context_generation,
        context_binding_digest=value.context_binding_digest,
    )


def test_client_maps_time_and_atomic_sample_without_protobuf_leakage() -> None:
    async def scenario() -> None:
        channel = FakeChannel()
        client = DriverClient(channel, 2.0, 1)
        host_generations = generations()
        context_generations = generations(context=True)

        def get_time(request):
            return driver_pb2.GetTimeResponse(
                contract_version=driver_pb2.ContractVersion(major=1, minor=0),
                result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
                observation=driver_pb2.DriverTimeObservation(
                    observation_id=request.identity.observation_id,
                    generation=wire_generation(host_generations),
                    time_unix_ns=1_735_689_600_000_000_000,
                    acquired_at_unix_ns=1_735_689_600_000_000_000,
                    clock_source=driver_pb2.CLOCK_SOURCE_SIMULATOR,
                    provenance="bundled-deterministic-simulator-clock",
                    uncertainty_ns=1_000_000,
                    quality=driver_pb2.OBSERVATION_QUALITY_GOOD,
                    validity=driver_pb2.OBSERVATION_VALIDITY_VALID,
                ),
            )

        def get_tm(request):
            sequence = 1
            return driver_pb2.GetTMResponse(
                contract_version=driver_pb2.ContractVersion(major=1, minor=0),
                result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
                sample=driver_pb2.DriverTelemetrySample(
                    observation_id=request.identity.observation_id,
                    generation=wire_generation(context_generations),
                    sample_identity=driver_pb2.SampleIdentity(
                        sample_id=sample_id_for(
                            SOURCE_ID, SOURCE_EPOCH, request.item_id, sequence
                        ),
                        item_id=request.item_id,
                        source_id=SOURCE_ID,
                        source_epoch=SOURCE_EPOCH,
                        source_sequence=sequence,
                    ),
                    item_identity=driver_pb2.ItemIdentity(
                        item_id=request.item_id,
                        qualified_name="SIM.POWER.BUS_VOLTAGE",
                        catalog_digest=CATALOG_DIGEST,
                    ),
                    raw_value=driver_pb2.ScalarValue(
                        kind=driver_pb2.SCALAR_KIND_UINT64, uint64_value=28_000
                    ),
                    engineering_value=driver_pb2.ScalarValue(
                        kind=driver_pb2.SCALAR_KIND_FINITE_DOUBLE,
                        finite_double_value=28.0,
                    ),
                    description="Synthetic DC bus voltage",
                    unit="V",
                    acquired_at_unix_ns=1_735_689_600_000_000_000,
                    source="SIMULATOR",
                    clock_provenance="bundled-deterministic-simulator-clock",
                    clock_uncertainty_ns=1_000_000,
                    validity=driver_pb2.OBSERVATION_VALIDITY_VALID,
                    quality=driver_pb2.OBSERVATION_QUALITY_GOOD,
                    quality_reason="deterministic-simulator",
                ),
            )

        channel.behaviors["/spell.driver.v1.DriverObservationService/GetTime"] = get_time
        channel.behaviors["/spell.driver.v1.DriverObservationService/GetTM"] = get_tm
        deadline = time.time_ns() + 1_000_000_000
        time_result = await client.get_time(
            GetTimeQuery("time-1", host_generations, "correlation-1", deadline)
        )
        assert time_result.code is ObservationResultCode.OK
        assert type(time_result.observation).__name__ == "DriverTimeObservation"
        assert not hasattr(time_result.observation, "DESCRIPTOR")

        tm_result = await client.get_tm(
            GetTMQuery(
                "tm-1",
                context_generations,
                "correlation-2",
                deadline,
                "TM.POWER.BUS_VOLTAGE",
                GetTMMode.CURRENT,
            )
        )
        assert tm_result.code is ObservationResultCode.OK
        assert tm_result.sample.raw_value.value == 28_000
        assert tm_result.sample.engineering_value.value == 28.0
        assert not hasattr(tm_result.sample, "DESCRIPTOR")

    asyncio.run(scenario())


def test_client_fails_closed_on_scalar_oneof_or_identity_mismatch() -> None:
    async def scenario() -> None:
        channel = FakeChannel()
        client = DriverClient(channel, 2.0, 1)
        expected = generations(context=True)

        def malformed(request):
            wrong = generations(context=True)
            wrong = GenerationTuple(
                wrong.server_profile_id,
                "other-host-generation",
                wrong.host_profile_digest,
                wrong.context_id,
                wrong.context_generation,
                wrong.context_binding_digest,
            )
            return driver_pb2.GetTMResponse(
                contract_version=driver_pb2.ContractVersion(major=1, minor=0),
                result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
                sample=driver_pb2.DriverTelemetrySample(
                    observation_id=request.identity.observation_id,
                    generation=wire_generation(wrong),
                ),
            )

        channel.behaviors["/spell.driver.v1.DriverObservationService/GetTM"] = malformed
        result = await client.get_tm(
            GetTMQuery(
                "tm-bad",
                expected,
                "correlation-bad",
                time.time_ns() + 1_000_000_000,
                "TM.POWER.BUS_VOLTAGE",
                GetTMMode.CURRENT,
            )
        )
        assert result.code is ObservationResultCode.CONTRACT_MISMATCH

    asyncio.run(scenario())
