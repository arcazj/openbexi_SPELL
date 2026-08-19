from __future__ import annotations

import asyncio
import time
from pathlib import Path

import grpc

from spell.driver.v1 import driver_pb2

from driver_host.config import JournalConfig
from driver_host.domain import Method
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.observation import (
    CATALOG_DIGEST,
    ClockSource,
    DeterministicObservationEngine,
    ObservationCode,
    ObservationFailure,
    SimulatorClock,
    source_epoch_for,
)
from driver_host.observation_service import DriverObservationService
from driver_host.tests.support import make_command, make_config, make_identity


class RpcAbort(Exception):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code


class AbortContext:
    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        raise RpcAbort(code, details)


def observation_identity(config, *, context: bool = False, suffix: str = "1"):
    identity = make_identity(config, context=context)
    return driver_pb2.ObservationRequestIdentity(
        contract_version=driver_pb2.ContractVersion(major=1, minor=0),
        server_profile_id=identity.server_profile_id,
        driver_host_generation=identity.driver_host_generation,
        host_profile_digest=identity.host_profile_digest,
        context_id=identity.context_id,
        context_generation=identity.context_generation,
        context_binding_digest=identity.context_binding_digest,
        observation_id=f"observation-{suffix}",
        correlation_id=f"correlation-{suffix}",
        deadline_unix_ns=time.time_ns() + 2_000_000_000,
        credential_epoch=config.credential_epoch,
    )


def test_clock_sources_provenance_regression_and_uncertainty_are_typed() -> None:
    fallback = SimulatorClock(
        source=ClockSource.HOST_FALLBACK,
        host_clock_ns=lambda: 1_735_689_600_000_000_000,
    ).read()
    assert fallback.source is ClockSource.HOST_FALLBACK
    assert fallback.provenance == "explicit-host-clock-fallback"
    assert "gcs" not in fallback.provenance

    simulator_gcs = SimulatorClock(
        source=ClockSource.SIMULATOR_GCS_TIME,
        monotonic_ns=lambda: 100,
    ).read()
    assert simulator_gcs.source is ClockSource.SIMULATOR_GCS_TIME
    assert simulator_gcs.provenance == "simulator-emulated-gcs-clock"

    values = iter((100, 200, 150))
    regressing = SimulatorClock(monotonic_ns=lambda: next(values))
    regressing.read()
    try:
        regressing.read()
    except ObservationFailure as exc:
        assert exc.code is ObservationCode.CLOCK_UNCERTAIN
    else:
        raise AssertionError("clock regression was accepted")

    uncertain = SimulatorClock(uncertainty_ns=60_000_000_001)
    try:
        uncertain.read()
    except ObservationFailure as exc:
        assert exc.code is ObservationCode.CLOCK_UNCERTAIN
    else:
        raise AssertionError("excessive uncertainty was accepted")


def test_source_restart_creates_a_new_epoch_and_restarts_sequence() -> None:
    async def scenario() -> None:
        host_generation = "host-observation-restart"
        first = DeterministicObservationEngine(
            host_generation, source_instance_id="source-instance-first"
        )
        restarted = DeterministicObservationEngine(
            host_generation, source_instance_id="source-instance-restarted"
        )
        first_sample = await first.current("TM.POWER.BUS_VOLTAGE")
        restarted_sample = await restarted.current("TM.POWER.BUS_VOLTAGE")
        assert first.source_epoch != restarted.source_epoch
        assert first_sample.source_sequence == restarted_sample.source_sequence == 1
        assert first_sample.source_epoch == first.source_epoch
        assert restarted_sample.source_epoch == restarted.source_epoch

    asyncio.run(scenario())


def test_service_time_current_next_gap_deadline_and_stale_fencing(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        journal = OperationJournal(
            tmp_path / "observation.sqlite",
            config.driver_host_generation,
            JournalConfig(max_entries=100, max_bytes=1_048_576),
        )
        host = SimulatorLifecycleHost(config, journal)
        context_identity = make_identity(config, context=True)
        opened = await host.execute(
            make_command(
                config,
                Method.OPEN_CONTEXT,
                "observation-open",
                identity=context_identity,
            )
        )
        assert opened.attempts[-1].result.value == "OK"
        operation_count = len(journal.list_operations())
        engine = DeterministicObservationEngine(
            config.driver_host_generation, tick_ns=10_000_000
        )
        service = DriverObservationService(config, host, engine=engine)
        try:
            time_response = await service.GetTime(
                driver_pb2.GetTimeRequest(
                    identity=observation_identity(config, suffix="time")
                ),
                AbortContext(),
            )
            assert time_response.result_code == driver_pb2.OBSERVATION_RESULT_CODE_OK
            assert time_response.observation.clock_source == driver_pb2.CLOCK_SOURCE_SIMULATOR
            assert time_response.observation.uncertainty_ns > 0

            expired_identity = observation_identity(config, suffix="time-expired")
            expired_identity.deadline_unix_ns = time.time_ns() - 1
            expired_time = await service.GetTime(
                driver_pb2.GetTimeRequest(identity=expired_identity), AbortContext()
            )
            assert expired_time.result_code == driver_pb2.OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED

            expired_tm_identity = observation_identity(
                config, context=True, suffix="current-expired"
            )
            expired_tm_identity.deadline_unix_ns = time.time_ns() - 1
            expired_tm = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=expired_tm_identity,
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert (
                expired_tm.result_code
                == driver_pb2.OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED
            )

            current_identity = observation_identity(
                config, context=True, suffix="current"
            )
            current = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=current_identity,
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert current.result_code == driver_pb2.OBSERVATION_RESULT_CODE_OK
            assert current.sample.item_identity.catalog_digest == CATALOG_DIGEST
            assert current.sample.sample_identity.source_sequence == 1
            assert current.sample.raw_value.uint64_value == 28_000
            assert current.sample.engineering_value.finite_double_value == 28.0
            assert current.sample.source == "SIMULATOR"
            assert current.sample.raw_value.WhichOneof("typed_value") == "uint64_value"
            assert current.sample.engineering_value.WhichOneof("typed_value") == "finite_double_value"

            next_response = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=observation_identity(config, context=True, suffix="next"),
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_NEXT,
                    source_epoch=current.sample.sample_identity.source_epoch,
                    after_source_sequence=1,
                ),
                AbortContext(),
            )
            assert next_response.result_code == driver_pb2.OBSERVATION_RESULT_CODE_OK
            assert next_response.sample.sample_identity.source_sequence == 2
            assert next_response.sample.raw_value.uint64_value == 23_000
            assert next_response.sample.engineering_value.finite_double_value == 23.0

            safe_mode = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=observation_identity(config, context=True, suffix="safe"),
                    item_id="TM.POWER.SAFE_MODE",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert safe_mode.result_code == driver_pb2.OBSERVATION_RESULT_CODE_OK
            assert safe_mode.sample.raw_value.WhichOneof("typed_value") == "boolean_value"
            assert safe_mode.sample.engineering_value.boolean_value is False

            thermal_mode = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=observation_identity(config, context=True, suffix="thermal"),
                    item_id="TM.THERMAL.MODE",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert thermal_mode.result_code == driver_pb2.OBSERVATION_RESULT_CODE_OK
            assert thermal_mode.sample.raw_value.string_value == "NOMINAL"
            assert thermal_mode.sample.engineering_value.string_value == "NOMINAL"

            missing = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=observation_identity(config, context=True, suffix="missing"),
                    item_id="TM.UNKNOWN",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert missing.result_code == driver_pb2.OBSERVATION_RESULT_CODE_NOT_FOUND

            gap = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=observation_identity(config, context=True, suffix="gap"),
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_NEXT,
                    source_epoch=engine.source_epoch,
                    after_source_sequence=0,
                ),
                AbortContext(),
            )
            assert gap.result_code == driver_pb2.OBSERVATION_RESULT_CODE_GAP
            assert gap.gap.first_available_sequence == 2
            assert gap.gap.last_available_sequence == 2

            deadline_identity = observation_identity(
                config, context=True, suffix="deadline"
            )
            deadline_identity.deadline_unix_ns = time.time_ns() + 1_000_000
            deadline = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=deadline_identity,
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_NEXT,
                    source_epoch=engine.source_epoch,
                    after_source_sequence=2,
                ),
                AbortContext(),
            )
            assert deadline.result_code == driver_pb2.OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED

            stale_identity = observation_identity(config, context=True, suffix="stale")
            stale_identity.context_generation = "other-generation"
            stale = await service.GetTM(
                driver_pb2.GetTMRequest(
                    identity=stale_identity,
                    item_id="TM.POWER.BUS_VOLTAGE",
                    mode=driver_pb2.GET_TM_MODE_CURRENT,
                ),
                AbortContext(),
            )
            assert stale.result_code == driver_pb2.OBSERVATION_RESULT_CODE_STALE_GENERATION
            assert len(journal.list_operations()) == operation_count
            assert service.dispatch_counts == {"GetTime": 1, "GetTM": 7}
        finally:
            host.close()

    asyncio.run(scenario())


def test_next_revalidates_context_after_wait_and_cancellation_is_typed(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "fence.sqlite",
                config.driver_host_generation,
                JournalConfig(max_entries=100, max_bytes=1_048_576),
            ),
        )
        context_identity = make_identity(config, context=True)
        await host.execute(
            make_command(config, Method.OPEN_CONTEXT, "fence-open", identity=context_identity)
        )
        engine = DeterministicObservationEngine(
            config.driver_host_generation, tick_ns=100_000_000
        )
        service = DriverObservationService(config, host, engine=engine)
        try:
            waiting = asyncio.create_task(
                service.GetTM(
                    driver_pb2.GetTMRequest(
                        identity=observation_identity(config, context=True, suffix="fence"),
                        item_id="TM.POWER.BUS_VOLTAGE",
                        mode=driver_pb2.GET_TM_MODE_NEXT,
                        source_epoch=engine.source_epoch,
                        after_source_sequence=1,
                    ),
                    AbortContext(),
                )
            )
            await asyncio.sleep(0.005)
            await host.execute(
                make_command(
                    config,
                    Method.CLOSE_CONTEXT,
                    "fence-close",
                    identity=context_identity,
                )
            )
            fenced = await waiting
            assert fenced.result_code == driver_pb2.OBSERVATION_RESULT_CODE_STALE_GENERATION

            await host.execute(
                make_command(config, Method.OPEN_CONTEXT, "cancel-open", identity=context_identity)
            )
            cancellation = asyncio.create_task(
                service.GetTM(
                    driver_pb2.GetTMRequest(
                        identity=observation_identity(config, context=True, suffix="cancel"),
                        item_id="TM.POWER.BUS_VOLTAGE",
                        mode=driver_pb2.GET_TM_MODE_NEXT,
                        source_epoch=engine.source_epoch,
                        after_source_sequence=engine.sequence,
                    ),
                    AbortContext(),
                )
            )
            await asyncio.sleep(0.005)
            cancellation.cancel()
            cancelled = await cancellation
            assert cancelled.result_code == driver_pb2.OBSERVATION_RESULT_CODE_CANCELLED
        finally:
            host.close()

    asyncio.run(scenario())
