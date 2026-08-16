"""Typed gRPC adapter for read-only simulator observations."""

from __future__ import annotations

import asyncio
import math
import time
from collections import Counter
from typing import Any, Optional

import grpc

from spell.driver.v1 import driver_pb2, driver_pb2_grpc

from .config import HostConfig
from .domain import GenerationIdentity, validate_digest, validate_identifier
from .lifecycle import SimulatorLifecycleHost
from .observation import (
    CATALOG_DIGEST,
    SOURCE_ID,
    DeterministicObservationEngine,
    ObservationCode,
    ObservationFailure,
    ScalarKind,
    ScalarValue,
    TelemetrySample,
)


CONTRACT_MAJOR = 1
CONTRACT_MINOR = 0
MAX_ACTIVE_OBSERVATIONS = 8


def _contract_version() -> Any:
    return driver_pb2.ContractVersion(major=CONTRACT_MAJOR, minor=CONTRACT_MINOR)


def _result_code(code: ObservationCode) -> int:
    return getattr(driver_pb2, f"OBSERVATION_RESULT_CODE_{code.value}")


def _error(failure: ObservationFailure) -> Any:
    return driver_pb2.ObservationError(
        code=_result_code(failure.code),
        safe_message=failure.safe_message,
        retryable=failure.retryable,
    )


def _generation(identity: GenerationIdentity) -> Any:
    return driver_pb2.ObservationGeneration(
        server_profile_id=identity.server_profile_id,
        driver_host_generation=identity.driver_host_generation,
        host_profile_digest=identity.host_profile_digest,
        context_id=identity.context_id,
        context_generation=identity.context_generation,
        context_binding_digest=identity.context_binding_digest,
    )


def _scalar(value: ScalarValue) -> Any:
    message = driver_pb2.ScalarValue(
        kind=getattr(driver_pb2, f"SCALAR_KIND_{value.kind.value}")
    )
    fields = {
        ScalarKind.BOOLEAN: "boolean_value",
        ScalarKind.INT64: "int64_value",
        ScalarKind.UINT64: "uint64_value",
        ScalarKind.FINITE_DOUBLE: "finite_double_value",
        ScalarKind.STRING: "string_value",
        ScalarKind.BYTES: "bytes_value",
    }
    if value.kind is ScalarKind.FINITE_DOUBLE and (
        type(value.value) is not float or not math.isfinite(value.value)
    ):
        raise ObservationFailure(
            ObservationCode.CONTRACT_MISMATCH,
            "simulator produced a non-finite telemetry value",
        )
    setattr(message, fields[value.kind], value.value)
    return message


def _sample_message(
    observation_id: str,
    identity: GenerationIdentity,
    sample: TelemetrySample,
) -> Any:
    return driver_pb2.DriverTelemetrySample(
        observation_id=observation_id,
        generation=_generation(identity),
        sample_identity=driver_pb2.SampleIdentity(
            sample_id=sample.sample_id,
            item_id=sample.item.item_id,
            source_id=SOURCE_ID,
            source_epoch=sample.source_epoch,
            source_sequence=sample.source_sequence,
        ),
        item_identity=driver_pb2.ItemIdentity(
            item_id=sample.item.item_id,
            qualified_name=sample.item.qualified_name,
            catalog_digest=CATALOG_DIGEST,
        ),
        raw_value=_scalar(sample.raw_value),
        engineering_value=_scalar(sample.engineering_value),
        description=sample.item.description,
        unit=sample.item.unit,
        acquired_at_unix_ns=sample.acquired_at_unix_ns,
        source="SIMULATOR",
        clock_provenance=sample.clock_provenance,
        clock_uncertainty_ns=sample.clock_uncertainty_ns,
        validity=getattr(driver_pb2, f"OBSERVATION_VALIDITY_{sample.validity.value}"),
        quality=getattr(driver_pb2, f"OBSERVATION_QUALITY_{sample.quality.value}"),
        quality_reason=sample.quality_reason,
    )


class DriverObservationService(driver_pb2_grpc.DriverObservationServiceServicer):
    """Read-only observations fenced by the lifecycle host's active context."""

    def __init__(
        self,
        config: HostConfig,
        host: SimulatorLifecycleHost,
        *,
        engine: Optional[DeterministicObservationEngine] = None,
    ) -> None:
        self.config = config
        self.host = host
        self.engine = engine or DeterministicObservationEngine(
            config.driver_host_generation
        )
        self.dispatch_counts: Counter[str] = Counter()
        self._active = 0

    async def _invalid(self, context: grpc.aio.ServicerContext) -> None:
        await context.abort(
            grpc.StatusCode.INVALID_ARGUMENT, "invalid bounded observation request"
        )

    def _identity(self, value: Any, *, require_context: bool) -> GenerationIdentity:
        if (
            value.contract_version.major != CONTRACT_MAJOR
            or value.contract_version.minor > CONTRACT_MINOR
        ):
            raise ObservationFailure(
                ObservationCode.CONTRACT_MISMATCH,
                "observation contract version is unsupported",
            )
        validate_identifier(value.server_profile_id, "server_profile_id")
        validate_identifier(value.driver_host_generation, "driver_host_generation")
        validate_digest(value.host_profile_digest, "host_profile_digest")
        validate_identifier(value.observation_id, "observation_id")
        validate_identifier(value.correlation_id, "correlation_id")
        if value.deadline_unix_ns <= 0 or value.credential_epoch < 1:
            raise ValueError("observation identity is incomplete")
        if require_context:
            validate_identifier(value.context_id, "context_id")
            validate_identifier(value.context_generation, "context_generation")
            validate_digest(value.context_binding_digest, "context_binding_digest")
        elif value.context_id or value.context_generation or value.context_binding_digest:
            raise ValueError("host observation cannot include a context tuple")
        return GenerationIdentity(
            server_profile_id=value.server_profile_id,
            driver_host_generation=value.driver_host_generation,
            host_profile_digest=value.host_profile_digest,
            context_id=value.context_id,
            context_generation=value.context_generation,
            context_binding_digest=value.context_binding_digest,
        )

    def _bound(self, identity: GenerationIdentity, credential_epoch: int) -> bool:
        return (
            identity.server_profile_id == self.config.server_profile_id
            and identity.driver_host_generation == self.config.driver_host_generation
            and identity.host_profile_digest == self.config.host_profile_digest
            and credential_epoch == self.config.credential_epoch
        )

    def _context_active(self, identity: GenerationIdentity) -> bool:
        snapshot = self.host.snapshot()
        return (
            snapshot.ready
            and len(snapshot.contexts) == 1
            and snapshot.contexts[0].ready
            and (
                snapshot.contexts[0].context_id,
                snapshot.contexts[0].context_generation,
                snapshot.contexts[0].context_binding_digest,
            )
            == (
                identity.context_id,
                identity.context_generation,
                identity.context_binding_digest,
            )
        )

    def _admit(self) -> bool:
        if self._active >= MAX_ACTIVE_OBSERVATIONS:
            return False
        self._active += 1
        return True

    @staticmethod
    def _time_failure(failure: ObservationFailure) -> Any:
        return driver_pb2.GetTimeResponse(
            contract_version=_contract_version(),
            result_code=_result_code(failure.code),
            error=_error(failure),
        )

    @staticmethod
    def _tm_failure(failure: ObservationFailure) -> Any:
        if failure.code is ObservationCode.GAP and failure.gap is not None:
            return driver_pb2.GetTMResponse(
                contract_version=_contract_version(),
                result_code=_result_code(failure.code),
                gap=driver_pb2.GapBounds(
                    source_epoch=failure.gap.source_epoch,
                    first_available_sequence=failure.gap.first_available_sequence,
                    last_available_sequence=failure.gap.last_available_sequence,
                ),
            )
        return driver_pb2.GetTMResponse(
            contract_version=_contract_version(),
            result_code=_result_code(failure.code),
            error=_error(failure),
        )

    async def GetTime(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        try:
            identity = self._identity(request.identity, require_context=False)
        except ObservationFailure as failure:
            return self._time_failure(failure)
        except ValueError:
            await self._invalid(context)
        if not self._bound(identity, request.identity.credential_epoch):
            return self._time_failure(
                ObservationFailure(
                    ObservationCode.STALE_GENERATION,
                    "driver host generation differs",
                )
            )
        if request.identity.deadline_unix_ns <= time.time_ns():
            return self._time_failure(
                ObservationFailure(
                    ObservationCode.DEADLINE_EXCEEDED,
                    "simulator time request deadline elapsed",
                )
            )
        if not self._admit():
            return self._time_failure(
                ObservationFailure(
                    ObservationCode.NOT_AVAILABLE,
                    "observation capacity is exhausted",
                    retryable=True,
                )
            )
        try:
            self.dispatch_counts["GetTime"] += 1
            reading = self.engine.get_time()
            return driver_pb2.GetTimeResponse(
                contract_version=_contract_version(),
                result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
                observation=driver_pb2.DriverTimeObservation(
                    observation_id=request.identity.observation_id,
                    generation=_generation(identity),
                    time_unix_ns=reading.time_unix_ns,
                    acquired_at_unix_ns=reading.acquired_at_unix_ns,
                    clock_source=getattr(
                        driver_pb2, f"CLOCK_SOURCE_{reading.source.value}"
                    ),
                    provenance=reading.provenance,
                    uncertainty_ns=reading.uncertainty_ns,
                    quality=getattr(
                        driver_pb2, f"OBSERVATION_QUALITY_{reading.quality.value}"
                    ),
                    validity=getattr(
                        driver_pb2, f"OBSERVATION_VALIDITY_{reading.validity.value}"
                    ),
                ),
            )
        except ObservationFailure as failure:
            return self._time_failure(failure)
        except Exception:
            return self._time_failure(
                ObservationFailure(
                    ObservationCode.INTERNAL,
                    "simulator time evidence is unavailable",
                )
            )
        finally:
            self._active -= 1

    async def GetTM(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        try:
            identity = self._identity(request.identity, require_context=True)
            validate_identifier(request.item_id, "item_id")
            mode = request.DESCRIPTOR.fields_by_name["mode"].enum_type.values_by_number.get(
                request.mode
            )
            if mode is None or mode.number == 0:
                raise ValueError("GetTM mode is unspecified")
            mode_name = mode.name.removeprefix("GET_TM_MODE_")
            if mode_name == "CURRENT":
                if request.source_epoch or request.after_source_sequence:
                    raise ValueError("CURRENT cannot include a source cursor")
            else:
                validate_identifier(request.source_epoch, "source_epoch")
        except ObservationFailure as failure:
            return self._tm_failure(failure)
        except ValueError:
            await self._invalid(context)
        if not self._bound(identity, request.identity.credential_epoch) or not self._context_active(identity):
            return self._tm_failure(
                ObservationFailure(
                    ObservationCode.STALE_GENERATION,
                    "active context generation differs",
                )
            )
        if request.identity.deadline_unix_ns <= time.time_ns():
            return self._tm_failure(
                ObservationFailure(
                    ObservationCode.DEADLINE_EXCEEDED,
                    "simulator telemetry request deadline elapsed",
                )
            )
        if not self._admit():
            return self._tm_failure(
                ObservationFailure(
                    ObservationCode.NOT_AVAILABLE,
                    "observation capacity is exhausted",
                    retryable=True,
                )
            )
        try:
            self.dispatch_counts["GetTM"] += 1
            if mode_name == "CURRENT":
                sample = await self.engine.current(request.item_id)
            else:
                sample = await self.engine.next(
                    request.item_id,
                    request.source_epoch,
                    request.after_source_sequence,
                    request.identity.deadline_unix_ns,
                )
            if not self._context_active(identity):
                raise ObservationFailure(
                    ObservationCode.STALE_GENERATION,
                    "context generation changed during observation",
                )
            return driver_pb2.GetTMResponse(
                contract_version=_contract_version(),
                result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK,
                sample=_sample_message(request.identity.observation_id, identity, sample),
            )
        except asyncio.CancelledError:
            return self._tm_failure(
                ObservationFailure(
                    ObservationCode.CANCELLED, "telemetry NEXT was cancelled"
                )
            )
        except ObservationFailure as failure:
            return self._tm_failure(failure)
        except Exception:
            return self._tm_failure(
                ObservationFailure(
                    ObservationCode.INTERNAL,
                    "simulator telemetry evidence is unavailable",
                )
            )
        finally:
            self._active -= 1


__all__ = ["DriverObservationService", "MAX_ACTIVE_OBSERVATIONS"]
