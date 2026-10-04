"""Authenticated additive DSS RPCs; command bodies have a closed typed shape."""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any
import grpc
from spell.driver.dss.v1 import dss_pb2, dss_pb2_grpc
from spell.driver.v1 import driver_pb2
from .dss_command import DssCommandDriver, DssUnavailable
from .dss_telemetry import DssTelemetryDriver
from .observation import ObservationFailure
from .observation_service import DriverObservationService


class DssService(dss_pb2_grpc.DssServiceServicer):
    def __init__(self, observation: DriverObservationService, command: DssCommandDriver, telemetry: DssTelemetryDriver):
        self.observation = observation
        self.command = command
        self.telemetry = telemetry

    @staticmethod
    def _arguments(values: Any) -> list[dict[str, Any]]:
        expected = {"LONG": "integer_value", "FLOAT": "float_value", "BOOLEAN": "boolean_value", "STRING": "string_value", "TIME": "string_value"}
        result = []
        for item in values:
            field = item.WhichOneof("value")
            if expected.get(item.value_type) != field:
                raise ValueError("DSS argument kind differs")
            result.append({"name": item.name, "value_type": item.value_type, "value_format": item.value_format, "radix": item.radix, "encoded": item.encoded, "value": getattr(item, field)})
        return result

    async def _admit(self, request: Any, context: Any, *, require_context: bool) -> None:
        try:
            identity = self.observation._identity(request.identity, require_context=require_context)
            if not self.observation._bound(identity, request.identity.credential_epoch):
                raise ValueError("stale host identity")
            if require_context and not self.observation._context_active(identity):
                raise ValueError("stale context identity")
            if request.identity.deadline_unix_ns <= time.time_ns():
                await context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "DSS request deadline elapsed")
        except (ValueError, ObservationFailure):
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "DSS generation identity is unavailable")

    async def Health(self, request: Any, context: Any) -> Any:
        await self._admit(request, context, require_context=False)
        try:
            return dss_pb2.HealthResponse(ready=True, status="READY", **self.telemetry.health())
        except DssUnavailable:
            try:
                return dss_pb2.HealthResponse(ready=False, status="TELEMETRY_STALE_OR_DISCONNECTED", **self.telemetry.health(require_fresh=False))
            except DssUnavailable:
                return dss_pb2.HealthResponse(ready=False, status="TELEMETRY_UNAVAILABLE")

    async def ClockEvidence(self, request: Any, context: Any) -> Any:
        await self._admit(request, context, require_context=False)
        try:
            reading, raw = self.telemetry.clock_evidence()
        except (DssUnavailable, ObservationFailure):
            await context.abort(grpc.StatusCode.UNAVAILABLE, "DSS clock packet is unavailable")
        identity = request.identity
        observation = driver_pb2.DriverTimeObservation(
            observation_id=identity.observation_id,
            generation=driver_pb2.ObservationGeneration(**{name:getattr(identity,name)
                for name in ("server_profile_id", "driver_host_generation", "host_profile_digest")}),
            time_unix_ns=reading.time_unix_ns, acquired_at_unix_ns=reading.acquired_at_unix_ns,
            clock_source=driver_pb2.CLOCK_SOURCE_SIMULATOR, provenance=reading.provenance,
            uncertainty_ns=reading.uncertainty_ns, quality=driver_pb2.OBSERVATION_QUALITY_GOOD,
            validity=driver_pb2.OBSERVATION_VALIDITY_VALID)
        return dss_pb2.ClockEvidenceResponse(time_response=driver_pb2.GetTimeResponse(
            contract_version=driver_pb2.ContractVersion(major=1,minor=0),
            result_code=driver_pb2.OBSERVATION_RESULT_CODE_OK, observation=observation),
            telemetry_packet=raw, packet_sha256=hashlib.sha256(raw).hexdigest())

    async def CommandStage(self, request: Any, context: Any) -> Any:
        await self._admit(request, context, require_context=True)
        try:
            health = self.telemetry.health()
            for name in ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id"):
                if getattr(request, name) != health[name]:
                    raise ValueError("DSS request identity differs from current decoded telemetry")
            arguments = self._arguments(request.arguments)
            body = {name: getattr(request, name) for name in ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "operation_id", "procedure_id", "execution_id", "plan_id", "element_id", "stage", "command_name", "command_digest")}
            body.update(schema_version="openbexi.dss.tc/1", arguments=arguments)
            if request.elements:
                body["elements"] = [{"element_id": item.element_id, "command_name": item.command_name, "command_digest": item.command_digest, "arguments": self._arguments(item.arguments)} for item in request.elements]
            if request.verification:
                body["verification"] = [{"channel": item.channel, "operator": item.operator, "expected": self._arguments([item.expected])[0]["value"], "tolerance": item.tolerance if item.HasField("tolerance") else None, "timeout_ms": item.timeout_ms if item.HasField("timeout_ms") else None} for item in request.verification]
                body["tolerance"] = request.tolerance
            if request.HasField("scheduling"):
                value = request.scheduling
                body["scheduling"] = {"target_sim_time_ns": value.target_sim_time_ns,
                    "anchor_sim_time_ns": value.anchor_sim_time_ns, "clock_epoch_unix_ns": value.clock_epoch_unix_ns,
                    "time": value.time if value.HasField("time") else None,
                    "release_time": value.release_time if value.HasField("release_time") else None,
                    "send_delay_ms": value.send_delay_ms, "delay_ms": value.delay_ms}
            result = await asyncio.to_thread(self.command.perform, body)
            return dss_pb2.CommandStageResponse(status="SETTLED", **{name: result[name] for name in ("acknowledgement_packet", "command_packet_sha256", "acknowledgement_packet_sha256")})
        except ValueError:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "DSS command violates the bounded shared profile")
        except DssUnavailable:
            return dss_pb2.CommandStageResponse(status="UNCERTAIN")

    async def PacketEvidence(self, request: Any, context: Any) -> Any:
        await self._admit(request, context, require_context=False)
        if not request.satellite_epoch or len(request.satellite_epoch) > 128 or len(request.operation_id) > 128:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "DSS evidence cursor is invalid")
        try:
            values = self.telemetry.evidence(request.satellite_epoch, request.sequence, request.operation_id, request.packet_sha256)
        except ValueError:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "DSS evidence digest is invalid")
        return dss_pb2.PacketEvidenceResponse(status="FOUND" if values else "NOT_AVAILABLE", packets=[dss_pb2.PacketEvidence(**value) for value in values])
