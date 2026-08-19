"""Typed gRPC service adapter for the Candidate A simulator lifecycle host."""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Optional

import grpc

from spell.driver.v1 import driver_pb2, driver_pb2_grpc

from .config import HostConfig
from .domain import (
    AttemptRecord,
    Certainty,
    ErrorCode,
    GenerationIdentity,
    Method,
    OperationCommand,
    OperationRecord,
    SafeFailure,
    validate_identifier,
)
from .lifecycle import HostSnapshot, SimulatorLifecycleHost


CONTRACT_MAJOR = 1
CONTRACT_MINOR = 0


_CAPABILITIES = (
    ("HOST", "HANDSHAKE", ("NONE",), "READ_ONLY"),
    ("HOST", "HEALTH", ("NONE",), "READ_ONLY"),
    (
        "CONTEXT_LIFECYCLE",
        "OPEN_CONTEXT",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
        "LIFECYCLE",
    ),
    (
        "CONTEXT_LIFECYCLE",
        "CLOSE_CONTEXT",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
        "LIFECYCLE",
    ),
    (
        "EXECUTION_LIFECYCLE",
        "ATTACH_EXECUTION",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
        "LIFECYCLE",
    ),
    (
        "EXECUTION_LIFECYCLE",
        "DETACH_EXECUTION",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
        "LIFECYCLE",
    ),
    (
        "OPERATION_RECONCILIATION",
        "CANCEL_LIFECYCLE_OPERATION",
        ("COOPERATIVE_CANCELLATION",),
        "LIFECYCLE",
    ),
    ("HOST", "DRAIN_HOST", ("COOPERATIVE_CANCELLATION",), "LIFECYCLE"),
    ("OPERATION_RECONCILIATION", "GET_OPERATION", ("NONE",), "READ_ONLY"),
)


def _contract_version() -> Any:
    return driver_pb2.ContractVersion(major=CONTRACT_MAJOR, minor=CONTRACT_MINOR)


def _safe_error(value: Optional[SafeFailure]) -> Any:
    if value is None:
        return driver_pb2.SafeError(code=driver_pb2.SAFE_ERROR_CODE_NONE)
    return driver_pb2.SafeError(
        code=getattr(driver_pb2, f"SAFE_ERROR_CODE_{value.code.value}"),
        safe_message=value.message,
        retryable=value.retryable,
    )


def _driver_identity(config: HostConfig) -> Any:
    return driver_pb2.DriverIdentity(
        logical_driver_id=config.logical_driver_id,
        implementation_version=config.implementation_version,
        simulator=True,
        server_profile_id=config.server_profile_id,
        driver_profile_id=config.driver_profile_id,
        driver_host_generation=config.driver_host_generation,
        host_configuration_schema=config.host_configuration_schema,
        host_profile_digest=config.host_profile_digest,
        credential_epoch=config.credential_epoch,
    )


def _capacity_limits(config: HostConfig) -> Any:
    return driver_pb2.CapacityLimits(
        max_contexts_per_host=config.capacity.max_contexts_per_host,
        max_attachments_per_context=config.capacity.max_attachments_per_context,
        max_lifecycle_operations_per_host=config.capacity.max_lifecycle_operations_per_host,
        max_lifecycle_operations_per_context=config.capacity.max_lifecycle_operations_per_context,
    )


def _capacity_use(snapshot: HostSnapshot) -> Any:
    return driver_pb2.CapacityUse(
        contexts=len(snapshot.contexts),
        attachments=len(snapshot.attachments),
        lifecycle_operations_host=snapshot.in_flight_host,
        lifecycle_operations_context=snapshot.in_flight_context,
    )


def _capability_messages() -> tuple[Any, ...]:
    return tuple(
        driver_pb2.CapabilityDescriptor(
            service=getattr(driver_pb2, f"INFRASTRUCTURE_SERVICE_{service}"),
            method=getattr(driver_pb2, f"RPC_METHOD_{method}"),
            modifiers=[
                getattr(driver_pb2, f"CAPABILITY_MODIFIER_{modifier}")
                for modifier in modifiers
            ],
            formats=[driver_pb2.CAPABILITY_FORMAT_PROTOBUF_BINARY],
            mutability=getattr(driver_pb2, f"MUTABILITY_{mutability}"),
            stream_support=driver_pb2.STREAM_SUPPORT_NONE,
        )
        for service, method, modifiers, mutability in _CAPABILITIES
    )


def _identity_message(
    identity: GenerationIdentity,
    *,
    operation_id: str = "",
    attempt_id: str = "",
    attempt_number: int = 0,
) -> Any:
    return driver_pb2.RequestIdentity(
        contract_version=_contract_version(),
        server_profile_id=identity.server_profile_id,
        driver_host_generation=identity.driver_host_generation,
        host_profile_digest=identity.host_profile_digest,
        context_id=identity.context_id,
        context_generation=identity.context_generation,
        context_binding_digest=identity.context_binding_digest,
        execution_id=identity.execution_id,
        execution_attachment_generation=identity.execution_attachment_generation,
        execution_attachment_digest=identity.execution_attachment_digest,
        driver_binding_id=identity.driver_binding_id,
        operation_id=operation_id,
        attempt_id=attempt_id,
        attempt_number=attempt_number,
    )


def _attempt_message(value: AttemptRecord) -> Any:
    certainty = driver_pb2.EFFECT_CERTAINTY_UNSPECIFIED
    if value.certainty is not None:
        certainty_names = {
            Certainty.NO_EFFECT: "NO_EFFECT",
            Certainty.EFFECT_CONFIRMED: "CONFIRMED",
            Certainty.EFFECT_POSSIBLE: "POSSIBLE",
            Certainty.EFFECT_UNKNOWN: "UNKNOWN",
        }
        certainty = getattr(
            driver_pb2, f"EFFECT_CERTAINTY_{certainty_names[value.certainty]}"
        )
    return driver_pb2.OperationAttempt(
        attempt_id=value.attempt_id,
        attempt_number=value.attempt_number,
        request_digest=value.request_digest,
        stage=getattr(driver_pb2, f"OPERATION_STAGE_{value.stage.value}"),
        effect_class=getattr(driver_pb2, f"EFFECT_CLASS_{value.effect.value}"),
        certainty_present=value.certainty is not None,
        certainty=certainty,
        result_code=getattr(driver_pb2, f"RESULT_CODE_{value.result.value}"),
        error=_safe_error(value.error),
        requested_unix_ms=value.requested_unix_ms,
        accepted_unix_ms=value.accepted_unix_ms,
        dispatched_unix_ms=value.dispatched_unix_ms,
        settled_unix_ms=value.settled_unix_ms,
        hook_traces=[
            driver_pb2.HookTrace(
                sequence=trace.sequence,
                hook_id=trace.hook_id,
                owner_layer=getattr(driver_pb2, f"HOOK_LAYER_{trace.layer.value}"),
                action=getattr(driver_pb2, f"HOOK_ACTION_{trace.action.value}"),
                result=getattr(driver_pb2, f"HOOK_RESULT_{trace.outcome.value}"),
                operation_id=value.operation_id,
                attempt_id=value.attempt_id,
                started_unix_ms=trace.started_unix_ms,
                completed_unix_ms=trace.completed_unix_ms,
                error=_safe_error(trace.error),
                identity=_identity_message(
                    trace.identity or value.identity,
                    operation_id=trace.operation_id or value.operation_id,
                    attempt_id=trace.attempt_id or value.attempt_id,
                    attempt_number=value.attempt_number,
                ),
                stage=getattr(driver_pb2, f"OPERATION_STAGE_{trace.stage.value}"),
                certainty_present=trace.certainty is not None,
                certainty=(
                    getattr(
                        driver_pb2,
                        "EFFECT_CERTAINTY_"
                        + {
                            Certainty.NO_EFFECT: "NO_EFFECT",
                            Certainty.EFFECT_CONFIRMED: "CONFIRMED",
                            Certainty.EFFECT_POSSIBLE: "POSSIBLE",
                            Certainty.EFFECT_UNKNOWN: "UNKNOWN",
                        }[trace.certainty],
                    )
                    if trace.certainty is not None
                    else driver_pb2.EFFECT_CERTAINTY_UNSPECIFIED
                ),
            )
            for trace in value.hook_traces
        ],
        identity=_identity_message(
            value.identity,
            operation_id=value.operation_id,
            attempt_id=value.attempt_id,
            attempt_number=value.attempt_number,
        ),
        attachment_reason=(
            getattr(driver_pb2, f"ATTACHMENT_REASON_{value.lifecycle_reason}")
            if value.lifecycle_reason
            else driver_pb2.ATTACHMENT_REASON_UNSPECIFIED
        ),
        replaced_driver_binding_id=value.replaced_driver_binding_id,
    )


def _operation_message(value: OperationRecord) -> Any:
    current = value.attempts[-1]
    return driver_pb2.OperationRecord(
        operation_id=value.operation_id,
        method=getattr(driver_pb2, f"RPC_METHOD_{value.method.name}"),
        identity=_identity_message(
            value.identity,
            operation_id=value.operation_id,
            attempt_id=current.attempt_id,
            attempt_number=current.attempt_number,
        ),
        current_attempt_id=value.current_attempt_id,
        attempts=[_attempt_message(attempt) for attempt in value.attempts],
    )


def _generation_identity(value: Any) -> GenerationIdentity:
    return GenerationIdentity(
        server_profile_id=value.server_profile_id,
        driver_host_generation=value.driver_host_generation,
        host_profile_digest=value.host_profile_digest,
        context_id=value.context_id,
        context_generation=value.context_generation,
        context_binding_digest=value.context_binding_digest,
        execution_id=value.execution_id,
        execution_attachment_generation=value.execution_attachment_generation,
        execution_attachment_digest=value.execution_attachment_digest,
        driver_binding_id=value.driver_binding_id,
    )


def _command(value: Any, method: Method, **fields: object) -> OperationCommand:
    identity = value.identity
    if (
        identity.contract_version.major != CONTRACT_MAJOR
        or identity.contract_version.minor > CONTRACT_MINOR
    ):
        raise ValueError("request contract version is unsupported")
    return OperationCommand(
        method=method,
        identity=_generation_identity(identity),
        operation_id=identity.operation_id,
        attempt_id=identity.attempt_id,
        attempt_number=identity.attempt_number,
        correlation_id=identity.correlation_id,
        deadline_unix_ms=identity.deadline_unix_ms,
        credential_epoch=identity.credential_epoch,
        **fields,
    )


def _enum_suffix(message: Any, field_name: str, prefix: str) -> str:
    field = message.DESCRIPTOR.fields_by_name[field_name]
    value = int(getattr(message, field_name))
    descriptor = field.enum_type.values_by_number.get(value)
    if descriptor is None or descriptor.number == 0:
        raise ValueError(f"{field_name} is unknown or unspecified")
    return descriptor.name.removeprefix(prefix)


class DriverInfrastructureService(
    driver_pb2_grpc.DriverInfrastructureServiceServicer
):
    """The one approved service; no future or procedure service is registered."""

    def __init__(self, config: HostConfig, host: SimulatorLifecycleHost) -> None:
        self.config = config
        self.host = host
        self.dispatch_counts: Counter[str] = Counter()

    async def _invalid(self, context: grpc.aio.ServicerContext) -> None:
        await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid bounded driver request")

    def _read_identity(
        self,
        value: Any,
        *,
        allow_unbound_generation: bool = False,
        allow_historical_identity: bool = False,
    ) -> None:
        if (
            value.contract_version.major != CONTRACT_MAJOR
            or value.contract_version.minor > CONTRACT_MINOR
        ):
            raise ValueError("request contract version is unsupported")
        if value.server_profile_id != self.config.server_profile_id:
            raise ValueError("server profile differs")
        if (
            not allow_historical_identity
            and value.host_profile_digest != self.config.host_profile_digest
        ):
            raise ValueError("host profile digest differs")
        if value.credential_epoch != self.config.credential_epoch:
            raise ValueError("credential epoch differs")
        if not (allow_unbound_generation or allow_historical_identity) and (
            value.driver_host_generation != self.config.driver_host_generation
        ):
            raise ValueError("driver host generation differs")
        for label in ("operation_id", "attempt_id", "correlation_id"):
            validate_identifier(getattr(value, label), label)
        if value.attempt_number < 1 or value.deadline_unix_ms <= 0:
            raise ValueError("read identity is incomplete")

    async def Handshake(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        snapshot = self.host.snapshot()
        error: Optional[SafeFailure] = None
        try:
            self._read_identity(
                request.identity,
                allow_historical_identity=True,
            )
            if (
                request.requested_version.major != CONTRACT_MAJOR
                or request.requested_version.minor > CONTRACT_MINOR
            ):
                error = SafeFailure(ErrorCode.VERSION_MISMATCH, "contract version is unsupported")
            elif request.expected_logical_driver_id != self.config.logical_driver_id:
                error = SafeFailure(ErrorCode.IDENTITY_MISMATCH, "logical driver identity differs")
            elif request.expected_host_profile_digest != self.config.host_profile_digest:
                error = SafeFailure(ErrorCode.DIGEST_MISMATCH, "host profile digest differs")
            else:
                requested = tuple(
                    item.SerializeToString(deterministic=True)
                    for item in request.required_capabilities
                )
                if len(requested) > len(_CAPABILITIES) or len(set(requested)) != len(
                    requested
                ):
                    raise ValueError("required capabilities are duplicated or unbounded")
                supported = {
                    item.SerializeToString(deterministic=True)
                    for item in _capability_messages()
                }
                if any(item not in supported for item in requested):
                    error = SafeFailure(ErrorCode.UNSUPPORTED, "required capability is unsupported")
        except ValueError:
            await self._invalid(context)
        self.dispatch_counts[Method.HANDSHAKE.value] += 1
        return driver_pb2.HandshakeResponse(
            contract_version=_contract_version(),
            driver=_driver_identity(self.config),
            host_state=getattr(driver_pb2, f"HOST_STATE_{snapshot.state.value}"),
            capabilities=_capability_messages(),
            capacity_limits=_capacity_limits(self.config),
            capacity_use=_capacity_use(snapshot),
            last_observed_unix_ms=snapshot.last_observed_unix_ms,
            error=_safe_error(error),
        )

    async def Health(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        try:
            self._read_identity(request.identity)
        except ValueError:
            await self._invalid(context)
        self.dispatch_counts[Method.HEALTH.value] += 1
        snapshot = self.host.snapshot()
        return driver_pb2.HealthResponse(
            contract_version=_contract_version(),
            driver=_driver_identity(self.config),
            host_state=getattr(driver_pb2, f"HOST_STATE_{snapshot.state.value}"),
            ready=snapshot.ready,
            capacity_limits=_capacity_limits(self.config),
            capacity_use=_capacity_use(snapshot),
            contexts=[
                driver_pb2.ContextHealth(
                    context_id=item.context_id,
                    context_generation=item.context_generation,
                    context_binding_digest=item.context_binding_digest,
                    state=getattr(driver_pb2, f"CONTEXT_STATE_{item.state.value}"),
                    ready=item.ready,
                    last_observed_unix_ms=item.last_observed_unix_ms,
                    capacity_use=_capacity_use(snapshot),
                )
                for item in snapshot.contexts
            ],
            attachments=[
                driver_pb2.AttachmentHealth(
                    execution_id=item.execution_id,
                    execution_attachment_generation=item.execution_attachment_generation,
                    execution_attachment_digest=item.execution_attachment_digest,
                    driver_binding_id=item.driver_binding_id,
                    state=getattr(driver_pb2, f"ATTACHMENT_STATE_{item.state.value}"),
                    last_observed_unix_ms=item.last_observed_unix_ms,
                )
                for item in snapshot.attachments
            ],
            last_observed_unix_ms=snapshot.last_observed_unix_ms,
        )

    async def _mutation(
        self,
        request: Any,
        context: grpc.aio.ServicerContext,
        method: Method,
        command_factory: Callable[[], OperationCommand],
    ) -> Any:
        try:
            command = command_factory()
        except ValueError:
            await self._invalid(context)
        bound = (
            command.identity.server_profile_id == self.config.server_profile_id
            and command.identity.driver_host_generation
            == self.config.driver_host_generation
            and command.identity.host_profile_digest == self.config.host_profile_digest
            and command.credential_epoch == self.config.credential_epoch
        )
        if bound:
            self.dispatch_counts[method.value] += 1
        try:
            operation = await self.host.execute(command)
        except Exception:
            await context.abort(
                grpc.StatusCode.INTERNAL, "driver lifecycle evidence is unavailable"
            )
        return driver_pb2.LifecycleOperationResponse(
            contract_version=_contract_version(), operation=_operation_message(operation)
        )

    async def OpenContext(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return await self._mutation(
            request,
            context,
            Method.OPEN_CONTEXT,
            lambda: _command(
                request,
                Method.OPEN_CONTEXT,
                context_schema_version=request.configuration.schema_version,
                context_profile_id=request.configuration.context_profile_id,
                synthetic_context_label=request.configuration.synthetic_context_label,
                expected_context_digest=request.configuration.expected_context_binding_digest,
            ),
        )

    async def CloseContext(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return await self._mutation(
            request,
            context,
            Method.CLOSE_CONTEXT,
            lambda: _command(
                request,
                Method.CLOSE_CONTEXT,
                detach_settled_attachments=request.detach_settled_attachments,
            ),
        )

    async def AttachExecution(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return await self._mutation(
            request,
            context,
            Method.ATTACH_EXECUTION,
            lambda: _command(
                request,
                Method.ATTACH_EXECUTION,
                attachment_schema_version=request.configuration.schema_version,
                attachment_profile_id=request.configuration.attachment_profile_id,
                synthetic_execution_label=request.configuration.synthetic_execution_label,
                expected_attachment_digest=request.configuration.expected_execution_attachment_digest,
                lifecycle_reason=_enum_suffix(
                    request.configuration, "reason", "ATTACHMENT_REASON_"
                ),
                replaced_driver_binding_id=(
                    request.configuration.replaced_driver_binding_id
                ),
            ),
        )

    async def DetachExecution(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return await self._mutation(
            request,
            context,
            Method.DETACH_EXECUTION,
            lambda: _command(
                request,
                Method.DETACH_EXECUTION,
                lifecycle_reason=_enum_suffix(request, "reason", "DETACHMENT_REASON_"),
            ),
        )

    async def CancelLifecycleOperation(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> Any:
        return await self._mutation(
            request,
            context,
            Method.CANCEL_LIFECYCLE_OPERATION,
            lambda: _command(
                request,
                Method.CANCEL_LIFECYCLE_OPERATION,
                target_operation_id=request.target_operation_id,
                target_attempt_id=request.target_attempt_id,
            ),
        )

    async def DrainHost(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return await self._mutation(
            request,
            context,
            Method.DRAIN_HOST,
            lambda: _command(
                request,
                Method.DRAIN_HOST,
                grace_period_ms=request.grace_period_ms,
            ),
        )

    async def GetOperation(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        try:
            # Reconciliation intentionally addresses the generation that
            # accepted the original attempt. Current mTLS identity and
            # credential epoch authenticate the caller independently.
            self._read_identity(request.identity, allow_unbound_generation=True)
            validate_identifier(request.target_operation_id, "target_operation_id")
            validate_identifier(
                request.target_attempt_id, "target_attempt_id", optional=True
            )
        except ValueError:
            await self._invalid(context)
        self.dispatch_counts[Method.GET_OPERATION.value] += 1
        try:
            operation = self.host.get_operation(
                request.target_operation_id, request.target_attempt_id
            )
        except KeyError:
            return driver_pb2.GetOperationResponse(
                contract_version=_contract_version(),
                error=_safe_error(
                    SafeFailure(ErrorCode.VALIDATION, "lifecycle operation was not found")
                ),
            )
        except Exception:
            await context.abort(
                grpc.StatusCode.INTERNAL, "driver lifecycle evidence is unavailable"
            )
        requested_identity = _generation_identity(request.identity)
        matching_attempts = (
            tuple(
                attempt
                for attempt in operation.attempts
                if attempt.attempt_id == request.target_attempt_id
            )
            if request.target_attempt_id
            else (operation.attempts[-1],)
        )
        if (
            len(matching_attempts) != 1
            or matching_attempts[0].identity != requested_identity
        ):
            await self._invalid(context)
        return driver_pb2.GetOperationResponse(
            contract_version=_contract_version(), operation=_operation_message(operation)
        )
