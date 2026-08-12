"""Async mTLS gateway client for the Candidate A driver host."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence, Tuple

import grpc

from spell.driver.v1 import driver_pb2, driver_pb2_grpc

from .driver_domain import (
    CONTRACT_MAJOR,
    CONTRACT_MAJOR_METADATA,
    CONTRACT_MINOR,
    CREDENTIAL_EPOCH_METADATA,
    DEFAULT_HOST_PROFILE_DIGEST,
    DEFAULT_LOGICAL_DRIVER_ID,
    DEFAULT_SERVER_PROFILE_ID,
    AttachmentHealth,
    AttachExecutionCommand,
    CancelLifecycleOperationCommand,
    Capability,
    Capacity,
    CloseContextCommand,
    ContextHealth,
    ContractVersion,
    DetachExecutionCommand,
    DrainHostCommand,
    DriverIdentity,
    DriverRpcMethod,
    EffectCertainty,
    EffectClass,
    GenerationTuple,
    GetOperationQuery,
    HandshakeResult,
    HealthResult,
    HookTrace,
    OpenContextCommand,
    OperationAttemptResult,
    OperationIdentity,
    OperationResult,
    OperationStage,
    ResultCode,
    SafeError,
)


MAX_MESSAGE_BYTES = 64 * 1024
SERVER_AUTHORITY = "spell-driver"
DRIVER_TARGET = "spell-driver:50051"


class DriverTransportError(RuntimeError):
    """A bounded transport failure with no peer-supplied detail."""

    def __init__(self, code: str) -> None:
        super().__init__(f"driver transport failed: {code}")
        self.code = code


def _read_credential(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    data = path.read_bytes()
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise ValueError(f"{label} has an invalid size")
    return data


def _enum_name(message: Any, field: str) -> str:
    descriptor = message.DESCRIPTOR.fields_by_name[field].enum_type
    return descriptor.values_by_number[int(getattr(message, field))].name


def _strip_prefix(value: str, prefix: str) -> str:
    return value.removeprefix(prefix)


def _safe_error(value: Any) -> Optional[SafeError]:
    code = _strip_prefix(_enum_name(value, "code"), "SAFE_ERROR_CODE_")
    if code in {"UNSPECIFIED", "NONE"} and not value.safe_message:
        return None
    return SafeError(code=code, message=value.safe_message, retryable=value.retryable)


def _driver_identity(value: Any) -> DriverIdentity:
    return DriverIdentity(
        logical_driver_id=value.logical_driver_id,
        implementation_version=value.implementation_version,
        simulator=value.simulator,
        server_profile_id=value.server_profile_id,
        driver_profile_id=value.driver_profile_id,
        driver_host_generation=value.driver_host_generation,
        host_configuration_schema=value.host_configuration_schema,
        host_profile_digest=value.host_profile_digest,
        credential_epoch=value.credential_epoch,
    )


def _generations(value: Any) -> GenerationTuple:
    return GenerationTuple(
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


def _capacity(limits: Any, use: Any) -> Capacity:
    return Capacity(
        max_contexts_per_host=limits.max_contexts_per_host,
        max_attachments_per_context=limits.max_attachments_per_context,
        max_lifecycle_operations_per_host=limits.max_lifecycle_operations_per_host,
        max_lifecycle_operations_per_context=limits.max_lifecycle_operations_per_context,
        contexts=use.contexts,
        attachments=use.attachments,
        lifecycle_operations_host=use.lifecycle_operations_host,
        lifecycle_operations_context=use.lifecycle_operations_context,
    )


def _capability(value: Any) -> Capability:
    method_name = _strip_prefix(_enum_name(value, "method"), "RPC_METHOD_")
    method = DriverRpcMethod[
        {
            "OPEN_CONTEXT": "OPEN_CONTEXT",
            "CLOSE_CONTEXT": "CLOSE_CONTEXT",
            "ATTACH_EXECUTION": "ATTACH_EXECUTION",
            "DETACH_EXECUTION": "DETACH_EXECUTION",
            "CANCEL_LIFECYCLE_OPERATION": "CANCEL_LIFECYCLE_OPERATION",
            "DRAIN_HOST": "DRAIN_HOST",
            "GET_OPERATION": "GET_OPERATION",
            "HANDSHAKE": "HANDSHAKE",
            "HEALTH": "HEALTH",
        }[method_name]
    ]
    modifiers = tuple(
        _strip_prefix(value.DESCRIPTOR.fields_by_name["modifiers"].enum_type.values_by_number[item].name, "CAPABILITY_MODIFIER_")
        for item in value.modifiers
    )
    formats = tuple(
        _strip_prefix(value.DESCRIPTOR.fields_by_name["formats"].enum_type.values_by_number[item].name, "CAPABILITY_FORMAT_")
        for item in value.formats
    )
    return Capability(
        service=_strip_prefix(_enum_name(value, "service"), "INFRASTRUCTURE_SERVICE_"),
        method=method,
        modifiers=modifiers,
        formats=formats,
        mutability=_strip_prefix(_enum_name(value, "mutability"), "MUTABILITY_"),
        stream_support=_strip_prefix(_enum_name(value, "stream_support"), "STREAM_SUPPORT_"),
    )


def _operation(value: Any) -> OperationResult:
    method_name = _strip_prefix(_enum_name(value, "method"), "RPC_METHOD_")
    method = DriverRpcMethod[
        {
            "HANDSHAKE": "HANDSHAKE",
            "HEALTH": "HEALTH",
            "OPEN_CONTEXT": "OPEN_CONTEXT",
            "CLOSE_CONTEXT": "CLOSE_CONTEXT",
            "ATTACH_EXECUTION": "ATTACH_EXECUTION",
            "DETACH_EXECUTION": "DETACH_EXECUTION",
            "CANCEL_LIFECYCLE_OPERATION": "CANCEL_LIFECYCLE_OPERATION",
            "DRAIN_HOST": "DRAIN_HOST",
            "GET_OPERATION": "GET_OPERATION",
        }[method_name]
    ]
    attempts = []
    for attempt in value.attempts:
        traces = tuple(
            HookTrace(
                sequence=trace.sequence,
                hook_id=trace.hook_id,
                owner_layer=_strip_prefix(_enum_name(trace, "owner_layer"), "HOOK_LAYER_"),
                action=_strip_prefix(_enum_name(trace, "action"), "HOOK_ACTION_"),
                result=_strip_prefix(_enum_name(trace, "result"), "HOOK_RESULT_"),
                started_unix_ms=trace.started_unix_ms,
                completed_unix_ms=trace.completed_unix_ms,
                error=_safe_error(trace.error),
                generations=_generations(trace.identity),
                operation_id=trace.operation_id,
                attempt_id=trace.attempt_id,
                stage=OperationStage(
                    _strip_prefix(_enum_name(trace, "stage"), "OPERATION_STAGE_")
                ),
                certainty=(
                    EffectCertainty(
                        {
                            "CONFIRMED": "EFFECT_CONFIRMED",
                            "POSSIBLE": "EFFECT_POSSIBLE",
                            "UNKNOWN": "EFFECT_UNKNOWN",
                            "NO_EFFECT": "NO_EFFECT",
                        }[
                            _strip_prefix(
                                _enum_name(trace, "certainty"), "EFFECT_CERTAINTY_"
                            )
                        ]
                    )
                    if trace.certainty_present
                    else None
                ),
            )
            for trace in attempt.hook_traces
        )
        certainty = None
        if attempt.certainty_present:
            certainty_name = _strip_prefix(
                _enum_name(attempt, "certainty"), "EFFECT_CERTAINTY_"
            )
            certainty = EffectCertainty(
                {
                    "CONFIRMED": "EFFECT_CONFIRMED",
                    "POSSIBLE": "EFFECT_POSSIBLE",
                    "UNKNOWN": "EFFECT_UNKNOWN",
                    "NO_EFFECT": "NO_EFFECT",
                }[certainty_name]
            )
        effect_name = _strip_prefix(_enum_name(attempt, "effect_class"), "EFFECT_CLASS_")
        attempts.append(
            OperationAttemptResult(
                attempt_id=attempt.attempt_id,
                attempt_number=attempt.attempt_number,
                request_digest=attempt.request_digest,
                stage=OperationStage(
                    _strip_prefix(_enum_name(attempt, "stage"), "OPERATION_STAGE_")
                ),
                effect_class=EffectClass(effect_name),
                certainty=certainty,
                result_code=ResultCode(
                    _strip_prefix(_enum_name(attempt, "result_code"), "RESULT_CODE_")
                ),
                error=_safe_error(attempt.error),
                requested_unix_ms=attempt.requested_unix_ms,
                accepted_unix_ms=attempt.accepted_unix_ms,
                dispatched_unix_ms=attempt.dispatched_unix_ms,
                settled_unix_ms=attempt.settled_unix_ms,
                hook_traces=traces,
                generations=_generations(attempt.identity),
                lifecycle_reason=(
                    _strip_prefix(
                        _enum_name(attempt, "attachment_reason"),
                        "ATTACHMENT_REASON_",
                    )
                    if attempt.attachment_reason
                    else ""
                ),
                replaced_driver_binding_id=attempt.replaced_driver_binding_id,
            )
        )
    return OperationResult(
        operation_id=value.operation_id,
        method=method,
        current_attempt_id=value.current_attempt_id,
        attempts=tuple(attempts),
    )


def _request_identity(identity: OperationIdentity) -> Any:
    generations = identity.generations
    return driver_pb2.RequestIdentity(
        contract_version=driver_pb2.ContractVersion(major=CONTRACT_MAJOR, minor=CONTRACT_MINOR),
        server_profile_id=generations.server_profile_id,
        driver_host_generation=generations.driver_host_generation,
        host_profile_digest=generations.host_profile_digest,
        context_id=generations.context_id,
        context_generation=generations.context_generation,
        context_binding_digest=generations.context_binding_digest,
        execution_id=generations.execution_id,
        execution_attachment_generation=generations.execution_attachment_generation,
        execution_attachment_digest=generations.execution_attachment_digest,
        driver_binding_id=generations.driver_binding_id,
        operation_id=identity.operation_id,
        attempt_id=identity.attempt_id,
        attempt_number=identity.attempt_number,
        correlation_id=identity.correlation_id,
        deadline_unix_ms=identity.deadline_unix_ms,
        credential_epoch=identity.credential_epoch,
    )


class DriverClient:
    """One no-retry, deadline-bounded mTLS channel to the bundled simulator."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        timeout_seconds: float,
        credential_epoch: int,
        host_profile_digest: str = DEFAULT_HOST_PROFILE_DIGEST,
    ) -> None:
        self._channel = channel
        self._stub = driver_pb2_grpc.DriverInfrastructureServiceStub(channel)
        self._timeout_seconds = timeout_seconds
        self._credential_epoch = credential_epoch
        self._host_profile_digest = host_profile_digest
        self._handshake: Optional[HandshakeResult] = None

    @classmethod
    def from_files(
        cls,
        target: str,
        ca_path: str | Path,
        cert_path: str | Path,
        key_path: str | Path,
        timeout_seconds: float,
        *,
        credential_epoch: int = 1,
        host_profile_digest: str = DEFAULT_HOST_PROFILE_DIGEST,
    ) -> "DriverClient":
        if target != DRIVER_TARGET:
            raise ValueError("driver target must be the bundled spell-driver service")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between zero and 30")
        if credential_epoch < 1:
            raise ValueError("credential_epoch must be at least one")
        if (
            len(host_profile_digest) != 64
            or any(value not in "0123456789abcdef" for value in host_profile_digest)
        ):
            raise ValueError("host_profile_digest must be a lowercase SHA-256 digest")
        ca_file = Path(ca_path)
        cert_file = Path(cert_path)
        key_file = Path(key_path)
        root_certificates = _read_credential(ca_file, "driver CA certificate")
        certificate_chain = _read_credential(cert_file, "gateway certificate")
        private_key = _read_credential(key_file, "gateway private key")
        try:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=root_certificates,
                private_key=private_key,
                certificate_chain=certificate_chain,
            )
        finally:
            private_key = b""
            key_file.unlink()
        options = (
            ("grpc.enable_retries", 0),
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
            ("grpc.ssl_target_name_override", SERVER_AUTHORITY),
            ("grpc.default_authority", SERVER_AUTHORITY),
        )
        channel = grpc.aio.secure_channel(target, credentials, options=options)
        return cls(
            channel,
            timeout_seconds,
            credential_epoch,
            host_profile_digest,
        )

    def _metadata(self) -> Tuple[Tuple[str, str], ...]:
        return (
            (CONTRACT_MAJOR_METADATA, str(CONTRACT_MAJOR)),
            (CREDENTIAL_EPOCH_METADATA, str(self._credential_epoch)),
        )

    async def _call(self, rpc: Any, request: Any) -> Any:
        try:
            return await rpc(
                request,
                timeout=self._timeout_seconds,
                metadata=self._metadata(),
                wait_for_ready=False,
            )
        except grpc.aio.AioRpcError as exc:
            raise DriverTransportError(exc.code().name) from None

    def _read_identity(self) -> Any:
        now = int(time.time() * 1000)
        handshake = self._handshake
        return driver_pb2.RequestIdentity(
            contract_version=driver_pb2.ContractVersion(
                major=CONTRACT_MAJOR, minor=CONTRACT_MINOR
            ),
            server_profile_id=(
                handshake.driver.server_profile_id if handshake else DEFAULT_SERVER_PROFILE_ID
            ),
            driver_host_generation=(
                handshake.driver.driver_host_generation if handshake else ""
            ),
            host_profile_digest=(
                handshake.driver.host_profile_digest
                if handshake
                else self._host_profile_digest
            ),
            operation_id=str(uuid.uuid4()),
            attempt_id=str(uuid.uuid4()),
            attempt_number=1,
            correlation_id=str(uuid.uuid4()),
            deadline_unix_ms=now + int(self._timeout_seconds * 1000),
            credential_epoch=self._credential_epoch,
        )

    async def handshake(self) -> HandshakeResult:
        response = await self._call(
            self._stub.Handshake,
            driver_pb2.HandshakeRequest(
                identity=self._read_identity(),
                requested_version=driver_pb2.ContractVersion(
                    major=CONTRACT_MAJOR, minor=CONTRACT_MINOR
                ),
                expected_logical_driver_id=DEFAULT_LOGICAL_DRIVER_ID,
                expected_host_profile_digest=self._host_profile_digest,
            ),
        )
        result = HandshakeResult(
            contract_version=ContractVersion(
                response.contract_version.major, response.contract_version.minor
            ),
            driver=_driver_identity(response.driver),
            host_state=_strip_prefix(_enum_name(response, "host_state"), "HOST_STATE_"),
            capabilities=tuple(_capability(value) for value in response.capabilities),
            capacity=_capacity(response.capacity_limits, response.capacity_use),
            last_observed_unix_ms=response.last_observed_unix_ms,
            error=_safe_error(response.error),
        )
        self._handshake = result
        return result

    async def health(self) -> HealthResult:
        response = await self._call(
            self._stub.Health, driver_pb2.HealthRequest(identity=self._read_identity())
        )
        return HealthResult(
            contract_version=ContractVersion(
                response.contract_version.major, response.contract_version.minor
            ),
            driver=_driver_identity(response.driver),
            host_state=_strip_prefix(_enum_name(response, "host_state"), "HOST_STATE_"),
            ready=response.ready,
            capacity=_capacity(response.capacity_limits, response.capacity_use),
            contexts=tuple(
                ContextHealth(
                    context_id=value.context_id,
                    context_generation=value.context_generation,
                    context_binding_digest=value.context_binding_digest,
                    state=_strip_prefix(_enum_name(value, "state"), "CONTEXT_STATE_"),
                    ready=value.ready,
                    last_observed_unix_ms=value.last_observed_unix_ms,
                )
                for value in response.contexts
            ),
            attachments=tuple(
                AttachmentHealth(
                    execution_id=value.execution_id,
                    execution_attachment_generation=value.execution_attachment_generation,
                    execution_attachment_digest=value.execution_attachment_digest,
                    driver_binding_id=value.driver_binding_id,
                    state=_strip_prefix(_enum_name(value, "state"), "ATTACHMENT_STATE_"),
                    last_observed_unix_ms=value.last_observed_unix_ms,
                )
                for value in response.attachments
            ),
            last_observed_unix_ms=response.last_observed_unix_ms,
            error=_safe_error(response.error),
        )

    async def open_context(self, request: OpenContextCommand) -> OperationResult:
        response = await self._call(
            self._stub.OpenContext,
            driver_pb2.OpenContextRequest(
                identity=_request_identity(request.identity),
                configuration=driver_pb2.ContextBindingConfiguration(
                    schema_version=request.configuration.schema_version,
                    context_profile_id=request.configuration.context_profile_id,
                    synthetic_context_label=request.configuration.synthetic_context_label,
                    expected_context_binding_digest=request.configuration.expected_digest,
                ),
            ),
        )
        return _operation(response.operation)

    async def close_context(self, request: CloseContextCommand) -> OperationResult:
        response = await self._call(
            self._stub.CloseContext,
            driver_pb2.CloseContextRequest(
                identity=_request_identity(request.identity),
                detach_settled_attachments=request.detach_settled_attachments,
            ),
        )
        return _operation(response.operation)

    async def attach_execution(self, request: AttachExecutionCommand) -> OperationResult:
        reason = (
            driver_pb2.ATTACHMENT_REASON_INITIAL_LOAD
            if request.configuration.reason == "INITIAL_LOAD"
            else driver_pb2.ATTACHMENT_REASON_RELOAD
        )
        response = await self._call(
            self._stub.AttachExecution,
            driver_pb2.AttachExecutionRequest(
                identity=_request_identity(request.identity),
                configuration=driver_pb2.ExecutionAttachmentConfiguration(
                    schema_version=request.configuration.schema_version,
                    attachment_profile_id=request.configuration.attachment_profile_id,
                    synthetic_execution_label=request.configuration.synthetic_execution_label,
                    expected_execution_attachment_digest=request.configuration.expected_digest,
                    reason=reason,
                    replaced_driver_binding_id=(
                        request.configuration.replaced_driver_binding_id
                    ),
                ),
            ),
        )
        return _operation(response.operation)

    async def detach_execution(self, request: DetachExecutionCommand) -> OperationResult:
        reason = getattr(driver_pb2, f"DETACHMENT_REASON_{request.reason}")
        response = await self._call(
            self._stub.DetachExecution,
            driver_pb2.DetachExecutionRequest(
                identity=_request_identity(request.identity), reason=reason
            ),
        )
        return _operation(response.operation)

    async def cancel_lifecycle_operation(
        self, request: CancelLifecycleOperationCommand
    ) -> OperationResult:
        response = await self._call(
            self._stub.CancelLifecycleOperation,
            driver_pb2.CancelLifecycleOperationRequest(
                identity=_request_identity(request.identity),
                target_operation_id=request.target_operation_id,
                target_attempt_id=request.target_attempt_id,
            ),
        )
        return _operation(response.operation)

    async def drain_host(self, request: DrainHostCommand) -> OperationResult:
        response = await self._call(
            self._stub.DrainHost,
            driver_pb2.DrainHostRequest(
                identity=_request_identity(request.identity),
                grace_period_ms=request.grace_period_ms,
            ),
        )
        return _operation(response.operation)

    async def get_operation(self, request: GetOperationQuery) -> OperationResult:
        identity = driver_pb2.RequestIdentity(
            contract_version=driver_pb2.ContractVersion(
                major=CONTRACT_MAJOR, minor=CONTRACT_MINOR
            ),
            server_profile_id=request.generations.server_profile_id,
            driver_host_generation=request.generations.driver_host_generation,
            host_profile_digest=request.generations.host_profile_digest,
            context_id=request.generations.context_id,
            context_generation=request.generations.context_generation,
            context_binding_digest=request.generations.context_binding_digest,
            execution_id=request.generations.execution_id,
            execution_attachment_generation=request.generations.execution_attachment_generation,
            execution_attachment_digest=request.generations.execution_attachment_digest,
            driver_binding_id=request.generations.driver_binding_id,
            operation_id=str(uuid.uuid4()),
            attempt_id=str(uuid.uuid4()),
            attempt_number=1,
            correlation_id=request.correlation_id,
            deadline_unix_ms=request.deadline_unix_ms,
            credential_epoch=request.credential_epoch,
        )
        response = await self._call(
            self._stub.GetOperation,
            driver_pb2.GetOperationRequest(
                identity=identity,
                target_operation_id=request.target_operation_id,
                target_attempt_id=request.target_attempt_id,
            ),
        )
        if _safe_error(response.error) is not None and not response.operation.operation_id:
            error = _safe_error(response.error)
            raise DriverTransportError(error.code if error else "INTERNAL")
        return _operation(response.operation)

    async def close(self) -> None:
        await self._channel.close()
