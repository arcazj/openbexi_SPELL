"""Proto-independent Candidate A gateway domain types.

These types deliberately contain infrastructure lifecycle data only. Procedure
source, IR, prompts, telemetry, and telecommand cannot be represented here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


CONTRACT_PACKAGE = "spell.driver.v1"
CONTRACT_MAJOR = 1
CONTRACT_MINOR = 0
CONTRACT_MAJOR_METADATA = "x-spell-contract-major"
CREDENTIAL_EPOCH_METADATA = "x-spell-credential-epoch"
DEFAULT_SERVER_PROFILE_ID = "local-synthetic"
DEFAULT_DRIVER_PROFILE_ID = "local-synthetic-simulator"
DEFAULT_LOGICAL_DRIVER_ID = "bundled-deterministic-simulator"
DEFAULT_HOST_SCHEMA = "spell.driver.host-profile/1"
DEFAULT_HOST_PROFILE_DIGEST = (
    "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
)

_BOUNDED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class DriverRpcMethod(str, Enum):
    HANDSHAKE = "Handshake"
    HEALTH = "Health"
    OPEN_CONTEXT = "OpenContext"
    CLOSE_CONTEXT = "CloseContext"
    ATTACH_EXECUTION = "AttachExecution"
    DETACH_EXECUTION = "DetachExecution"
    CANCEL_LIFECYCLE_OPERATION = "CancelLifecycleOperation"
    DRAIN_HOST = "DrainHost"
    GET_OPERATION = "GetOperation"


@dataclass(frozen=True)
class CapabilityDefinition:
    method: DriverRpcMethod
    service: str
    mutability: str
    modifiers: Tuple[str, ...]
    format: str = "PROTOBUF_BINARY"
    stream_support: str = "NONE"


CAPABILITY_MATRIX = (
    CapabilityDefinition(DriverRpcMethod.HANDSHAKE, "HOST", "READ_ONLY", ("NONE",)),
    CapabilityDefinition(DriverRpcMethod.HEALTH, "HOST", "READ_ONLY", ("NONE",)),
    CapabilityDefinition(
        DriverRpcMethod.OPEN_CONTEXT,
        "CONTEXT_LIFECYCLE",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
    ),
    CapabilityDefinition(
        DriverRpcMethod.CLOSE_CONTEXT,
        "CONTEXT_LIFECYCLE",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
    ),
    CapabilityDefinition(
        DriverRpcMethod.ATTACH_EXECUTION,
        "EXECUTION_LIFECYCLE",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
    ),
    CapabilityDefinition(
        DriverRpcMethod.DETACH_EXECUTION,
        "EXECUTION_LIFECYCLE",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION", "DETERMINISTIC_FAULT_POINT"),
    ),
    CapabilityDefinition(
        DriverRpcMethod.CANCEL_LIFECYCLE_OPERATION,
        "OPERATION_RECONCILIATION",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION",),
    ),
    CapabilityDefinition(
        DriverRpcMethod.DRAIN_HOST,
        "HOST",
        "LIFECYCLE",
        ("COOPERATIVE_CANCELLATION",),
    ),
    CapabilityDefinition(
        DriverRpcMethod.GET_OPERATION,
        "OPERATION_RECONCILIATION",
        "READ_ONLY",
        ("NONE",),
    ),
)


class OperationStage(str, Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    DISPATCHED = "DISPATCHED"
    RECONCILING = "RECONCILING"
    SETTLED = "SETTLED"


class EffectClass(str, Enum):
    NONE = "NONE"
    CONTEXT_OPEN = "CONTEXT_OPEN"
    CONTEXT_CLOSE = "CONTEXT_CLOSE"
    EXECUTION_ATTACH = "EXECUTION_ATTACH"
    EXECUTION_DETACH = "EXECUTION_DETACH"
    LIFECYCLE_CANCEL = "LIFECYCLE_CANCEL"
    HOST_DRAIN = "HOST_DRAIN"


class EffectCertainty(str, Enum):
    NO_EFFECT = "NO_EFFECT"
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    EFFECT_POSSIBLE = "EFFECT_POSSIBLE"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"


class ResultCode(str, Enum):
    OK = "OK"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICT = "CONFLICT"
    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    CANCELLED = "CANCELLED"
    ALREADY_SETTLED = "ALREADY_SETTLED"
    STALE_GENERATION = "STALE_GENERATION"
    JOURNAL_UNAVAILABLE = "JOURNAL_UNAVAILABLE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    INTERNAL = "INTERNAL"


def _bounded_id(value: str, label: str, *, optional: bool = False) -> None:
    if optional and not value:
        return
    if _BOUNDED_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded identifier")


def _digest(value: str, label: str, *, optional: bool = False) -> None:
    if optional and not value:
        return
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class ContractVersion:
    major: int = CONTRACT_MAJOR
    minor: int = CONTRACT_MINOR


@dataclass(frozen=True)
class GenerationTuple:
    server_profile_id: str
    driver_host_generation: str
    host_profile_digest: str
    context_id: str = ""
    context_generation: str = ""
    context_binding_digest: str = ""
    execution_id: str = ""
    execution_attachment_generation: str = ""
    execution_attachment_digest: str = ""
    driver_binding_id: str = ""

    def __post_init__(self) -> None:
        _bounded_id(self.server_profile_id, "server_profile_id")
        _bounded_id(self.driver_host_generation, "driver_host_generation")
        _digest(self.host_profile_digest, "host_profile_digest")
        for label in (
            "context_id",
            "context_generation",
            "execution_id",
            "execution_attachment_generation",
            "driver_binding_id",
        ):
            _bounded_id(getattr(self, label), label, optional=True)
        _digest(self.context_binding_digest, "context_binding_digest", optional=True)
        _digest(
            self.execution_attachment_digest,
            "execution_attachment_digest",
            optional=True,
        )
        context_values = (
            self.context_id,
            self.context_generation,
            self.context_binding_digest,
        )
        if any(context_values) and not all(context_values):
            raise ValueError("context identity, generation, and digest must be supplied together")
        attachment_values = (
            self.execution_id,
            self.execution_attachment_generation,
            self.execution_attachment_digest,
            self.driver_binding_id,
        )
        if any(attachment_values) and not all(attachment_values):
            raise ValueError("execution attachment identity must be supplied as a complete tuple")
        if any(attachment_values) and not all(context_values):
            raise ValueError("an execution attachment requires a complete context tuple")

    def canonical(self) -> dict[str, str]:
        return {
            "server_profile_id": self.server_profile_id,
            "driver_host_generation": self.driver_host_generation,
            "host_profile_digest": self.host_profile_digest,
            "context_id": self.context_id,
            "context_generation": self.context_generation,
            "context_binding_digest": self.context_binding_digest,
            "execution_id": self.execution_id,
            "execution_attachment_generation": self.execution_attachment_generation,
            "execution_attachment_digest": self.execution_attachment_digest,
            "driver_binding_id": self.driver_binding_id,
        }


@dataclass(frozen=True)
class OperationIdentity:
    generations: GenerationTuple
    operation_id: str
    attempt_id: str
    attempt_number: int
    correlation_id: str
    deadline_unix_ms: int
    credential_epoch: int = 1

    def __post_init__(self) -> None:
        _bounded_id(self.operation_id, "operation_id")
        _bounded_id(self.attempt_id, "attempt_id")
        _bounded_id(self.correlation_id, "correlation_id")
        if self.attempt_number < 1:
            raise ValueError("attempt_number must be at least one")
        if self.deadline_unix_ms <= 0:
            raise ValueError("deadline_unix_ms must be positive")
        if self.credential_epoch < 1:
            raise ValueError("credential_epoch must be at least one")


@dataclass(frozen=True)
class ContextConfiguration:
    schema_version: str
    context_profile_id: str
    synthetic_context_label: str
    expected_digest: str

    def __post_init__(self) -> None:
        _bounded_id(self.schema_version, "context schema_version")
        _bounded_id(self.context_profile_id, "context_profile_id")
        _bounded_id(self.synthetic_context_label, "synthetic_context_label")
        _digest(self.expected_digest, "context expected_digest")


@dataclass(frozen=True)
class AttachmentConfiguration:
    schema_version: str
    attachment_profile_id: str
    synthetic_execution_label: str
    expected_digest: str
    reason: str = "INITIAL_LOAD"
    replaced_driver_binding_id: str = ""

    def __post_init__(self) -> None:
        _bounded_id(self.schema_version, "attachment schema_version")
        _bounded_id(self.attachment_profile_id, "attachment_profile_id")
        _bounded_id(self.synthetic_execution_label, "synthetic_execution_label")
        _digest(self.expected_digest, "attachment expected_digest")
        if self.reason not in {"INITIAL_LOAD", "RELOAD"}:
            raise ValueError("attachment reason is unsupported")
        if self.reason == "RELOAD":
            _bounded_id(
                self.replaced_driver_binding_id,
                "replaced_driver_binding_id",
            )
        elif self.replaced_driver_binding_id:
            raise ValueError(
                "initial attachment cannot name a replaced driver binding"
            )


@dataclass(frozen=True)
class OpenContextCommand:
    identity: OperationIdentity
    configuration: ContextConfiguration

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


@dataclass(frozen=True)
class CloseContextCommand:
    identity: OperationIdentity
    detach_settled_attachments: bool = False

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


@dataclass(frozen=True)
class AttachExecutionCommand:
    identity: OperationIdentity
    configuration: AttachmentConfiguration

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


@dataclass(frozen=True)
class DetachExecutionCommand:
    identity: OperationIdentity
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in {
            "FINISHED",
            "ABORTED",
            "RELOAD",
            "EXPLICIT_UNLOAD",
            "CONTEXT_CLOSE",
            "HOST_DRAIN",
        }:
            raise ValueError("detachment reason is unsupported")

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


@dataclass(frozen=True)
class CancelLifecycleOperationCommand:
    identity: OperationIdentity
    target_operation_id: str
    target_attempt_id: str

    def __post_init__(self) -> None:
        _bounded_id(self.target_operation_id, "target_operation_id")
        _bounded_id(self.target_attempt_id, "target_attempt_id")

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


@dataclass(frozen=True)
class DrainHostCommand:
    identity: OperationIdentity
    grace_period_ms: int

    def __post_init__(self) -> None:
        if not 0 <= self.grace_period_ms <= 30_000:
            raise ValueError("grace_period_ms must be between zero and 30000")

    @property
    def request_digest(self) -> str:
        return canonical_request_digest(self)


def canonical_request_digest(
    command: OpenContextCommand
    | CloseContextCommand
    | AttachExecutionCommand
    | DetachExecutionCommand
    | CancelLifecycleOperationCommand
    | DrainHostCommand,
) -> str:
    identity = command.identity
    payload: dict[str, object] = {
        "method": "",
        "identity": identity.generations.canonical(),
        "operation_id": identity.operation_id,
        "context_schema_version": "",
        "context_profile_id": "",
        "synthetic_context_label": "",
        "expected_context_digest": "",
        "attachment_schema_version": "",
        "attachment_profile_id": "",
        "synthetic_execution_label": "",
        "expected_attachment_digest": "",
        "lifecycle_reason": "",
        "replaced_driver_binding_id": "",
        "detach_settled_attachments": False,
        "target_operation_id": "",
        "target_attempt_id": "",
        "grace_period_ms": 0,
    }
    if isinstance(command, OpenContextCommand):
        payload.update(
            method=DriverRpcMethod.OPEN_CONTEXT.value,
            context_schema_version=command.configuration.schema_version,
            context_profile_id=command.configuration.context_profile_id,
            synthetic_context_label=command.configuration.synthetic_context_label,
            expected_context_digest=command.configuration.expected_digest,
        )
    elif isinstance(command, CloseContextCommand):
        payload.update(
            method=DriverRpcMethod.CLOSE_CONTEXT.value,
            detach_settled_attachments=command.detach_settled_attachments,
        )
    elif isinstance(command, AttachExecutionCommand):
        payload.update(
            method=DriverRpcMethod.ATTACH_EXECUTION.value,
            attachment_schema_version=command.configuration.schema_version,
            attachment_profile_id=command.configuration.attachment_profile_id,
            synthetic_execution_label=command.configuration.synthetic_execution_label,
            expected_attachment_digest=command.configuration.expected_digest,
            lifecycle_reason=command.configuration.reason,
            replaced_driver_binding_id=(
                command.configuration.replaced_driver_binding_id
            ),
        )
    elif isinstance(command, DetachExecutionCommand):
        payload.update(
            method=DriverRpcMethod.DETACH_EXECUTION.value,
            lifecycle_reason=command.reason,
        )
    elif isinstance(command, CancelLifecycleOperationCommand):
        payload.update(
            method=DriverRpcMethod.CANCEL_LIFECYCLE_OPERATION.value,
            target_operation_id=command.target_operation_id,
            target_attempt_id=command.target_attempt_id,
        )
    elif isinstance(command, DrainHostCommand):
        payload.update(
            method=DriverRpcMethod.DRAIN_HOST.value,
            grace_period_ms=command.grace_period_ms,
        )
    else:
        raise TypeError("unsupported Candidate A command type")
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class GetOperationQuery:
    generations: GenerationTuple
    target_operation_id: str
    target_attempt_id: str
    correlation_id: str
    deadline_unix_ms: int
    credential_epoch: int = 1

    def __post_init__(self) -> None:
        _bounded_id(self.target_operation_id, "target_operation_id")
        _bounded_id(self.target_attempt_id, "target_attempt_id", optional=True)
        _bounded_id(self.correlation_id, "correlation_id")
        if self.deadline_unix_ms <= 0:
            raise ValueError("deadline_unix_ms must be positive")
        if self.credential_epoch < 1:
            raise ValueError("credential_epoch must be at least one")


@dataclass(frozen=True)
class SafeError:
    code: str
    message: str
    retryable: bool = False


@dataclass(frozen=True)
class Capacity:
    max_contexts_per_host: int
    max_attachments_per_context: int
    max_lifecycle_operations_per_host: int
    max_lifecycle_operations_per_context: int
    contexts: int = 0
    attachments: int = 0
    lifecycle_operations_host: int = 0
    lifecycle_operations_context: int = 0


@dataclass(frozen=True)
class Capability:
    service: str
    method: DriverRpcMethod
    modifiers: Tuple[str, ...]
    formats: Tuple[str, ...]
    mutability: str
    stream_support: str


@dataclass(frozen=True)
class DriverIdentity:
    logical_driver_id: str
    implementation_version: str
    simulator: bool
    server_profile_id: str
    driver_profile_id: str
    driver_host_generation: str
    host_configuration_schema: str
    host_profile_digest: str
    credential_epoch: int


@dataclass(frozen=True)
class HandshakeResult:
    contract_version: ContractVersion
    driver: DriverIdentity
    host_state: str
    capabilities: Tuple[Capability, ...]
    capacity: Capacity
    last_observed_unix_ms: int
    error: Optional[SafeError] = None


@dataclass(frozen=True)
class ContextHealth:
    context_id: str
    context_generation: str
    context_binding_digest: str
    state: str
    ready: bool
    last_observed_unix_ms: int


@dataclass(frozen=True)
class AttachmentHealth:
    execution_id: str
    execution_attachment_generation: str
    execution_attachment_digest: str
    driver_binding_id: str
    state: str
    last_observed_unix_ms: int


@dataclass(frozen=True)
class HealthResult:
    contract_version: ContractVersion
    driver: DriverIdentity
    host_state: str
    ready: bool
    capacity: Capacity
    contexts: Tuple[ContextHealth, ...]
    attachments: Tuple[AttachmentHealth, ...]
    last_observed_unix_ms: int
    error: Optional[SafeError] = None


@dataclass(frozen=True)
class HookTrace:
    sequence: int
    hook_id: str
    owner_layer: str
    action: str
    result: str
    started_unix_ms: int
    completed_unix_ms: int
    error: Optional[SafeError] = None
    generations: Optional[GenerationTuple] = None
    operation_id: str = ""
    attempt_id: str = ""
    stage: Optional[OperationStage] = None
    certainty: Optional[EffectCertainty] = None


@dataclass(frozen=True)
class OperationAttemptResult:
    attempt_id: str
    attempt_number: int
    request_digest: str
    stage: OperationStage
    effect_class: EffectClass
    certainty: Optional[EffectCertainty]
    result_code: ResultCode
    error: Optional[SafeError]
    requested_unix_ms: int
    accepted_unix_ms: int
    dispatched_unix_ms: int
    settled_unix_ms: int
    hook_traces: Tuple[HookTrace, ...] = field(default_factory=tuple)
    generations: Optional[GenerationTuple] = None
    lifecycle_reason: str = ""
    replaced_driver_binding_id: str = ""


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    method: DriverRpcMethod
    current_attempt_id: str
    attempts: Tuple[OperationAttemptResult, ...]


@dataclass(frozen=True)
class OperationIntent:
    identity: OperationIdentity
    method: DriverRpcMethod
    request_digest: str
    effect_class: EffectClass

    def __post_init__(self) -> None:
        _digest(self.request_digest, "request_digest")


@dataclass(frozen=True)
class OperationTransition:
    operation_id: str
    attempt_id: str
    attempt_number: int
    stage: OperationStage
    certainty: Optional[EffectCertainty]
    result_code: Optional[ResultCode]
    safe_error_code: Optional[str]
    safe_error_message: Optional[str]
    evidence: str
    occurred_unix_ms: int
