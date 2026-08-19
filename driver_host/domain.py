"""Internal typed lifecycle domain for the deterministic simulator host."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional, Tuple


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Method(str, Enum):
    HANDSHAKE = "Handshake"
    HEALTH = "Health"
    OPEN_CONTEXT = "OpenContext"
    CLOSE_CONTEXT = "CloseContext"
    ATTACH_EXECUTION = "AttachExecution"
    DETACH_EXECUTION = "DetachExecution"
    CANCEL_LIFECYCLE_OPERATION = "CancelLifecycleOperation"
    DRAIN_HOST = "DrainHost"
    GET_OPERATION = "GetOperation"


class Stage(str, Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    DISPATCHED = "DISPATCHED"
    RECONCILING = "RECONCILING"
    SETTLED = "SETTLED"


class Certainty(str, Enum):
    NO_EFFECT = "NO_EFFECT"
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    EFFECT_POSSIBLE = "EFFECT_POSSIBLE"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"


class Effect(str, Enum):
    NONE = "NONE"
    CONTEXT_OPEN = "CONTEXT_OPEN"
    CONTEXT_CLOSE = "CONTEXT_CLOSE"
    EXECUTION_ATTACH = "EXECUTION_ATTACH"
    EXECUTION_DETACH = "EXECUTION_DETACH"
    LIFECYCLE_CANCEL = "LIFECYCLE_CANCEL"
    HOST_DRAIN = "HOST_DRAIN"


class Result(str, Enum):
    OK = "OK"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
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


class ErrorCode(str, Enum):
    NONE = "NONE"
    VALIDATION = "VALIDATION"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    GENERATION_MISMATCH = "GENERATION_MISMATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    UNSUPPORTED = "UNSUPPORTED"
    CAPACITY = "CAPACITY"
    DEADLINE = "DEADLINE"
    CANCELLED = "CANCELLED"
    CONFLICT = "CONFLICT"
    JOURNAL = "JOURNAL"
    HOOK = "HOOK"
    INTERNAL = "INTERNAL"


class HostState(str, Enum):
    STARTING = "STARTING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    DRAINING = "DRAINING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"


class ContextState(str, Enum):
    OPENING = "OPENING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"


class AttachmentState(str, Enum):
    ATTACHING = "ATTACHING"
    ATTACHED = "ATTACHED"
    DETACHING = "DETACHING"
    DETACHED = "DETACHED"
    FAILED = "FAILED"


class HookLayer(str, Enum):
    CONTEXT_CONFIGURATION = "CONTEXT_CONFIGURATION"
    CONTEXT_FIXTURE = "CONTEXT_FIXTURE"
    ATTACHMENT_CONFIGURATION = "ATTACHMENT_CONFIGURATION"
    ATTACHMENT_FIXTURE = "ATTACHMENT_FIXTURE"
    HOST = "HOST"


class HookAction(str, Enum):
    SETUP = "SETUP"
    CLEANUP = "CLEANUP"
    COMPENSATE = "COMPENSATE"


class HookOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


METHOD_EFFECT = {
    Method.OPEN_CONTEXT: Effect.CONTEXT_OPEN,
    Method.CLOSE_CONTEXT: Effect.CONTEXT_CLOSE,
    Method.ATTACH_EXECUTION: Effect.EXECUTION_ATTACH,
    Method.DETACH_EXECUTION: Effect.EXECUTION_DETACH,
    Method.CANCEL_LIFECYCLE_OPERATION: Effect.LIFECYCLE_CANCEL,
    Method.DRAIN_HOST: Effect.HOST_DRAIN,
}


def validate_identifier(value: str, label: str, *, optional: bool = False) -> None:
    if optional and not value:
        return
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded identifier")


def validate_digest(value: str, label: str, *, optional: bool = False) -> None:
    if optional and not value:
        return
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class GenerationIdentity:
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
        validate_identifier(self.server_profile_id, "server_profile_id")
        validate_identifier(self.driver_host_generation, "driver_host_generation")
        validate_digest(self.host_profile_digest, "host_profile_digest")
        for label in (
            "context_id",
            "context_generation",
            "execution_id",
            "execution_attachment_generation",
            "driver_binding_id",
        ):
            validate_identifier(getattr(self, label), label, optional=True)
        validate_digest(self.context_binding_digest, "context_binding_digest", optional=True)
        validate_digest(
            self.execution_attachment_digest,
            "execution_attachment_digest",
            optional=True,
        )
        context_values = (
            self.context_id,
            self.context_generation,
            self.context_binding_digest,
        )
        attachment_values = (
            self.execution_id,
            self.execution_attachment_generation,
            self.execution_attachment_digest,
            self.driver_binding_id,
        )
        if any(context_values) and not all(context_values):
            raise ValueError("context generation tuple must be complete")
        if any(attachment_values) and not all(attachment_values):
            raise ValueError("execution attachment generation tuple must be complete")
        if any(attachment_values) and not all(context_values):
            raise ValueError("execution attachment requires a complete context tuple")

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
class OperationCommand:
    method: Method
    identity: GenerationIdentity
    operation_id: str
    attempt_id: str
    attempt_number: int
    correlation_id: str
    deadline_unix_ms: int
    credential_epoch: int
    context_schema_version: str = ""
    context_profile_id: str = ""
    synthetic_context_label: str = ""
    expected_context_digest: str = ""
    attachment_schema_version: str = ""
    attachment_profile_id: str = ""
    synthetic_execution_label: str = ""
    expected_attachment_digest: str = ""
    lifecycle_reason: str = ""
    replaced_driver_binding_id: str = ""
    detach_settled_attachments: bool = False
    target_operation_id: str = ""
    target_attempt_id: str = ""
    grace_period_ms: int = 0

    def __post_init__(self) -> None:
        if self.method not in METHOD_EFFECT:
            raise ValueError("operation method is not a Candidate A mutation")
        for label in ("operation_id", "attempt_id", "correlation_id"):
            validate_identifier(getattr(self, label), label)
        if self.attempt_number < 1:
            raise ValueError("attempt_number must be at least one")
        if self.deadline_unix_ms <= 0:
            raise ValueError("deadline_unix_ms must be positive")
        if self.credential_epoch < 1:
            raise ValueError("credential_epoch must be at least one")
        if not 0 <= self.grace_period_ms <= 30_000:
            raise ValueError("grace_period_ms is outside the bounded range")
        for label in (
            "context_schema_version",
            "context_profile_id",
            "synthetic_context_label",
            "attachment_schema_version",
            "attachment_profile_id",
            "synthetic_execution_label",
            "lifecycle_reason",
            "replaced_driver_binding_id",
            "target_operation_id",
            "target_attempt_id",
        ):
            validate_identifier(getattr(self, label), label, optional=True)
        validate_digest(self.expected_context_digest, "expected_context_digest", optional=True)
        validate_digest(
            self.expected_attachment_digest,
            "expected_attachment_digest",
            optional=True,
        )
        if self.method is Method.ATTACH_EXECUTION:
            if self.lifecycle_reason == "RELOAD":
                validate_identifier(
                    self.replaced_driver_binding_id,
                    "replaced_driver_binding_id",
                )
            elif self.lifecycle_reason == "INITIAL_LOAD":
                if self.replaced_driver_binding_id:
                    raise ValueError(
                        "initial attachment cannot name a replaced driver binding"
                    )

    @property
    def effect(self) -> Effect:
        return METHOD_EFFECT[self.method]

    def canonical_payload(self) -> dict[str, object]:
        return {
            "method": self.method.value,
            "identity": self.identity.canonical(),
            "operation_id": self.operation_id,
            "context_schema_version": self.context_schema_version,
            "context_profile_id": self.context_profile_id,
            "synthetic_context_label": self.synthetic_context_label,
            "expected_context_digest": self.expected_context_digest,
            "attachment_schema_version": self.attachment_schema_version,
            "attachment_profile_id": self.attachment_profile_id,
            "synthetic_execution_label": self.synthetic_execution_label,
            "expected_attachment_digest": self.expected_attachment_digest,
            "lifecycle_reason": self.lifecycle_reason,
            "replaced_driver_binding_id": self.replaced_driver_binding_id,
            "detach_settled_attachments": self.detach_settled_attachments,
            "target_operation_id": self.target_operation_id,
            "target_attempt_id": self.target_attempt_id,
            "grace_period_ms": self.grace_period_ms,
        }

    @property
    def request_digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class SafeFailure:
    code: ErrorCode
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if len(self.message.encode("utf-8")) > 256:
            raise ValueError("safe error message exceeds 256 bytes")


@dataclass(frozen=True)
class HookTraceRecord:
    sequence: int
    hook_id: str
    layer: HookLayer
    action: HookAction
    outcome: HookOutcome
    started_unix_ms: int
    completed_unix_ms: int
    error: Optional[SafeFailure] = None
    identity: Optional[GenerationIdentity] = None
    operation_id: str = ""
    attempt_id: str = ""
    stage: Stage = Stage.DISPATCHED
    certainty: Optional[Certainty] = Certainty.EFFECT_POSSIBLE


@dataclass(frozen=True)
class AttemptRecord:
    operation_id: str
    method: Method
    identity: GenerationIdentity
    attempt_id: str
    attempt_number: int
    request_digest: str
    effect: Effect
    stage: Stage
    certainty: Optional[Certainty]
    result: Result
    error: Optional[SafeFailure]
    requested_unix_ms: int
    accepted_unix_ms: int = 0
    dispatched_unix_ms: int = 0
    settled_unix_ms: int = 0
    hook_traces: Tuple[HookTraceRecord, ...] = field(default_factory=tuple)
    lifecycle_reason: str = ""
    replaced_driver_binding_id: str = ""

    def evolve(self, **changes: object) -> "AttemptRecord":
        return replace(self, **changes)


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    method: Method
    identity: GenerationIdentity
    current_attempt_id: str
    attempts: Tuple[AttemptRecord, ...]
