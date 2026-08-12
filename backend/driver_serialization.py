from __future__ import annotations

from datetime import timezone
from typing import Any, Iterable

from .driver_models import (
    DriverBinding,
    DriverCapability,
    DriverContextGeneration,
    DriverHostGeneration,
    DriverOperation,
    DriverOperationAttempt,
    DriverOperationTransition,
    DriverProfile,
)


def _iso(value) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def capability_dict(capability: DriverCapability) -> dict[str, Any]:
    return {
        "service": capability.service,
        "method": capability.method,
        "modifiers": list(capability.modifiers),
        "formats": list(capability.formats),
        "mutability": capability.mutability,
        "stream_support": capability.stream_support,
    }


def driver_dict(
    profile: DriverProfile,
    host: DriverHostGeneration | None,
    capabilities: Iterable[DriverCapability] = (),
) -> dict[str, Any]:
    return {
        "id": profile.id,
        "server_profile_id": profile.server_profile_id,
        "logical_driver_id": profile.logical_driver_id,
        "simulator": profile.simulator,
        "enabled": profile.enabled,
        "current_host_generation_id": host.id if host else None,
        "host_generation_number": host.generation_number if host else None,
        "state": host.state if host else "DISABLED",
        "ready": bool(host and host.ready),
        "contract_package": profile.contract_package,
        "contract_version": host.contract_version if host else None,
        "implementation_version": host.implementation_version if host else None,
        "configuration_schema_version": profile.configuration_schema_version,
        "configuration_digest": profile.configuration_digest,
        "credential_epoch": host.credential_epoch if host else profile.credential_epoch,
        "capabilities": [capability_dict(item) for item in capabilities],
        "capacity": {
            "max_contexts_per_host": (
                host.max_contexts if host else profile.max_contexts_per_host
            ),
            "contexts_in_use": host.contexts_in_use if host else 0,
            "max_attachments_per_context": profile.max_attachments_per_context,
            "max_lifecycle_operations_per_host": (
                host.max_lifecycle_operations
                if host
                else profile.max_lifecycle_operations_per_host
            ),
            "lifecycle_operations_per_host_in_use": (
                host.lifecycle_operations_in_use if host else 0
            ),
            "max_lifecycle_operations_per_context": (
                profile.max_lifecycle_operations_per_context
            ),
        },
        "last_observed_at": _iso(host.last_observed_at) if host else None,
        "revision": host.revision if host else profile.revision,
    }


def context_generation_dict(context: DriverContextGeneration) -> dict[str, Any]:
    return {
        "context_id": context.context_id,
        "context_generation_id": context.id,
        "generation_number": context.generation_number,
        "host_generation_id": context.host_generation_id,
        "state": context.state,
        "ready": context.ready,
        "configuration_schema_version": context.configuration_schema_version,
        "configuration_digest": context.configuration_digest,
        "capacity": {
            "max_attachments": context.max_attachments,
            "attachments_in_use": context.attachments_in_use,
            "max_lifecycle_operations": context.max_lifecycle_operations,
            "lifecycle_operations_in_use": context.lifecycle_operations_in_use,
        },
        "last_observed_at": _iso(context.last_observed_at),
        "created_at": _iso(context.created_at),
        "closed_at": _iso(context.closed_at),
        "revision": context.revision,
    }


def binding_dict(binding: DriverBinding) -> dict[str, Any]:
    return {
        "driver_binding_id": binding.id,
        "execution_id": binding.execution_id,
        "context_generation_id": binding.context_generation_id,
        "replacement_of_driver_binding_id": binding.replacement_of_binding_id,
        "capacity_reserved": binding.capacity_reserved,
        "replacement_pending": binding.replacement_pending,
        "attachment_generation_id": binding.attachment_generation_id,
        "attachment_generation_number": binding.attachment_generation_number,
        "state": binding.state,
        "configuration_schema_version": binding.configuration_schema_version,
        "configuration_digest": binding.configuration_digest,
        "last_observed_at": _iso(binding.last_observed_at),
        "created_at": _iso(binding.created_at),
        "detached_at": _iso(binding.detached_at),
        "revision": binding.revision,
    }


def attempt_dict(attempt: DriverOperationAttempt) -> dict[str, Any]:
    return {
        "attempt_id": attempt.id,
        "attempt_number": attempt.attempt_number,
        "request_digest": attempt.request_digest,
        "effect_class": attempt.effect_class,
        "server_profile_id": attempt.server_profile_id,
        "host_generation_id": attempt.host_generation_id,
        "context_generation_id": attempt.context_generation_id,
        "execution_id": attempt.execution_id,
        "attachment_generation_id": attempt.attachment_generation_id,
        "driver_binding_id": attempt.binding_id,
        "host_configuration_digest": attempt.host_configuration_digest,
        "context_configuration_digest": attempt.context_configuration_digest,
        "attachment_configuration_digest": attempt.attachment_configuration_digest,
        "target_operation_id": attempt.target_operation_id,
        "target_attempt_id": attempt.target_attempt_id,
        "lifecycle_reason": attempt.lifecycle_reason,
        "replaced_driver_binding_id": attempt.replaced_binding_id,
        "credential_epoch": attempt.credential_epoch,
        "deadline_at": _iso(attempt.deadline_at),
        "effect_observed_at": _iso(attempt.effect_observed_at),
        "projection_outcome": attempt.projection_outcome,
        "created_at": _iso(attempt.created_at),
    }


def transition_dict(transition: DriverOperationTransition) -> dict[str, Any]:
    return {
        "transition_id": transition.id,
        "attempt_id": transition.attempt_id,
        "sequence": transition.sequence,
        "stage": transition.stage,
        "certainty": transition.certainty,
        "disposition": transition.disposition,
        "safe_error": (
            {
                "code": transition.safe_error_code,
                "message": transition.safe_error_message,
            }
            if transition.safe_error_code or transition.safe_error_message
            else None
        ),
        "evidence_digest": transition.evidence_digest,
        "actor": transition.actor,
        "correlation_id": transition.correlation_id,
        "created_at": _iso(transition.created_at),
    }


def operation_dict(
    operation: DriverOperation,
    attempts: Iterable[DriverOperationAttempt] = (),
    transitions: Iterable[DriverOperationTransition] = (),
) -> dict[str, Any]:
    return {
        "operation_id": operation.id,
        "method": operation.method,
        "request_digest": operation.request_digest,
        "effect_class": operation.effect_class,
        "host_generation_id": operation.host_generation_id,
        "context_generation_id": operation.context_generation_id,
        "driver_binding_id": operation.binding_id,
        "target_operation_id": operation.target_operation_id,
        "target_attempt_id": operation.target_attempt_id,
        "lifecycle_reason": operation.lifecycle_reason,
        "replaced_driver_binding_id": operation.replaced_binding_id,
        "current_attempt_id": operation.current_attempt_id,
        "current_attempt_number": operation.current_attempt_number,
        "stage": operation.stage,
        "certainty": operation.certainty,
        "requires_reconciliation": operation.requires_reconciliation,
        "capacity_reserved": operation.capacity_reserved,
        "disposition": operation.disposition,
        "safe_error": (
            {"code": operation.safe_error_code, "message": operation.safe_error_message}
            if operation.safe_error_code or operation.safe_error_message
            else None
        ),
        "deadline_at": _iso(operation.deadline_at),
        "attempts": [attempt_dict(item) for item in attempts],
        "transitions": [transition_dict(item) for item in transitions],
        "created_at": _iso(operation.created_at),
        "updated_at": _iso(operation.updated_at),
        "settled_at": _iso(operation.settled_at),
        "effect_observed_at": _iso(operation.effect_observed_at),
        "revision": operation.revision,
    }


__all__ = [
    "attempt_dict",
    "binding_dict",
    "capability_dict",
    "context_generation_dict",
    "driver_dict",
    "operation_dict",
    "transition_dict",
]
