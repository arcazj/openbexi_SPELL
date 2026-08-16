from __future__ import annotations

from datetime import timezone
from typing import Any

from .operator_models import (
    ControllerLease,
    ExecutionOperatorState,
    MonitorSubscription,
    OperatorCommand,
    OperatorContext,
    OperatorPrompt,
    ParentChildLink,
    ProcedureCatalogEntry,
    ProcedureCatalogRevision,
    ProcedureSchedule,
    PromptAttempt,
    ScheduleOccurrence,
)


def iso(value) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def context_dict(context: OperatorContext) -> dict[str, Any]:
    return {
        "id": context.id,
        "name": context.name,
        "description": context.description,
        "settings": context.settings,
        "enabled": context.enabled,
        "revision": context.revision,
        "created_at": iso(context.created_at),
        "updated_at": iso(context.updated_at),
    }


def catalog_revision_dict(
    revision: ProcedureCatalogRevision, *, include_source: bool = False
) -> dict[str, Any]:
    result = {
        "id": revision.id,
        "catalog_id": revision.catalog_id,
        "revision": revision.revision,
        "source_digest": revision.source_digest,
        "bundle_digest": revision.bundle_digest,
        "ir_version": revision.ir_version,
        "properties": revision.properties,
        "step_count": len(revision.steps),
        "created_by": revision.created_by,
        "created_at": iso(revision.created_at),
    }
    if include_source:
        result.update(source=revision.source, steps=revision.steps)
    return result


def catalog_entry_dict(
    entry: ProcedureCatalogEntry,
    revision: ProcedureCatalogRevision | None = None,
    *,
    include_source: bool = False,
) -> dict[str, Any]:
    result = {
        "id": entry.id,
        "procedure_ref": entry.procedure_ref,
        "name": entry.name,
        "description": entry.description,
        "entrypoint": entry.entrypoint,
        "current_revision": entry.current_revision,
        "created_at": iso(entry.created_at),
        "updated_at": iso(entry.updated_at),
    }
    if revision is not None:
        result["revision"] = catalog_revision_dict(
            revision, include_source=include_source
        )
    return result


def lease_dict(lease: ControllerLease) -> dict[str, Any]:
    return {
        "id": lease.id,
        "execution_id": lease.execution_id,
        "revision": lease.revision,
        "control_fencing_token": lease.fencing_token,
        "holder_subject_id": lease.holder_subject_id,
        "holder_session_id": lease.holder_session_id,
        "client_instance_key_id": lease.client_instance_key_id,
        "issued_at_database_time": iso(lease.issued_at),
        "expires_at_database_time": iso(lease.expires_at),
        "state": lease.state,
        "reason": lease.reason,
        "predecessor_lease_id": lease.predecessor_lease_id,
        "terminated_at": iso(lease.terminated_at),
        "termination_reason": lease.termination_reason,
    }


def monitor_dict(subscription: MonitorSubscription) -> dict[str, Any]:
    return {
        "id": subscription.id,
        "execution_id": subscription.execution_id,
        "subject_id": subscription.subject_id,
        "session_id": subscription.session_id,
        "client_instance_key_id": subscription.client_instance_key_id,
        "mode": "M",
        "state": subscription.state,
        "created_at": iso(subscription.created_at),
        "closed_at": iso(subscription.closed_at),
    }


def operator_state_dict(state: ExecutionOperatorState) -> dict[str, Any]:
    return {
        "execution_id": state.execution_id,
        "state": state.state,
        "resume_state": state.resume_state,
        "current_safe_point_id": state.current_safe_point_id,
        "current_step": state.current_step,
        "current_line": state.current_line,
        "current_lexical_frame_id": state.current_lexical_frame_id,
        "current_reachability_id": state.current_reachability_id,
        "source_digest": state.source_digest,
        "context_id": state.context_id,
        "catalog_revision_id": state.catalog_revision_id,
        "ownership_mode": state.ownership_mode,
        "revision": state.revision,
        "control_fencing_token": state.control_fencing_token,
        "current_lease_id": state.current_lease_id,
        "hold_reason": state.hold_reason,
        "settings": state.settings,
        "control_loss": (
            {
                "fencing_token": state.control_loss_fencing_token,
                "requested_at": iso(state.control_loss_requested_at),
                "applied_at": iso(state.control_loss_applied_at),
                "safe_point_id": state.control_loss_safe_point_id,
                "event_id": state.control_loss_event_id,
                "published_at": iso(state.control_loss_published_at),
            }
            if state.control_loss_fencing_token is not None
            else None
        ),
        "saved_resume_target": state.saved_resume_target,
        "effect_certainty": state.effect_certainty,
        "automatic": state.automatic,
        "background_allowed": state.background_allowed,
        "visible": state.visible,
        "predecessor_execution_id": state.predecessor_execution_id,
        "depth": state.depth,
        "attached_by": state.attached_by,
        "attached_at": iso(state.attached_at),
        "updated_at": iso(state.updated_at),
    }


def command_dict(command: OperatorCommand) -> dict[str, Any]:
    return {
        "id": command.id,
        "execution_id": command.execution_id,
        "type": command.command_type,
        "state": command.state,
        "expected_execution_revision": command.expected_execution_revision,
        "accepted_execution_revision": command.accepted_execution_revision,
        "accepted_lease_id": command.accepted_lease_id,
        "accepted_lease_revision": command.accepted_lease_revision,
        "accepted_fencing_token": command.accepted_fencing_token,
        "safe_point": command.safe_point,
        "target": command.target,
        "actor": command.actor,
        "role": command.role,
        "reason": command.reason,
        "correlation_id": command.correlation_id,
        "request": command.request_payload,
        "result": command.result_payload,
        "application_safe_point_id": command.application_safe_point_id,
        "applied_event_id": command.applied_event_id,
        "effect_certainty_before": command.effect_certainty_before,
        "effect_certainty_after": command.effect_certainty_after,
        "revision": command.revision,
        "rejection_code": command.rejection_code,
        "legacy_command_id": command.legacy_command_id,
        "created_at": iso(command.created_at),
        "updated_at": iso(command.updated_at),
        "settled_at": iso(command.settled_at),
    }


def prompt_dict(prompt: OperatorPrompt) -> dict[str, Any]:
    return {
        "id": prompt.id,
        "execution_id": prompt.execution_id,
        "legacy_prompt_id": prompt.legacy_prompt_id,
        "step_index": prompt.step_index,
        "revision": prompt.revision,
        "state": prompt.state,
        "type": prompt.prompt_type,
        "input_kind": prompt.input_kind,
        "list_mode": prompt.list_mode,
        "question": prompt.question,
        "options": prompt.options,
        "option_revision": prompt.option_revision,
        "default": prompt.default_value,
        "settings": prompt.settings_snapshot,
        "warning_at": iso(prompt.warning_at),
        "response_deadline": iso(prompt.response_deadline),
        "no_controller_deadline": iso(prompt.no_controller_deadline),
        "warning_emitted_at": iso(prompt.warning_emitted_at),
        "attempt_count": prompt.attempt_count,
        "settlement_delivery_attempts": prompt.settlement_delivery_attempts,
        "settlement_delivered_at": iso(prompt.settlement_delivered_at),
        "settlement": (
            {
                "id": prompt.settlement_id,
                "outcome": prompt.settlement_outcome,
                "value": prompt.settled_value,
                "actor": prompt.settled_by,
                "settled_at": iso(prompt.settled_at),
            }
            if prompt.settlement_id is not None
            else None
        ),
        "created_at": iso(prompt.created_at),
        "opened_at": iso(prompt.opened_at),
    }


def prompt_attempt_dict(attempt: PromptAttempt) -> dict[str, Any]:
    return {
        "id": attempt.id,
        "prompt_id": attempt.prompt_id,
        "prompt_revision": attempt.prompt_revision,
        "actor": attempt.actor,
        "action": attempt.action,
        "outcome": attempt.outcome,
        "value_digest": attempt.value_digest,
        "settlement_id": attempt.settlement_id,
        "controller_lease_id": attempt.controller_lease_id,
        "accepted_lease_revision": attempt.accepted_lease_revision,
        "control_fencing_token": attempt.control_fencing_token,
        "created_at": iso(attempt.created_at),
    }


def schedule_dict(schedule: ProcedureSchedule) -> dict[str, Any]:
    return {
        "id": schedule.id,
        "revision": schedule.revision,
        "controller_execution_id": schedule.controller_execution_id,
        "schedule_type": schedule.schedule_type,
        "original_target": schedule.original_target,
        "original_offset": schedule.original_offset,
        "original_duration_seconds": schedule.original_duration_seconds,
        "target_at_database_time": iso(schedule.target_at),
        "catalog_revision_id": schedule.catalog_revision_id,
        "procedure_catalog_id": schedule.procedure_catalog_id,
        "procedure_revision": schedule.procedure_revision,
        "bundle_digest": schedule.bundle_digest,
        "context_id": schedule.context_id,
        "arguments": schedule.arguments,
        "arguments_digest": schedule.arguments_digest,
        "automatic": schedule.automatic,
        "background_allowed": schedule.background_allowed,
        "visible": schedule.visible,
        "misfire_policy": schedule.misfire_policy,
        "maximum_lateness_seconds": schedule.maximum_lateness_seconds,
        "state": schedule.state,
        "created_by": schedule.created_by,
        "occurrence_id": schedule.occurrence_id,
        "execution_id": schedule.fired_execution_id,
        "error": (
            {"code": schedule.error_code, "message": schedule.error_message}
            if schedule.error_code is not None
            else None
        ),
        "created_at_database_time": iso(schedule.created_at),
        "updated_at_database_time": iso(schedule.updated_at),
        "settled_at_database_time": iso(schedule.settled_at),
    }


def occurrence_dict(occurrence: ScheduleOccurrence) -> dict[str, Any]:
    return {
        "id": occurrence.id,
        "schedule_id": occurrence.schedule_id,
        "target_at_database_time": iso(occurrence.target_at),
        "state": occurrence.state,
        "execution_id": occurrence.execution_id,
        "claimed_at": iso(occurrence.claimed_at),
        "settled_at": iso(occurrence.settled_at),
    }


def relationship_dict(link: ParentChildLink) -> dict[str, Any]:
    return {
        "id": link.id,
        "startproc_id": link.startproc_id,
        "parent_execution_id": link.parent_execution_id,
        "child_execution_id": link.child_execution_id,
        "child_catalog_revision_id": link.child_catalog_revision_id,
        "arguments_digest": link.arguments_digest,
        "blocking": link.blocking,
        "visible": link.visible,
        "automatic": link.automatic,
        "created_at": iso(link.created_at),
    }
