from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.engine import Connection


VERSION = "0004_operator_workspace"
metadata = MetaData()

# Existing tables are declared only so static foreign keys resolve. They are
# never created or changed by this migration.
executions = Table("executions", metadata, Column("id", String(36), primary_key=True))
events = Table("events", metadata, Column("id", String(36), primary_key=True))
commands = Table("commands", metadata, Column("id", String(36), primary_key=True))
prompts = Table("prompts", metadata, Column("id", String(36), primary_key=True))

operator_contexts = Table(
    "operator_contexts",
    metadata,
    Column("id", String(100), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("description", Text, nullable=False),
    Column("settings", JSON, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("revision >= 0", name="ck_operator_context_revision"),
)

procedure_catalog_entries = Table(
    "procedure_catalog_entries",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("procedure_ref", String(200), nullable=False),
    Column("name", String(200), nullable=False),
    Column("description", Text, nullable=False),
    Column("entrypoint", String(200), nullable=False),
    Column("current_revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("procedure_ref", name="uq_procedure_catalog_ref"),
    CheckConstraint("current_revision > 0", name="ck_procedure_catalog_revision"),
)

procedure_catalog_revisions = Table(
    "procedure_catalog_revisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("catalog_id", String(64), ForeignKey("procedure_catalog_entries.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("source_digest", String(64), nullable=False),
    Column("bundle_digest", String(64), nullable=False),
    Column("ir_version", String(20), nullable=False),
    Column("source", Text, nullable=False),
    Column("steps", JSON, nullable=False),
    Column("properties", JSON, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("catalog_id", "revision", name="uq_procedure_catalog_revision"),
    CheckConstraint("revision > 0", name="ck_procedure_revision_number"),
    CheckConstraint("length(source_digest) = 64", name="ck_procedure_revision_source_digest"),
    CheckConstraint("length(bundle_digest) = 64", name="ck_procedure_revision_bundle_digest"),
)
Index("ix_procedure_catalog_revisions_catalog_id", procedure_catalog_revisions.c.catalog_id)
Index("ix_procedure_catalog_revisions_source_digest", procedure_catalog_revisions.c.source_digest)
Index("ix_procedure_catalog_revisions_bundle_digest", procedure_catalog_revisions.c.bundle_digest)

execution_operator_states = Table(
    "execution_operator_states",
    metadata,
    Column("execution_id", String(36), ForeignKey("executions.id"), primary_key=True),
    Column("state", String(30), nullable=False),
    Column("resume_state", String(30), nullable=True),
    Column("current_safe_point_id", String(128), nullable=True),
    Column("current_step", Integer, nullable=True),
    Column("current_line", Integer, nullable=True),
    Column("current_lexical_frame_id", String(256), nullable=True),
    Column("current_reachability_id", String(512), nullable=True),
    Column("source_digest", String(64), nullable=False),
    Column("context_id", String(100), ForeignKey("operator_contexts.id"), nullable=False),
    Column(
        "catalog_revision_id",
        String(64),
        ForeignKey("procedure_catalog_revisions.id"),
        nullable=False,
    ),
    Column("ownership_mode", String(20), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("control_fencing_token", Integer, nullable=False),
    Column("current_lease_id", String(64), nullable=True),
    Column("hold_reason", String(80), nullable=True),
    Column("settings", JSON, nullable=False),
    Column("control_loss_fencing_token", Integer, nullable=True),
    Column("control_loss_requested_at", DateTime(timezone=True), nullable=True),
    Column("control_loss_applied_at", DateTime(timezone=True), nullable=True),
    Column("control_loss_safe_point_id", String(128), nullable=True),
    Column("control_loss_event_id", String(36), ForeignKey("events.id"), nullable=True),
    Column("control_loss_published_at", DateTime(timezone=True), nullable=True),
    Column("saved_resume_target", JSON, nullable=False),
    Column("effect_certainty", String(30), nullable=False),
    Column("automatic", Boolean, nullable=False),
    Column("background_allowed", Boolean, nullable=False),
    Column("visible", Boolean, nullable=False),
    Column("predecessor_execution_id", String(36), ForeignKey("executions.id"), nullable=True),
    Column("depth", Integer, nullable=False),
    Column("attached_by", String(200), nullable=False),
    Column("attached_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint(
        "ownership_mode IN ('C','B','CONTROL_LOST')",
        name="ck_execution_operator_ownership_mode",
    ),
    CheckConstraint("revision >= 0", name="ck_execution_operator_revision"),
    CheckConstraint("control_fencing_token >= 0", name="ck_execution_operator_fence"),
    CheckConstraint(
        "effect_certainty IN ('NO_EFFECT','EFFECT_CONFIRMED','EFFECT_POSSIBLE','EFFECT_UNKNOWN')",
        name="ck_execution_operator_effect_certainty",
    ),
)
Index("ix_execution_operator_states_context_id", execution_operator_states.c.context_id)
Index(
    "ix_execution_operator_states_catalog_revision_id",
    execution_operator_states.c.catalog_revision_id,
)

controller_leases = Table(
    "controller_leases",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("fencing_token", Integer, nullable=False),
    Column("holder_subject_id", String(200), nullable=False),
    Column("holder_session_id", String(128), nullable=False),
    Column("client_instance_key_id", String(128), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("state", String(20), nullable=False),
    Column("reason", Text, nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("predecessor_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=True),
    Column("terminated_at", DateTime(timezone=True), nullable=True),
    Column("termination_reason", String(80), nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "execution_id", "holder_subject_id", "idempotency_key",
        name="uq_controller_lease_acquisition",
    ),
    CheckConstraint(
        "state IN ('ACTIVE','RELEASED','EXPIRED','REVOKED','TRANSFERRED')",
        name="ck_controller_lease_state",
    ),
    CheckConstraint("revision > 0", name="ck_controller_lease_revision"),
    CheckConstraint("fencing_token > 0", name="ck_controller_lease_fence"),
)
Index("ix_controller_leases_execution_id", controller_leases.c.execution_id)
Index(
    "uq_controller_lease_active_execution",
    controller_leases.c.execution_id,
    unique=True,
    sqlite_where=text("state = 'ACTIVE'"),
    postgresql_where=text("state = 'ACTIVE'"),
)

monitor_subscriptions = Table(
    "monitor_subscriptions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("subject_id", String(200), nullable=False),
    Column("session_id", String(128), nullable=False),
    Column("client_instance_key_id", String(128), nullable=False),
    Column("state", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("closed_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("state IN ('ACTIVE','CLOSED')", name="ck_monitor_subscription_state"),
)
Index("ix_monitor_subscriptions_execution_id", monitor_subscriptions.c.execution_id)
Index(
    "uq_monitor_subscription_active_identity",
    monitor_subscriptions.c.execution_id,
    monitor_subscriptions.c.subject_id,
    monitor_subscriptions.c.session_id,
    monitor_subscriptions.c.client_instance_key_id,
    unique=True,
    sqlite_where=text("state = 'ACTIVE'"),
    postgresql_where=text("state = 'ACTIVE'"),
)

controller_handovers = Table(
    "controller_handovers",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("requester_subject_id", String(200), nullable=False),
    Column("requester_session_id", String(128), nullable=False),
    Column("requester_client_instance_key_id", String(128), nullable=False),
    Column(
        "requester_monitor_id",
        String(64),
        ForeignKey("monitor_subscriptions.id"),
        nullable=False,
    ),
    Column("responsibility_acknowledgement", Text, nullable=False),
    Column("expected_execution_revision", Integer, nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("requested_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("approved_by", String(200), nullable=True),
    Column("predecessor_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=True),
    Column("successor_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint(
        "execution_id", "requester_subject_id", "idempotency_key",
        name="uq_controller_handover_request",
    ),
    CheckConstraint(
        "state IN ('REQUESTED','COMPLETED','CANCELLED','EXPIRED')",
        name="ck_controller_handover_state",
    ),
)
Index("ix_controller_handovers_execution_id", controller_handovers.c.execution_id)

operator_requests = Table(
    "operator_requests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("scope", String(200), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("resource_type", String(60), nullable=False),
    Column("resource_id", String(64), nullable=False),
    Column("response", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("scope", "actor", "idempotency_key", name="uq_operator_request"),
    CheckConstraint("length(request_digest) = 64", name="ck_operator_request_digest"),
)

operator_audit_events = Table(
    "operator_audit_events",
    metadata,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("id", String(64), nullable=False, unique=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=True),
    Column("aggregate_type", String(60), nullable=False),
    Column("aggregate_id", String(64), nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_operator_audit_events_execution_id", operator_audit_events.c.execution_id)
Index("ix_operator_audit_events_aggregate_id", operator_audit_events.c.aggregate_id)
Index("ix_operator_audit_events_event_type", operator_audit_events.c.event_type)

operator_commands = Table(
    "operator_commands",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("command_type", String(40), nullable=False),
    Column("state", String(30), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("expected_execution_revision", Integer, nullable=False),
    Column("accepted_execution_revision", Integer, nullable=True),
    Column("accepted_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=True),
    Column("accepted_lease_revision", Integer, nullable=True),
    Column("accepted_fencing_token", Integer, nullable=True),
    Column("safe_point", String(40), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("role", String(30), nullable=False),
    Column("reason", Text, nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("target", JSON, nullable=False),
    Column("request_payload", JSON, nullable=False),
    Column("result_payload", JSON, nullable=False),
    Column("application_safe_point_id", String(128), nullable=True),
    Column("applied_event_id", String(64), nullable=True),
    Column("effect_certainty_before", String(30), nullable=False),
    Column("effect_certainty_after", String(30), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("rejection_code", String(80), nullable=True),
    Column("legacy_command_id", String(36), ForeignKey("commands.id"), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("execution_id", "idempotency_key", name="uq_operator_command"),
    CheckConstraint(
        "state IN ('RECEIVED','VALIDATING','ACCEPTED','WAITING_SAFE_POINT','APPLYING','RECONCILING','SETTLED','REJECTED','CANCELLED','SUPERSEDED','FAILED')",
        name="ck_operator_command_state",
    ),
    CheckConstraint(
        "effect_certainty_before IN ('NO_EFFECT','EFFECT_CONFIRMED','EFFECT_POSSIBLE','EFFECT_UNKNOWN')",
        name="ck_operator_command_effect_certainty_before",
    ),
    CheckConstraint(
        "effect_certainty_after IN ('NO_EFFECT','EFFECT_CONFIRMED','EFFECT_POSSIBLE','EFFECT_UNKNOWN')",
        name="ck_operator_command_effect_certainty_after",
    ),
    CheckConstraint("revision >= 0", name="ck_operator_command_revision"),
)
Index("ix_operator_commands_execution_id", operator_commands.c.execution_id)

operator_prompts = Table(
    "operator_prompts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("legacy_prompt_id", String(36), ForeignKey("prompts.id"), nullable=True, unique=True),
    Column("step_index", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("prompt_type", String(30), nullable=False),
    Column("input_kind", String(30), nullable=False),
    Column("list_mode", String(20), nullable=True),
    Column("question", Text, nullable=False),
    Column("options", JSON, nullable=False),
    Column("option_revision", Integer, nullable=False),
    Column("default_value", JSON, nullable=True),
    Column("settings_snapshot", JSON, nullable=False),
    Column("warning_at", DateTime(timezone=True), nullable=True),
    Column("response_deadline", DateTime(timezone=True), nullable=True),
    Column("no_controller_deadline", DateTime(timezone=True), nullable=True),
    Column("warning_emitted_at", DateTime(timezone=True), nullable=True),
    Column("attempt_count", Integer, nullable=False),
    Column("settlement_id", String(64), nullable=True, unique=True),
    Column("settlement_outcome", String(40), nullable=True),
    Column("settled_value", JSON, nullable=True),
    Column("settled_by", String(200), nullable=True),
    Column("settlement_delivery_attempts", Integer, nullable=False),
    Column("settlement_delivered_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=True),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("state IN ('CREATED','OPEN','SETTLED')", name="ck_operator_prompt_state"),
    CheckConstraint("revision > 0", name="ck_operator_prompt_revision"),
    CheckConstraint("attempt_count >= 0", name="ck_operator_prompt_attempt_count"),
)
Index("ix_operator_prompts_execution_id", operator_prompts.c.execution_id)

operator_prompt_attempts = Table(
    "operator_prompt_attempts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("prompt_id", String(64), ForeignKey("operator_prompts.id"), nullable=False),
    Column("prompt_revision", Integer, nullable=False),
    Column("actor", String(200), nullable=False),
    Column("action", String(20), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("outcome", String(40), nullable=False),
    Column("value_digest", String(64), nullable=True),
    Column("settlement_id", String(64), nullable=True),
    Column("controller_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=True),
    Column("accepted_lease_revision", Integer, nullable=True),
    Column("control_fencing_token", Integer, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("prompt_id", "actor", "idempotency_key", name="uq_prompt_attempt"),
)
Index("ix_operator_prompt_attempts_prompt_id", operator_prompt_attempts.c.prompt_id)

inspection_edit_operations = Table(
    "inspection_edit_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("state", String(30), nullable=False),
    Column("path", String(200), nullable=False),
    Column("scope", String(40), nullable=False),
    Column("declared_type", String(40), nullable=False),
    Column("value", JSON, nullable=False),
    Column("old_value_digest", String(64), nullable=False),
    Column("new_value_digest", String(64), nullable=False),
    Column("expected_value_revision", Integer, nullable=False),
    Column("expected_execution_revision", Integer, nullable=False),
    Column("authoritative_variables", JSON, nullable=False),
    Column("controller_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=False),
    Column("accepted_lease_revision", Integer, nullable=False),
    Column("control_fencing_token", Integer, nullable=False),
    Column("actor", String(200), nullable=False),
    Column("reason", Text, nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("delivery_attempts", Integer, nullable=False),
    Column("last_delivery_attempt_at", DateTime(timezone=True), nullable=True),
    Column("application_id", String(64), nullable=True),
    Column("application_safe_point_id", String(128), nullable=True),
    Column("applied_execution_revision", Integer, nullable=True),
    Column("rejection_code", String(80), nullable=True),
    Column("result_payload", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("execution_id", "idempotency_key", name="uq_inspection_edit_request"),
    CheckConstraint(
        "state IN ('PENDING_SAFE_POINT','APPLYING','APPLIED','REJECTED','CANCELLED')",
        name="ck_inspection_edit_state",
    ),
)
Index("ix_inspection_edit_operations_execution_id", inspection_edit_operations.c.execution_id)

operator_breakpoints = Table(
    "operator_breakpoints",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("source_digest", String(64), nullable=False),
    Column("line_id", String(128), nullable=False),
    Column(
        "bound_command_id",
        String(64),
        ForeignKey("operator_commands.id"),
        nullable=True,
        unique=True,
    ),
    Column("one_shot", Boolean, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_operator_breakpoints_execution_id", operator_breakpoints.c.execution_id)
Index(
    "uq_operator_breakpoint_unbound",
    operator_breakpoints.c.execution_id,
    operator_breakpoints.c.source_digest,
    operator_breakpoints.c.line_id,
    unique=True,
    sqlite_where=text("bound_command_id IS NULL"),
    postgresql_where=text("bound_command_id IS NULL"),
)

operator_user_actions = Table(
    "operator_user_actions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("name", String(100), nullable=False),
    Column("label", String(200), nullable=False),
    Column("severity", String(20), nullable=False),
    Column("handler_id", String(128), nullable=False),
    Column("source_digest", String(64), nullable=False),
    Column("definition", JSON, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("dismissed", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("execution_id", "name", "revision", name="uq_operator_user_action"),
)
Index("ix_operator_user_actions_execution_id", operator_user_actions.c.execution_id)

operator_user_action_invocations = Table(
    "operator_user_action_invocations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("action_id", String(64), ForeignKey("operator_user_actions.id"), nullable=False),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("action_revision", Integer, nullable=False),
    Column("expected_execution_revision", Integer, nullable=False),
    Column("accepted_lease_id", String(64), ForeignKey("controller_leases.id"), nullable=False),
    Column("accepted_lease_revision", Integer, nullable=False),
    Column("accepted_fencing_token", Integer, nullable=False),
    Column("state", String(30), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("arguments", JSON, nullable=False),
    Column("pinned_handler", JSON, nullable=False),
    Column("handler_digest", String(64), nullable=False),
    Column("delivery_attempts", Integer, nullable=False),
    Column("last_delivery_attempt_at", DateTime(timezone=True), nullable=True),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    Column("result_payload", JSON, nullable=False),
    Column("rejection_code", String(80), nullable=True),
    Column("application_safe_point_id", String(128), nullable=True),
    Column("applied_event_id", String(64), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("action_id", "idempotency_key", name="uq_user_action_invocation"),
)
Index("ix_operator_user_action_invocations_action_id", operator_user_action_invocations.c.action_id)
Index(
    "ix_operator_user_action_invocations_execution_id",
    operator_user_action_invocations.c.execution_id,
)

procedure_schedules = Table(
    "procedure_schedules",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("controller_execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("schedule_type", String(20), nullable=False),
    Column("original_target", String(200), nullable=False),
    Column("original_offset", String(10), nullable=True),
    Column("original_duration_seconds", String(40), nullable=True),
    Column("target_at", DateTime(timezone=True), nullable=False),
    Column(
        "catalog_revision_id",
        String(64),
        ForeignKey("procedure_catalog_revisions.id"),
        nullable=False,
    ),
    Column(
        "procedure_catalog_id",
        String(64),
        ForeignKey("procedure_catalog_entries.id"),
        nullable=False,
    ),
    Column("procedure_revision", Integer, nullable=False),
    Column("bundle_digest", String(64), nullable=False),
    Column("context_id", String(100), ForeignKey("operator_contexts.id"), nullable=False),
    Column("arguments", JSON, nullable=False),
    Column("arguments_digest", String(64), nullable=False),
    Column("automatic", Boolean, nullable=False),
    Column("background_allowed", Boolean, nullable=False),
    Column("visible", Boolean, nullable=False),
    Column("misfire_policy", String(20), nullable=False),
    Column("maximum_lateness_seconds", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("occurrence_id", String(64), nullable=True, unique=True),
    Column("fired_execution_id", String(36), ForeignKey("executions.id"), nullable=True, unique=True),
    Column("error_code", String(80), nullable=True),
    Column("error_message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("created_by", "idempotency_key", name="uq_procedure_schedule_request"),
    CheckConstraint(
        "state IN ('PENDING','CLAIMED','FIRED','CANCELLED','MISSED','ERROR')",
        name="ck_procedure_schedule_state",
    ),
    CheckConstraint("schedule_type IN ('RELATIVE','ABSOLUTE')", name="ck_schedule_type"),
    CheckConstraint("revision >= 0", name="ck_schedule_revision"),
    CheckConstraint("length(arguments_digest) = 64", name="ck_schedule_arguments_digest"),
    CheckConstraint("procedure_revision >= 1", name="ck_schedule_procedure_revision"),
    CheckConstraint("length(bundle_digest) = 64", name="ck_schedule_bundle_digest"),
)
Index("ix_procedure_schedules_controller_execution_id", procedure_schedules.c.controller_execution_id)
Index("ix_procedure_schedules_target_at", procedure_schedules.c.target_at)
Index("ix_procedure_schedules_catalog_revision_id", procedure_schedules.c.catalog_revision_id)
Index("ix_procedure_schedules_procedure_catalog_id", procedure_schedules.c.procedure_catalog_id)
Index("ix_procedure_schedules_context_id", procedure_schedules.c.context_id)
Index("ix_procedure_schedules_state", procedure_schedules.c.state)

schedule_occurrences = Table(
    "schedule_occurrences",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("schedule_id", String(64), ForeignKey("procedure_schedules.id"), nullable=False),
    Column("target_at", DateTime(timezone=True), nullable=False),
    Column("state", String(20), nullable=False),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=True),
    Column("claimed_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("schedule_id", "target_at", name="uq_schedule_occurrence_target"),
    CheckConstraint(
        "state IN ('CLAIMED','FIRED','MISSED','ERROR')",
        name="ck_schedule_occurrence_state",
    ),
)
Index("ix_schedule_occurrences_schedule_id", schedule_occurrences.c.schedule_id)

startproc_operations = Table(
    "startproc_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("parent_execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("expected_parent_revision", Integer, nullable=False),
    Column(
        "parent_catalog_revision_id",
        String(64),
        ForeignKey("procedure_catalog_revisions.id"),
        nullable=False,
    ),
    Column("child_procedure_ref", String(200), nullable=False),
    Column(
        "resolved_child_catalog_revision_id",
        String(64),
        ForeignKey("procedure_catalog_revisions.id"),
        nullable=True,
    ),
    Column("library_revision", Integer, nullable=True),
    Column("bundle_digest", String(64), nullable=True),
    Column("dependency_closure", JSON, nullable=False),
    Column("arguments", JSON, nullable=False),
    Column("arguments_digest", String(64), nullable=False),
    Column("blocking", Boolean, nullable=False),
    Column("visible", Boolean, nullable=False),
    Column("automatic", Boolean, nullable=False),
    Column("depth", Integer, nullable=False),
    Column("state", String(30), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("saved_successor", JSON, nullable=False),
    Column("child_execution_id", String(36), ForeignKey("executions.id"), nullable=True, unique=True),
    Column("result_payload", JSON, nullable=False),
    Column("rejection_code", String(80), nullable=True),
    Column("effect_certainty", String(30), nullable=False),
    Column("result_delivery_attempts", Integer, nullable=False),
    Column("result_last_attempt_at", DateTime(timezone=True), nullable=True),
    Column("result_applied_at", DateTime(timezone=True), nullable=True),
    Column("result_applied_parent_revision", Integer, nullable=True),
    Column("result_applied_parent_step", Integer, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("parent_execution_id", "idempotency_key", name="uq_startproc_request"),
    CheckConstraint(
        "state IN ('REQUESTED','VALIDATING','ADMITTING','CHILD_CREATED','WAITING_CHILD','SETTLED','REJECTED','CANCELLED','RECONCILING')",
        name="ck_startproc_state",
    ),
    CheckConstraint("depth >= 1 AND depth <= 8", name="ck_startproc_depth"),
)
Index("ix_startproc_operations_parent_execution_id", startproc_operations.c.parent_execution_id)

parent_child_links = Table(
    "parent_child_links",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("startproc_id", String(64), ForeignKey("startproc_operations.id"), nullable=False),
    Column("parent_execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("child_execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column(
        "child_catalog_revision_id",
        String(64),
        ForeignKey("procedure_catalog_revisions.id"),
        nullable=False,
    ),
    Column("arguments_digest", String(64), nullable=False),
    Column("blocking", Boolean, nullable=False),
    Column("visible", Boolean, nullable=False),
    Column("automatic", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("startproc_id", name="uq_parent_child_startproc"),
    UniqueConstraint("parent_execution_id", "child_execution_id", name="uq_parent_child_pair"),
)
Index("ix_parent_child_links_parent_execution_id", parent_child_links.c.parent_execution_id)
Index("ix_parent_child_links_child_execution_id", parent_child_links.c.child_execution_id)


NEW_TABLES = (
    operator_contexts,
    procedure_catalog_entries,
    procedure_catalog_revisions,
    execution_operator_states,
    controller_leases,
    monitor_subscriptions,
    controller_handovers,
    operator_requests,
    operator_audit_events,
    operator_commands,
    operator_prompts,
    operator_prompt_attempts,
    inspection_edit_operations,
    operator_breakpoints,
    operator_user_actions,
    operator_user_action_invocations,
    procedure_schedules,
    schedule_occurrences,
    startproc_operations,
    parent_child_links,
)


def upgrade(connection: Connection) -> None:
    """Add the bounded v0.6 durable operator workspace ledger."""

    for table in NEW_TABLES:
        table.create(connection, checkfirst=True)
    if connection.execute(
        operator_contexts.select().where(operator_contexts.c.id == "simulator")
    ).first() is None:
        now = datetime.now(timezone.utc)
        connection.execute(
            operator_contexts.insert().values(
                id="simulator",
                name="Local Synthetic Simulator",
                description="Local deterministic synthetic non-CUI execution context",
                settings={
                    "PROMPT_WARNING_DELAY": None,
                    "PROMPT_RESPONSE_TIMEOUT": None,
                    "NO_CONTROLLER_GRACE": None,
                },
                enabled=True,
                revision=0,
                created_by="migration:v0.6",
                created_at=now,
                updated_at=now,
            )
        )


__all__ = ["NEW_TABLES", "VERSION", "metadata", "upgrade"]
