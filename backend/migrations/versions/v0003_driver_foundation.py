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
)
from sqlalchemy.engine import Connection


VERSION = "0003_driver_foundation"
DEFAULT_PROFILE_ID = "local-synthetic-simulator"
DEFAULT_PROFILE_DIGEST = "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"

# This migration is deliberately independent of the live ORM. Applied migration
# history must not change when a later release edits backend.driver_models.
metadata = MetaData()

driver_profiles = Table(
    "driver_profiles",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("server_profile_id", String(128), nullable=False),
    Column("logical_driver_id", String(128), nullable=False, unique=True),
    Column("simulator", Boolean, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("contract_package", String(128), nullable=False),
    Column("configuration_schema_version", String(128), nullable=False),
    Column("configuration_digest", String(64), nullable=False),
    Column("credential_reference", String(200), nullable=False),
    Column("credential_epoch", Integer, nullable=False),
    Column("max_contexts_per_host", Integer, nullable=False),
    Column("max_attachments_per_context", Integer, nullable=False),
    Column("max_lifecycle_operations_per_host", Integer, nullable=False),
    Column("max_lifecycle_operations_per_context", Integer, nullable=False),
    Column("journal_max_entries", Integer, nullable=False),
    Column("journal_max_bytes", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("length(configuration_digest) = 64", name="ck_driver_profile_digest"),
    CheckConstraint("credential_epoch >= 1", name="ck_driver_profile_credential_epoch"),
    CheckConstraint("max_contexts_per_host > 0", name="ck_driver_profile_context_capacity"),
    CheckConstraint(
        "max_attachments_per_context > 0",
        name="ck_driver_profile_attachment_capacity",
    ),
    CheckConstraint(
        "max_lifecycle_operations_per_host > 0",
        name="ck_driver_profile_host_operation_capacity",
    ),
    CheckConstraint(
        "max_lifecycle_operations_per_context > 0",
        name="ck_driver_profile_context_operation_capacity",
    ),
    CheckConstraint("journal_max_entries > 0", name="ck_driver_profile_journal_entries"),
    CheckConstraint("journal_max_bytes > 0", name="ck_driver_profile_journal_bytes"),
    CheckConstraint("revision >= 0", name="ck_driver_profile_revision"),
)

driver_host_generations = Table(
    "driver_host_generations",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("profile_id", String(128), ForeignKey("driver_profiles.id"), nullable=False),
    Column("generation_number", Integer, nullable=False),
    Column("logical_driver_id", String(128), nullable=False),
    Column("simulator", Boolean, nullable=False),
    Column("contract_version", String(40), nullable=False),
    Column("implementation_version", String(80), nullable=False),
    Column("configuration_schema_version", String(128), nullable=False),
    Column("configuration_digest", String(64), nullable=False),
    Column("credential_epoch", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("ready", Boolean, nullable=False),
    Column("max_contexts", Integer, nullable=False),
    Column("contexts_in_use", Integer, nullable=False),
    Column("max_lifecycle_operations", Integer, nullable=False),
    Column("lifecycle_operations_in_use", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("last_observed_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("closed_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("profile_id", "generation_number", name="uq_driver_host_profile_generation"),
    CheckConstraint("generation_number > 0", name="ck_driver_host_generation_number"),
    CheckConstraint("length(configuration_digest) = 64", name="ck_driver_host_digest"),
    CheckConstraint("credential_epoch >= 1", name="ck_driver_host_credential_epoch"),
    CheckConstraint(
        "state IN ('STARTING', 'READY', 'DEGRADED', 'DRAINING', 'CLOSED', 'FAILED')",
        name="ck_driver_host_state",
    ),
    CheckConstraint("max_contexts > 0", name="ck_driver_host_context_capacity"),
    CheckConstraint("max_lifecycle_operations > 0", name="ck_driver_host_operation_capacity"),
    CheckConstraint(
        "contexts_in_use >= 0 AND contexts_in_use <= max_contexts",
        name="ck_driver_host_context_use",
    ),
    CheckConstraint(
        "lifecycle_operations_in_use >= 0 "
        "AND lifecycle_operations_in_use <= max_lifecycle_operations",
        name="ck_driver_host_operation_use",
    ),
    CheckConstraint("revision >= 0", name="ck_driver_host_revision"),
)
Index(
    "ix_driver_host_profile_state",
    driver_host_generations.c.profile_id,
    driver_host_generations.c.state,
)

driver_capabilities = Table(
    "driver_capabilities",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        nullable=False,
    ),
    Column("service", String(100), nullable=False),
    Column("method", String(100), nullable=False),
    Column("modifiers", JSON, nullable=False),
    Column("formats", JSON, nullable=False),
    Column("mutability", String(20), nullable=False),
    Column("stream_support", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "host_generation_id",
        "method",
        name="uq_driver_capability_identity",
    ),
    CheckConstraint(
        "service IN ('HOST', 'CONTEXT_LIFECYCLE', 'EXECUTION_LIFECYCLE', "
        "'OPERATION_RECONCILIATION')",
        name="ck_driver_capability_service",
    ),
    CheckConstraint(
        "mutability IN ('READ_ONLY', 'LIFECYCLE')",
        name="ck_driver_capability_mutability",
    ),
    CheckConstraint("stream_support = 'NONE'", name="ck_driver_capability_stream_support"),
)
Index("ix_driver_capabilities_host_generation_id", driver_capabilities.c.host_generation_id)

driver_contexts = Table(
    "driver_contexts",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("profile_id", String(128), ForeignKey("driver_profiles.id"), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_driver_contexts_profile_id", driver_contexts.c.profile_id)

driver_context_generations = Table(
    "driver_context_generations",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("context_id", String(128), ForeignKey("driver_contexts.id"), nullable=False),
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        nullable=False,
    ),
    Column("generation_number", Integer, nullable=False),
    Column("configuration_schema_version", String(128), nullable=False),
    Column("configuration_digest", String(64), nullable=False),
    Column("parent_host_configuration_digest", String(64), nullable=False),
    Column("state", String(20), nullable=False),
    Column("ready", Boolean, nullable=False),
    Column("max_attachments", Integer, nullable=False),
    Column("attachments_in_use", Integer, nullable=False),
    Column("max_lifecycle_operations", Integer, nullable=False),
    Column("lifecycle_operations_in_use", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("last_observed_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("closed_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("context_id", "generation_number", name="uq_driver_context_generation"),
    CheckConstraint("generation_number > 0", name="ck_driver_context_generation_number"),
    CheckConstraint("length(configuration_digest) = 64", name="ck_driver_context_digest"),
    CheckConstraint(
        "state IN ('OPENING', 'ACTIVE', 'DEGRADED', 'CLOSING', 'CLOSED', 'FAILED')",
        name="ck_driver_context_state",
    ),
    CheckConstraint("max_attachments > 0", name="ck_driver_context_attachment_capacity"),
    CheckConstraint("max_lifecycle_operations > 0", name="ck_driver_context_operation_capacity"),
    CheckConstraint(
        "attachments_in_use >= 0 AND attachments_in_use <= max_attachments",
        name="ck_driver_context_attachment_use",
    ),
    CheckConstraint(
        "lifecycle_operations_in_use >= 0 "
        "AND lifecycle_operations_in_use <= max_lifecycle_operations",
        name="ck_driver_context_operation_use",
    ),
    CheckConstraint("revision >= 0", name="ck_driver_context_revision"),
)
Index(
    "ix_driver_context_host_state",
    driver_context_generations.c.host_generation_id,
    driver_context_generations.c.state,
)

driver_bindings = Table(
    "driver_bindings",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column(
        "replacement_of_binding_id",
        String(128),
        ForeignKey("driver_bindings.id"),
        nullable=True,
    ),
    Column("capacity_reserved", Boolean, nullable=False),
    Column("replacement_pending", Boolean, nullable=False),
    Column("execution_id", String(128), nullable=False),
    Column("attachment_generation_id", String(128), nullable=False),
    Column("attachment_generation_number", Integer, nullable=False),
    Column("configuration_schema_version", String(128), nullable=False),
    Column("configuration_digest", String(64), nullable=False),
    Column("parent_context_configuration_digest", String(64), nullable=False),
    Column("state", String(20), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("last_observed_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("detached_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("attachment_generation_id", name="uq_driver_attachment_generation_id"),
    UniqueConstraint(
        "context_generation_id",
        "execution_id",
        "attachment_generation_number",
        name="uq_driver_execution_attachment_generation",
    ),
    CheckConstraint(
        "attachment_generation_number > 0",
        name="ck_driver_attachment_generation_number",
    ),
    CheckConstraint("length(configuration_digest) = 64", name="ck_driver_binding_digest"),
    CheckConstraint(
        "state IN ('ATTACHING', 'ATTACHED', 'DETACHING', 'DETACHED', 'FAILED')",
        name="ck_driver_binding_state",
    ),
    CheckConstraint(
        "NOT replacement_pending OR "
        "(replacement_of_binding_id IS NOT NULL AND NOT capacity_reserved)",
        name="ck_driver_binding_pending_replacement",
    ),
    CheckConstraint(
        "state NOT IN ('DETACHED', 'FAILED') OR NOT capacity_reserved",
        name="ck_driver_binding_terminal_capacity",
    ),
    CheckConstraint(
        "replacement_of_binding_id IS NULL OR replacement_of_binding_id <> id",
        name="ck_driver_binding_replacement_not_self",
    ),
    CheckConstraint("revision >= 0", name="ck_driver_binding_revision"),
)
Index(
    "ix_driver_binding_execution_state",
    driver_bindings.c.execution_id,
    driver_bindings.c.state,
)

driver_operations = Table(
    "driver_operations",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("method", String(40), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("effect_class", String(100), nullable=False),
    Column("actor", String(200), nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        nullable=False,
    ),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=True,
    ),
    Column("binding_id", String(128), ForeignKey("driver_bindings.id"), nullable=True),
    Column("target_operation_id", String(128), nullable=True),
    Column("target_attempt_id", String(128), nullable=True),
    Column("lifecycle_reason", String(40), nullable=True),
    Column("replaced_binding_id", String(128), ForeignKey("driver_bindings.id"), nullable=True),
    Column("current_attempt_number", Integer, nullable=False),
    Column("current_attempt_id", String(128), nullable=False),
    Column("deadline_at", DateTime(timezone=True), nullable=False),
    Column("stage", String(20), nullable=False),
    Column("certainty", String(30), nullable=False),
    Column("disposition", String(60), nullable=True),
    Column("safe_error_code", String(80), nullable=True),
    Column("safe_error_message", Text, nullable=True),
    Column("requires_reconciliation", Boolean, nullable=False),
    Column("capacity_reserved", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    Column("effect_observed_at", DateTime(timezone=True), nullable=True),
    CheckConstraint(
        "method IN ('OpenContext', 'CloseContext', 'AttachExecution', "
        "'DetachExecution', 'CancelLifecycleOperation', 'DrainHost')",
        name="ck_driver_operation_method",
    ),
    CheckConstraint("length(request_digest) = 64", name="ck_driver_operation_digest"),
    CheckConstraint(
        "effect_class IN ('CONTEXT_OPEN', 'CONTEXT_CLOSE', 'EXECUTION_ATTACH', "
        "'EXECUTION_DETACH', 'LIFECYCLE_CANCEL', 'HOST_DRAIN')",
        name="ck_driver_operation_effect_class",
    ),
    CheckConstraint(
        "stage IN ('REQUESTED', 'ACCEPTED', 'DISPATCHED', 'RECONCILING', 'SETTLED')",
        name="ck_driver_operation_stage",
    ),
    CheckConstraint(
        "certainty IN ('NO_EFFECT', 'EFFECT_CONFIRMED', 'EFFECT_POSSIBLE', 'EFFECT_UNKNOWN')",
        name="ck_driver_operation_certainty",
    ),
    CheckConstraint("current_attempt_number > 0", name="ck_driver_operation_attempt_number"),
    CheckConstraint(
        "stage <> 'SETTLED' OR NOT capacity_reserved",
        name="ck_driver_operation_terminal_capacity",
    ),
    CheckConstraint(
        "stage <> 'RECONCILING' OR NOT capacity_reserved",
        name="ck_driver_operation_reconciliation_capacity",
    ),
    CheckConstraint("revision >= 0", name="ck_driver_operation_revision"),
)
Index(
    "ix_driver_operation_stage_updated",
    driver_operations.c.stage,
    driver_operations.c.updated_at,
)
Index(
    "ix_driver_operation_context",
    driver_operations.c.context_generation_id,
    driver_operations.c.created_at,
)
Index(
    "ix_driver_operation_binding",
    driver_operations.c.binding_id,
    driver_operations.c.created_at,
)

driver_operation_attempts = Table(
    "driver_operation_attempts",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("operation_id", String(128), ForeignKey("driver_operations.id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("effect_class", String(100), nullable=False),
    Column("server_profile_id", String(128), nullable=False),
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        nullable=False,
    ),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=True,
    ),
    Column("binding_id", String(128), ForeignKey("driver_bindings.id"), nullable=True),
    Column("execution_id", String(128), nullable=True),
    Column("attachment_generation_id", String(128), nullable=True),
    Column("host_configuration_digest", String(64), nullable=False),
    Column("context_configuration_digest", String(64), nullable=True),
    Column("attachment_configuration_digest", String(64), nullable=True),
    Column("target_operation_id", String(128), nullable=True),
    Column("target_attempt_id", String(128), nullable=True),
    Column("lifecycle_reason", String(40), nullable=True),
    Column("replaced_binding_id", String(128), ForeignKey("driver_bindings.id"), nullable=True),
    Column("credential_epoch", Integer, nullable=False),
    Column("deadline_at", DateTime(timezone=True), nullable=False),
    Column("effect_observed_at", DateTime(timezone=True), nullable=True),
    Column("projection_outcome", String(60), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("operation_id", "attempt_number", name="uq_driver_operation_attempt_number"),
    CheckConstraint("attempt_number > 0", name="ck_driver_attempt_number"),
    CheckConstraint("credential_epoch >= 1", name="ck_driver_attempt_credential_epoch"),
    CheckConstraint("length(request_digest) = 64", name="ck_driver_attempt_request_digest"),
    CheckConstraint(
        "effect_class IN ('CONTEXT_OPEN', 'CONTEXT_CLOSE', 'EXECUTION_ATTACH', "
        "'EXECUTION_DETACH', 'LIFECYCLE_CANCEL', 'HOST_DRAIN')",
        name="ck_driver_attempt_effect_class",
    ),
    CheckConstraint("length(host_configuration_digest) = 64", name="ck_driver_attempt_host_digest"),
    CheckConstraint(
        "context_configuration_digest IS NULL "
        "OR length(context_configuration_digest) = 64",
        name="ck_driver_attempt_context_digest",
    ),
    CheckConstraint(
        "attachment_configuration_digest IS NULL "
        "OR length(attachment_configuration_digest) = 64",
        name="ck_driver_attempt_attachment_digest",
    ),
)
Index(
    "ix_driver_attempt_operation_created",
    driver_operation_attempts.c.operation_id,
    driver_operation_attempts.c.created_at,
)

driver_operation_transitions = Table(
    "driver_operation_transitions",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("operation_id", String(128), ForeignKey("driver_operations.id"), nullable=False),
    Column(
        "attempt_id",
        String(128),
        ForeignKey("driver_operation_attempts.id"),
        nullable=False,
    ),
    Column("sequence", Integer, nullable=False),
    Column("stage", String(20), nullable=False),
    Column("certainty", String(30), nullable=False),
    Column("disposition", String(60), nullable=True),
    Column("safe_error_code", String(80), nullable=True),
    Column("safe_error_message", Text, nullable=True),
    Column("evidence_digest", String(64), nullable=True),
    Column("actor", String(200), nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("attempt_id", "sequence", name="uq_driver_attempt_transition_sequence"),
    CheckConstraint("sequence > 0", name="ck_driver_transition_sequence"),
    CheckConstraint(
        "stage IN ('REQUESTED', 'ACCEPTED', 'DISPATCHED', 'RECONCILING', 'SETTLED')",
        name="ck_driver_transition_stage",
    ),
    CheckConstraint(
        "certainty IN ('NO_EFFECT', 'EFFECT_CONFIRMED', 'EFFECT_POSSIBLE', 'EFFECT_UNKNOWN')",
        name="ck_driver_transition_certainty",
    ),
    CheckConstraint(
        "evidence_digest IS NULL OR length(evidence_digest) = 64",
        name="ck_driver_transition_evidence_digest",
    ),
)
Index(
    "ix_driver_transition_operation_created",
    driver_operation_transitions.c.operation_id,
    driver_operation_transitions.c.created_at,
)

driver_audit_events = Table(
    "driver_audit_events",
    metadata,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("id", String(128), nullable=False, unique=True),
    Column("event_type", String(100), nullable=False),
    Column("operation_id", String(128), ForeignKey("driver_operations.id"), nullable=True),
    Column(
        "attempt_id",
        String(128),
        ForeignKey("driver_operation_attempts.id"),
        nullable=True,
    ),
    Column("actor", String(200), nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index(
    "ix_driver_audit_operation_sequence",
    driver_audit_events.c.operation_id,
    driver_audit_events.c.sequence,
)
Index(
    "ix_driver_audit_event_type_sequence",
    driver_audit_events.c.event_type,
    driver_audit_events.c.sequence,
)

driver_outbox = Table(
    "driver_outbox",
    metadata,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(128), ForeignKey("driver_audit_events.id"), nullable=False, unique=True),
    Column("topic", String(100), nullable=False),
    Column("aggregate_type", String(60), nullable=False),
    Column("aggregate_id", String(128), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("delivery_attempts", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("published_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("delivery_attempts >= 0", name="ck_driver_outbox_delivery_attempts"),
)
Index("ix_driver_outbox_pending", driver_outbox.c.published_at, driver_outbox.c.sequence)


def upgrade(connection: Connection) -> None:
    """Add the canonical v0.4 driver ledger and a disabled local profile."""

    metadata.create_all(connection, checkfirst=True)
    if connection.execute(
        driver_profiles.select().where(driver_profiles.c.id == DEFAULT_PROFILE_ID)
    ).first() is None:
        now = datetime.now(timezone.utc)
        connection.execute(
            driver_profiles.insert().values(
                id=DEFAULT_PROFILE_ID,
                server_profile_id="local-synthetic",
                logical_driver_id="bundled-deterministic-simulator",
                simulator=True,
                enabled=False,
                contract_package="spell.driver.v1",
                configuration_schema_version="spell.driver.host-profile/1",
                configuration_digest=DEFAULT_PROFILE_DIGEST,
                credential_reference="local-v04-driver-mtls",
                credential_epoch=1,
                max_contexts_per_host=1,
                max_attachments_per_context=1,
                max_lifecycle_operations_per_host=8,
                max_lifecycle_operations_per_context=8,
                journal_max_entries=10_000,
                journal_max_bytes=16_777_216,
                revision=0,
                created_at=now,
                updated_at=now,
            )
        )
