from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base, utc_now
from .models import new_id


HOST_STATES = ("STARTING", "READY", "DEGRADED", "DRAINING", "CLOSED", "FAILED")
CONTEXT_STATES = ("OPENING", "ACTIVE", "DEGRADED", "CLOSING", "CLOSED", "FAILED")
BINDING_STATES = ("ATTACHING", "ATTACHED", "DETACHING", "DETACHED", "FAILED")
OPERATION_STAGES = ("REQUESTED", "ACCEPTED", "DISPATCHED", "RECONCILING", "SETTLED")
EFFECT_CERTAINTIES = (
    "NO_EFFECT",
    "EFFECT_CONFIRMED",
    "EFFECT_POSSIBLE",
    "EFFECT_UNKNOWN",
)
LIFECYCLE_METHODS = (
    "OpenContext",
    "CloseContext",
    "AttachExecution",
    "DetachExecution",
    "CancelLifecycleOperation",
    "DrainHost",
)
LIFECYCLE_EFFECT_CLASSES = (
    "CONTEXT_OPEN",
    "CONTEXT_CLOSE",
    "EXECUTION_ATTACH",
    "EXECUTION_DETACH",
    "LIFECYCLE_CANCEL",
    "HOST_DRAIN",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class DriverProfile(Base):
    __tablename__ = "driver_profiles"
    __table_args__ = (
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

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    logical_driver_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    simulator: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    contract_package: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    credential_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_contexts_per_host: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attachments_per_context: Mapped[int] = mapped_column(Integer, nullable=False)
    max_lifecycle_operations_per_host: Mapped[int] = mapped_column(Integer, nullable=False)
    max_lifecycle_operations_per_context: Mapped[int] = mapped_column(Integer, nullable=False)
    journal_max_entries: Mapped[int] = mapped_column(Integer, nullable=False)
    journal_max_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class DriverHostGeneration(Base):
    __tablename__ = "driver_host_generations"
    __table_args__ = (
        UniqueConstraint("profile_id", "generation_number", name="uq_driver_host_profile_generation"),
        CheckConstraint("generation_number > 0", name="ck_driver_host_generation_number"),
        CheckConstraint("length(configuration_digest) = 64", name="ck_driver_host_digest"),
        CheckConstraint("credential_epoch >= 1", name="ck_driver_host_credential_epoch"),
        CheckConstraint(f"state IN ({_quoted(HOST_STATES)})", name="ck_driver_host_state"),
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
        Index("ix_driver_host_profile_state", "profile_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    profile_id: Mapped[str] = mapped_column(ForeignKey("driver_profiles.id"), nullable=False)
    generation_number: Mapped[int] = mapped_column(Integer, nullable=False)
    logical_driver_id: Mapped[str] = mapped_column(String(128), nullable=False)
    simulator: Mapped[bool] = mapped_column(Boolean, nullable=False)
    contract_version: Mapped[str] = mapped_column(String(40), nullable=False)
    implementation_version: Mapped[str] = mapped_column(String(80), nullable=False)
    configuration_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="STARTING")
    ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_contexts: Mapped[int] = mapped_column(Integer, nullable=False)
    contexts_in_use: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_lifecycle_operations: Mapped[int] = mapped_column(Integer, nullable=False)
    lifecycle_operations_in_use: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class DriverCapability(Base):
    __tablename__ = "driver_capabilities"
    __table_args__ = (
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

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False, index=True
    )
    service: Mapped[str] = mapped_column(String(100), nullable=False)
    method: Mapped[str] = mapped_column(String(100), nullable=False)
    modifiers: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    formats: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    mutability: Mapped[str] = mapped_column(String(20), nullable=False)
    stream_support: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverContext(Base):
    __tablename__ = "driver_contexts"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("driver_profiles.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverContextGeneration(Base):
    __tablename__ = "driver_context_generations"
    __table_args__ = (
        UniqueConstraint("context_id", "generation_number", name="uq_driver_context_generation"),
        CheckConstraint("generation_number > 0", name="ck_driver_context_generation_number"),
        CheckConstraint("length(configuration_digest) = 64", name="ck_driver_context_digest"),
        CheckConstraint(f"state IN ({_quoted(CONTEXT_STATES)})", name="ck_driver_context_state"),
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
        Index("ix_driver_context_host_state", "host_generation_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_id: Mapped[str] = mapped_column(ForeignKey("driver_contexts.id"), nullable=False)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False
    )
    generation_number: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_host_configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="OPENING")
    ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_attachments: Mapped[int] = mapped_column(Integer, nullable=False)
    attachments_in_use: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_lifecycle_operations: Mapped[int] = mapped_column(Integer, nullable=False)
    lifecycle_operations_in_use: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class DriverBinding(Base):
    __tablename__ = "driver_bindings"
    __table_args__ = (
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
        CheckConstraint(f"state IN ({_quoted(BINDING_STATES)})", name="ck_driver_binding_state"),
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
        Index("ix_driver_binding_execution_state", "execution_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False
    )
    replacement_of_binding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("driver_bindings.id")
    )
    capacity_reserved: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    replacement_pending: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attachment_generation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attachment_generation_number: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_context_configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="ATTACHING")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    detached_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class DriverOperation(Base):
    __tablename__ = "driver_operations"
    __table_args__ = (
        CheckConstraint(f"method IN ({_quoted(LIFECYCLE_METHODS)})", name="ck_driver_operation_method"),
        CheckConstraint("length(request_digest) = 64", name="ck_driver_operation_digest"),
        CheckConstraint(
            f"effect_class IN ({_quoted(LIFECYCLE_EFFECT_CLASSES)})",
            name="ck_driver_operation_effect_class",
        ),
        CheckConstraint(f"stage IN ({_quoted(OPERATION_STAGES)})", name="ck_driver_operation_stage"),
        CheckConstraint(
            f"certainty IN ({_quoted(EFFECT_CERTAINTIES)})",
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
        Index("ix_driver_operation_stage_updated", "stage", "updated_at"),
        Index("ix_driver_operation_context", "context_generation_id", "created_at"),
        Index("ix_driver_operation_binding", "binding_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    method: Mapped[str] = mapped_column(String(40), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    effect_class: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False
    )
    context_generation_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("driver_context_generations.id")
    )
    binding_id: Mapped[Optional[str]] = mapped_column(ForeignKey("driver_bindings.id"))
    target_operation_id: Mapped[Optional[str]] = mapped_column(String(128))
    target_attempt_id: Mapped[Optional[str]] = mapped_column(String(128))
    lifecycle_reason: Mapped[Optional[str]] = mapped_column(String(40))
    replaced_binding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("driver_bindings.id")
    )
    current_attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_attempt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stage: Mapped[str] = mapped_column(String(20), nullable=False, default="ACCEPTED")
    certainty: Mapped[str] = mapped_column(String(30), nullable=False, default="NO_EFFECT")
    disposition: Mapped[Optional[str]] = mapped_column(String(60))
    safe_error_code: Mapped[Optional[str]] = mapped_column(String(80))
    safe_error_message: Mapped[Optional[str]] = mapped_column(Text)
    requires_reconciliation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    capacity_reserved: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    settled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    effect_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )


class DriverOperationAttempt(Base):
    __tablename__ = "driver_operation_attempts"
    __table_args__ = (
        UniqueConstraint("operation_id", "attempt_number", name="uq_driver_operation_attempt_number"),
        CheckConstraint("attempt_number > 0", name="ck_driver_attempt_number"),
        CheckConstraint("credential_epoch >= 1", name="ck_driver_attempt_credential_epoch"),
        CheckConstraint("length(request_digest) = 64", name="ck_driver_attempt_request_digest"),
        CheckConstraint(
            f"effect_class IN ({_quoted(LIFECYCLE_EFFECT_CLASSES)})",
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
        Index("ix_driver_attempt_operation_created", "operation_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    operation_id: Mapped[str] = mapped_column(ForeignKey("driver_operations.id"), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    effect_class: Mapped[str] = mapped_column(String(100), nullable=False)
    server_profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False
    )
    context_generation_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("driver_context_generations.id")
    )
    binding_id: Mapped[Optional[str]] = mapped_column(ForeignKey("driver_bindings.id"))
    execution_id: Mapped[Optional[str]] = mapped_column(String(128))
    attachment_generation_id: Mapped[Optional[str]] = mapped_column(String(128))
    host_configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_configuration_digest: Mapped[Optional[str]] = mapped_column(String(64))
    attachment_configuration_digest: Mapped[Optional[str]] = mapped_column(String(64))
    target_operation_id: Mapped[Optional[str]] = mapped_column(String(128))
    target_attempt_id: Mapped[Optional[str]] = mapped_column(String(128))
    lifecycle_reason: Mapped[Optional[str]] = mapped_column(String(40))
    replaced_binding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("driver_bindings.id")
    )
    credential_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effect_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    projection_outcome: Mapped[Optional[str]] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverOperationTransition(Base):
    __tablename__ = "driver_operation_transitions"
    __table_args__ = (
        UniqueConstraint("attempt_id", "sequence", name="uq_driver_attempt_transition_sequence"),
        CheckConstraint("sequence > 0", name="ck_driver_transition_sequence"),
        CheckConstraint(f"stage IN ({_quoted(OPERATION_STAGES)})", name="ck_driver_transition_stage"),
        CheckConstraint(
            f"certainty IN ({_quoted(EFFECT_CERTAINTIES)})",
            name="ck_driver_transition_certainty",
        ),
        CheckConstraint(
            "evidence_digest IS NULL OR length(evidence_digest) = 64",
            name="ck_driver_transition_evidence_digest",
        ),
        Index("ix_driver_transition_operation_created", "operation_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    operation_id: Mapped[str] = mapped_column(ForeignKey("driver_operations.id"), nullable=False)
    attempt_id: Mapped[str] = mapped_column(
        ForeignKey("driver_operation_attempts.id"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[str] = mapped_column(String(20), nullable=False)
    certainty: Mapped[str] = mapped_column(String(30), nullable=False)
    disposition: Mapped[Optional[str]] = mapped_column(String(60))
    safe_error_code: Mapped[Optional[str]] = mapped_column(String(80))
    safe_error_message: Mapped[Optional[str]] = mapped_column(Text)
    evidence_digest: Mapped[Optional[str]] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverAuditEvent(Base):
    __tablename__ = "driver_audit_events"
    __table_args__ = (
        Index("ix_driver_audit_operation_sequence", "operation_id", "sequence"),
        Index("ix_driver_audit_event_type_sequence", "event_type", "sequence"),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    operation_id: Mapped[Optional[str]] = mapped_column(ForeignKey("driver_operations.id"))
    attempt_id: Mapped[Optional[str]] = mapped_column(ForeignKey("driver_operation_attempts.id"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverOutboxEvent(Base):
    __tablename__ = "driver_outbox"
    __table_args__ = (
        CheckConstraint("delivery_attempts >= 0", name="ck_driver_outbox_delivery_attempts"),
        Index("ix_driver_outbox_pending", "published_at", "sequence"),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("driver_audit_events.id"), nullable=False, unique=True
    )
    topic: Mapped[str] = mapped_column(String(100), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(60), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


__all__ = [
    "BINDING_STATES",
    "CONTEXT_STATES",
    "DriverAuditEvent",
    "DriverBinding",
    "DriverCapability",
    "DriverContext",
    "DriverContextGeneration",
    "DriverHostGeneration",
    "DriverOperation",
    "DriverOperationAttempt",
    "DriverOperationTransition",
    "DriverOutboxEvent",
    "DriverProfile",
    "EFFECT_CERTAINTIES",
    "HOST_STATES",
    "LIFECYCLE_EFFECT_CLASSES",
    "LIFECYCLE_METHODS",
    "OPERATION_STAGES",
]
