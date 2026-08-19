from __future__ import annotations

from datetime import datetime
from typing import Any

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


OWNERSHIP_MODES = ("C", "B", "CONTROL_LOST")
LEASE_STATES = ("ACTIVE", "RELEASED", "EXPIRED", "REVOKED", "TRANSFERRED")
COMMAND_STATES = (
    "RECEIVED",
    "VALIDATING",
    "ACCEPTED",
    "WAITING_SAFE_POINT",
    "APPLYING",
    "RECONCILING",
    "SETTLED",
    "REJECTED",
    "CANCELLED",
    "SUPERSEDED",
    "FAILED",
)
PROMPT_STATES = ("CREATED", "OPEN", "SETTLED")
SCHEDULE_STATES = ("PENDING", "CLAIMED", "FIRED", "CANCELLED", "MISSED", "ERROR")
STARTPROC_STATES = (
    "REQUESTED",
    "VALIDATING",
    "ADMITTING",
    "CHILD_CREATED",
    "WAITING_CHILD",
    "SETTLED",
    "REJECTED",
    "CANCELLED",
    "RECONCILING",
)


class OperatorContext(Base):
    __tablename__ = "operator_contexts"
    __table_args__ = (
        CheckConstraint("revision >= 0", name="ck_operator_context_revision"),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class ProcedureCatalogEntry(Base):
    __tablename__ = "procedure_catalog_entries"
    __table_args__ = (
        UniqueConstraint("procedure_ref", name="uq_procedure_catalog_ref"),
        CheckConstraint("current_revision > 0", name="ck_procedure_catalog_revision"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    procedure_ref: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    entrypoint: Mapped[str] = mapped_column(String(200))
    current_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class ProcedureCatalogRevision(Base):
    __tablename__ = "procedure_catalog_revisions"
    __table_args__ = (
        UniqueConstraint("catalog_id", "revision", name="uq_procedure_catalog_revision"),
        CheckConstraint("revision > 0", name="ck_procedure_revision_number"),
        CheckConstraint("length(source_digest) = 64", name="ck_procedure_revision_source_digest"),
        CheckConstraint("length(bundle_digest) = 64", name="ck_procedure_revision_bundle_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    catalog_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_entries.id"), index=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    bundle_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ir_version: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ExecutionOperatorState(Base):
    __tablename__ = "execution_operator_states"
    __table_args__ = (
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

    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.id"), primary_key=True
    )
    state: Mapped[str] = mapped_column(String(30), default="REQUESTED", nullable=False)
    resume_state: Mapped[str | None] = mapped_column(String(30), nullable=True)
    current_safe_point_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_lexical_frame_id: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )
    current_reachability_id: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_id: Mapped[str] = mapped_column(ForeignKey("operator_contexts.id"), index=True)
    catalog_revision_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_revisions.id"), index=True
    )
    ownership_mode: Mapped[str] = mapped_column(String(20), default="CONTROL_LOST")
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    control_fencing_token: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_lease_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hold_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    control_loss_fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    control_loss_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    control_loss_applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    control_loss_safe_point_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    control_loss_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("events.id"), nullable=True
    )
    control_loss_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    saved_resume_target: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    effect_certainty: Mapped[str] = mapped_column(String(30), default="NO_EFFECT")
    automatic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    background_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    visible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    predecessor_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.id"), nullable=True
    )
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attached_by: Mapped[str] = mapped_column(String(200), nullable=False)
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class ControllerLease(Base):
    __tablename__ = "controller_leases"
    __table_args__ = (
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

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False)
    holder_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    holder_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    client_instance_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    predecessor_lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=True
    )
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    termination_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "uq_controller_lease_active_execution",
    ControllerLease.execution_id,
    unique=True,
    sqlite_where=text("state = 'ACTIVE'"),
    postgresql_where=text("state = 'ACTIVE'"),
)


class MonitorSubscription(Base):
    __tablename__ = "monitor_subscriptions"
    __table_args__ = (
        CheckConstraint("state IN ('ACTIVE','CLOSED')", name="ck_monitor_subscription_state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    client_instance_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "uq_monitor_subscription_active_identity",
    MonitorSubscription.execution_id,
    MonitorSubscription.subject_id,
    MonitorSubscription.session_id,
    MonitorSubscription.client_instance_key_id,
    unique=True,
    sqlite_where=text("state = 'ACTIVE'"),
    postgresql_where=text("state = 'ACTIVE'"),
)


class ControllerHandover(Base):
    __tablename__ = "controller_handovers"
    __table_args__ = (
        UniqueConstraint(
            "execution_id", "requester_subject_id", "idempotency_key",
            name="uq_controller_handover_request",
        ),
        CheckConstraint(
            "state IN ('REQUESTED','COMPLETED','CANCELLED','EXPIRED')",
            name="ck_controller_handover_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="REQUESTED", nullable=False)
    requester_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    requester_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requester_client_instance_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requester_monitor_id: Mapped[str] = mapped_column(
        ForeignKey("monitor_subscriptions.id"), nullable=False
    )
    responsibility_acknowledgement: Mapped[str] = mapped_column(Text, nullable=False)
    expected_execution_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    predecessor_lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=True
    )
    successor_lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OperatorRequest(Base):
    __tablename__ = "operator_requests"
    __table_args__ = (
        UniqueConstraint("scope", "actor", "idempotency_key", name="uq_operator_request"),
        CheckConstraint("length(request_digest) = 64", name="ck_operator_request_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    scope: Mapped[str] = mapped_column(String(200), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(60), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class OperatorAuditEvent(Base):
    __tablename__ = "operator_audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(64), default=new_id, unique=True, nullable=False)
    execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.id"), nullable=True, index=True
    )
    aggregate_type: Mapped[str] = mapped_column(String(60), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class OperatorCommand(Base):
    __tablename__ = "operator_commands"
    __table_args__ = (
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

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    command_type: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_execution_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_execution_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    accepted_lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=True
    )
    accepted_lease_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    accepted_fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    safe_point: Mapped[str] = mapped_column(String(40), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    application_safe_point_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effect_certainty_before: Mapped[str] = mapped_column(String(30), default="NO_EFFECT")
    effect_certainty_after: Mapped[str] = mapped_column(String(30), default="NO_EFFECT")
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejection_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    legacy_command_id: Mapped[str | None] = mapped_column(
        ForeignKey("commands.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OperatorPrompt(Base):
    __tablename__ = "operator_prompts"
    __table_args__ = (
        CheckConstraint("state IN ('CREATED','OPEN','SETTLED')", name="ck_operator_prompt_state"),
        CheckConstraint("revision > 0", name="ck_operator_prompt_revision"),
        CheckConstraint("attempt_count >= 0", name="ck_operator_prompt_attempt_count"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    legacy_prompt_id: Mapped[str | None] = mapped_column(
        ForeignKey("prompts.id"), unique=True, nullable=True
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="CREATED", nullable=False)
    prompt_type: Mapped[str] = mapped_column(String(30), nullable=False)
    input_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    list_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    options: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    option_revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    default_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    settings_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    warning_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    no_controller_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    warning_emitted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    settlement_id: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    settlement_outcome: Mapped[str | None] = mapped_column(String(40), nullable=True)
    settled_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    settled_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    settlement_delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    settlement_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PromptAttempt(Base):
    __tablename__ = "operator_prompt_attempts"
    __table_args__ = (
        UniqueConstraint("prompt_id", "actor", "idempotency_key", name="uq_prompt_attempt"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    prompt_id: Mapped[str] = mapped_column(ForeignKey("operator_prompts.id"), index=True)
    prompt_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    value_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    settlement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    controller_lease_id: Mapped[str | None] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=True
    )
    accepted_lease_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    control_fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class InspectionEditOperation(Base):
    __tablename__ = "inspection_edit_operations"
    __table_args__ = (
        UniqueConstraint(
            "execution_id", "idempotency_key", name="uq_inspection_edit_request"
        ),
        CheckConstraint(
            "state IN ('PENDING_SAFE_POINT','APPLYING','APPLIED','REJECTED','CANCELLED')",
            name="ck_inspection_edit_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    path: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[str] = mapped_column(String(40), nullable=False)
    declared_type: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    old_value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    new_value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_value_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_execution_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    authoritative_variables: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    controller_lease_id: Mapped[str] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=False
    )
    accepted_lease_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    control_fencing_token: Mapped[int] = mapped_column(Integer, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_delivery_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    application_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    application_safe_point_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_execution_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rejection_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OperatorBreakpoint(Base):
    __tablename__ = "operator_breakpoints"
    __table_args__ = (
        Index(
            "uq_operator_breakpoint_unbound",
            "execution_id",
            "source_digest",
            "line_id",
            unique=True,
            sqlite_where=text("bound_command_id IS NULL"),
            postgresql_where=text("bound_command_id IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    line_id: Mapped[str] = mapped_column(String(128), nullable=False)
    bound_command_id: Mapped[str | None] = mapped_column(
        ForeignKey("operator_commands.id"), unique=True, nullable=True
    )
    one_shot: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class OperatorUserAction(Base):
    __tablename__ = "operator_user_actions"
    __table_args__ = (
        UniqueConstraint("execution_id", "name", "revision", name="uq_operator_user_action"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    handler_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class OperatorUserActionInvocation(Base):
    __tablename__ = "operator_user_action_invocations"
    __table_args__ = (
        UniqueConstraint("action_id", "idempotency_key", name="uq_user_action_invocation"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    action_id: Mapped[str] = mapped_column(ForeignKey("operator_user_actions.id"), index=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    action_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_execution_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_lease_id: Mapped[str] = mapped_column(
        ForeignKey("controller_leases.id"), nullable=False
    )
    accepted_lease_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_fencing_token: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    pinned_handler: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    handler_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_delivery_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    rejection_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    application_safe_point_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProcedureSchedule(Base):
    __tablename__ = "procedure_schedules"
    __table_args__ = (
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

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    controller_execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    original_target: Mapped[str] = mapped_column(String(200), nullable=False)
    original_offset: Mapped[str | None] = mapped_column(String(10), nullable=True)
    original_duration_seconds: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    catalog_revision_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_revisions.id"), index=True
    )
    procedure_catalog_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_entries.id"), index=True
    )
    procedure_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_id: Mapped[str] = mapped_column(ForeignKey("operator_contexts.id"), index=True)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    arguments_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    automatic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    background_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    visible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    misfire_policy: Mapped[str] = mapped_column(String(20), default="FIRE_ONCE")
    maximum_lateness_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    occurrence_id: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    fired_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.id"), unique=True, nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScheduleOccurrence(Base):
    __tablename__ = "schedule_occurrences"
    __table_args__ = (
        UniqueConstraint("schedule_id", "target_at", name="uq_schedule_occurrence_target"),
        CheckConstraint(
            "state IN ('CLAIMED','FIRED','MISSED','ERROR')",
            name="ck_schedule_occurrence_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(ForeignKey("procedure_schedules.id"), index=True)
    target_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    execution_id: Mapped[str | None] = mapped_column(ForeignKey("executions.id"), nullable=True)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class StartProcOperation(Base):
    __tablename__ = "startproc_operations"
    __table_args__ = (
        UniqueConstraint("parent_execution_id", "idempotency_key", name="uq_startproc_request"),
        CheckConstraint(
            "state IN ('REQUESTED','VALIDATING','ADMITTING','CHILD_CREATED','WAITING_CHILD','SETTLED','REJECTED','CANCELLED','RECONCILING')",
            name="ck_startproc_state",
        ),
        CheckConstraint("depth >= 1 AND depth <= 8", name="ck_startproc_depth"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parent_execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    expected_parent_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_catalog_revision_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_revisions.id"), nullable=False
    )
    child_procedure_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    resolved_child_catalog_revision_id: Mapped[str | None] = mapped_column(
        ForeignKey("procedure_catalog_revisions.id"), nullable=True
    )
    library_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bundle_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dependency_closure: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    arguments_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    blocking: Mapped[bool] = mapped_column(Boolean, nullable=False)
    visible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    automatic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    saved_successor: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    child_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.id"), unique=True, nullable=True
    )
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    rejection_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    effect_certainty: Mapped[str] = mapped_column(String(30), default="NO_EFFECT")
    result_delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    result_applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    result_applied_parent_revision: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    result_applied_parent_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ParentChildLink(Base):
    __tablename__ = "parent_child_links"
    __table_args__ = (
        UniqueConstraint("startproc_id", name="uq_parent_child_startproc"),
        UniqueConstraint("parent_execution_id", "child_execution_id", name="uq_parent_child_pair"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    startproc_id: Mapped[str] = mapped_column(ForeignKey("startproc_operations.id"))
    parent_execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    child_execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    child_catalog_revision_id: Mapped[str] = mapped_column(
        ForeignKey("procedure_catalog_revisions.id"), nullable=False
    )
    arguments_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    blocking: Mapped[bool] = mapped_column(Boolean, nullable=False)
    visible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    automatic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


__all__ = [
    "COMMAND_STATES",
    "LEASE_STATES",
    "OWNERSHIP_MODES",
    "PROMPT_STATES",
    "SCHEDULE_STATES",
    "STARTPROC_STATES",
    "ControllerLease",
    "ControllerHandover",
    "ExecutionOperatorState",
    "InspectionEditOperation",
    "MonitorSubscription",
    "OperatorAuditEvent",
    "OperatorBreakpoint",
    "OperatorCommand",
    "OperatorContext",
    "OperatorPrompt",
    "OperatorRequest",
    "OperatorUserAction",
    "OperatorUserActionInvocation",
    "ParentChildLink",
    "ProcedureCatalogEntry",
    "ProcedureCatalogRevision",
    "ProcedureSchedule",
    "PromptAttempt",
    "ScheduleOccurrence",
    "StartProcOperation",
]
