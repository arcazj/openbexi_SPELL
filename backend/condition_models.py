"""Durable v0.7 condition, WaitFor, and telemetry-schedule projections."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


VERIFY_STATES = (
    "CREATED",
    "DELAYED",
    "RETRY_WAIT",
    "TRUE",
    "FALSE",
    "INDETERMINATE",
    "TIMED_OUT",
    "CANCELLED",
    "REJECTED",
    "FAILED",
)
VERIFY_TERMINAL_STATES = frozenset(
    {"TRUE", "FALSE", "INDETERMINATE", "TIMED_OUT", "CANCELLED", "REJECTED", "FAILED"}
)
WAIT_STATES = (
    "CREATED",
    "WAITING",
    "INTERRUPTED",
    "SATISFIED",
    "TIMED_OUT",
    "CANCELLED",
    "FAILED",
)
WAIT_TERMINAL_STATES = frozenset({"SATISFIED", "TIMED_OUT", "CANCELLED", "FAILED"})
SCHEDULE_STATES = ("PENDING", "CLAIMED", "FIRED", "CANCELLED", "MISSED", "ERROR")
SCHEDULE_TERMINAL_STATES = frozenset({"FIRED", "CANCELLED", "MISSED", "ERROR"})


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class ConditionPlanRecord(Base):
    __tablename__ = "condition_plans"
    __table_args__ = (
        CheckConstraint("length(plan_digest) = 64", name="ck_condition_plan_digest"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    canonical_plan: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ConditionEvaluationRecord(Base):
    __tablename__ = "condition_evaluations"
    __table_args__ = (
        UniqueConstraint(
            "operation_kind",
            "operation_id",
            "attempt_number",
            name="uq_condition_evaluation_attempt",
        ),
        CheckConstraint("attempt_number > 0", name="ck_condition_evaluation_attempt"),
        CheckConstraint("snapshot_cursor >= 0", name="ck_condition_evaluation_cursor"),
        CheckConstraint("length(plan_digest) = 64", name="ck_condition_evaluation_plan_digest"),
        CheckConstraint("length(result_digest) = 64", name="ck_condition_evaluation_result_digest"),
        CheckConstraint(
            "composite_result IN ('TRUE','FALSE','INDETERMINATE','REJECTED')",
            name="ck_condition_evaluation_result",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan_id: Mapped[str] = mapped_column(
        ForeignKey("condition_plans.id"), nullable=False, index=True
    )
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_revision: Mapped[str] = mapped_column(String(128), nullable=False)
    operation_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    operation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    composite_result: Mapped[str] = mapped_column(String(30), nullable=False)
    leaf_results: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    consumed_sample_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(160), nullable=False)
    result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ConditionEvaluationSample(Base):
    __tablename__ = "condition_evaluation_samples"
    __table_args__ = (
        UniqueConstraint("evaluation_id", "sample_id", name="uq_condition_evaluation_sample"),
        CheckConstraint("ordinal >= 0", name="ck_condition_evaluation_sample_ordinal"),
        CheckConstraint("length(sample_id) = 64", name="ck_condition_evaluation_sample_digest"),
    )

    evaluation_id: Mapped[str] = mapped_column(
        ForeignKey("condition_evaluations.id"), primary_key=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[str] = mapped_column(String(64), nullable=False)


class VerifyOperation(Base):
    __tablename__ = "verify_operations"
    __table_args__ = (
        UniqueConstraint("request_scope", "idempotency_key", name="uq_verify_request"),
        CheckConstraint(f"state IN ({_quoted(VERIFY_STATES)})", name="ck_verify_state"),
        CheckConstraint("revision >= 0", name="ck_verify_revision"),
        CheckConstraint("attempt_count >= 0", name="ck_verify_attempt_count"),
        CheckConstraint("retry_count >= 0", name="ck_verify_retry_count"),
        CheckConstraint("delay_ns >= 0", name="ck_verify_delay"),
        CheckConstraint("timeout_ns >= 0", name="ck_verify_timeout"),
        CheckConstraint("retry_interval_ns >= 0", name="ck_verify_retry_interval"),
        CheckConstraint("deadline_monotonic_ns >= 0", name="ck_verify_deadline_monotonic"),
        CheckConstraint(
            "clock_anchor_monotonic_ns >= 0", name="ck_verify_clock_anchor_monotonic"
        ),
        CheckConstraint(
            "length(monotonic_epoch) BETWEEN 1 AND 128", name="ck_verify_monotonic_epoch"
        ),
        CheckConstraint("start_snapshot_cursor >= 0", name="ck_verify_start_cursor"),
        CheckConstraint("length(request_digest) = 64", name="ck_verify_request_digest"),
        CheckConstraint("length(plan_digest) = 64", name="ck_verify_plan_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_id: Mapped[str] = mapped_column(ForeignKey("condition_plans.id"), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_revision: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    delay_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    timeout_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_interval_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    start_snapshot_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_snapshot_cursor: Mapped[int | None] = mapped_column(BigInteger)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    monotonic_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    last_evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("condition_evaluations.id")
    )
    final_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    failure_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WaitForOperation(Base):
    __tablename__ = "waitfor_operations"
    __table_args__ = (
        UniqueConstraint(
            "execution_id", "statement_id", "idempotency_key", name="uq_waitfor_request"
        ),
        CheckConstraint(f"state IN ({_quoted(WAIT_STATES)})", name="ck_waitfor_state"),
        CheckConstraint(
            "wait_type IN ('RELATIVE','ABSOLUTE','TELEMETRY_CONDITION')",
            name="ck_waitfor_type",
        ),
        CheckConstraint("revision >= 0", name="ck_waitfor_revision"),
        CheckConstraint("attempt_count >= 0", name="ck_waitfor_attempt_count"),
        CheckConstraint("retry_count >= 0", name="ck_waitfor_retry_count"),
        CheckConstraint("retry_interval_ns >= 0", name="ck_waitfor_retry_interval"),
        CheckConstraint("deadline_monotonic_ns >= 0", name="ck_waitfor_deadline_monotonic"),
        CheckConstraint(
            "clock_anchor_monotonic_ns >= 0", name="ck_waitfor_clock_anchor_monotonic"
        ),
        CheckConstraint(
            "length(monotonic_epoch) BETWEEN 1 AND 128", name="ck_waitfor_monotonic_epoch"
        ),
        CheckConstraint("start_snapshot_cursor >= 0", name="ck_waitfor_start_cursor"),
        CheckConstraint("length(request_digest) = 64", name="ck_waitfor_request_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    statement_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    wait_type: Mapped[str] = mapped_column(String(30), nullable=False)
    original_target: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    canonical_target: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    plan_id: Mapped[str | None] = mapped_column(ForeignKey("condition_plans.id"))
    plan_digest: Mapped[str | None] = mapped_column(String(64))
    policy_id: Mapped[str | None] = mapped_column(String(128))
    policy_revision: Mapped[str | None] = mapped_column(String(128))
    start_snapshot_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_snapshot_cursor: Mapped[int | None] = mapped_column(BigInteger)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_interval_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    deadline_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    monotonic_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    last_evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("condition_evaluations.id")
    )
    terminal_evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("condition_evaluations.id")
    )
    terminal_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    failure_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TelemetryConditionSchedule(Base):
    __tablename__ = "telemetry_condition_schedules"
    __table_args__ = (
        UniqueConstraint("created_by", "idempotency_key", name="uq_telemetry_schedule_request"),
        CheckConstraint(f"state IN ({_quoted(SCHEDULE_STATES)})", name="ck_telemetry_schedule_state"),
        CheckConstraint("revision >= 0", name="ck_telemetry_schedule_revision"),
        CheckConstraint("attempt_count >= 0", name="ck_telemetry_schedule_attempt_count"),
        CheckConstraint("retry_count >= 0", name="ck_telemetry_schedule_retry_count"),
        CheckConstraint("retry_interval_ns >= 0", name="ck_telemetry_schedule_retry_interval"),
        CheckConstraint(
            "deadline_monotonic_ns >= 0", name="ck_telemetry_schedule_deadline_monotonic"
        ),
        CheckConstraint(
            "clock_anchor_monotonic_ns >= 0",
            name="ck_telemetry_schedule_clock_anchor_monotonic",
        ),
        CheckConstraint(
            "length(monotonic_epoch) BETWEEN 1 AND 128",
            name="ck_telemetry_schedule_monotonic_epoch",
        ),
        CheckConstraint("start_snapshot_cursor >= 0", name="ck_telemetry_schedule_start_cursor"),
        CheckConstraint("procedure_revision > 0", name="ck_telemetry_schedule_procedure_revision"),
        CheckConstraint("length(bundle_digest) = 64", name="ck_telemetry_schedule_bundle_digest"),
        CheckConstraint("length(arguments_digest) = 64", name="ck_telemetry_schedule_arguments_digest"),
        CheckConstraint("length(request_digest) = 64", name="ck_telemetry_schedule_request_digest"),
        CheckConstraint("length(plan_digest) = 64", name="ck_telemetry_schedule_plan_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(ForeignKey("condition_plans.id"), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_revision: Mapped[str] = mapped_column(String(128), nullable=False)
    start_snapshot_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_snapshot_cursor: Mapped[int | None] = mapped_column(BigInteger)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_interval_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    deadline_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_monotonic_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    clock_anchor_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    monotonic_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    controller_execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.id"), nullable=False, index=True
    )
    procedure_catalog_id: Mapped[str] = mapped_column(String(128), nullable=False)
    procedure_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_id: Mapped[str] = mapped_column(String(128), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    arguments_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    automatic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    background_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    visible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("condition_evaluations.id")
    )
    winning_evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("condition_evaluations.id")
    )
    occurrence_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    fired_execution_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TelemetryScheduleOccurrence(Base):
    __tablename__ = "telemetry_schedule_occurrences"
    __table_args__ = (
        UniqueConstraint("schedule_id", name="uq_telemetry_schedule_occurrence_schedule"),
        UniqueConstraint(
            "schedule_id", "condition_result_digest", name="uq_telemetry_schedule_occurrence_result"
        ),
        CheckConstraint(
            "state IN ('CLAIMED','FIRED','ERROR')", name="ck_telemetry_schedule_occurrence_state"
        ),
        CheckConstraint(
            "length(condition_result_digest) = 64",
            name="ck_telemetry_schedule_occurrence_result_digest",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_condition_schedules.id"), nullable=False, index=True
    )
    evaluation_id: Mapped[str] = mapped_column(
        ForeignKey("condition_evaluations.id"), nullable=False
    )
    condition_result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    execution_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("ix_verify_operations_state_due", VerifyOperation.state, VerifyOperation.next_attempt_at)
Index("ix_waitfor_operations_state_due", WaitForOperation.state, WaitForOperation.next_attempt_at)
Index(
    "ix_telemetry_condition_schedules_state_due",
    TelemetryConditionSchedule.state,
    TelemetryConditionSchedule.next_attempt_at,
)


__all__ = [
    "ConditionEvaluationRecord",
    "ConditionEvaluationSample",
    "ConditionPlanRecord",
    "SCHEDULE_STATES",
    "SCHEDULE_TERMINAL_STATES",
    "TelemetryConditionSchedule",
    "TelemetryScheduleOccurrence",
    "VERIFY_STATES",
    "VERIFY_TERMINAL_STATES",
    "VerifyOperation",
    "WAIT_STATES",
    "WAIT_TERMINAL_STATES",
    "WaitForOperation",
]
