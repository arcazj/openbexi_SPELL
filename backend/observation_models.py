from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

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

from .database import Base, utc_now
from .database_types import UInt64Decimal
from .models import new_id


VALIDITIES = ("VALID", "INVALID", "UNKNOWN")
QUALITIES = ("GOOD", "SUSPECT", "BAD", "UNKNOWN")
FRESHNESS_STATES = ("FRESH", "STALE", "UNKNOWN")
SYNCHRONIZATION_STATES = ("COMPLETE", "GAPPED", "NO_SAMPLE")
ALARM_STATES = (
    "NOT_ALARMED",
    "WARNING_LOW",
    "WARNING_HIGH",
    "CRITICAL_LOW",
    "CRITICAL_HIGH",
    "INDETERMINATE",
)
ALARM_SEVERITIES = ("NONE", "WARNING", "CRITICAL", "INDETERMINATE")


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class ObservationStream(Base):
    __tablename__ = "observation_streams"
    __table_args__ = (
        UniqueConstraint(
            "authorization_scope",
            "context_generation_id",
            name="uq_observation_stream_scope_context",
        ),
        UniqueConstraint("stream_epoch", name="uq_observation_stream_epoch"),
        CheckConstraint("last_sequence >= 0", name="ck_observation_stream_sequence"),
        CheckConstraint("revision >= 0", name="ck_observation_stream_revision"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    authorization_scope: Mapped[str] = mapped_column(String(100), nullable=False)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False, index=True
    )
    stream_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class ObservationFreshnessPolicy(Base):
    __tablename__ = "observation_freshness_policies"
    __table_args__ = (
        UniqueConstraint("policy_id", "revision", name="uq_observation_policy_revision"),
        CheckConstraint("length(definition_digest) = 64", name="ck_observation_policy_digest"),
        CheckConstraint("max_age_ns >= 0", name="ck_observation_policy_max_age"),
        CheckConstraint(
            "max_clock_uncertainty_ns >= 0",
            name="ck_observation_policy_uncertainty",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revision: Mapped[str] = mapped_column(String(80), nullable=False)
    definition_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    max_age_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_clock_uncertainty_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    accepted_qualities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    required_validity: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriverTimeObservation(Base):
    __tablename__ = "driver_time_observations"
    __table_args__ = (
        CheckConstraint("length(payload_digest) = 64", name="ck_driver_time_payload_digest"),
        CheckConstraint(
            "length(uncertainty_ns) = 20 AND "
            "uncertainty_ns >= '00000000000000000000' AND "
            "uncertainty_ns <= '18446744073709551615'",
            name="ck_driver_time_uncertainty",
        ),
        CheckConstraint(
            f"quality IN ({_quoted(QUALITIES)})", name="ck_driver_time_quality"
        ),
        CheckConstraint(
            f"validity IN ({_quoted(VALIDITIES)})", name="ck_driver_time_validity"
        ),
        Index("ix_driver_time_host_received", "host_generation_id", "received_at_unix_ns"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False
    )
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    time_unix_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    acquired_at_unix_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_at_unix_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    clock_source: Mapped[str] = mapped_column(String(40), nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    uncertainty_ns: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    quality: Mapped[str] = mapped_column(String(20), nullable=False)
    validity: Mapped[str] = mapped_column(String(20), nullable=False)


class DriverTimeHead(Base):
    __tablename__ = "driver_time_heads"
    __table_args__ = (
        CheckConstraint("revision >= 0", name="ck_driver_time_head_revision"),
    )

    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), primary_key=True
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_time_observations.id"), nullable=False, unique=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TelemetrySample(Base):
    __tablename__ = "telemetry_samples"
    __table_args__ = (
        UniqueConstraint(
            "context_generation_id",
            "source_id",
            "source_epoch",
            "item_id",
            "source_sequence",
            name="uq_telemetry_sample_source_identity",
        ),
        CheckConstraint("length(id) = 64", name="ck_telemetry_sample_id"),
        CheckConstraint("length(catalog_digest) = 64", name="ck_telemetry_sample_catalog_digest"),
        CheckConstraint("length(payload_digest) = 64", name="ck_telemetry_sample_payload_digest"),
        CheckConstraint(
            "length(source_sequence) = 20 AND "
            "source_sequence >= '00000000000000000001' AND "
            "source_sequence <= '18446744073709551615'",
            name="ck_telemetry_sample_sequence",
        ),
        CheckConstraint(
            "length(clock_uncertainty_ns) = 20 AND "
            "clock_uncertainty_ns >= '00000000000000000000' AND "
            "clock_uncertainty_ns <= '18446744073709551615'",
            name="ck_telemetry_sample_uncertainty",
        ),
        CheckConstraint(
            f"validity IN ({_quoted(VALIDITIES)})", name="ck_telemetry_sample_validity"
        ),
        CheckConstraint(
            f"quality IN ({_quoted(QUALITIES)})", name="ck_telemetry_sample_quality"
        ),
        CheckConstraint(
            f"freshness IN ({_quoted(FRESHNESS_STATES)})",
            name="ck_telemetry_sample_freshness",
        ),
        Index("ix_telemetry_sample_context_item_received", "context_generation_id", "item_id", "received_at_unix_ns"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    observation_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    host_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_host_generations.id"), nullable=False
    )
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False
    )
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    qualified_name: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    source_sequence: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    raw_value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    engineering_value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    unit: Mapped[str] = mapped_column(String(128), nullable=False)
    acquired_at_unix_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_at_unix_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    clock_provenance: Mapped[str] = mapped_column(Text, nullable=False)
    clock_uncertainty_ns: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    validity: Mapped[str] = mapped_column(String(20), nullable=False)
    quality: Mapped[str] = mapped_column(String(20), nullable=False)
    quality_reason: Mapped[str] = mapped_column(Text, nullable=False)
    freshness: Mapped[str] = mapped_column(String(20), nullable=False)
    freshness_policy_id: Mapped[str] = mapped_column(
        ForeignKey("observation_freshness_policies.id"), nullable=False
    )
    freshness_policy_revision: Mapped[str] = mapped_column(String(80), nullable=False)
    fresh_until_unix_ns: Mapped[Optional[int]] = mapped_column(BigInteger)


class TelemetryItemHead(Base):
    __tablename__ = "telemetry_item_heads"
    __table_args__ = (
        UniqueConstraint(
            "context_generation_id", "item_id", name="uq_telemetry_item_head"
        ),
        CheckConstraint(
            "length(source_sequence) = 20 AND "
            "source_sequence >= '00000000000000000001' AND "
            "source_sequence <= '18446744073709551615'",
            name="ck_telemetry_head_sequence",
        ),
        CheckConstraint("revision >= 0", name="ck_telemetry_head_revision"),
        CheckConstraint(
            f"freshness IN ({_quoted(FRESHNESS_STATES)})",
            name="ck_telemetry_head_freshness",
        ),
        CheckConstraint(
            f"synchronization_state IN ({_quoted(SYNCHRONIZATION_STATES)})",
            name="ck_telemetry_head_sync",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False, index=True
    )
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sample_id: Mapped[str] = mapped_column(ForeignKey("telemetry_samples.id"), nullable=False)
    catalog_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    source_sequence: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    freshness: Mapped[str] = mapped_column(String(20), nullable=False)
    synchronization_state: Mapped[str] = mapped_column(String(20), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TelemetrySourceCursor(Base):
    __tablename__ = "telemetry_source_cursors"
    __table_args__ = (
        UniqueConstraint(
            "context_generation_id",
            "source_id",
            "item_id",
            name="uq_telemetry_source_cursor",
        ),
        CheckConstraint(
            "length(source_sequence) = 20 AND "
            "source_sequence >= '00000000000000000001' AND "
            "source_sequence <= '18446744073709551615'",
            name="ck_telemetry_cursor_sequence",
        ),
        CheckConstraint("revision >= 0", name="ck_telemetry_cursor_revision"),
        CheckConstraint(
            f"synchronization_state IN ({_quoted(SYNCHRONIZATION_STATES)})",
            name="ck_telemetry_cursor_sync",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False, index=True
    )
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    source_sequence: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    sample_id: Mapped[str] = mapped_column(ForeignKey("telemetry_samples.id"), nullable=False)
    synchronization_state: Mapped[str] = mapped_column(String(20), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TelemetryGap(Base):
    __tablename__ = "telemetry_gaps"
    __table_args__ = (
        UniqueConstraint(
            "context_generation_id",
            "source_id",
            "item_id",
            "source_epoch",
            "expected_sequence",
            "observed_sequence",
            name="uq_telemetry_gap_bounds",
        ),
        CheckConstraint(
            "length(expected_sequence) = 20 AND "
            "expected_sequence >= '00000000000000000001' AND "
            "expected_sequence <= '18446744073709551615'",
            name="ck_telemetry_gap_expected",
        ),
        CheckConstraint(
            "length(observed_sequence) = 20 AND "
            "observed_sequence >= expected_sequence AND "
            "observed_sequence <= '18446744073709551615'",
            name="ck_telemetry_gap_observed",
        ),
        CheckConstraint("state IN ('OPEN', 'RESOLVED')", name="ck_telemetry_gap_state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False, index=True
    )
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_sequence: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    observed_sequence: Mapped[int] = mapped_column(UInt64Decimal(), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    resolution_sample_id: Mapped[Optional[str]] = mapped_column(ForeignKey("telemetry_samples.id"))


class TelemetryLimitSet(Base):
    __tablename__ = "telemetry_limit_sets"
    __table_args__ = (
        UniqueConstraint("limit_set_id", "limit_revision", name="uq_telemetry_limit_revision"),
        UniqueConstraint(
            "item_id", "catalog_digest", "limit_revision", name="uq_telemetry_item_limit_revision"
        ),
        CheckConstraint("length(catalog_digest) = 64", name="ck_telemetry_limit_catalog_digest"),
        CheckConstraint("length(definition_digest) = 64", name="ck_telemetry_limit_definition_digest"),
        CheckConstraint("value_domain IN ('RAW', 'ENGINEERING')", name="ck_telemetry_limit_domain"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    limit_set_id: Mapped[str] = mapped_column(String(128), nullable=False)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    catalog_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    limit_revision: Mapped[str] = mapped_column(String(80), nullable=False)
    value_domain: Mapped[str] = mapped_column(String(20), nullable=False)
    unit: Mapped[str] = mapped_column(String(128), nullable=False)
    bands: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    definition_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TelemetryLimitHead(Base):
    __tablename__ = "telemetry_limit_heads"
    __table_args__ = (
        UniqueConstraint("item_id", "catalog_digest", name="uq_telemetry_limit_head"),
        CheckConstraint("revision >= 0", name="ck_telemetry_limit_head_revision"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    limit_definition_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_limit_sets.id"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TelemetryAlarmObservation(Base):
    __tablename__ = "telemetry_alarm_observations"
    __table_args__ = (
        CheckConstraint(f"state IN ({_quoted(ALARM_STATES)})", name="ck_telemetry_alarm_state"),
        CheckConstraint(
            f"severity IN ({_quoted(ALARM_SEVERITIES)})", name="ck_telemetry_alarm_severity"
        ),
        CheckConstraint("length(payload_digest) = 64", name="ck_telemetry_alarm_payload_digest"),
        CheckConstraint("projection_sequence >= 0", name="ck_telemetry_alarm_projection_sequence"),
        Index("ix_telemetry_alarm_context_item_evaluated", "context_generation_id", "item_id", "evaluated_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False
    )
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sample_id: Mapped[Optional[str]] = mapped_column(ForeignKey("telemetry_samples.id"))
    limit_definition_id: Mapped[Optional[str]] = mapped_column(ForeignKey("telemetry_limit_sets.id"))
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evaluated_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON)
    quality: Mapped[str] = mapped_column(String(20), nullable=False)
    validity: Mapped[str] = mapped_column(String(20), nullable=False)
    freshness: Mapped[str] = mapped_column(String(20), nullable=False)
    boolean_value: Mapped[Optional[bool]] = mapped_column(Boolean)
    stream_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    projection_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)


class TelemetryAlarmHead(Base):
    __tablename__ = "telemetry_alarm_heads"
    __table_args__ = (
        UniqueConstraint(
            "context_generation_id", "item_id", name="uq_telemetry_alarm_head"
        ),
        CheckConstraint("revision >= 0", name="ck_telemetry_alarm_head_revision"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    context_generation_id: Mapped[str] = mapped_column(
        ForeignKey("driver_context_generations.id"), nullable=False, index=True
    )
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    alarm_observation_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_alarm_observations.id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    sample_id: Mapped[Optional[str]] = mapped_column(String(64))
    limit_definition_id: Mapped[Optional[str]] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ObservationOutboxEvent(Base):
    __tablename__ = "observation_outbox"
    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "stream_epoch",
            "projection_sequence",
            name="uq_observation_outbox_cursor",
        ),
        CheckConstraint("projection_sequence > 0", name="ck_observation_outbox_sequence"),
        CheckConstraint("delivery_attempts >= 0", name="ck_observation_outbox_delivery_attempts"),
        Index("ix_observation_outbox_pending", "published_at", "created_at"),
        Index("ix_observation_outbox_replay", "stream_id", "stream_epoch", "projection_sequence"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=new_id)
    stream_id: Mapped[str] = mapped_column(ForeignKey("observation_streams.id"), nullable=False)
    stream_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    projection_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(60), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


__all__ = [
    "ALARM_SEVERITIES",
    "ALARM_STATES",
    "DriverTimeHead",
    "DriverTimeObservation",
    "FRESHNESS_STATES",
    "ObservationFreshnessPolicy",
    "ObservationOutboxEvent",
    "ObservationStream",
    "QUALITIES",
    "SYNCHRONIZATION_STATES",
    "TelemetryAlarmHead",
    "TelemetryAlarmObservation",
    "TelemetryGap",
    "TelemetryItemHead",
    "TelemetryLimitHead",
    "TelemetryLimitSet",
    "TelemetrySample",
    "TelemetrySourceCursor",
    "VALIDITIES",
]
