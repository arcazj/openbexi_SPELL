from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
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

from backend.database_types import UInt64Decimal


VERSION = "0005_observation_projection"
metadata = MetaData()

# Existing tables resolve static foreign keys only. This migration never creates
# or changes the accepted v0.4 lifecycle tables.
driver_host_generations = Table(
    "driver_host_generations", metadata, Column("id", String(128), primary_key=True)
)
driver_context_generations = Table(
    "driver_context_generations", metadata, Column("id", String(128), primary_key=True)
)

observation_streams = Table(
    "observation_streams",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("authorization_scope", String(100), nullable=False),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("stream_epoch", String(128), nullable=False),
    Column("last_sequence", BigInteger, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "authorization_scope",
        "context_generation_id",
        name="uq_observation_stream_scope_context",
    ),
    UniqueConstraint("stream_epoch", name="uq_observation_stream_epoch"),
    CheckConstraint("last_sequence >= 0", name="ck_observation_stream_sequence"),
    CheckConstraint("revision >= 0", name="ck_observation_stream_revision"),
)
Index("ix_observation_streams_context_generation_id", observation_streams.c.context_generation_id)

observation_freshness_policies = Table(
    "observation_freshness_policies",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("policy_id", String(128), nullable=False),
    Column("revision", String(80), nullable=False),
    Column("definition_digest", String(64), nullable=False),
    Column("max_age_ns", BigInteger, nullable=False),
    Column("max_clock_uncertainty_ns", BigInteger, nullable=False),
    Column("accepted_qualities", JSON, nullable=False),
    Column("required_validity", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("policy_id", "revision", name="uq_observation_policy_revision"),
    CheckConstraint("length(definition_digest) = 64", name="ck_observation_policy_digest"),
    CheckConstraint("max_age_ns >= 0", name="ck_observation_policy_max_age"),
    CheckConstraint(
        "max_clock_uncertainty_ns >= 0", name="ck_observation_policy_uncertainty"
    ),
)

driver_time_observations = Table(
    "driver_time_observations",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        nullable=False,
    ),
    Column("payload_digest", String(64), nullable=False),
    Column("time_unix_ns", BigInteger, nullable=False),
    Column("acquired_at_unix_ns", BigInteger, nullable=False),
    Column("received_at_unix_ns", BigInteger, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("clock_source", String(40), nullable=False),
    Column("provenance", Text, nullable=False),
    Column("uncertainty_ns", UInt64Decimal(), nullable=False),
    Column("quality", String(20), nullable=False),
    Column("validity", String(20), nullable=False),
    CheckConstraint("length(payload_digest) = 64", name="ck_driver_time_payload_digest"),
    CheckConstraint(
        "length(uncertainty_ns) = 20 AND "
        "uncertainty_ns >= '00000000000000000000' AND "
        "uncertainty_ns <= '18446744073709551615'",
        name="ck_driver_time_uncertainty",
    ),
    CheckConstraint(
        "quality IN ('GOOD', 'SUSPECT', 'BAD', 'UNKNOWN')",
        name="ck_driver_time_quality",
    ),
    CheckConstraint(
        "validity IN ('VALID', 'INVALID', 'UNKNOWN')",
        name="ck_driver_time_validity",
    ),
)
Index(
    "ix_driver_time_host_received",
    driver_time_observations.c.host_generation_id,
    driver_time_observations.c.received_at_unix_ns,
)

driver_time_heads = Table(
    "driver_time_heads",
    metadata,
    Column(
        "host_generation_id",
        String(128),
        ForeignKey("driver_host_generations.id"),
        primary_key=True,
    ),
    Column(
        "observation_id",
        String(128),
        ForeignKey("driver_time_observations.id"),
        nullable=False,
        unique=True,
    ),
    Column("revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("revision >= 0", name="ck_driver_time_head_revision"),
)

telemetry_samples = Table(
    "telemetry_samples",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("observation_id", String(128), nullable=False, unique=True),
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
        nullable=False,
    ),
    Column("payload_digest", String(64), nullable=False),
    Column("item_id", String(128), nullable=False),
    Column("qualified_name", String(128), nullable=False),
    Column("catalog_digest", String(64), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("source_epoch", String(128), nullable=False),
    Column("source_sequence", UInt64Decimal(), nullable=False),
    Column("raw_value", JSON, nullable=False),
    Column("engineering_value", JSON, nullable=False),
    Column("description", Text, nullable=False),
    Column("unit", String(128), nullable=False),
    Column("acquired_at_unix_ns", BigInteger, nullable=False),
    Column("received_at_unix_ns", BigInteger, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("source", String(128), nullable=False),
    Column("clock_provenance", Text, nullable=False),
    Column("clock_uncertainty_ns", UInt64Decimal(), nullable=False),
    Column("validity", String(20), nullable=False),
    Column("quality", String(20), nullable=False),
    Column("quality_reason", Text, nullable=False),
    Column("freshness", String(20), nullable=False),
    Column(
        "freshness_policy_id",
        String(128),
        ForeignKey("observation_freshness_policies.id"),
        nullable=False,
    ),
    Column("freshness_policy_revision", String(80), nullable=False),
    Column("fresh_until_unix_ns", BigInteger),
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
        "validity IN ('VALID', 'INVALID', 'UNKNOWN')",
        name="ck_telemetry_sample_validity",
    ),
    CheckConstraint(
        "quality IN ('GOOD', 'SUSPECT', 'BAD', 'UNKNOWN')",
        name="ck_telemetry_sample_quality",
    ),
    CheckConstraint(
        "freshness IN ('FRESH', 'STALE', 'UNKNOWN')",
        name="ck_telemetry_sample_freshness",
    ),
)
Index(
    "ix_telemetry_sample_context_item_received",
    telemetry_samples.c.context_generation_id,
    telemetry_samples.c.item_id,
    telemetry_samples.c.received_at_unix_ns,
)

telemetry_item_heads = Table(
    "telemetry_item_heads",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("item_id", String(128), nullable=False),
    Column("sample_id", String(64), ForeignKey("telemetry_samples.id"), nullable=False),
    Column("catalog_digest", String(64), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("source_epoch", String(128), nullable=False),
    Column("source_sequence", UInt64Decimal(), nullable=False),
    Column("freshness", String(20), nullable=False),
    Column("synchronization_state", String(20), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("context_generation_id", "item_id", name="uq_telemetry_item_head"),
    CheckConstraint(
        "length(source_sequence) = 20 AND "
        "source_sequence >= '00000000000000000001' AND "
        "source_sequence <= '18446744073709551615'",
        name="ck_telemetry_head_sequence",
    ),
    CheckConstraint("revision >= 0", name="ck_telemetry_head_revision"),
    CheckConstraint(
        "freshness IN ('FRESH', 'STALE', 'UNKNOWN')",
        name="ck_telemetry_head_freshness",
    ),
    CheckConstraint(
        "synchronization_state IN ('COMPLETE', 'GAPPED', 'NO_SAMPLE')",
        name="ck_telemetry_head_sync",
    ),
)
Index("ix_telemetry_item_heads_context_generation_id", telemetry_item_heads.c.context_generation_id)

telemetry_source_cursors = Table(
    "telemetry_source_cursors",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("source_id", String(128), nullable=False),
    Column("item_id", String(128), nullable=False),
    Column("source_epoch", String(128), nullable=False),
    Column("source_sequence", UInt64Decimal(), nullable=False),
    Column("sample_id", String(64), ForeignKey("telemetry_samples.id"), nullable=False),
    Column("synchronization_state", String(20), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "context_generation_id", "source_id", "item_id", name="uq_telemetry_source_cursor"
    ),
    CheckConstraint(
        "length(source_sequence) = 20 AND "
        "source_sequence >= '00000000000000000001' AND "
        "source_sequence <= '18446744073709551615'",
        name="ck_telemetry_cursor_sequence",
    ),
    CheckConstraint("revision >= 0", name="ck_telemetry_cursor_revision"),
    CheckConstraint(
        "synchronization_state IN ('COMPLETE', 'GAPPED', 'NO_SAMPLE')",
        name="ck_telemetry_cursor_sync",
    ),
)
Index(
    "ix_telemetry_source_cursors_context_generation_id",
    telemetry_source_cursors.c.context_generation_id,
)

telemetry_gaps = Table(
    "telemetry_gaps",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("source_id", String(128), nullable=False),
    Column("item_id", String(128), nullable=False),
    Column("source_epoch", String(128), nullable=False),
    Column("expected_sequence", UInt64Decimal(), nullable=False),
    Column("observed_sequence", UInt64Decimal(), nullable=False),
    Column("state", String(20), nullable=False),
    Column("detected_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True)),
    Column("resolution_sample_id", String(64), ForeignKey("telemetry_samples.id")),
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
Index("ix_telemetry_gaps_context_generation_id", telemetry_gaps.c.context_generation_id)

telemetry_limit_sets = Table(
    "telemetry_limit_sets",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("limit_set_id", String(128), nullable=False),
    Column("item_id", String(128), nullable=False),
    Column("catalog_digest", String(64), nullable=False),
    Column("limit_revision", String(80), nullable=False),
    Column("value_domain", String(20), nullable=False),
    Column("unit", String(128), nullable=False),
    Column("bands", JSON, nullable=False),
    Column("definition_digest", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("limit_set_id", "limit_revision", name="uq_telemetry_limit_revision"),
    UniqueConstraint(
        "item_id",
        "catalog_digest",
        "limit_revision",
        name="uq_telemetry_item_limit_revision",
    ),
    CheckConstraint("length(catalog_digest) = 64", name="ck_telemetry_limit_catalog_digest"),
    CheckConstraint(
        "length(definition_digest) = 64", name="ck_telemetry_limit_definition_digest"
    ),
    CheckConstraint(
        "value_domain IN ('RAW', 'ENGINEERING')", name="ck_telemetry_limit_domain"
    ),
)
Index("ix_telemetry_limit_sets_item_id", telemetry_limit_sets.c.item_id)

telemetry_limit_heads = Table(
    "telemetry_limit_heads",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("item_id", String(128), nullable=False),
    Column("catalog_digest", String(64), nullable=False),
    Column(
        "limit_definition_id",
        String(128),
        ForeignKey("telemetry_limit_sets.id"),
        nullable=False,
    ),
    Column("revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("item_id", "catalog_digest", name="uq_telemetry_limit_head"),
    CheckConstraint("revision >= 0", name="ck_telemetry_limit_head_revision"),
)

telemetry_alarm_observations = Table(
    "telemetry_alarm_observations",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("item_id", String(128), nullable=False),
    Column("sample_id", String(64), ForeignKey("telemetry_samples.id")),
    Column("limit_definition_id", String(128), ForeignKey("telemetry_limit_sets.id")),
    Column("state", String(30), nullable=False),
    Column("severity", String(20), nullable=False),
    Column("evaluated_value", JSON),
    Column("quality", String(20), nullable=False),
    Column("validity", String(20), nullable=False),
    Column("freshness", String(20), nullable=False),
    Column("boolean_value", Boolean),
    Column("stream_epoch", String(128), nullable=False),
    Column("projection_sequence", BigInteger, nullable=False),
    Column("evaluated_at", DateTime(timezone=True), nullable=False),
    Column("reason", Text, nullable=False),
    Column("payload_digest", String(64), nullable=False),
    CheckConstraint(
        "state IN ('NOT_ALARMED', 'WARNING_LOW', 'WARNING_HIGH', "
        "'CRITICAL_LOW', 'CRITICAL_HIGH', 'INDETERMINATE')",
        name="ck_telemetry_alarm_state",
    ),
    CheckConstraint(
        "severity IN ('NONE', 'WARNING', 'CRITICAL', 'INDETERMINATE')",
        name="ck_telemetry_alarm_severity",
    ),
    CheckConstraint("length(payload_digest) = 64", name="ck_telemetry_alarm_payload_digest"),
    CheckConstraint(
        "projection_sequence >= 0", name="ck_telemetry_alarm_projection_sequence"
    ),
)
Index(
    "ix_telemetry_alarm_context_item_evaluated",
    telemetry_alarm_observations.c.context_generation_id,
    telemetry_alarm_observations.c.item_id,
    telemetry_alarm_observations.c.evaluated_at,
)

telemetry_alarm_heads = Table(
    "telemetry_alarm_heads",
    metadata,
    Column("id", String(128), primary_key=True),
    Column(
        "context_generation_id",
        String(128),
        ForeignKey("driver_context_generations.id"),
        nullable=False,
    ),
    Column("item_id", String(128), nullable=False),
    Column(
        "alarm_observation_id",
        String(128),
        ForeignKey("telemetry_alarm_observations.id"),
        nullable=False,
    ),
    Column("state", String(30), nullable=False),
    Column("sample_id", String(64)),
    Column("limit_definition_id", String(128)),
    Column("reason", Text, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("context_generation_id", "item_id", name="uq_telemetry_alarm_head"),
    CheckConstraint("revision >= 0", name="ck_telemetry_alarm_head_revision"),
)
Index(
    "ix_telemetry_alarm_heads_context_generation_id",
    telemetry_alarm_heads.c.context_generation_id,
)

observation_outbox = Table(
    "observation_outbox",
    metadata,
    Column("id", String(128), primary_key=True),
    Column("stream_id", String(128), ForeignKey("observation_streams.id"), nullable=False),
    Column("stream_epoch", String(128), nullable=False),
    Column("projection_sequence", BigInteger, nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("aggregate_type", String(60), nullable=False),
    Column("aggregate_id", String(128), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("delivery_attempts", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("published_at", DateTime(timezone=True)),
    UniqueConstraint(
        "stream_id",
        "stream_epoch",
        "projection_sequence",
        name="uq_observation_outbox_cursor",
    ),
    CheckConstraint("projection_sequence > 0", name="ck_observation_outbox_sequence"),
    CheckConstraint(
        "delivery_attempts >= 0", name="ck_observation_outbox_delivery_attempts"
    ),
)
Index("ix_observation_outbox_pending", observation_outbox.c.published_at, observation_outbox.c.created_at)
Index(
    "ix_observation_outbox_replay",
    observation_outbox.c.stream_id,
    observation_outbox.c.stream_epoch,
    observation_outbox.c.projection_sequence,
)


NEW_TABLES = (
    observation_streams,
    observation_freshness_policies,
    driver_time_observations,
    driver_time_heads,
    telemetry_samples,
    telemetry_item_heads,
    telemetry_source_cursors,
    telemetry_gaps,
    telemetry_limit_sets,
    telemetry_limit_heads,
    telemetry_alarm_observations,
    telemetry_alarm_heads,
    observation_outbox,
)

DEFAULT_POLICY_ID = "simulator-default:v07-r1"
DEFAULT_CATALOG_DIGEST = "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94"
DEFAULT_LIMIT_DEFINITION_ID = "LIMIT.TM.POWER.BUS_VOLTAGE:v07-r1"
DEFAULT_LIMIT_BANDS = {
    "HARD_LOW": {
        "enabled": True,
        "threshold": {"type": "FINITE_DOUBLE", "value": 22.0},
        "inclusive": False,
        "hysteresis": {"type": "FINITE_DOUBLE", "value": 0.0},
    },
    "SOFT_LOW": {
        "enabled": True,
        "threshold": {"type": "FINITE_DOUBLE", "value": 24.0},
        "inclusive": False,
        "hysteresis": {"type": "FINITE_DOUBLE", "value": 0.0},
    },
    "SOFT_HIGH": {
        "enabled": True,
        "threshold": {"type": "FINITE_DOUBLE", "value": 30.0},
        "inclusive": False,
        "hysteresis": {"type": "FINITE_DOUBLE", "value": 0.0},
    },
    "HARD_HIGH": {
        "enabled": True,
        "threshold": {"type": "FINITE_DOUBLE", "value": 32.0},
        "inclusive": False,
        "hysteresis": {"type": "FINITE_DOUBLE", "value": 0.0},
    },
}


def upgrade(connection: Connection) -> None:
    """Add the v0.7 read-only durable observation projection."""

    for table in NEW_TABLES:
        table.create(connection, checkfirst=True)

    now = datetime.now(timezone.utc)
    if connection.execute(
        observation_freshness_policies.select().where(
            observation_freshness_policies.c.id == DEFAULT_POLICY_ID
        )
    ).first() is None:
        connection.execute(
            observation_freshness_policies.insert().values(
                id=DEFAULT_POLICY_ID,
                policy_id="simulator-default",
                revision="v07-r1",
                definition_digest=(
                    "43799d5f5fd3e4f5744e4de5b302c10fe27d3601130ba14c0ee31bd62712702e"
                ),
                max_age_ns=5_000_000_000,
                max_clock_uncertainty_ns=1_000_000_000,
                accepted_qualities=["GOOD"],
                required_validity="VALID",
                created_at=now,
            )
        )

    if connection.execute(
        telemetry_limit_sets.select().where(
            telemetry_limit_sets.c.id == DEFAULT_LIMIT_DEFINITION_ID
        )
    ).first() is None:
        connection.execute(
            telemetry_limit_sets.insert().values(
                id=DEFAULT_LIMIT_DEFINITION_ID,
                limit_set_id="LIMIT.TM.POWER.BUS_VOLTAGE",
                item_id="TM.POWER.BUS_VOLTAGE",
                catalog_digest=DEFAULT_CATALOG_DIGEST,
                limit_revision="v07-r1",
                value_domain="ENGINEERING",
                unit="V",
                bands=DEFAULT_LIMIT_BANDS,
                definition_digest=(
                    "4812329aa1bb968cc35eab6e3604c528e85a29af425be69d991f92d7a06e617f"
                ),
                created_at=now,
            )
        )
        connection.execute(
            telemetry_limit_heads.insert().values(
                id="limit-head:TM.POWER.BUS_VOLTAGE",
                item_id="TM.POWER.BUS_VOLTAGE",
                catalog_digest=DEFAULT_CATALOG_DIGEST,
                limit_definition_id=DEFAULT_LIMIT_DEFINITION_ID,
                revision=0,
                updated_at=now,
            )
        )


__all__ = [
    "DEFAULT_CATALOG_DIGEST",
    "DEFAULT_LIMIT_BANDS",
    "DEFAULT_LIMIT_DEFINITION_ID",
    "DEFAULT_POLICY_ID",
    "NEW_TABLES",
    "VERSION",
    "metadata",
    "upgrade",
]
