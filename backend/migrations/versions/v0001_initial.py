from __future__ import annotations

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Connection


VERSION = "0001_initial"

# This migration is deliberately independent of the live ORM. Applied migration
# history must not change when a later release edits backend.models.
metadata = MetaData()

executions = Table(
    "executions",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("procedure_id", String(200), nullable=False),
    Column("procedure_name", String(200), nullable=False),
    Column("procedure_hash", String(64), nullable=False),
    Column("procedure_source", Text, nullable=False),
    Column("steps", JSON, nullable=False),
    Column("context_id", String(100), nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("creation_idempotency_key", String(200), nullable=False),
    Column("state", String(40), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("current_step", Integer, nullable=False),
    Column("total_steps", Integer, nullable=False),
    Column("worker_generation", Integer, nullable=False),
    Column("next_sequence", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("created_by", "creation_idempotency_key", name="uq_execution_creation"),
)
Index("ix_executions_procedure_id", executions.c.procedure_id)
Index("ix_executions_state", executions.c.state)

events = Table(
    "events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("source", String(60), nullable=False),
    Column("severity", String(20), nullable=False),
    Column("correlation_id", String(36), nullable=True),
    Column("causation_id", String(36), nullable=True),
    Column("payload", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("execution_id", "sequence", name="uq_event_execution_sequence"),
)
Index("ix_events_event_type", events.c.event_type)
Index("ix_event_execution_sequence", events.c.execution_id, events.c.sequence)

commands = Table(
    "commands",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("command_type", String(40), nullable=False),
    Column("status", String(30), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("expected_revision", Integer, nullable=False),
    Column("actor", String(200), nullable=False),
    Column("role", String(30), nullable=False),
    Column("reason", Text, nullable=False),
    Column("correlation_id", String(36), nullable=False),
    Column("request_payload", JSON, nullable=False),
    Column("result_payload", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("execution_id", "idempotency_key", name="uq_command_idempotency"),
)

prompts = Table(
    "prompts",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("execution_id", String(36), ForeignKey("executions.id"), nullable=False),
    Column("step_index", Integer, nullable=False),
    Column("status", String(30), nullable=False),
    Column("question", Text, nullable=False),
    Column("choices", JSON, nullable=False),
    Column("default_choice", String(200), nullable=True),
    Column("response", String(200), nullable=True),
    Column("responded_by", String(200), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("responded_at", DateTime(timezone=True), nullable=True),
)
Index("ix_prompts_execution_id", prompts.c.execution_id)


def upgrade(connection: Connection) -> None:
    """Create the immutable v0.2 baseline or baseline existing tables."""

    metadata.create_all(connection, checkfirst=True)
