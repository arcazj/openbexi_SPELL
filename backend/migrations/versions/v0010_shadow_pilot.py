"""Immutable local shadow-pilot report and operation ledger schema."""
from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, MetaData, String, Table, UniqueConstraint, inspect, text
from .v0008_development_environment import _actual_structure, _expected_structure

VERSION = "0010_shadow_pilot"
REQUIRED_PREDECESSOR = "0009_procedure_catalog_availability"
metadata = MetaData()
runs = Table("shadow_pilot_runs", metadata,
    Column("id", String(36), primary_key=True), Column("creator", String(200), nullable=False),
    Column("request_hash", String(64), nullable=False), Column("plan", JSON, nullable=False),
    Column("report", JSON, nullable=False), Column("report_sha256", String(64), nullable=False),
    Column("state", String(32), nullable=False), Column("revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False), Column("origin", JSON, nullable=True),
    CheckConstraint("revision > 0", name="ck_shadow_pilot_revision"),
    CheckConstraint("state IN ('PENDING_REVIEW','REVIEWED_READ_ONLY','INCIDENT_READ_ONLY','ROLLED_BACK_READ_ONLY','RESTORED_READ_ONLY')", name="ck_shadow_pilot_state"))
events = Table("shadow_pilot_events", metadata,
    Column("operation_id", String(36), primary_key=True),
    Column("run_id", String(36), ForeignKey("shadow_pilot_runs.id"), nullable=False, index=True),
    Column("request_hash", String(64), nullable=False), Column("action", String(16), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("actor", String(200), nullable=False), Column("reason", String(900), nullable=False),
    Column("result", JSON, nullable=False), Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("action IN ('CREATE','REVIEW','INCIDENT','ROLLBACK','RESTORE')", name="ck_shadow_pilot_action"),
    CheckConstraint("revision > 0", name="ck_shadow_pilot_event_revision"),
    UniqueConstraint("run_id", "revision", name="uq_shadow_pilot_event_revision"))
NEW_TABLES = (runs, events)


def upgrade(connection):
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("unsupported shadow-pilot database")
    if not connection.scalar(text("SELECT 1 FROM schema_migrations WHERE version=:v"), {"v": REQUIRED_PREDECESSOR}):
        raise RuntimeError("shadow-pilot predecessor is missing")
    if set(table.name for table in NEW_TABLES) & set(inspect(connection).get_table_names()):
        raise RuntimeError("shadow-pilot table already exists")
    metadata.create_all(connection, checkfirst=False)
    verify(connection)


def verify(connection):
    for table in NEW_TABLES:
        if table.name not in inspect(connection).get_table_names() or _actual_structure(connection, table.name) != _expected_structure(connection, table):
            raise RuntimeError("shadow-pilot schema differs")
