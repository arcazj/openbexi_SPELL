"""Durable intent/result boundary for each nested DSS language case."""
from sqlalchemy import CheckConstraint, Column, DateTime, JSON, MetaData, String, Table, inspect, text
from .v0008_development_environment import _actual_structure, _expected_structure

VERSION = "0011_dss_language_ledger"
REQUIRED_PREDECESSOR = "0010_shadow_pilot"
metadata = MetaData()
language_cases = Table("dss_language_cases", metadata,
    Column("request_id", String(36), primary_key=True),
    Column("subject", String(200), primary_key=True),
    Column("execution_id", String(200), nullable=False, index=True),
    Column("request_hash", String(64), nullable=False),
    Column("request", JSON, nullable=False),
    Column("binding_hash", String(64), nullable=False),
    Column("state", String(16), nullable=False),
    Column("result", JSON, nullable=True),
    Column("result_hash", String(64), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("settled_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("state IN ('DISPATCHING','SETTLED')", name="ck_dss_language_case_state"))


def upgrade(connection):
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("unsupported DSS language ledger database")
    if not connection.scalar(text("SELECT 1 FROM schema_migrations WHERE version=:v"), {"v": REQUIRED_PREDECESSOR}):
        raise RuntimeError("DSS language ledger predecessor is missing")
    if language_cases.name in inspect(connection).get_table_names():
        raise RuntimeError("DSS language ledger already exists")
    metadata.create_all(connection, checkfirst=False)
    verify(connection)


def verify(connection):
    if (language_cases.name not in inspect(connection).get_table_names()
            or _actual_structure(connection, language_cases.name) != _expected_structure(connection, language_cases)):
        raise RuntimeError("DSS language ledger schema differs")
