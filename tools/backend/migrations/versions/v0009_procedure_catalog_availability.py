"""Add durable availability tombstones for procedure catalog entries."""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
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
    and_,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection

from .v0008_development_environment import (
    _actual_structure,
    _expected_structure,
)


VERSION = "0009_procedure_catalog_availability"
REQUIRED_PREDECESSOR = "0008_development_environment"

metadata = MetaData()

procedure_catalog_entries = Table(
    "procedure_catalog_entries",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("current_revision", Integer, nullable=False),
)

procedure_catalog_revisions = Table(
    "procedure_catalog_revisions",
    metadata,
    Column("catalog_id", String(64), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("properties", JSON, nullable=False),
)

procedure_catalog_availability = Table(
    "procedure_catalog_availability",
    metadata,
    Column(
        "catalog_id",
        String(64),
        ForeignKey("procedure_catalog_entries.id"),
        primary_key=True,
    ),
    Column("state", String(20), nullable=False),
    Column("source_kind", String(20), nullable=False),
    Column("availability_revision", Integer, nullable=False),
    Column("updated_by", String(200), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint(
        "state IN ('ACTIVE','INACTIVE')",
        name="ck_procedure_catalog_availability_state",
    ),
    CheckConstraint(
        "source_kind IN ('BUILT_IN','PROMOTED','HISTORICAL')",
        name="ck_procedure_catalog_source_kind",
    ),
    CheckConstraint(
        "availability_revision > 0",
        name="ck_procedure_catalog_availability_revision",
    ),
    Index("ix_procedure_catalog_availability_state", "state"),
)

NEW_TABLES = (procedure_catalog_availability,)


def _predecessor_is_applied(connection: Connection) -> bool:
    if "schema_migrations" not in inspect(connection).get_table_names():
        return False
    return (
        connection.execute(
            text("SELECT 1 FROM schema_migrations WHERE version = :version"),
            {"version": REQUIRED_PREDECESSOR},
        ).first()
        is not None
    )


def _source_kind(properties: Any) -> str:
    if not isinstance(properties, dict):
        raise RuntimeError("procedure catalog current revision properties are invalid")
    if properties.get("legacy_execution_snapshot") is True:
        return "HISTORICAL"
    if properties.get("development_bundle_digest") is not None:
        return "PROMOTED"
    return "BUILT_IN"


def _backfill(connection: Connection) -> None:
    rows = connection.execute(
        select(
            procedure_catalog_entries.c.id,
            procedure_catalog_revisions.c.properties,
        ).select_from(
            procedure_catalog_entries.join(
                procedure_catalog_revisions,
                and_(
                    procedure_catalog_revisions.c.catalog_id
                    == procedure_catalog_entries.c.id,
                    procedure_catalog_revisions.c.revision
                    == procedure_catalog_entries.c.current_revision,
                ),
            )
        )
    ).all()
    entry_count = connection.scalar(
        select(func.count()).select_from(procedure_catalog_entries)
    )
    if len(rows) != entry_count:
        raise RuntimeError("procedure catalog current revision is incomplete")
    now = connection.scalar(select(func.current_timestamp()))
    values = []
    for catalog_id, properties in rows:
        source_kind = _source_kind(properties)
        values.append(
            {
                "catalog_id": catalog_id,
                "state": "INACTIVE" if source_kind == "HISTORICAL" else "ACTIVE",
                "source_kind": source_kind,
                "availability_revision": 1,
                "updated_by": f"migration:{VERSION}",
                "updated_at": now,
            }
        )
    if values:
        connection.execute(procedure_catalog_availability.insert(), values)


def upgrade(connection: Connection) -> None:
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("procedure catalog availability backend is unsupported")
    if not _predecessor_is_applied(connection):
        raise RuntimeError(
            "procedure catalog availability migration requires "
            f"{REQUIRED_PREDECESSOR}"
        )
    if procedure_catalog_availability.name in inspect(connection).get_table_names():
        raise RuntimeError("procedure catalog availability table already exists")
    procedure_catalog_availability.create(connection, checkfirst=False)
    _backfill(connection)
    verify(connection)


def verify(connection: Connection) -> None:
    inspector = inspect(connection)
    if procedure_catalog_availability.name not in inspector.get_table_names():
        raise RuntimeError("procedure catalog availability table is missing")
    if _actual_structure(
        connection, procedure_catalog_availability.name
    ) != _expected_structure(connection, procedure_catalog_availability):
        raise RuntimeError("procedure catalog availability structure differs")

    missing = connection.scalar(
        select(func.count())
        .select_from(
            procedure_catalog_entries.outerjoin(
                procedure_catalog_availability,
                procedure_catalog_availability.c.catalog_id
                == procedure_catalog_entries.c.id,
            )
        )
        .where(procedure_catalog_availability.c.catalog_id.is_(None))
    )
    invalid = connection.scalar(
        select(func.count())
        .select_from(procedure_catalog_availability)
        .where(
            (procedure_catalog_availability.c.state.not_in(("ACTIVE", "INACTIVE")))
            | (
                procedure_catalog_availability.c.source_kind.not_in(
                    ("BUILT_IN", "PROMOTED", "HISTORICAL")
                )
            )
            | (procedure_catalog_availability.c.availability_revision <= 0)
        )
    )
    orphaned = connection.scalar(
        select(func.count())
        .select_from(
            procedure_catalog_availability.outerjoin(
                procedure_catalog_entries,
                procedure_catalog_entries.c.id
                == procedure_catalog_availability.c.catalog_id,
            )
        )
        .where(procedure_catalog_entries.c.id.is_(None))
    )
    if missing or invalid or orphaned:
        raise RuntimeError("procedure catalog availability data differs")


__all__ = [
    "NEW_TABLES",
    "REQUIRED_PREDECESSOR",
    "VERSION",
    "metadata",
    "procedure_catalog_availability",
    "upgrade",
    "verify",
]
