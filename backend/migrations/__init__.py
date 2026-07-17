from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, MetaData, String, Table, inspect, select
from sqlalchemy.engine import Connection, Engine

from .versions import v0001_initial, v0002_execution_variables


MIGRATIONS = (v0001_initial, v0002_execution_variables)
metadata = MetaData()
schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", String(100), primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)


def run_migrations(engine: Engine) -> tuple[str, ...]:
    """Apply pending migrations transactionally and return newly applied versions."""

    applied_now: list[str] = []
    with engine.begin() as connection:
        _migration_lock(connection)
        schema_migrations.create(connection, checkfirst=True)
        applied = set(connection.execute(select(schema_migrations.c.version)).scalars())
        known_versions = [migration.VERSION for migration in MIGRATIONS]
        unknown_versions = applied.difference(known_versions)
        if unknown_versions:
            raise RuntimeError("database contains unsupported migration versions")
        applied_indexes = [
            index for index, version in enumerate(known_versions) if version in applied
        ]
        expected_prefix = set(known_versions[: max(applied_indexes, default=-1) + 1])
        if applied != expected_prefix:
            raise RuntimeError("database migration history is not a valid prefix")
        for migration in MIGRATIONS:
            if migration.VERSION in applied:
                continue
            migration.upgrade(connection)
            connection.execute(
                schema_migrations.insert().values(
                    version=migration.VERSION,
                    applied_at=datetime.now(timezone.utc),
                )
            )
            applied_now.append(migration.VERSION)
    return tuple(applied_now)


def database_version(engine: Engine) -> str | None:
    if "schema_migrations" not in inspect(engine).get_table_names():
        return None
    with engine.connect() as connection:
        versions = set(connection.execute(select(schema_migrations.c.version)).scalars())
    return next(
        (migration.VERSION for migration in reversed(MIGRATIONS) if migration.VERSION in versions),
        None,
    )


def _migration_lock(connection: Connection) -> None:
    if connection.dialect.name == "postgresql":
        # Transaction-scoped and released automatically on commit or rollback.
        connection.exec_driver_sql("SELECT pg_advisory_xact_lock(731035003)")


__all__ = ["MIGRATIONS", "database_version", "run_migrations"]
