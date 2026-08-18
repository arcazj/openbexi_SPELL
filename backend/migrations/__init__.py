from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, DateTime, MetaData, String, Table, inspect, select
from sqlalchemy.engine import Connection, Engine

from .versions import (
    v0001_initial,
    v0002_execution_variables,
    v0003_driver_foundation,
    v0004_operator_workspace,
    v0005_observation_projection,
    v0006_observation_conditions,
    v0007_data_local_service,
)


MIGRATIONS = (
    v0001_initial,
    v0002_execution_variables,
    v0003_driver_foundation,
    v0004_operator_workspace,
    v0005_observation_projection,
    v0006_observation_conditions,
    v0007_data_local_service,
)
metadata = MetaData()
schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", String(100), primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)


def run_migrations(
    engine: Engine,
    *,
    v0007_backup_directory: Path | str | None = None,
) -> tuple[str, ...]:
    """Apply pending migrations transactionally and return newly applied versions."""

    applied_now: list[str] = []
    cleanup_v0007_after_rollback = False
    try:
        with engine.begin() as connection:
            _migration_lock(connection)
            schema_migrations.create(connection, checkfirst=True)
            applied = set(
                connection.execute(select(schema_migrations.c.version)).scalars()
            )
            known_versions = [migration.VERSION for migration in MIGRATIONS]
            unknown_versions = applied.difference(known_versions)
            if unknown_versions:
                raise RuntimeError("database contains unsupported migration versions")
            applied_indexes = [
                index
                for index, version in enumerate(known_versions)
                if version in applied
            ]
            expected_prefix = set(known_versions[: max(applied_indexes, default=-1) + 1])
            if applied != expected_prefix:
                raise RuntimeError("database migration history is not a valid prefix")
            for migration in MIGRATIONS:
                if migration.VERSION in applied:
                    continue
                try:
                    if migration.VERSION == v0007_data_local_service.VERSION:
                        v0007_data_local_service.preflight(
                            connection,
                            backup_directory=v0007_backup_directory,
                        )
                    migration.upgrade(connection)
                    connection.execute(
                        schema_migrations.insert().values(
                            version=migration.VERSION,
                            applied_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception:
                    if migration.VERSION == v0007_data_local_service.VERSION:
                        cleanup_v0007_after_rollback = (
                            v0007_data_local_service.failed_upgrade_requires_cleanup(
                                connection
                            )
                        )
                    raise
                if migration.VERSION == v0007_data_local_service.VERSION:
                    v0007_data_local_service.finalize_upgrade(connection)
                applied_now.append(migration.VERSION)
            if v0007_data_local_service.VERSION in applied | set(applied_now):
                v0007_data_local_service.verify(connection)
    except Exception:
        if cleanup_v0007_after_rollback:
            with engine.begin() as cleanup_connection:
                v0007_data_local_service.cleanup_failed_upgrade(
                    cleanup_connection, created_here=True
                )
        raise
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
    if connection.dialect.name == "sqlite":
        driver_connection = connection.connection.driver_connection
        if not driver_connection.in_transaction:
            # Python's legacy sqlite3 transaction mode does not start a
            # transaction for SELECT or DDL. Acquire the write transaction
            # explicitly so every migration DDL statement rolls back together.
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        return
    if connection.dialect.name == "postgresql":
        # Transaction-scoped and released automatically on commit or rollback.
        connection.exec_driver_sql("SELECT pg_advisory_xact_lock(731035003)")


__all__ = ["MIGRATIONS", "database_version", "run_migrations"]
