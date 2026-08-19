from __future__ import annotations

import tempfile
import time
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine

from backend.database import Base
from backend.migrations import schema_migrations
from backend.migrations import run_migrations as run_product_migrations
from backend.migrations.versions import (
    v0008_development_environment,
    v0009_procedure_catalog_availability,
)


_POSTGRES_SESSION_DRAIN_TIMEOUT_SECONDS = 5.0
_POSTGRES_SESSION_DRAIN_INTERVAL_SECONDS = 0.05


def trusted_test_backup_directory(engine: Engine) -> Path:
    database = engine.url.database
    if engine.dialect.name == "sqlite" and database not in {None, "", ":memory:"}:
        root = Path(database).resolve(strict=False).parent
    else:
        root = Path(tempfile.gettempdir()).resolve() / "openbexi-spell-test-backups"
    target = root / "v0007-preflight"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    return target


def run_migrations(engine: Engine) -> tuple[str, ...]:
    return run_product_migrations(
        engine,
        v0007_backup_directory=trusted_test_backup_directory(engine),
    )


def _drain_postgresql_test_sessions(connection) -> None:
    deadline = time.monotonic() + _POSTGRES_SESSION_DRAIN_TIMEOUT_SECONDS
    terminate = text(
        """
        SELECT pid, pg_terminate_backend(pid) AS terminated
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
        ORDER BY pid
        """
    )
    while True:
        connection.exec_driver_sql("SELECT pg_stat_clear_snapshot()")
        sessions = connection.execute(terminate).all()
        if not sessions:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "PostgreSQL test reset timed out draining dedicated test "
                "database sessions"
            )
        time.sleep(_POSTGRES_SESSION_DRAIN_INTERVAL_SECONDS)


def reset_test_database(engine: Engine) -> None:
    """Remove every product-owned database object between shared-DB tests."""

    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            configured_database = engine.url.database
            current_database = connection.scalar(text("SELECT current_database()"))
            allowed_databases = {"spell_test", "spell_migration_test"}
            if (
                configured_database not in allowed_databases
                or current_database != configured_database
            ):
                raise RuntimeError(
                    "PostgreSQL test reset requires the exact dedicated test database"
                )
            # Discard pooled idle connections before terminating checked-out or
            # external sessions. The reset connection remains valid until this
            # transaction ends and the replacement pool starts clean.
            engine.dispose()
            _drain_postgresql_test_sessions(connection)
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
            return
        if connection.dialect.name != "sqlite":
            raise RuntimeError("test database reset supports only SQLite and PostgreSQL")

        # Migration-owned tables must not depend on which ORM modules happened
        # to be imported before this helper runs.
        for table in reversed(v0009_procedure_catalog_availability.NEW_TABLES):
            table.drop(connection, checkfirst=True)
        for table in reversed(v0008_development_environment.NEW_TABLES):
            table.drop(connection, checkfirst=True)
        Base.metadata.drop_all(connection)
        schema_migrations.drop(connection, checkfirst=True)


__all__ = [
    "reset_test_database",
    "run_migrations",
    "trusted_test_backup_directory",
]
