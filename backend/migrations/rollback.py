from __future__ import annotations

from sqlalchemy import func, inspect, select
from sqlalchemy.engine import Engine

from backend.driver_repository import DEFAULT_PROFILE_ID
from backend.migrations import _migration_lock, schema_migrations
from backend.migrations.versions import v0003_driver_foundation, v0004_operator_workspace


class UnsafeDriverRollbackError(RuntimeError):
    pass


def rollback_driver_foundation(engine: Engine) -> tuple[str, ...]:
    """Remove v0.4 tables only when no driver state or evidence exists."""

    with engine.begin() as connection:
        _migration_lock(connection)
        tables = set(inspect(connection).get_table_names())
        required = {item.name for item in v0003_driver_foundation.metadata.sorted_tables}
        if not required <= tables or "schema_migrations" not in tables:
            raise UnsafeDriverRollbackError("v0.4 driver schema is incomplete")
        applied = set(connection.execute(select(schema_migrations.c.version)).scalars())
        if v0003_driver_foundation.VERSION not in applied:
            raise UnsafeDriverRollbackError("v0.4 driver migration is not applied")
        if v0004_operator_workspace.VERSION in applied:
            raise UnsafeDriverRollbackError(
                "later migrations depend on the driver foundation"
            )

        profiles = connection.execute(
            select(
                v0003_driver_foundation.driver_profiles.c.id,
                v0003_driver_foundation.driver_profiles.c.enabled,
            )
        ).all()
        if profiles != [(DEFAULT_PROFILE_ID, False)]:
            raise UnsafeDriverRollbackError(
                "driver profile is enabled or differs from the disabled default"
            )
        for table in v0003_driver_foundation.metadata.sorted_tables:
            if table.name == "driver_profiles":
                continue
            if connection.scalar(select(func.count()).select_from(table)):
                raise UnsafeDriverRollbackError(
                    "driver history exists; retain backup and reconciliation evidence"
                )

        dropped = tuple(
            table.name for table in reversed(v0003_driver_foundation.metadata.sorted_tables)
        )
        v0003_driver_foundation.metadata.drop_all(connection, checkfirst=False)
        connection.execute(
            schema_migrations.delete().where(
                schema_migrations.c.version == v0003_driver_foundation.VERSION
            )
        )
        return dropped


__all__ = ["UnsafeDriverRollbackError", "rollback_driver_foundation"]
