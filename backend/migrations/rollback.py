from __future__ import annotations

from sqlalchemy import func, inspect, select
from sqlalchemy.engine import Engine

from backend.driver_repository import DEFAULT_PROFILE_ID
from backend.migrations import _migration_lock, schema_migrations
from backend.migrations.versions import (
    v0001_initial,
    v0002_execution_variables,
    v0003_driver_foundation,
    v0004_operator_workspace,
    v0005_observation_projection,
    v0006_observation_conditions,
    v0007_data_local_service,
)
from backend.data_models import (
    CANONICAL_SCHEMA_SHA256,
    DATA_TABLE_NAMES,
    data_schema_fingerprints,
)


class UnsafeDriverRollbackError(RuntimeError):
    pass


class UnsafeDataRollbackError(RuntimeError):
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
        if any(
            version in applied
            for version in (
                v0004_operator_workspace.VERSION,
                v0005_observation_projection.VERSION,
                v0006_observation_conditions.VERSION,
                v0007_data_local_service.VERSION,
            )
        ):
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


def rollback_data_local_service(engine: Engine) -> tuple[str, ...]:
    """Remove v0.8 only when its schema is exact, empty, and unactivated."""

    with engine.begin() as connection:
        _migration_lock(connection)
        tables = set(inspect(connection).get_table_names())
        required = set(DATA_TABLE_NAMES)
        if "schema_migrations" not in tables or not required <= tables:
            raise UnsafeDataRollbackError("v0.8 data schema is incomplete")

        known_tables = {
            "schema_migrations",
            *(table.name for table in v0001_initial.metadata.sorted_tables),
            *(table.name for table in v0003_driver_foundation.metadata.sorted_tables),
            *(table.name for table in v0004_operator_workspace.NEW_TABLES),
            *(table.name for table in v0005_observation_projection.NEW_TABLES),
            *(table.name for table in v0006_observation_conditions.NEW_TABLES),
            *DATA_TABLE_NAMES,
        }
        unknown_tables = tables - known_tables
        if unknown_tables:
            raise UnsafeDataRollbackError(
                "unknown database objects prevent v0.8 rollback: "
                + ", ".join(sorted(unknown_tables))
            )

        applied = set(connection.execute(select(schema_migrations.c.version)).scalars())
        if v0007_data_local_service.VERSION not in applied:
            raise UnsafeDataRollbackError("v0.8 data migration is not applied")
        known_versions = {
            v0001_initial.VERSION,
            v0002_execution_variables.VERSION,
            v0003_driver_foundation.VERSION,
            v0004_operator_workspace.VERSION,
            v0005_observation_projection.VERSION,
            v0006_observation_conditions.VERSION,
            v0007_data_local_service.VERSION,
        }
        later_or_unknown = applied - known_versions
        if later_or_unknown:
            raise UnsafeDataRollbackError(
                "later or unknown migrations prevent v0.8 rollback"
            )

        try:
            v0007_data_local_service.verify(connection)
        except RuntimeError as exc:
            raise UnsafeDataRollbackError(
                "v0.8 schema fingerprint does not match"
            ) from exc
        fingerprints = connection.execute(
            select(data_schema_fingerprints)
        ).mappings().all()
        if len(fingerprints) != 1:
            raise UnsafeDataRollbackError(
                "v0.8 schema fingerprint record cardinality differs"
            )
        fingerprint = fingerprints[0]
        if (
            fingerprint["migration_id"] != v0007_data_local_service.VERSION
            or fingerprint["backend_kind"] != connection.dialect.name
            or fingerprint["canonical_schema_sha256"] != CANONICAL_SCHEMA_SHA256
            or fingerprint["activated"]
        ):
            raise UnsafeDataRollbackError(
                "v0.8 schema is activated or its fingerprint differs"
            )

        for table in v0007_data_local_service.NEW_TABLES:
            if table.name == data_schema_fingerprints.name:
                continue
            if connection.scalar(select(func.count()).select_from(table)):
                raise UnsafeDataRollbackError(
                    "v0.8 data or evidence exists; restore a verified backup instead"
                )

        dropped = tuple(
            table.name for table in reversed(v0007_data_local_service.NEW_TABLES)
        )
        for table in reversed(v0007_data_local_service.NEW_TABLES):
            table.drop(connection, checkfirst=False)
        connection.execute(
            schema_migrations.delete().where(
                schema_migrations.c.version == v0007_data_local_service.VERSION
            )
        )
        return dropped


__all__ = [
    "UnsafeDataRollbackError",
    "UnsafeDriverRollbackError",
    "rollback_data_local_service",
    "rollback_driver_foundation",
]
