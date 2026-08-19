"""Add the bounded local data-service schema without changing v0.7 tables."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import MetaData, inspect, select, text
from sqlalchemy.engine import Connection

from backend.data_models import (
    CANONICAL_SCHEMA_SHA256,
    DATA_TABLES,
    DATA_TABLE_NAMES,
    MIGRATION_ID,
    data_schema_fingerprints,
    verify_persisted_schema_fingerprint,
)
from backend.models import Execution
from backend.secure_filesystem import (
    fsync_directory,
    open_owned_directory,
    open_regular_file,
    read_stream,
    unlink_regular_file,
)


VERSION = MIGRATION_ID
REQUIRED_PREDECESSOR = "0006_observation_conditions"
_CREATED_MARKER = "spell.v0007.created_by_upgrade"
_PREFLIGHT_MARKER = "spell.v0007.preflight"
V07_SCHEMA_FINGERPRINT_VERSION = "spell.v07.schema-fingerprint/1"
V07_TABLE_NAMES = frozenset(
    {
        "commands",
        "condition_evaluation_samples",
        "condition_evaluations",
        "condition_plans",
        "controller_handovers",
        "controller_leases",
        "driver_audit_events",
        "driver_bindings",
        "driver_capabilities",
        "driver_context_generations",
        "driver_contexts",
        "driver_host_generations",
        "driver_operation_attempts",
        "driver_operation_transitions",
        "driver_operations",
        "driver_outbox",
        "driver_profiles",
        "driver_time_heads",
        "driver_time_observations",
        "events",
        "execution_operator_states",
        "executions",
        "inspection_edit_operations",
        "monitor_subscriptions",
        "observation_freshness_policies",
        "observation_outbox",
        "observation_streams",
        "operator_audit_events",
        "operator_breakpoints",
        "operator_commands",
        "operator_contexts",
        "operator_prompt_attempts",
        "operator_prompts",
        "operator_requests",
        "operator_user_action_invocations",
        "operator_user_actions",
        "parent_child_links",
        "procedure_catalog_entries",
        "procedure_catalog_revisions",
        "procedure_schedules",
        "prompts",
        "schedule_occurrences",
        "schema_migrations",
        "startproc_operations",
        "telemetry_alarm_heads",
        "telemetry_alarm_observations",
        "telemetry_condition_schedules",
        "telemetry_gaps",
        "telemetry_item_heads",
        "telemetry_limit_heads",
        "telemetry_limit_sets",
        "telemetry_samples",
        "telemetry_schedule_occurrences",
        "telemetry_source_cursors",
        "verify_operations",
        "waitfor_operations",
    }
)
V07_SCHEMA_SHA256_BY_BACKEND = {
    "sqlite": "da6eca9aebddd3d9b273835fbec65b77368069f7ce085e226bd28321a395ddde",
    "postgresql": "a060bf6821f9d0c4ef7f9d3c99baee678cd8b8569007af58d4b3ed0fda7a0219",
}

metadata = MetaData()
Execution.__table__.to_metadata(metadata)
for source in DATA_TABLES:
    source.to_metadata(metadata)
_NEW_TABLE_NAME_SET = frozenset(DATA_TABLE_NAMES)
NEW_TABLES = tuple(
    table for table in metadata.sorted_tables if table.name in _NEW_TABLE_NAME_SET
)


def _normalized_sql(value: Any) -> str | None:
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value).strip()).upper()


def _named_database_objects(connection: Connection) -> dict[str, list[str]]:
    if connection.dialect.name == "sqlite":
        rows = connection.exec_driver_sql(
            "SELECT type, name FROM sqlite_master "
            "WHERE type IN ('trigger', 'view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).all()
        return {
            "functions": [],
            "schemas": ["main"],
            "triggers": [name for kind, name in rows if kind == "trigger"],
            "views": [name for kind, name in rows if kind == "view"],
        }
    if connection.dialect.name == "postgresql":
        functions = connection.exec_driver_sql(
            "SELECT p.proname FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' ORDER BY p.proname"
        ).scalars()
        triggers = connection.exec_driver_sql(
            "SELECT t.tgname FROM pg_trigger t "
            "JOIN pg_class c ON c.oid = t.tgrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND NOT t.tgisinternal ORDER BY t.tgname"
        ).scalars()
        schemas = connection.exec_driver_sql(
            "SELECT nspname FROM pg_namespace "
            "WHERE nspname NOT LIKE 'pg_%%' AND nspname <> 'information_schema' "
            "ORDER BY nspname"
        ).scalars()
        return {
            "functions": list(functions),
            "schemas": list(schemas),
            "triggers": list(triggers),
            "views": sorted(inspect(connection).get_view_names(schema="public")),
        }
    raise RuntimeError("v0.8 data migration backend is unsupported")


def canonical_v07_schema_payload(connection: Connection) -> dict[str, Any]:
    """Return the closed, deterministic physical v0.7 schema description."""

    inspector = inspect(connection)
    tables: list[dict[str, Any]] = []
    for table_name in sorted(inspector.get_table_names()):
        columns = []
        for column in inspector.get_columns(table_name):
            columns.append(
                {
                    "default": _normalized_sql(column.get("default")),
                    "name": column["name"],
                    "nullable": bool(column["nullable"]),
                    "type": _normalized_sql(column["type"]),
                }
            )
        primary = inspector.get_pk_constraint(table_name)
        foreign_keys = sorted(
            (
                tuple(item.get("constrained_columns") or ()),
                item.get("referred_schema") or "public",
                item.get("referred_table"),
                tuple(item.get("referred_columns") or ()),
                _normalized_sql((item.get("options") or {}).get("ondelete"))
                or "RESTRICT",
                _normalized_sql((item.get("options") or {}).get("onupdate"))
                or "RESTRICT",
            )
            for item in inspector.get_foreign_keys(table_name)
        )
        unique_constraints = sorted(
            [
                (
                    item.get("name"),
                    tuple(item.get("column_names") or ()),
                )
                for item in inspector.get_unique_constraints(table_name)
            ],
            key=lambda item: (str(item[0]), item[1]),
        )
        checks = sorted(
            [
                (
                    item.get("name"),
                    _normalized_sql(item.get("sqltext")),
                )
                for item in inspector.get_check_constraints(table_name)
            ],
            key=lambda item: (str(item[0]), str(item[1])),
        )
        indexes = sorted(
            [
                (
                    item.get("name"),
                    bool(item.get("unique")),
                    tuple(item.get("column_names") or ()),
                )
                for item in inspector.get_indexes(table_name)
                if not item.get("duplicates_constraint")
            ],
            key=lambda item: (str(item[0]), item[1], item[2]),
        )
        tables.append(
            {
                "checks": checks,
                "columns": columns,
                "foreign_keys": foreign_keys,
                "indexes": indexes,
                "name": table_name,
                "primary_key": tuple(primary.get("constrained_columns") or ()),
                "unique_constraints": unique_constraints,
            }
        )
    try:
        sequences = sorted(inspector.get_sequence_names())
    except NotImplementedError:
        sequences = []
    return {
        "backend": connection.dialect.name,
        "named_objects": _named_database_objects(connection),
        "schema_version": V07_SCHEMA_FINGERPRINT_VERSION,
        "sequences": sequences,
        "tables": tables,
    }


def live_v07_schema_sha256(connection: Connection) -> str:
    payload = canonical_v07_schema_payload(connection)
    raw = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _verify_exact_v07_schema(connection: Connection) -> str:
    if not _predecessor_is_applied(connection):
        raise RuntimeError(
            "v0.8 data migration requires 0006_observation_conditions"
        )
    actual_tables = set(inspect(connection).get_table_names())
    if actual_tables != V07_TABLE_NAMES:
        missing = sorted(V07_TABLE_NAMES - actual_tables)
        unexpected = sorted(actual_tables - V07_TABLE_NAMES)
        raise RuntimeError(
            "v0.7 schema object inventory differs before v0.8 migration; "
            f"missing={missing!r}; unexpected={unexpected!r}"
        )
    named = _named_database_objects(connection)
    if named["views"] or named["triggers"] or named["functions"]:
        raise RuntimeError("v0.7 schema contains unexpected named objects")
    expected_schemas = ["main"] if connection.dialect.name == "sqlite" else ["public"]
    if named["schemas"] != expected_schemas:
        raise RuntimeError("v0.7 schema namespace inventory differs")
    expected = V07_SCHEMA_SHA256_BY_BACKEND.get(connection.dialect.name)
    if expected is None:
        raise RuntimeError("v0.8 data migration backend is unsupported")
    actual = live_v07_schema_sha256(connection)
    if actual != expected:
        raise RuntimeError("v0.7 schema fingerprint differs before v0.8 migration")
    return actual


def _verify_backup_directory(value: Path | str | None) -> Path:
    if value is None:
        raise RuntimeError("v0.8 data migration requires an explicit backup directory")
    directory = Path(value)
    if not directory.is_absolute():
        raise RuntimeError("v0.8 data migration backup directory must be absolute")
    probe_name = f".spell-v0007-probe-{uuid4().hex}"
    payload = b"spell.v0007.backup-destination-probe/1\n"
    owned_directory = None
    created = False
    try:
        owned_directory = open_owned_directory(directory)
        with open_regular_file(
            owned_directory,
            probe_name,
            create=True,
            writable=True,
        ) as stream:
            created = True
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            if read_stream(stream) != payload:
                raise RuntimeError(
                    "v0.8 data migration backup directory probe differs"
                )
        if not unlink_regular_file(owned_directory, probe_name):
            raise RuntimeError(
                "v0.8 data migration backup directory probe disappeared"
            )
        created = False
        fsync_directory(owned_directory)
    except Exception as exc:
        if owned_directory is not None and created:
            try:
                unlink_regular_file(owned_directory, probe_name)
            except OSError:
                pass
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(
            "v0.8 data migration backup directory must be an existing, safely "
            "writable non-link directory"
        ) from exc
    finally:
        if owned_directory is not None:
            owned_directory.close()
    return directory.absolute()


def preflight(
    connection: Connection, *, backup_directory: Path | str | None
) -> dict[str, str]:
    """Verify the exact predecessor and durable backup destination before DDL."""

    backup = _verify_backup_directory(backup_directory)
    fingerprint = _verify_exact_v07_schema(connection)
    result = {
        "backup_directory": str(backup),
        "schema_sha256": fingerprint,
    }
    connection.info[_PREFLIGHT_MARKER] = result
    return result


def _predecessor_is_applied(connection: Connection) -> bool:
    if "schema_migrations" not in inspect(connection).get_table_names():
        return False
    return bool(
        connection.scalar(
            text(
                "SELECT COUNT(*) FROM schema_migrations "
                "WHERE version = :required_predecessor"
            ),
            {"required_predecessor": REQUIRED_PREDECESSOR},
        )
    )


def upgrade(connection: Connection) -> None:
    """Create exactly the v0.8 tables and its immutable fingerprint record."""

    if not _predecessor_is_applied(connection):
        raise RuntimeError(
            "v0.8 data migration requires 0006_observation_conditions"
        )
    preflight_result = connection.info.get(_PREFLIGHT_MARKER)
    if type(preflight_result) is not dict or set(preflight_result) != {
        "backup_directory",
        "schema_sha256",
    }:
        raise RuntimeError("v0.8 data migration requires successful preflight")
    if _verify_exact_v07_schema(connection) != preflight_result["schema_sha256"]:
        raise RuntimeError("v0.7 schema changed after v0.8 migration preflight")

    connection.info[_CREATED_MARKER] = True
    for table in NEW_TABLES:
        table.create(connection, checkfirst=False)
    connection.execute(
        data_schema_fingerprints.insert().values(
            migration_id=VERSION,
            backend_kind=connection.dialect.name,
            canonical_schema_sha256=CANONICAL_SCHEMA_SHA256,
            activated=False,
        )
    )
    verify_persisted_schema_fingerprint(connection)


def failed_upgrade_requires_cleanup(connection: Connection) -> bool:
    """Capture whether SQLite cleanup is needed after transaction rollback."""

    connection.info.pop(_PREFLIGHT_MARKER, None)
    created_here = bool(connection.info.pop(_CREATED_MARKER, False))
    return created_here and connection.dialect.name == "sqlite"


def cleanup_failed_upgrade(
    connection: Connection, *, created_here: bool | None = None
) -> None:
    """Undo SQLite DDL only when this exact invocation created the objects."""

    if created_here is None:
        created_here = failed_upgrade_requires_cleanup(connection)
    if created_here and connection.dialect.name == "sqlite":
        for table in reversed(NEW_TABLES):
            table.drop(connection, checkfirst=True)


def finalize_upgrade(connection: Connection) -> None:
    connection.info.pop(_CREATED_MARKER, None)
    connection.info.pop(_PREFLIGHT_MARKER, None)


def verify(connection: Connection, *, require_activated: bool = False) -> None:
    verify_persisted_schema_fingerprint(
        connection, require_activated=require_activated
    )


__all__ = [
    "CANONICAL_SCHEMA_SHA256",
    "NEW_TABLES",
    "REQUIRED_PREDECESSOR",
    "V07_SCHEMA_FINGERPRINT_VERSION",
    "V07_SCHEMA_SHA256_BY_BACKEND",
    "V07_TABLE_NAMES",
    "VERSION",
    "canonical_v07_schema_payload",
    "metadata",
    "cleanup_failed_upgrade",
    "failed_upgrade_requires_cleanup",
    "finalize_upgrade",
    "live_v07_schema_sha256",
    "preflight",
    "upgrade",
    "verify",
]
