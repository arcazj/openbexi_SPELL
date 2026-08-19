"""Add the migration-owned bounded v0.9 development schema."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    inspect,
    text,
)
from sqlalchemy.engine import Connection


VERSION = "0008_development_environment"
REQUIRED_PREDECESSOR = "0007_data_local_service"
SCHEMA_FINGERPRINT_VERSION = "spell.v09.development-schema/1"
BUNDLE_IMMUTABLE_COLUMNS = (
    "bundle_digest",
    "project_id",
    "history_revision_id",
    "bundle_bytes",
    "byte_length",
    "manifest",
    "source_tree_digest",
    "validation_report_digest",
    "author_subject",
    "review_subject",
    "builder_identity",
    "created_at_database_time",
)
BUNDLE_IMMUTABILITY_TRIGGERS = frozenset(
    {"trg_dev_bundle_immutable_update", "trg_dev_bundle_immutable_delete"}
)

metadata = MetaData()


def _time(name: str) -> Column[Any]:
    return Column(
        name,
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )


development_projects = Table(
    "development_projects",
    metadata,
    Column("project_id", String(128), primary_key=True),
    Column("workspace_id", String(128), nullable=False),
    Column("display_name", String(256), nullable=False),
    Column("normalized_name", String(256), nullable=False),
    Column("owner_subject", String(200), nullable=False),
    Column("author_subject", String(200), nullable=False),
    Column("case_policy", String(24), nullable=False),
    Column("workspace_revision", BigInteger, nullable=False),
    Column("base_history_revision_id", String(128)),
    Column("base_bundle_digest", String(64)),
    Column("manifest", JSON, nullable=False),
    Column("closed", Boolean, nullable=False),
    _time("created_at_database_time"),
    _time("updated_at_database_time"),
    CheckConstraint("workspace_revision >= 0", name="ck_dev_project_revision"),
    CheckConstraint(
        "case_policy IN ('CASE_SENSITIVE','CASE_INSENSITIVE')",
        name="ck_dev_project_case_policy",
    ),
    UniqueConstraint("workspace_id", name="uq_dev_project_workspace"),
    UniqueConstraint("owner_subject", "normalized_name", name="uq_dev_project_name"),
)

development_resources = Table(
    "development_resources",
    metadata,
    Column("resource_id", String(128), primary_key=True),
    Column(
        "project_id",
        String(128),
        ForeignKey("development_projects.project_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("path", String(512), nullable=False),
    Column("path_identity", String(512), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("media_type", String(160), nullable=False),
    Column("content", LargeBinary, nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column("byte_length", Integer, nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("created_by_subject", String(200), nullable=False),
    Column("updated_by_subject", String(200), nullable=False),
    _time("created_at_database_time"),
    _time("updated_at_database_time"),
    UniqueConstraint("project_id", "path_identity", name="uq_dev_resource_path"),
    CheckConstraint("revision >= 1", name="ck_dev_resource_revision"),
    CheckConstraint("byte_length >= 0", name="ck_dev_resource_size"),
    Index("ix_dev_resource_project_path", "project_id", "path"),
)

development_idempotency = Table(
    "development_idempotency",
    metadata,
    Column("record_id", String(128), primary_key=True),
    Column("actor_subject", String(200), nullable=False),
    Column("operation_scope", String(256), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("response", JSON, nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint(
        "actor_subject",
        "operation_scope",
        "idempotency_key",
        name="uq_dev_idempotency",
    ),
)

development_audit_events = Table(
    "development_audit_events",
    metadata,
    Column("audit_id", String(128), primary_key=True),
    Column("project_id", String(128)),
    Column("actor_subject", String(200), nullable=False),
    Column("actor_role", String(24), nullable=False),
    Column("action", String(80), nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("previous_revision", BigInteger),
    Column("new_revision", BigInteger),
    Column("payload", JSON, nullable=False),
    _time("created_at_database_time"),
    Index("ix_dev_audit_project_time", "project_id", "created_at_database_time"),
)

development_outbox = Table(
    "development_outbox",
    metadata,
    Column("event_id", String(128), primary_key=True),
    Column("topic", String(128), nullable=False),
    Column("aggregate_id", String(128), nullable=False),
    Column("aggregate_revision", BigInteger, nullable=False),
    Column("payload", JSON, nullable=False),
    Column("published", Boolean, nullable=False),
    _time("created_at_database_time"),
    Index("ix_dev_outbox_topic_time", "topic", "created_at_database_time"),
)

development_analysis_jobs = Table(
    "development_analysis_jobs",
    metadata,
    Column("job_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("workspace_revision", BigInteger, nullable=False),
    Column("scope", String(24), nullable=False),
    Column("scope_path", String(512)),
    Column("reparse_libraries", Boolean, nullable=False),
    Column("state", String(32), nullable=False),
    Column("progress", Integer, nullable=False),
    Column("actor_subject", String(200), nullable=False),
    Column("tool_version", String(64), nullable=False),
    Column("input_digest", String(64), nullable=False),
    Column("report", LargeBinary),
    Column("report_sha256", String(64)),
    Column("failure_code", String(80)),
    _time("created_at_database_time"),
    Column("started_at_database_time", DateTime(timezone=True)),
    Column("completed_at_database_time", DateTime(timezone=True)),
    CheckConstraint("progress BETWEEN 0 AND 100", name="ck_dev_job_progress"),
    Index("ix_dev_job_project_revision", "project_id", "workspace_revision"),
)

development_problems = Table(
    "development_problems",
    metadata,
    Column("problem_id", String(128), primary_key=True),
    Column("diagnostic_id", String(64), nullable=False),
    Column("job_id", String(128), ForeignKey("development_analysis_jobs.job_id"), nullable=False),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("workspace_revision", BigInteger, nullable=False),
    Column("source_path", String(512), nullable=False),
    Column("start_line", Integer, nullable=False),
    Column("start_column", Integer, nullable=False),
    Column("end_line", Integer, nullable=False),
    Column("end_column", Integer, nullable=False),
    Column("severity", String(16), nullable=False),
    Column("code", String(64), nullable=False),
    Column("message", Text, nullable=False),
    Column("remediation_ref", String(256), nullable=False),
    Column("tool_version", String(64), nullable=False),
    Column("language_profile", String(80), nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint(
        "project_id", "workspace_revision", "diagnostic_id", name="uq_dev_problem"
    ),
    Index(
        "ix_dev_problem_sort",
        "project_id",
        "source_path",
        "start_line",
        "start_column",
    ),
)

development_library_cache = Table(
    "development_library_cache",
    metadata,
    Column("cache_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("cache_kind", String(24), nullable=False),
    Column("content_digest", String(64), nullable=False),
    Column("language_profile", String(80), nullable=False),
    Column("tool_version", String(64), nullable=False),
    Column("canonical_result", LargeBinary, nullable=False),
    Column("result_sha256", String(64), nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint(
        "project_id",
        "cache_kind",
        "content_digest",
        "language_profile",
        "tool_version",
        name="uq_dev_library_cache_key",
    ),
)

development_history_revisions = Table(
    "development_history_revisions",
    metadata,
    Column("history_revision_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("ordinal", BigInteger, nullable=False),
    Column("parent_revision_ids", JSON, nullable=False),
    Column("tree_digest", String(64), nullable=False),
    Column("tree_bytes", LargeBinary, nullable=False),
    Column("snapshot_bytes", LargeBinary, nullable=False),
    Column("author_subject", String(200), nullable=False),
    Column("message", Text, nullable=False),
    Column("message_digest", String(64), nullable=False),
    Column("validation_job_id", String(128), nullable=False),
    Column("validation_summary_digest", String(64), nullable=False),
    Column("workspace_revision", BigInteger, nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint("project_id", "ordinal", name="uq_dev_history_ordinal"),
)

development_history_reviews = Table(
    "development_history_reviews",
    metadata,
    Column("review_id", String(128), primary_key=True),
    Column(
        "history_revision_id",
        String(128),
        ForeignKey("development_history_revisions.history_revision_id"),
        nullable=False,
    ),
    Column("review_revision", BigInteger, nullable=False),
    Column("reviewer_subject", String(200), nullable=False),
    Column("decision", String(24), nullable=False),
    Column("reason", Text, nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint("history_revision_id", name="uq_dev_history_review"),
)

development_conflicts = Table(
    "development_conflicts",
    metadata,
    Column("conflict_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("path", String(512), nullable=False),
    Column("base_path", String(512), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("conflict_digest", String(64), nullable=False),
    Column("base_history_revision_id", String(128), nullable=False),
    Column("base_workspace_revision", BigInteger, nullable=False),
    Column("detected_workspace_revision", BigInteger, nullable=False),
    Column("ours_resource_id", String(128)),
    Column("ours_resource_revision", BigInteger),
    Column("ours_path", String(512)),
    Column("base_kind", String(32), nullable=False),
    Column("base_media_type", String(160), nullable=False),
    Column("ours_kind", String(32)),
    Column("ours_media_type", String(160)),
    Column("theirs_kind", String(32)),
    Column("theirs_media_type", String(160)),
    Column("base_content", LargeBinary),
    Column("ours_content", LargeBinary),
    Column("theirs_content", LargeBinary),
    Column("resolved", Boolean, nullable=False),
    Column("resolution_digest", String(64)),
    _time("created_at_database_time"),
    Column("resolved_at_database_time", DateTime(timezone=True)),
)

development_import_provenance = Table(
    "development_import_provenance",
    metadata,
    Column("operation_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("actor_subject", String(200), nullable=False),
    Column("original_filename", String(512), nullable=False),
    Column("original_media_type", String(160), nullable=False),
    Column("original_byte_length", BigInteger, nullable=False),
    Column("original_bytes_sha256", String(64), nullable=False),
    Column("original_bytes", LargeBinary, nullable=False),
    Column("imported_tree_sha256", String(64), nullable=False),
    Column("canonical_tree_sha256", String(64), nullable=False),
    Column("base_workspace_revision", BigInteger, nullable=False),
    Column("status", String(32), nullable=False),
    Column("conflict_paths", JSON, nullable=False),
    Column(
        "audit_id",
        String(128),
        ForeignKey("development_audit_events.audit_id"),
        nullable=False,
    ),
    _time("created_at_database_time"),
    CheckConstraint(
        "status IN ('QUARANTINED','APPLYING','APPLIED','NO_CHANGE','CONFLICT','DISCARDED')",
        name="ck_dev_import_status",
    ),
    UniqueConstraint("audit_id", name="uq_dev_import_audit"),
)

development_dictionary_artifacts = Table(
    "development_dictionary_artifacts",
    metadata,
    Column(
        "resource_id",
        String(128),
        ForeignKey("development_resources.resource_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("dictionary_id", String(256), nullable=False),
    Column("source_format", String(8), nullable=False),
    Column("base_revision", BigInteger, nullable=False),
    Column("original_bytes", LargeBinary, nullable=False),
    Column("original_bytes_sha256", String(64), nullable=False),
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("canonical_bytes_sha256", String(64), nullable=False),
    Column("canonical_state", JSON, nullable=False),
    _time("created_at_database_time"),
    _time("updated_at_database_time"),
)

development_catalog_snapshots = Table(
    "development_catalog_snapshots",
    metadata,
    Column("snapshot_id", String(128), primary_key=True),
    Column(
        "resource_id",
        String(128),
        ForeignKey("development_resources.resource_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("catalog_id", String(128), nullable=False),
    Column("catalog_revision", BigInteger, nullable=False),
    Column("catalog_kind", String(32), nullable=False),
    Column("content_digest", String(64), nullable=False),
    Column("canonical_snapshot", LargeBinary, nullable=False),
    Column("entries", JSON, nullable=False),
    Column("dependencies", JSON, nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint(
        "project_id", "catalog_id", "catalog_revision", name="uq_dev_catalog_snapshot"
    ),
)

development_presence = Table(
    "development_presence",
    metadata,
    Column("presence_id", String(128), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column("resource_id", String(128)),
    Column("subject", String(200), nullable=False),
    Column("client_instance_id", String(128), nullable=False),
    Column("status", String(32), nullable=False),
    _time("updated_at_database_time"),
    Column("expires_at_database_time", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "project_id", "subject", "client_instance_id", name="uq_dev_presence_subject"
    ),
)

development_bundles = Table(
    "development_bundles",
    metadata,
    Column("bundle_digest", String(64), primary_key=True),
    Column("project_id", String(128), ForeignKey("development_projects.project_id"), nullable=False),
    Column(
        "history_revision_id",
        String(128),
        ForeignKey("development_history_revisions.history_revision_id"),
        nullable=False,
    ),
    Column("bundle_bytes", LargeBinary, nullable=False),
    Column("byte_length", BigInteger, nullable=False),
    Column("manifest", JSON, nullable=False),
    Column("source_tree_digest", String(64), nullable=False),
    Column("validation_report_digest", String(64), nullable=False),
    Column("author_subject", String(200), nullable=False),
    Column("review_subject", String(200), nullable=False),
    Column("builder_identity", String(128), nullable=False),
    Column("state", String(24), nullable=False),
    Column("state_revision", BigInteger, nullable=False),
    Column("approved_by_subject", String(200)),
    Column("approval_reason", Text),
    _time("created_at_database_time"),
    _time("updated_at_database_time"),
    CheckConstraint("state_revision >= 1", name="ck_dev_bundle_revision"),
)

development_catalog_entries = Table(
    "development_catalog_entries",
    metadata,
    Column("procedure_id", String(200), primary_key=True),
    Column("registry_revision", BigInteger, nullable=False),
    Column("current_bundle_digest", String(64)),
    Column("previous_bundle_digest", String(64)),
    Column("state", String(24), nullable=False),
    Column("updated_by_subject", String(200), nullable=False),
    _time("created_at_database_time"),
    _time("updated_at_database_time"),
)

development_promotion_decisions = Table(
    "development_promotion_decisions",
    metadata,
    Column("decision_id", String(128), primary_key=True),
    Column("procedure_id", String(200), nullable=False),
    Column("registry_revision", BigInteger, nullable=False),
    Column("operation", String(32), nullable=False),
    Column("previous_bundle_digest", String(64)),
    Column("new_bundle_digest", String(64)),
    Column("actor_subject", String(200), nullable=False),
    Column("reason", Text, nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint(
        "procedure_id", "registry_revision", name="uq_dev_decision_revision"
    ),
)

development_runtime_pins = Table(
    "development_runtime_pins",
    metadata,
    Column("pin_id", String(128), primary_key=True),
    Column("runtime_kind", String(24), nullable=False),
    Column("runtime_id", String(128), nullable=False),
    Column("procedure_id", String(200), nullable=False),
    Column("bundle_digest", String(64), nullable=False),
    _time("created_at_database_time"),
    UniqueConstraint("runtime_kind", "runtime_id", name="uq_dev_runtime_pin"),
)

NEW_TABLES = tuple(metadata.sorted_tables)
DEVELOPMENT_TABLE_NAMES = tuple(sorted(table.name for table in NEW_TABLES))


def _normalized_sql(value: Any) -> str | None:
    if value is None:
        return None
    result = re.sub(r"\s+", " ", str(value).strip()).upper()
    while result.startswith("(") and result.endswith(")"):
        candidate = result[1:-1].strip()
        depth = 0
        balanced = True
        for character in candidate:
            depth += character == "("
            depth -= character == ")"
            if depth < 0:
                balanced = False
                break
        if not balanced or depth != 0:
            break
        result = candidate
    return result


def _normalized_check_sql(value: Any) -> str | None:
    result = _normalized_sql(value)
    if result is None:
        return None

    # PostgreSQL rewrites equivalent IN and BETWEEN constraints while storing
    # them in pg_constraint. Normalize those server-owned representations back
    # to the migration-authored logical form before comparing structures.
    result = re.sub(
        r"::(?:CHARACTER VARYING|TEXT)(?:\[\])?",
        "",
        result,
    )
    any_match = re.fullmatch(r"(.+?) = ANY \(ARRAY\[(.*)\]\)", result)
    if any_match is not None:
        result = f"{any_match.group(1)} IN ({any_match.group(2)})"
    result = re.sub(r",\s+", ",", result)
    between_match = re.fullmatch(
        r"([A-Z_][A-Z0-9_]*) >= (.+?) AND \1 <= (.+)", result
    )
    if between_match is not None:
        result = (
            f"{between_match.group(1)} BETWEEN "
            f"{between_match.group(2)} AND {between_match.group(3)}"
        )
    return _normalized_sql(result)


def _type_sql(value: Any, connection: Connection) -> str:
    try:
        compiled = value.compile(dialect=connection.dialect)
    except AttributeError:
        compiled = value
    return str(_normalized_sql(compiled))


def _expected_structure(connection: Connection, table: Table) -> dict[str, Any]:
    foreign_keys = []
    for constraint in table.foreign_key_constraints:
        foreign_keys.append(
            (
                tuple(element.parent.name for element in constraint.elements),
                constraint.referred_table.schema,
                constraint.referred_table.name,
                tuple(element.column.name for element in constraint.elements),
                _normalized_sql(constraint.ondelete) or "RESTRICT",
                _normalized_sql(constraint.onupdate) or "RESTRICT",
            )
        )
    unique_constraints = sorted(
        (
            constraint.name,
            tuple(column.name for column in constraint.columns),
        )
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    checks = sorted(
        (constraint.name, _normalized_check_sql(constraint.sqltext))
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    )
    indexes = sorted(
        (index.name, bool(index.unique), tuple(column.name for column in index.columns))
        for index in table.indexes
    )
    return {
        "checks": checks,
        "columns": [
            {
                "default": _normalized_sql(
                    column.server_default.arg if column.server_default is not None else None
                ),
                "name": column.name,
                "nullable": bool(column.nullable),
                "type": _type_sql(column.type, connection),
            }
            for column in table.columns
        ],
        "foreign_keys": sorted(foreign_keys),
        "indexes": indexes,
        "primary_key": tuple(column.name for column in table.primary_key.columns),
        "unique_constraints": unique_constraints,
    }


def _actual_structure(connection: Connection, table_name: str) -> dict[str, Any]:
    inspector = inspect(connection)
    foreign_keys = sorted(
        (
            tuple(item.get("constrained_columns") or ()),
            item.get("referred_schema"),
            item.get("referred_table"),
            tuple(item.get("referred_columns") or ()),
            _normalized_sql((item.get("options") or {}).get("ondelete")) or "RESTRICT",
            _normalized_sql((item.get("options") or {}).get("onupdate")) or "RESTRICT",
        )
        for item in inspector.get_foreign_keys(table_name)
    )
    unique_constraints = sorted(
        (
            item.get("name"),
            tuple(item.get("column_names") or ()),
        )
        for item in inspector.get_unique_constraints(table_name)
    )
    checks = sorted(
        (item.get("name"), _normalized_check_sql(item.get("sqltext")))
        for item in inspector.get_check_constraints(table_name)
    )
    indexes = sorted(
        (
            item.get("name"),
            bool(item.get("unique")),
            tuple(item.get("column_names") or ()),
        )
        for item in inspector.get_indexes(table_name)
        if not item.get("duplicates_constraint")
    )
    return {
        "checks": checks,
        "columns": [
            {
                "default": _normalized_sql(column.get("default")),
                "name": column["name"],
                "nullable": bool(column["nullable"]),
                "type": _type_sql(column["type"], connection),
            }
            for column in inspector.get_columns(table_name)
        ],
        "foreign_keys": foreign_keys,
        "indexes": indexes,
        "primary_key": tuple(
            inspector.get_pk_constraint(table_name).get("constrained_columns") or ()
        ),
        "unique_constraints": unique_constraints,
    }


def _logical_schema_payload() -> dict[str, Any]:
    return {
        "bundle_immutability": {
            "delete_forbidden": True,
            "immutable_columns": BUNDLE_IMMUTABLE_COLUMNS,
        },
        "schema_version": SCHEMA_FINGERPRINT_VERSION,
        "tables": [
            {
                "checks": sorted(
                    (constraint.name, _normalized_sql(constraint.sqltext))
                    for constraint in table.constraints
                    if isinstance(constraint, CheckConstraint)
                ),
                "columns": [
                    (
                        column.name,
                        column.type.__class__.__name__,
                        getattr(column.type, "length", None),
                        bool(column.nullable),
                    )
                    for column in table.columns
                ],
                "foreign_keys": sorted(
                    (
                        tuple(element.parent.name for element in constraint.elements),
                        constraint.referred_table.name,
                        tuple(element.column.name for element in constraint.elements),
                        constraint.ondelete or "RESTRICT",
                    )
                    for constraint in table.foreign_key_constraints
                ),
                "name": table.name,
                "primary_key": tuple(column.name for column in table.primary_key.columns),
                "unique_constraints": sorted(
                    (constraint.name, tuple(column.name for column in constraint.columns))
                    for constraint in table.constraints
                    if isinstance(constraint, UniqueConstraint)
                ),
            }
            for table in sorted(NEW_TABLES, key=lambda item: item.name)
        ],
    }


MIGRATION_SCHEMA_FINGERPRINT = hashlib.sha256(
    json.dumps(
        _logical_schema_payload(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
).hexdigest()


def _predecessor_is_applied(connection: Connection) -> bool:
    if "schema_migrations" not in inspect(connection).get_table_names():
        return False
    row = connection.execute(
        text("SELECT 1 FROM schema_migrations WHERE version = :version"),
        {"version": REQUIRED_PREDECESSOR},
    ).first()
    return row is not None


def _install_bundle_immutability(connection: Connection) -> None:
    if connection.dialect.name == "sqlite":
        columns = ", ".join(BUNDLE_IMMUTABLE_COLUMNS)
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_dev_bundle_immutable_update "
            f"BEFORE UPDATE OF {columns} ON development_bundles "
            "BEGIN SELECT RAISE(ABORT, 'development bundle payload is immutable'); END"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_dev_bundle_immutable_delete "
            "BEFORE DELETE ON development_bundles "
            "BEGIN SELECT RAISE(ABORT, 'development bundle retention forbids deletion'); END"
        )
        return
    comparisons = " OR ".join(
        (
            f"NEW.{column}::text IS DISTINCT FROM OLD.{column}::text"
            if column == "manifest"
            else f"NEW.{column} IS DISTINCT FROM OLD.{column}"
        )
        for column in BUNDLE_IMMUTABLE_COLUMNS
    )
    connection.exec_driver_sql(
        "CREATE OR REPLACE FUNCTION spell_dev_bundle_immutable_guard() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP = 'DELETE' THEN "
        "RAISE EXCEPTION 'development bundle retention forbids deletion' "
        "USING ERRCODE = '23514'; END IF; "
        f"IF {comparisons} THEN "
        "RAISE EXCEPTION 'development bundle payload is immutable' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$"
    )
    connection.exec_driver_sql(
        "CREATE TRIGGER trg_dev_bundle_immutable_update "
        "BEFORE UPDATE ON development_bundles FOR EACH ROW "
        "EXECUTE FUNCTION spell_dev_bundle_immutable_guard()"
    )
    connection.exec_driver_sql(
        "CREATE TRIGGER trg_dev_bundle_immutable_delete "
        "BEFORE DELETE ON development_bundles FOR EACH ROW "
        "EXECUTE FUNCTION spell_dev_bundle_immutable_guard()"
    )


def _bundle_immutability_triggers(connection: Connection) -> frozenset[str]:
    if connection.dialect.name == "sqlite":
        rows = connection.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = 'development_bundles'"
            )
        ).all()
    else:
        rows = connection.execute(
            text(
                "SELECT trigger_name FROM information_schema.triggers "
                "WHERE event_object_schema = current_schema() "
                "AND event_object_table = 'development_bundles'"
            )
        ).all()
    return frozenset(str(row[0]) for row in rows)


def upgrade(connection: Connection) -> None:
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("v0.9 development migration backend is unsupported")
    if not _predecessor_is_applied(connection):
        raise RuntimeError(
            "v0.9 development migration requires 0007_data_local_service"
        )
    existing = set(inspect(connection).get_table_names())
    collisions = sorted(existing.intersection(DEVELOPMENT_TABLE_NAMES))
    if collisions:
        raise RuntimeError(
            f"v0.9 development schema already contains unmanaged tables: {collisions!r}"
        )
    metadata.create_all(connection, tables=list(NEW_TABLES), checkfirst=False)
    _install_bundle_immutability(connection)
    verify(connection)


def verify(connection: Connection) -> None:
    inspector = inspect(connection)
    existing = set(inspector.get_table_names())
    missing = sorted(set(DEVELOPMENT_TABLE_NAMES).difference(existing))
    if missing:
        raise RuntimeError(f"v0.9 development schema is incomplete: {missing!r}")
    for table in NEW_TABLES:
        expected = _expected_structure(connection, table)
        actual = _actual_structure(connection, table.name)
        if actual != expected:
            raise RuntimeError(
                f"v0.9 development table {table.name} structure differs"
            )
    if _bundle_immutability_triggers(connection) != BUNDLE_IMMUTABILITY_TRIGGERS:
        raise RuntimeError("v0.9 development bundle immutability triggers differ")


__all__ = [
    "BUNDLE_IMMUTABILITY_TRIGGERS",
    "BUNDLE_IMMUTABLE_COLUMNS",
    "DEVELOPMENT_TABLE_NAMES",
    "MIGRATION_SCHEMA_FINGERPRINT",
    "NEW_TABLES",
    "REQUIRED_PREDECESSOR",
    "SCHEMA_FINGERPRINT_VERSION",
    "VERSION",
    "metadata",
    "upgrade",
    "verify",
]
