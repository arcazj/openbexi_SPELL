from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import (
    CheckConstraint,
    Index,
    MetaData,
    Table,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.engine import make_url

import backend.migrations as migration_runner
from backend.database import Base
from backend.migrations import database_version, run_migrations, schema_migrations
from backend.migrations.versions import (
    v0001_initial,
    v0002_execution_variables,
    v0003_driver_foundation,
    v0004_operator_workspace,
)


DRIVER_TABLES = tuple(
    table.name for table in v0003_driver_foundation.metadata.sorted_tables
)
OPERATOR_TABLES = tuple(
    table.name for table in v0004_operator_workspace.NEW_TABLES
)
V03_TABLES = ("executions", "events", "commands", "prompts")


def reset_migration_database(engine) -> None:
    with engine.begin() as connection:
        for table in reversed(OPERATOR_TABLES):
            connection.exec_driver_sql(f"DROP TABLE IF EXISTS {table} CASCADE")
        for table in reversed(DRIVER_TABLES):
            connection.exec_driver_sql(f"DROP TABLE IF EXISTS {table} CASCADE")
        for table in (
            "schema_migrations",
            "prompts",
            "commands",
            "events",
            "executions",
        ):
            connection.exec_driver_sql(f"DROP TABLE IF EXISTS {table} CASCADE")


def assert_driver_schema_contract(engine) -> None:
    """Prove the static migration reflects the same contract on each dialect."""

    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    assert set(DRIVER_TABLES) <= actual_tables
    for expected in v0003_driver_foundation.metadata.sorted_tables:
        table_name = expected.name
        actual_columns = {item["name"]: item for item in inspector.get_columns(table_name)}
        assert set(actual_columns) == set(expected.columns.keys())
        assert {
            name for name, column in actual_columns.items() if not column["nullable"]
        } == {
            column.name for column in expected.columns if not column.nullable
        }
        assert set(inspector.get_pk_constraint(table_name)["constrained_columns"]) == {
            column.name for column in expected.primary_key.columns
        }

        expected_unique = {
            tuple(column.name for column in constraint.columns)
            for constraint in expected.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        actual_unique = {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(table_name)
        }
        assert expected_unique <= actual_unique
        expected_named_unique = {
            constraint.name
            for constraint in expected.constraints
            if isinstance(constraint, UniqueConstraint) and constraint.name is not None
        }
        actual_named_unique = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints(table_name)
        }
        assert expected_named_unique <= actual_named_unique

        expected_checks = {
            constraint.name
            for constraint in expected.constraints
            if isinstance(constraint, CheckConstraint)
        }
        actual_checks = {
            constraint["name"]
            for constraint in inspector.get_check_constraints(table_name)
        }
        assert expected_checks <= actual_checks

        expected_foreign_keys = {
            (
                tuple(column.name for column in constraint.columns),
                constraint.referred_table.name,
                tuple(element.column.name for element in constraint.elements),
            )
            for constraint in expected.foreign_key_constraints
        }
        actual_foreign_keys = {
            (
                tuple(constraint["constrained_columns"]),
                constraint["referred_table"],
                tuple(constraint["referred_columns"]),
            )
            for constraint in inspector.get_foreign_keys(table_name)
        }
        assert expected_foreign_keys == actual_foreign_keys

        expected_indexes = {
            (index.name, tuple(column.name for column in index.columns))
            for index in expected.indexes
            if isinstance(index, Index)
        }
        actual_indexes = {
            (index["name"], tuple(index["column_names"]))
            for index in inspector.get_indexes(table_name)
            if not index.get("duplicates_constraint")
        }
        assert expected_indexes <= actual_indexes

    with engine.connect() as connection:
        profile = connection.execute(
            text(
                "SELECT id, server_profile_id, logical_driver_id, simulator, enabled, "
                "contract_package, configuration_schema_version, configuration_digest, "
                "credential_reference, credential_epoch, max_contexts_per_host, "
                "max_attachments_per_context, max_lifecycle_operations_per_host, "
                "max_lifecycle_operations_per_context, journal_max_entries, "
                "journal_max_bytes, revision FROM driver_profiles"
            )
        ).mappings().one()
    assert dict(profile) == {
        "id": "local-synthetic-simulator",
        "server_profile_id": "local-synthetic",
        "logical_driver_id": "bundled-deterministic-simulator",
        "simulator": True,
        "enabled": False,
        "contract_package": "spell.driver.v1",
        "configuration_schema_version": "spell.driver.host-profile/1",
        "configuration_digest": (
            "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
        ),
        "credential_reference": "local-v04-driver-mtls",
        "credential_epoch": 1,
        "max_contexts_per_host": 1,
        "max_attachments_per_context": 1,
        "max_lifecycle_operations_per_host": 8,
        "max_lifecycle_operations_per_context": 8,
        "journal_max_entries": 10_000,
        "journal_max_bytes": 16_777_216,
        "revision": 0,
    }


def assert_operator_schema_contract(engine) -> None:
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    assert set(OPERATOR_TABLES) <= actual_tables
    for expected in v0004_operator_workspace.NEW_TABLES:
        table_name = expected.name
        actual_columns = {item["name"]: item for item in inspector.get_columns(table_name)}
        assert set(actual_columns) == set(expected.columns.keys())
        assert {
            name for name, column in actual_columns.items() if not column["nullable"]
        } == {
            column.name for column in expected.columns if not column.nullable
        }
        assert set(inspector.get_pk_constraint(table_name)["constrained_columns"]) == {
            column.name for column in expected.primary_key.columns
        }
        expected_foreign_keys = {
            (
                tuple(column.name for column in constraint.columns),
                constraint.referred_table.name,
                tuple(element.column.name for element in constraint.elements),
            )
            for constraint in expected.foreign_key_constraints
        }
        actual_foreign_keys = {
            (
                tuple(constraint["constrained_columns"]),
                constraint["referred_table"],
                tuple(constraint["referred_columns"]),
            )
            for constraint in inspector.get_foreign_keys(table_name)
        }
        assert expected_foreign_keys == actual_foreign_keys
        expected_checks = {
            constraint.name
            for constraint in expected.constraints
            if isinstance(constraint, CheckConstraint)
        }
        actual_checks = {
            constraint["name"]
            for constraint in inspector.get_check_constraints(table_name)
        }
        assert expected_checks <= actual_checks
    with engine.connect() as connection:
        context = connection.execute(
            text(
                "SELECT id, name, settings, revision "
                "FROM operator_contexts WHERE id='simulator'"
            )
        ).mappings().one()
    assert context["id"] == "simulator"
    assert context["name"] == "Local Synthetic Simulator"
    assert context["revision"] == 0


def seed_populated_v02_schema(engine) -> None:
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO executions "
            "(id, procedure_id, procedure_name, procedure_hash, procedure_source, steps, "
            "ir_version, variables, context_id, created_by, creation_idempotency_key, "
            "state, revision, current_step, total_steps, worker_generation, next_sequence, "
            "created_at, updated_at) VALUES "
            "('legacy-id', 'legacy-procedure', 'Legacy Procedure', "
            "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
            "'Log(''legacy'')', '[{\"type\":\"log\"}]', '0.2', '{}', 'simulator', "
            "'legacy.operator', 'legacy-create', 'completed', 3, 1, 1, 1, 2, "
            "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        connection.exec_driver_sql(
            "INSERT INTO events "
            "(id, execution_id, sequence, event_type, source, severity, payload, created_at) "
            "VALUES ('legacy-event', 'legacy-id', 1, 'step.log', 'supervisor', 'info', "
            "'{\"message\":\"legacy\"}', CURRENT_TIMESTAMP)"
        )
        connection.exec_driver_sql(
            "INSERT INTO commands "
            "(id, execution_id, command_type, status, idempotency_key, expected_revision, "
            "actor, role, reason, correlation_id, request_payload, result_payload, "
            "created_at, completed_at) VALUES "
            "('legacy-command', 'legacy-id', 'start', 'completed', 'legacy-start', 0, "
            "'legacy.operator', 'operator', 'legacy test', 'legacy-correlation', '{}', '{}', "
            "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        connection.exec_driver_sql(
            "INSERT INTO prompts "
            "(id, execution_id, step_index, status, question, choices, default_choice, "
            "response, responded_by, created_at, responded_at) VALUES "
            "('legacy-prompt', 'legacy-id', 0, 'responded', 'Continue?', '[\"yes\"]', "
            "'yes', 'yes', 'legacy.operator', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        connection.exec_driver_sql("ALTER TABLE executions DROP COLUMN variables")
        connection.exec_driver_sql("ALTER TABLE executions DROP COLUMN ir_version")


def assert_v02_records_preserved(engine) -> None:
    with engine.connect() as connection:
        execution = connection.execute(
            text(
                "SELECT procedure_hash, ir_version, variables "
                "FROM executions WHERE id = 'legacy-id'"
            )
        ).one()
        assert execution.procedure_hash == "a" * 64
        assert execution.ir_version == "0.2"
        variables = execution.variables
        normalized_variables = json.loads(variables) if isinstance(variables, str) else variables
        assert normalized_variables == {}
        assert connection.scalar(text("SELECT COUNT(*) FROM events WHERE id='legacy-event'")) == 1
        assert connection.scalar(
            text("SELECT COUNT(*) FROM commands WHERE id='legacy-command'")
        ) == 1
        assert connection.scalar(
            text("SELECT COUNT(*) FROM prompts WHERE id='legacy-prompt'")
        ) == 1


def seed_populated_v03_schema(engine) -> None:
    """Construct the accepted v0.3 schema without consulting the live ORM."""

    applied_at = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    with engine.begin() as connection:
        schema_migrations.create(connection, checkfirst=True)
        v0001_initial.upgrade(connection)
        connection.execute(
            schema_migrations.insert().values(
                version=v0001_initial.VERSION,
                applied_at=applied_at,
            )
        )
        v0002_execution_variables.upgrade(connection)
        connection.execute(
            schema_migrations.insert().values(
                version=v0002_execution_variables.VERSION,
                applied_at=applied_at,
            )
        )
        accepted_v03_executions = Table(
            "executions", MetaData(), autoload_with=connection
        )
        connection.execute(
            accepted_v03_executions.insert().values(
                id="v03-execution",
                procedure_id="accepted-v03-procedure",
                procedure_name="Accepted v0.3 Procedure",
                procedure_hash="3" * 64,
                procedure_source='Telemetry("SIM.TEMP")\nPrompt("Continue?")',
                steps=[
                    {"type": "telemetry", "channel": "SIM.TEMP"},
                    {"type": "prompt", "question": "Continue?"},
                ],
                context_id="simulator",
                created_by="v03.operator",
                creation_idempotency_key="v03-create-key",
                state="recovery_required",
                revision=7,
                current_step=1,
                total_steps=2,
                worker_generation=3,
                next_sequence=8,
                created_at=applied_at,
                updated_at=applied_at,
                ir_version="0.3",
                variables={"counter": 7, "enabled": True, "label": "checkpoint"},
            )
        )
        event_types = (
            "procedure.loaded",
            "execution.created",
            "telemetry.sampled",
            "prompt.opened",
            "execution.checkpointed",
            "audit.recorded",
            "recovery.required",
        )
        for sequence, event_type in enumerate(event_types, start=1):
            connection.execute(
                v0001_initial.events.insert().values(
                    id=f"v03-event-{sequence}",
                    execution_id="v03-execution",
                    sequence=sequence,
                    event_type=event_type,
                    source="supervisor",
                    severity="info",
                    correlation_id="00000000-0000-0000-0000-000000000901",
                    causation_id="00000000-0000-0000-0000-000000000902",
                    payload={
                        "sequence": sequence,
                        "checkpoint": {"counter": 7},
                        "report_fragment": event_type == "audit.recorded",
                    },
                    created_at=applied_at,
                )
            )
        connection.execute(
            v0001_initial.commands.insert().values(
                id="v03-command",
                execution_id="v03-execution",
                command_type="recover",
                status="completed",
                idempotency_key="v03-recover-key",
                expected_revision=6,
                actor="v03.operator",
                role="operator",
                reason="recover accepted v0.3 checkpoint",
                correlation_id="00000000-0000-0000-0000-000000000903",
                request_payload={"expected_revision": 6},
                result_payload={"state": "recovery_required"},
                created_at=applied_at,
                completed_at=applied_at,
            )
        )
        connection.execute(
            v0001_initial.prompts.insert().values(
                id="v03-prompt",
                execution_id="v03-execution",
                step_index=1,
                status="responded",
                question="Continue?",
                choices=["yes", "no"],
                default_choice="yes",
                response="yes",
                responded_by="v03.operator",
                created_at=applied_at,
                responded_at=applied_at,
            )
        )


def canonical_v03_snapshot(engine) -> dict[str, list[dict[str, object]]]:
    snapshot: dict[str, list[dict[str, object]]] = {}
    with engine.connect() as connection:
        for table_name in V03_TABLES:
            table = Table(table_name, MetaData(), autoload_with=connection)
            ordering = tuple(table.primary_key.columns)
            rows = connection.execute(table.select().order_by(*ordering)).mappings()
            snapshot[table_name] = [dict(row) for row in rows]
    return snapshot


def assert_populated_v03_upgrade_preserves_every_record(engine) -> None:
    seed_populated_v03_schema(engine)
    before = canonical_v03_snapshot(engine)

    assert run_migrations(engine) == (
        "0003_driver_foundation",
        "0004_operator_workspace",
    )
    assert canonical_v03_snapshot(engine) == before
    assert database_version(engine) == "0004_operator_workspace"
    assert_driver_schema_contract(engine)
    assert_operator_schema_contract(engine)
    with engine.connect() as connection:
        assert connection.scalar(
            text("SELECT COUNT(*) FROM driver_profiles WHERE enabled")
        ) == 0
        for table_name in DRIVER_TABLES:
            if table_name == "driver_profiles":
                continue
            assert connection.scalar(text(f"SELECT COUNT(*) FROM {table_name}")) == 0


def test_migrations_create_fresh_schema_and_are_idempotent(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")

    assert run_migrations(engine) == (
        "0001_initial",
        "0002_execution_variables",
        "0003_driver_foundation",
        "0004_operator_workspace",
    )
    assert run_migrations(engine) == ()
    assert database_version(engine) == "0004_operator_workspace"
    tables = set(inspect(engine).get_table_names())
    assert {"schema_migrations", "executions", "events", "commands", "prompts"} <= tables
    assert {
        "driver_profiles",
        "driver_host_generations",
        "driver_capabilities",
        "driver_contexts",
        "driver_context_generations",
        "driver_bindings",
        "driver_operations",
        "driver_operation_attempts",
        "driver_operation_transitions",
        "driver_audit_events",
        "driver_outbox",
    } <= tables
    assert_driver_schema_contract(engine)
    assert_operator_schema_contract(engine)


def test_migrations_upgrade_populated_v02_sqlite_database(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    seed_populated_v02_schema(engine)

    run_migrations(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("executions")}
    assert {"variables", "ir_version"} <= columns
    assert_v02_records_preserved(engine)
    assert_operator_schema_contract(engine)


def test_migrations_upgrade_populated_v03_sqlite_database_without_record_drift(
    tmp_path,
) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'accepted-v03.db').as_posix()}")
    assert_populated_v03_upgrade_preserves_every_record(engine)


def test_failed_migration_rolls_back_and_remains_pending(tmp_path, monkeypatch) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'rollback.db').as_posix()}")
    run_migrations(engine)

    def fail_after_write(connection) -> None:
        connection.execute(
            text(
                "INSERT INTO schema_migrations (version, applied_at) "
                "VALUES ('9998_transient_write', CURRENT_TIMESTAMP)"
            )
        )
        raise RuntimeError("controlled migration failure")

    failing = SimpleNamespace(VERSION="9999_controlled_failure", upgrade=fail_after_write)
    monkeypatch.setattr(
        migration_runner,
        "MIGRATIONS",
        (*migration_runner.MIGRATIONS, failing),
    )

    with pytest.raises(RuntimeError, match="controlled migration failure"):
        run_migrations(engine)

    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM schema_migrations "
                "WHERE version IN ('9998_transient_write', '9999_controlled_failure')"
            )
        ) == 0


@pytest.mark.parametrize(
    ("stored_versions", "expected_error"),
    [
        (("9999_future",), "unsupported migration versions"),
        (("0002_execution_variables",), "history is not a valid prefix"),
    ],
)
def test_migrations_reject_unknown_or_gapped_history(
    tmp_path, stored_versions: tuple[str, ...], expected_error: str
) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'invalid-history.db').as_posix()}")
    run_migrations(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM schema_migrations")
        for version in stored_versions:
            connection.execute(
                text(
                    "INSERT INTO schema_migrations (version, applied_at) "
                    "VALUES (:version, CURRENT_TIMESTAMP)"
                ),
                {"version": version},
            )

    with pytest.raises(RuntimeError, match=expected_error):
        run_migrations(engine)


def postgresql_migration_engine():
    database_url = os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"]
    assert make_url(database_url).database == "spell_migration_test"
    return create_engine(database_url)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_migrations_create_fresh_postgresql_schema_and_are_idempotent() -> None:
    engine = postgresql_migration_engine()
    reset_migration_database(engine)

    assert run_migrations(engine) == (
        "0001_initial",
        "0002_execution_variables",
        "0003_driver_foundation",
        "0004_operator_workspace",
    )
    assert run_migrations(engine) == ()
    assert database_version(engine) == "0004_operator_workspace"
    assert_driver_schema_contract(engine)
    assert_operator_schema_contract(engine)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_migrations_upgrade_populated_v02_postgresql_database() -> None:
    engine = postgresql_migration_engine()
    reset_migration_database(engine)
    seed_populated_v02_schema(engine)

    run_migrations(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("executions")}
    assert {"variables", "ir_version"} <= columns
    assert_v02_records_preserved(engine)
    assert_driver_schema_contract(engine)
    assert_operator_schema_contract(engine)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift() -> None:
    engine = postgresql_migration_engine()
    reset_migration_database(engine)
    assert_populated_v03_upgrade_preserves_every_record(engine)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_failed_postgresql_migration_rolls_back_and_remains_pending(
    monkeypatch,
) -> None:
    engine = postgresql_migration_engine()
    reset_migration_database(engine)
    run_migrations(engine)

    def fail_after_write(connection) -> None:
        connection.execute(
            text(
                "INSERT INTO schema_migrations (version, applied_at) "
                "VALUES ('9998_transient_write', CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "UPDATE driver_profiles SET enabled = TRUE "
                "WHERE id = 'local-synthetic-simulator'"
            )
        )
        raise RuntimeError("controlled PostgreSQL migration failure")

    failing = SimpleNamespace(VERSION="9999_controlled_failure", upgrade=fail_after_write)
    monkeypatch.setattr(
        migration_runner,
        "MIGRATIONS",
        (*migration_runner.MIGRATIONS, failing),
    )

    with pytest.raises(RuntimeError, match="controlled PostgreSQL migration failure"):
        run_migrations(engine)

    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM schema_migrations "
                "WHERE version IN ('9998_transient_write', '9999_controlled_failure')"
            )
        ) == 0
        assert connection.scalar(
            text(
                "SELECT enabled FROM driver_profiles "
                "WHERE id = 'local-synthetic-simulator'"
            )
        ) is False
