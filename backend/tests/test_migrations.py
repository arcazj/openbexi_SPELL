from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

import backend.migrations as migration_runner
from backend.database import Base
from backend.migrations import database_version, run_migrations


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


def test_migrations_create_fresh_schema_and_are_idempotent(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")

    assert run_migrations(engine) == ("0001_initial", "0002_execution_variables")
    assert run_migrations(engine) == ()
    assert database_version(engine) == "0002_execution_variables"
    tables = set(inspect(engine).get_table_names())
    assert {"schema_migrations", "executions", "events", "commands", "prompts"} <= tables


def test_migrations_upgrade_populated_v02_sqlite_database(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    seed_populated_v02_schema(engine)

    run_migrations(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("executions")}
    assert {"variables", "ir_version"} <= columns
    assert_v02_records_preserved(engine)


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


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_migrations_upgrade_populated_v02_postgresql_database() -> None:
    database_url = os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"]
    assert make_url(database_url).database == "spell_migration_test"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE IF EXISTS schema_migrations CASCADE")
        connection.exec_driver_sql("DROP TABLE IF EXISTS prompts CASCADE")
        connection.exec_driver_sql("DROP TABLE IF EXISTS commands CASCADE")
        connection.exec_driver_sql("DROP TABLE IF EXISTS events CASCADE")
        connection.exec_driver_sql("DROP TABLE IF EXISTS executions CASCADE")
    seed_populated_v02_schema(engine)

    run_migrations(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("executions")}
    assert {"variables", "ir_version"} <= columns
    assert_v02_records_preserved(engine)
