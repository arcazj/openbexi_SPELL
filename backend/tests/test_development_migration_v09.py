from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from backend.migrations.versions import v0008_development_environment as migration


def _predecessor(engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE schema_migrations ("
            "version VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL)"
        )
        connection.execute(
            text(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (:version, CURRENT_TIMESTAMP)"
            ),
            {"version": migration.REQUIRED_PREDECESSOR},
        )


@pytest.mark.parametrize(
    ("authored", "reflected"),
    (
        (
            "case_policy IN ('CASE_SENSITIVE','CASE_INSENSITIVE')",
            "case_policy::text = ANY (ARRAY['CASE_SENSITIVE'::character varying, "
            "'CASE_INSENSITIVE'::character varying]::text[])",
        ),
        (
            "status IN ('QUARANTINED','APPLYING','APPLIED')",
            "status::text = ANY (ARRAY['QUARANTINED'::character varying, "
            "'APPLYING'::character varying, 'APPLIED'::character varying]::text[])",
        ),
        ("progress BETWEEN 0 AND 100", "progress >= 0 AND progress <= 100"),
    ),
)
def test_v0008_normalizes_equivalent_postgresql_check_reflection(
    authored: str, reflected: str
) -> None:
    assert migration._normalized_check_sql(reflected) == migration._normalized_check_sql(
        authored
    )


def test_v0008_is_static_and_verifies_complete_sqlite_structure(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'development.sqlite').as_posix()}")
    _predecessor(engine)

    with engine.begin() as connection:
        migration.upgrade(connection)
        migration.verify(connection)

    assert set(migration.DEVELOPMENT_TABLE_NAMES) <= set(inspect(engine).get_table_names())
    assert len(migration.DEVELOPMENT_TABLE_NAMES) == 19
    assert len(migration.MIGRATION_SCHEMA_FINGERPRINT) == 64
    assert "development_models" not in Path(migration.__file__).read_text(encoding="utf-8")


def test_v0008_rejects_collision_and_structural_tamper(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'collision.sqlite').as_posix()}")
    _predecessor(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE development_projects (project_id VARCHAR(128) PRIMARY KEY)"
        )
        with pytest.raises(RuntimeError, match="unmanaged tables"):
            migration.upgrade(connection)
    assert "development_resources" not in inspect(engine).get_table_names()

    clean = create_engine(f"sqlite:///{(tmp_path / 'tamper.sqlite').as_posix()}")
    _predecessor(clean)
    with clean.begin() as connection:
        migration.upgrade(connection)
        connection.exec_driver_sql("DROP INDEX ix_dev_resource_project_path")
        with pytest.raises(RuntimeError, match="structure differs"):
            migration.verify(connection)


def test_v0008_requires_predecessor_and_repeat_upgrade_is_rejected() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE schema_migrations ("
            "version VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL)"
        )
        with pytest.raises(RuntimeError, match="requires 0007"):
            migration.upgrade(connection)
        connection.execute(
            text(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (:version, CURRENT_TIMESTAMP)"
            ),
            {"version": migration.REQUIRED_PREDECESSOR},
        )
        migration.upgrade(connection)
        with pytest.raises(RuntimeError, match="unmanaged tables"):
            migration.upgrade(connection)
