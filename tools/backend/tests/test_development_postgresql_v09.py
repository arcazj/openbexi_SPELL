from __future__ import annotations

import hashlib
import os
import re
import threading

import pytest
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from backend.development_bundle_builder import InProcessDualBundleBuilder
from backend.development_domain import DevelopmentConflictError
from backend.development_models import DevelopmentResource
from backend.development_service import DevelopmentService
from backend.migrations import MIGRATIONS, database_version
from backend.migrations.versions import v0008_development_environment as migration
from backend.tests.migration_support import reset_test_database, run_migrations
from backend.tests.test_development_runtime_race_v09 import _promote
from backend.tests.test_development_service_v09 import OPERATOR, _create_project


POSTGRES_URL = os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL")
postgres_required = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="dedicated PostgreSQL migration database not configured",
)


def _postgres_engine():
    assert POSTGRES_URL is not None
    assert make_url(POSTGRES_URL).database == "spell_migration_test"
    return create_engine(POSTGRES_URL, pool_pre_ping=True)


def _reset(engine) -> None:
    reset_test_database(engine)


@postgres_required
def test_v0008_postgresql_schema_and_logical_fingerprint_match_contract() -> None:
    engine = _postgres_engine()
    _reset(engine)
    try:
        applied = run_migrations(engine)
        assert migration.VERSION in applied
        assert applied[-1] == MIGRATIONS[-1].VERSION
        assert database_version(engine) == MIGRATIONS[-1].VERSION
        with engine.connect() as connection:
            migration.verify(connection)
            for table in migration.NEW_TABLES:
                assert migration._actual_structure(
                    connection, table.name
                ) == migration._expected_structure(connection, table)
        assert set(migration.DEVELOPMENT_TABLE_NAMES).issubset(
            inspect(engine).get_table_names(schema="public")
        )
        assert re.fullmatch(r"[0-9a-f]{64}", migration.MIGRATION_SCHEMA_FINGERPRINT)
    finally:
        _reset(engine)
        engine.dispose()


@postgres_required
def test_postgresql_development_idempotency_race_and_catalog_promotion() -> None:
    engine = _postgres_engine()
    _reset(engine)
    run_migrations(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    service = DevelopmentService(factory, bundle_builder=InProcessDualBundleBuilder())
    try:
        project = _create_project(service, "PostgreSQL race")
        source = "# @procedure local/pg-race\nLog('postgres')\n"
        digest = hashlib.sha256(source.encode()).hexdigest()
        barrier = threading.Barrier(2)
        results: list[object] = []

        def create() -> None:
            barrier.wait()
            try:
                results.append(
                    service.create_resource(
                        project["project_id"],
                        **OPERATOR,
                        path="procedures/pg-race.spell.py",
                        kind="PROCEDURE",
                        media_type="text/x-python",
                        content=source,
                        content_sha256=digest,
                        expected_workspace_revision=1,
                        idempotency_key="postgres-same-key",
                    )
                )
            except Exception as exc:
                results.append(exc)

        threads = [threading.Thread(target=create) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            assert not thread.is_alive()
        successful = [item for item in results if not isinstance(item, Exception)]
        failures = [item for item in results if isinstance(item, Exception)]
        assert len(successful) >= 1
        assert all(isinstance(item, DevelopmentConflictError) for item in failures)
        while len(successful) < 2:
            replay = service.create_resource(
                project["project_id"],
                **OPERATOR,
                path="procedures/pg-race.spell.py",
                kind="PROCEDURE",
                media_type="text/x-python",
                content=source,
                content_sha256=digest,
                expected_workspace_revision=1,
                idempotency_key="postgres-same-key",
            )
            successful.append(replay)
        assert sorted(item["replayed"] for item in successful) == [False, True]
        with factory() as session:
            assert session.scalar(
                select(func.count()).select_from(DevelopmentResource).where(
                    DevelopmentResource.project_id == project["project_id"],
                    DevelopmentResource.path == "procedures/pg-race.spell.py",
                )
            ) == 1

        _, bundle = _promote(service)
        catalog = service.get_catalog_entry(
            "local/runtime", subject="viewer", role="viewer"
        )["catalog_entry"]
        assert catalog["state"] == "PROMOTED"
        assert catalog["current_bundle_digest"] == bundle["bundle_digest"]
    finally:
        _reset(engine)
        engine.dispose()
