from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import MetaData, Table, create_engine, inspect

from backend.database import create_database
from backend.driver_domain import CAPABILITY_MATRIX
from backend.driver_repository import (
    DEFAULT_PROFILE_ID,
    CapabilitySpec,
    DriverRepository,
)
from backend.migrations import database_version, run_migrations
from backend.migrations.rollback import (
    UnsafeDriverRollbackError,
    rollback_driver_foundation,
)
from backend.tests.test_migrations import (
    V03_TABLES,
    canonical_v03_snapshot,
    seed_populated_v03_schema,
)


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _uid(value: int) -> str:
    return str(UUID(int=value))


def _all_table_snapshot(engine) -> dict[str, list[dict[str, object]]]:
    snapshot: dict[str, list[dict[str, object]]] = {}
    with engine.connect() as connection:
        for table_name in sorted(inspect(connection).get_table_names()):
            table = Table(table_name, MetaData(), autoload_with=connection)
            ordering = tuple(table.primary_key.columns)
            statement = table.select()
            if ordering:
                statement = statement.order_by(*ordering)
            snapshot[table_name] = [
                dict(row) for row in connection.execute(statement).mappings()
            ]
    return snapshot


def _repository_with_host(path: Path) -> tuple[DriverRepository, object]:
    engine, factory = create_database(f"sqlite:///{path.as_posix()}")
    run_migrations(engine)
    repository = DriverRepository(factory)
    repository.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="backup-test",
        correlation_id=_uid(700),
    )
    capabilities = tuple(
        CapabilitySpec(
            service=item.service,
            method=item.method.value,
            mutability=item.mutability,
            modifiers=item.modifiers,
            formats=(item.format,),
            stream_support=item.stream_support,
        )
        for item in CAPABILITY_MATRIX
    )
    repository.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=_uid(701),
        contract_version="1.0",
        implementation_version="0.4.0-test",
        capabilities=capabilities,
        actor="backup-test",
        correlation_id=_uid(702),
    )
    repository.record_host_state(
        _uid(701),
        "READY",
        expected_revision=0,
        actor="backup-test",
        correlation_id=_uid(703),
        observed_at=NOW,
    )
    return repository, engine


def _accept(repository: DriverRepository, number: int) -> dict[str, object]:
    return repository.accept_operation(
        operation_id=_uid(720 + number * 2),
        attempt_id=_uid(721 + number * 2),
        method="DrainHost",
        request_digest=f"{number:x}" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=_uid(701),
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="backup-test",
        correlation_id=_uid(740 + number),
        deadline_at=NOW + timedelta(minutes=1),
    )


def _transition(
    repository: DriverRepository,
    number: int,
    current: dict[str, object],
    *,
    stage: str,
    certainty: str,
    disposition: str | None = None,
) -> dict[str, object]:
    return repository.append_operation_transition(
        _uid(720 + number * 2),
        _uid(721 + number * 2),
        expected_revision=int(current["revision"]),
        stage=stage,
        certainty=certainty,
        disposition=disposition,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest=f"{number:x}" * 64,
        actor="backup-test",
        correlation_id=_uid(750 + number),
        terminal_observed_at=NOW if stage == "SETTLED" else None,
    )


def _seed_operation_truth_table(repository: DriverRepository) -> None:
    _accept(repository, 1)

    dispatched = _accept(repository, 2)
    _transition(
        repository,
        2,
        dispatched,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
    )

    possible = _accept(repository, 3)
    possible = _transition(
        repository,
        3,
        possible,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
    )
    _transition(
        repository,
        3,
        possible,
        stage="RECONCILING",
        certainty="EFFECT_POSSIBLE",
        disposition="RESPONSE_LOST",
    )

    unknown = _accept(repository, 4)
    unknown = _transition(
        repository,
        4,
        unknown,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
    )
    _transition(
        repository,
        4,
        unknown,
        stage="RECONCILING",
        certainty="EFFECT_UNKNOWN",
        disposition="JOURNAL_UNAVAILABLE",
    )

    confirmed = _accept(repository, 5)
    confirmed = _transition(
        repository,
        5,
        confirmed,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
    )
    _transition(
        repository,
        5,
        confirmed,
        stage="SETTLED",
        certainty="EFFECT_CONFIRMED",
        disposition="OK",
    )

    no_effect = _accept(repository, 6)
    _transition(
        repository,
        6,
        no_effect,
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
    )


def test_sqlite_backup_restore_retains_truth_table_tombstones_and_rejects_unsafe_rollback(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "project.sqlite"
    backup_path = tmp_path / "project.backup.sqlite"
    restored_path = tmp_path / "project.restored.sqlite"
    repository, engine = _repository_with_host(source_path)
    _seed_operation_truth_table(repository)
    expected = _all_table_snapshot(engine)

    source = engine.raw_connection()
    backup = sqlite3.connect(backup_path)
    try:
        source.driver_connection.backup(backup)
    finally:
        backup.close()
        source.close()
        engine.dispose()

    with sqlite3.connect(backup_path) as backup, sqlite3.connect(restored_path) as restored:
        backup.backup(restored)
    restored_engine = create_engine(f"sqlite:///{restored_path.as_posix()}")
    try:
        assert _all_table_snapshot(restored_engine) == expected
        with pytest.raises(UnsafeDriverRollbackError, match="driver"):
            rollback_driver_foundation(restored_engine)
        assert _all_table_snapshot(restored_engine) == expected

        restored_repository = DriverRepository(
            create_database(f"sqlite:///{restored_path.as_posix()}")[1]
        )
        before = _all_table_snapshot(restored_engine)
        replayed = _accept(restored_repository, 2)
        assert replayed["stage"] == "DISPATCHED"
        assert replayed["certainty"] == "EFFECT_POSSIBLE"
        assert _all_table_snapshot(restored_engine) == before
    finally:
        restored_engine.dispose()


def test_safe_rollback_restores_exact_populated_v03_records_and_revision(
    tmp_path: Path,
) -> None:
    path = tmp_path / "safe-rollback.sqlite"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    seed_populated_v03_schema(engine)
    expected = canonical_v03_snapshot(engine)
    assert run_migrations(engine) == ("0003_driver_foundation",)

    dropped = rollback_driver_foundation(engine)

    assert dropped
    assert database_version(engine) == "0002_execution_variables"
    assert canonical_v03_snapshot(engine) == expected
    assert not set(dropped).intersection(V03_TABLES)
    assert not set(dropped).intersection(inspect(engine).get_table_names())
