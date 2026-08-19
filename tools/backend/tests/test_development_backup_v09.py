from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.data_backup import (
    BackupCorruptionError,
    _aggregate_digest,
    canonical_backup_manifest_bytes,
    create_sqlite_backup,
    restore_sqlite_backup,
    verify_backup_bundle,
)
from backend.development_service import DevelopmentService
from backend.migrations import MIGRATIONS, run_migrations


def _current_service(tmp_path: Path) -> tuple[DevelopmentService, object]:
    engine = create_engine(f"sqlite:///{(tmp_path / 'source.sqlite').as_posix()}")
    migration_backups = tmp_path / "migration-backups"
    migration_backups.mkdir()
    run_migrations(engine, v0007_backup_directory=migration_backups)
    return DevelopmentService(sessionmaker(engine, expire_on_commit=False)), engine


def test_v09_backup_restore_preserves_development_state_and_rejects_schema_tamper(
    tmp_path: Path,
) -> None:
    service, engine = _current_service(tmp_path)
    project = service.create_project(
        subject="author@example.com",
        role="operator",
        name="Backed up project",
        case_policy="CASE_INSENSITIVE",
        manifest=None,
        idempotency_key="create-backup-project",
    )["project"]
    source = "# @procedure local/backup\nLog('persisted')\n"
    service.create_resource(
        project["project_id"],
        subject="author@example.com",
        role="operator",
        path="procedures/backup.spell.py",
        kind="PROCEDURE",
        media_type="text/x-python",
        content=source,
        content_sha256=hashlib.sha256(source.encode()).hexdigest(),
        expected_workspace_revision=1,
        idempotency_key="create-backup-source",
    )

    bundle = tmp_path / "backup"
    manifest = create_sqlite_backup(engine, bundle)
    assert manifest["migration_head"] == MIGRATIONS[-1].VERSION
    assert verify_backup_bundle(bundle) == manifest

    restored = tmp_path / "restored"
    assert restore_sqlite_backup(bundle, restored) == manifest
    restored_engine = create_engine(
        f"sqlite:///{(restored / 'database.sqlite').as_posix()}"
    )
    try:
        restored_service = DevelopmentService(
            sessionmaker(restored_engine, expire_on_commit=False)
        )
        workspace = restored_service.workspace_snapshot(
            project["project_id"], subject="viewer@example.com", role="viewer"
        )["workspace"]
        assert workspace["project"]["workspace_revision"] == 2
        assert [item["path"] for item in workspace["resources"]] == [
            "procedures",
            "procedures/backup.spell.py",
            "spell-project.yaml",
        ]
    finally:
        restored_engine.dispose()

    tampered = tmp_path / "tampered"
    shutil.copytree(bundle, tampered)
    with sqlite3.connect(tampered / "database.sqlite") as connection:
        connection.execute("DROP INDEX ix_dev_problem_sort")
    manifest_path = tampered / "manifest.json"
    tampered_manifest = json.loads(manifest_path.read_bytes())
    database_bytes = (tampered / "database.sqlite").read_bytes()
    for item in tampered_manifest["file_inventory"]:
        if item["path"] == "database.sqlite":
            item["size"] = len(database_bytes)
    tampered_manifest["file_sha256"]["database.sqlite"] = hashlib.sha256(
        database_bytes
    ).hexdigest()
    tampered_manifest["aggregate_sha256"] = _aggregate_digest(
        tampered_manifest["file_inventory"], tampered_manifest["file_sha256"]
    )
    manifest_path.write_bytes(canonical_backup_manifest_bytes(tampered_manifest))
    with pytest.raises(BackupCorruptionError, match="verification failed"):
        verify_backup_bundle(tampered)
