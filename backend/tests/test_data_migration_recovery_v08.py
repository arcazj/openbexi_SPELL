from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

import backend.data_backup as data_backup
import backend.migrations as migration_runner
from backend.app import create_app
from backend.auth import AuthConfig
from backend.config import Settings
from backend.data_backup import (
    BackupCorruptionError,
    DataBackupError,
    UnsafeRestoreError,
    canonical_backup_manifest_bytes,
    create_postgresql_backup,
    create_sqlite_backup,
    restore_postgresql_backup,
    restore_sqlite_backup,
    validate_postgresql_restore_target,
    verify_backup_bundle,
)
from backend.data_models import (
    CANONICAL_SCHEMA_SHA256,
    DATA_TABLE_NAMES,
    DataSchemaError,
    activate_data_schema,
    canonical_shared_namespace_state_bytes,
    canonical_virtual_root_configuration_bytes,
    canonical_virtual_root_state_bytes,
    data_container_revisions,
    data_containers,
    data_integrity_errors,
    data_dictionaries,
    data_dictionary_revisions,
    data_mutation_idempotency,
    data_schema_fingerprints,
    shared_entries,
    shared_namespaces,
    schema_validation_errors,
    verify_data_integrity,
    virtual_file_roots,
    virtual_files,
)
from backend.database import create_database
from backend.data_values import make_typed_value, typed_value_digest
from backend.data_state import (
    CorruptContainerError,
    runtime_container_commit_digest,
    validate_container_history,
)
from backend.dictionary_exchange import (
    DictionaryEntry,
    DictionaryRecord,
    ImportOperation,
    build_db_document,
    build_imp_document,
)
from backend.models import Execution
from backend.migrations import database_version, schema_migrations
from backend.migrations.rollback import (
    UnsafeDataRollbackError,
    rollback_data_local_service,
)
from backend.migrations.versions import v0007_data_local_service
from backend.tests.migration_support import run_migrations


EXPECTED_DATA_TABLES = {
    "data_catalogs",
    "data_schema_fingerprints",
    "data_catalog_revisions",
    "data_catalog_entries",
    "data_dependencies",
    "data_dictionaries",
    "data_dictionary_revisions",
    "data_containers",
    "data_container_revisions",
    "shared_namespaces",
    "shared_entries",
    "virtual_file_roots",
    "virtual_files",
    "data_mutation_idempotency",
    "data_audit_outbox",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sqlite_engine(path: Path):
    engine, _ = create_database(f"sqlite:///{path.as_posix()}")
    return engine


class _VirtualBackupProvider:
    def __init__(self, objects: dict[tuple[str, str], tuple[str, bytes]]) -> None:
        self.objects = dict(objects)
        self.add_extra_after_read = False

    def inventory(self):
        return tuple(sorted(self.objects))

    def read(self, root_id: str, virtual_path: str, content_digest: str) -> bytes:
        stored_path, payload = self.objects[(root_id, content_digest)]
        assert stored_path == virtual_path
        if self.add_extra_after_read:
            self.objects[(root_id, "f" * 64)] = ("orphan.bin", b"orphan")
        return payload


def _seed_virtual_reference(
    engine,
    payload: bytes,
    *,
    root_id: str = "project-root",
    root_kind: str = "PROJECT_DATA",
    owner_id: str = "project-a",
    virtual_path: str = "results/payload.bin",
) -> tuple[_VirtualBackupProvider, str]:
    digest = _sha(payload)
    node = {
        "root_id": root_id,
        "virtual_path": virtual_path,
        "revision": 1,
        "parent_path": "results",
        "node_type": "FILE",
        "encoding": "BINARY",
        "byte_length": len(payload),
        "content_digest": digest,
        "tombstoned": False,
    }
    root = {
        "root_id": root_id,
        "root_kind": root_kind,
        "owner_id": owner_id,
        "acl_revision": 1,
        "quota_bytes": 1_048_576,
        "quota_nodes": 100,
    }
    with engine.begin() as connection:
        connection.execute(
            virtual_file_roots.insert().values(
                **root,
                current_revision=1,
                content_digest=_sha(
                    canonical_virtual_root_state_bytes(root_id, [node])
                ),
                configuration_digest=_sha(
                    canonical_virtual_root_configuration_bytes(root)
                ),
                used_bytes=len(payload),
                used_nodes=1,
                active=True,
            )
        )
        connection.execute(
            virtual_files.insert().values(
                **node,
                created_by_principal="operator-a",
            )
        )
    provider = _VirtualBackupProvider(
        {(root_id, digest): (virtual_path, payload)}
    )
    return provider, f"virtual-files/{root_id}/{digest}"


def _rewrite_sqlite_table_definition(engine, table_name: str, old: str, new: str) -> None:
    engine.dispose()
    connection = sqlite3.connect(str(engine.url.database))
    try:
        original = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()[0]
        assert old in original
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET sql=? WHERE type='table' AND name=?",
            (original.replace(old, new, 1), table_name),
        )
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()
    finally:
        connection.close()


def _seed_dictionary_revision(engine) -> tuple[bytes, bytes, bytes]:
    alpha_value = make_typed_value("INT64", 7)
    alpha_digest = typed_value_digest(alpha_value)
    entry_state = json.dumps(
        {
            "schema_version": "spell.data.dictionary-state/1",
            "entries": [
                {
                    "entry_id": "alpha",
                    "revision": 1,
                    "tombstoned": False,
                    "qualified_name": "TEST.alpha",
                    "value": alpha_value,
                    "value_digest": alpha_digest,
                },
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    source = build_imp_document(
        "test-dictionary",
        0,
        (
            DictionaryRecord(
                ImportOperation.UPSERT,
                "alpha",
                0,
                "TEST.alpha",
                alpha_value,
                alpha_digest,
            ),
        ),
    )
    canonical_source = source.canonical_bytes
    original = (json.dumps(source.as_payload(), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    state_digest = _sha(entry_state)
    exported_content_digest = build_db_document(
        "test-dictionary",
        1,
        (DictionaryEntry("alpha", "TEST.alpha", alpha_value, alpha_digest),),
    ).content_digest
    assert exported_content_digest != state_digest
    with engine.begin() as connection:
        connection.execute(
            data_dictionaries.insert().values(
                dictionary_id="test-dictionary",
                owner_id="owner",
                authorization_scope="LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE",
                current_revision=1,
                current_content_digest=exported_content_digest,
                acl_revision=1,
                tombstoned=False,
            )
        )
        connection.execute(
            data_dictionary_revisions.insert().values(
                owner_id="owner",
                dictionary_id="test-dictionary",
                revision=1,
                base_revision=0,
                source_format="IMP",
                content_digest=exported_content_digest,
                canonical_entry_state=entry_state,
                canonical_entry_state_sha256=state_digest,
                canonical_source_document=canonical_source,
                canonical_source_document_sha256=_sha(canonical_source),
                original_media_type="application/vnd.openbexi.spell.dictionary-imp+json",
                original_byte_length=len(original),
                original_bytes_sha256=_sha(original),
                original_bytes=original,
                actor_principal_id="operator-a",
                caller_binding_kind="HTTP_MUTATION",
                caller_binding_digest="1" * 64,
            )
        )
        verify_data_integrity(connection)
    return entry_state, canonical_source, original


def _seed_rehashed_semantic_corruption(engine, target: str) -> None:
    if target.startswith("dictionary"):
        _seed_dictionary_revision(engine)
        with engine.begin() as connection:
            if target == "dictionary_state":
                raw = b'{"entries":[],"schema_version":"invalid"}'
                connection.execute(
                    data_dictionary_revisions.update().values(
                        canonical_entry_state=raw,
                        canonical_entry_state_sha256=_sha(raw),
                    )
                )
            elif target == "dictionary_content_digest":
                connection.execute(
                    data_dictionary_revisions.update().values(content_digest="f" * 64)
                )
                connection.execute(
                    data_dictionaries.update().values(current_content_digest="f" * 64)
                )
            elif target == "dictionary_source":
                raw = b'{"schema_version":"invalid"}'
                connection.execute(
                    data_dictionary_revisions.update().values(
                        canonical_source_document=raw,
                        canonical_source_document_sha256=_sha(raw),
                        original_byte_length=len(raw),
                        original_bytes=raw,
                        original_bytes_sha256=_sha(raw),
                    )
                )
            elif target == "dictionary_chain":
                row = connection.execute(
                    select(data_dictionary_revisions)
                ).mappings().one()
                payload = json.loads(row["canonical_entry_state"])
                payload["entries"][0]["revision"] = 2
                raw = json.dumps(
                    payload, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
                connection.execute(
                    data_dictionary_revisions.update().values(
                        canonical_entry_state=raw,
                        canonical_entry_state_sha256=_sha(raw),
                    )
                )
            else:
                raise AssertionError(f"unsupported corruption target: {target}")
        return

    if target == "container_chain":
        first_value = make_typed_value("STRING", "first")
        second_value = make_typed_value("STRING", "resurrected")
        first_digest = typed_value_digest(first_value)
        second_digest = typed_value_digest(second_value)

        def container_state(
            variable_revision: int,
            *,
            tombstoned: bool,
            value: dict[str, object] | None,
            value_digest: str,
        ) -> bytes:
            return json.dumps(
                {
                    "schema_version": "spell.data.container-state/1",
                    "variables": [
                        {
                            "declared_type": "STRING",
                            "name": "value",
                            "revision": variable_revision,
                            "tombstoned": tombstoned,
                            "value": value,
                            "value_digest": value_digest,
                            "variable_id": "value",
                        }
                    ],
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

        states = (
            container_state(
                1,
                tombstoned=False,
                value=first_value,
                value_digest=first_digest,
            ),
            container_state(
                2,
                tombstoned=True,
                value=None,
                value_digest=first_digest,
            ),
            container_state(
                3,
                tombstoned=False,
                value=second_value,
                value_digest=second_digest,
            ),
        )
        with engine.begin() as connection:
            connection.execute(
                data_containers.insert().values(
                    container_id="resurrected-container",
                    kind="DATA_CONTAINER",
                    owner_id="namespace-a",
                    current_revision=3,
                    schema_revision=1,
                    current_content_digest=_sha(states[-1]),
                    acl_revision=1,
                    mutable=True,
                    tombstoned=False,
                )
            )
            connection.execute(
                data_container_revisions.insert(),
                [
                    {
                        "kind": "DATA_CONTAINER",
                        "owner_id": "namespace-a",
                        "container_id": "resurrected-container",
                        "revision": revision,
                        "schema_revision": 1,
                        "commit_binding_digest": "a" * 64,
                        "content_digest": _sha(state),
                        "canonical_variables": state,
                        "tombstoned": False,
                        "created_by_principal": "operator-a",
                    }
                    for revision, state in enumerate(states, 1)
                ],
            )
        return

    if target == "container_state":
        raw = b'{"schema_version":"invalid","variables":[]}'
        digest = _sha(raw)
        with engine.begin() as connection:
            connection.execute(
                data_containers.insert().values(
                    container_id="corrupt-container",
                    kind="DATA_CONTAINER",
                    owner_id="namespace-a",
                    current_revision=1,
                    schema_revision=1,
                    current_content_digest=digest,
                    acl_revision=1,
                    mutable=True,
                    tombstoned=False,
                )
            )
            connection.execute(
                data_container_revisions.insert().values(
                    kind="DATA_CONTAINER",
                    owner_id="namespace-a",
                    container_id="corrupt-container",
                    revision=1,
                    schema_revision=1,
                    commit_binding_digest="a" * 64,
                    content_digest=digest,
                    canonical_variables=raw,
                    tombstoned=False,
                    created_by_principal="operator-a",
                )
            )
        return

    if target == "shared_value":
        raw = b'{"schema_version":"spell.data.value/1","type":"STRING","value":7}'
        digest = _sha(raw)
        entry = {
            "entry_id": "corrupt-entry",
            "key": "alpha",
            "revision": 1,
            "tombstoned": False,
            "value_digest": digest,
        }
        namespace_digest = _sha(canonical_shared_namespace_state_bytes([entry]))
        with engine.begin() as connection:
            connection.execute(
                shared_namespaces.insert().values(
                    namespace_id="corrupt-namespace",
                    scope="PROJECT",
                    owner_id="project-a",
                    current_revision=1,
                    current_content_digest=namespace_digest,
                    acl_revision=1,
                    tombstoned=False,
                )
            )
            connection.execute(
                shared_entries.insert().values(
                    scope="PROJECT",
                    owner_id="project-a",
                    namespace_id="corrupt-namespace",
                    entry_id="corrupt-entry",
                    revision=1,
                    key="alpha",
                    canonical_value=raw,
                    value_digest=digest,
                    tombstoned=False,
                    updated_by_principal="operator-a",
                )
            )
        return

    if target == "shared_chain":
        first_value = make_typed_value("STRING", "first")
        second_value = make_typed_value("STRING", "resurrected")
        first_raw = json.dumps(
            first_value, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        second_raw = json.dumps(
            second_value, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        first_digest = _sha(first_raw)
        second_digest = _sha(second_raw)
        latest = {
            "entry_id": "resurrected-entry",
            "key": "alpha",
            "revision": 3,
            "tombstoned": False,
            "value_digest": second_digest,
        }
        namespace_digest = _sha(canonical_shared_namespace_state_bytes([latest]))
        with engine.begin() as connection:
            connection.execute(
                shared_namespaces.insert().values(
                    namespace_id="resurrected-namespace",
                    scope="PROJECT",
                    owner_id="project-a",
                    current_revision=4,
                    current_content_digest=namespace_digest,
                    acl_revision=1,
                    tombstoned=False,
                )
            )
            connection.execute(
                shared_entries.insert(),
                [
                    {
                        "scope": "PROJECT",
                        "owner_id": "project-a",
                        "namespace_id": "resurrected-namespace",
                        "entry_id": "resurrected-entry",
                        "revision": 1,
                        "key": "alpha",
                        "canonical_value": first_raw,
                        "value_digest": first_digest,
                        "tombstoned": False,
                        "updated_by_principal": "operator-a",
                    },
                    {
                        "scope": "PROJECT",
                        "owner_id": "project-a",
                        "namespace_id": "resurrected-namespace",
                        "entry_id": "resurrected-entry",
                        "revision": 2,
                        "key": "alpha",
                        "canonical_value": None,
                        "value_digest": first_digest,
                        "tombstoned": True,
                        "updated_by_principal": "operator-a",
                    },
                    {
                        "scope": "PROJECT",
                        "owner_id": "project-a",
                        "namespace_id": "resurrected-namespace",
                        "entry_id": "resurrected-entry",
                        "revision": 3,
                        "key": "alpha",
                        "canonical_value": second_raw,
                        "value_digest": second_digest,
                        "tombstoned": False,
                        "updated_by_principal": "operator-a",
                    },
                ],
            )
        return

    raise AssertionError(f"unsupported corruption target: {target}")


def test_v0007_creates_exact_fifteen_tables_and_persists_unactivated_fingerprint(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "schema.sqlite")
    applied = run_migrations(engine)
    assert applied[-1] == "0007_data_local_service"
    assert database_version(engine) == "0007_data_local_service"
    assert set(DATA_TABLE_NAMES) == EXPECTED_DATA_TABLES
    tables = set(inspect(engine).get_table_names())
    assert {
        name
        for name in tables
        if name.startswith(("data_", "shared_", "virtual_file"))
    } == EXPECTED_DATA_TABLES
    assert schema_validation_errors(engine) == []
    with engine.connect() as connection:
        fingerprint = connection.execute(
            select(data_schema_fingerprints)
        ).mappings().one()
    assert fingerprint["migration_id"] == "0007_data_local_service"
    assert fingerprint["backend_kind"] == "sqlite"
    assert fingerprint["canonical_schema_sha256"] == CANONICAL_SCHEMA_SHA256
    assert fingerprint["activated"] is False
    assert fingerprint["created_at_database_time"] is not None
    assert run_migrations(engine) == ()


def test_bigint_revisions_and_binary_container_state_cross_32_bit_exactly(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "bigint.sqlite")
    run_migrations(engine)
    revision = (1 << 31) + 17
    state = b'{"schema_version":"spell.data.container-state/1","variables":[]}'
    digest = _sha(state)
    with engine.begin() as connection:
        connection.execute(
            data_containers.insert().values(
                container_id="persistent-large-revision",
                kind="DATA_CONTAINER",
                owner_id="namespace-a",
                execution_id=None,
                admission_worker_generation=None,
                admission_execution_revision=None,
                admission_binding_digest=None,
                current_revision=revision,
                schema_revision=revision,
                current_content_digest=digest,
                acl_revision=revision,
                mutable=True,
                tombstoned=False,
            )
        )
        connection.execute(
            data_container_revisions.insert().values(
                kind="DATA_CONTAINER",
                owner_id="namespace-a",
                container_id="persistent-large-revision",
                revision=revision,
                schema_revision=revision,
                checkpoint_sequence=None,
                execution_revision=None,
                worker_generation=None,
                commit_binding_digest="a" * 64,
                content_digest=digest,
                canonical_variables=state,
                tombstoned=False,
                created_by_principal="operator-a",
            )
        )
        stored = connection.execute(
            select(data_container_revisions).where(
                data_container_revisions.c.container_id
                == "persistent-large-revision"
            )
        ).mappings().one()
    assert stored["revision"] == revision
    assert stored["schema_revision"] == revision
    assert stored["canonical_variables"] == state

    with engine.connect() as connection:
        with pytest.raises(DataSchemaError, match="container history"):
            verify_data_integrity(connection)


def test_sparse_bigint_revision_chain_is_rejected_without_range_materialization() -> None:
    with pytest.raises(CorruptContainerError, match="revision chain"):
        validate_container_history(
            {"current_revision": (1 << 62) + 17},
            [({"revision": 1}, None)],
        )


def test_runtime_container_ownership_and_args_immutability_are_constrained(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "runtime-containers.sqlite")
    run_migrations(engine)
    now = datetime.now(timezone.utc)
    state = b'{"schema_version":"spell.data.container-state/1","variables":[]}'
    digest = _sha(state)
    container_id = "execution-v08.ARGS"
    admission_digest = "b" * 64
    commit_digest = runtime_container_commit_digest(
        caller_digest=admission_digest,
        worker_generation=0,
        container_id=container_id,
        container_revision=1,
        content_digest=digest,
        checkpoint_sequence=0,
        execution_revision=0,
    )
    with engine.begin() as connection:
        connection.execute(
            Execution.__table__.insert().values(
                id="execution-v08",
                procedure_id="procedure-v08",
                procedure_name="procedure-v08",
                procedure_hash="f" * 64,
                procedure_source="proc procedure-v08 {}",
                steps=[],
                ir_version="0.8",
                variables={},
                context_id="test",
                created_by="operator-a",
                creation_idempotency_key="create-v08",
                state="created",
                revision=0,
                current_step=0,
                total_steps=0,
                worker_generation=0,
                next_sequence=1,
                created_at=now,
                updated_at=now,
            )
        )
        connection.execute(
            data_containers.insert().values(
                container_id=container_id,
                kind="ARGS",
                owner_id="execution-v08",
                execution_id="execution-v08",
                admission_worker_generation=0,
                admission_execution_revision=0,
                admission_binding_digest=admission_digest,
                current_revision=1,
                schema_revision=1,
                current_content_digest=digest,
                acl_revision=0,
                mutable=False,
                tombstoned=False,
            )
        )
        connection.execute(
            data_container_revisions.insert().values(
                kind="ARGS",
                owner_id="execution-v08",
                container_id=container_id,
                revision=1,
                schema_revision=1,
                checkpoint_sequence=0,
                execution_revision=0,
                worker_generation=0,
                commit_binding_digest=commit_digest,
                content_digest=digest,
                canonical_variables=state,
                tombstoned=False,
                created_by_principal="procedure-runtime",
            )
        )
        verify_data_integrity(connection)

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                data_containers.update()
                .where(data_containers.c.container_id == container_id)
                .values(current_revision=2)
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                data_containers.insert().values(
                    container_id="unbound-local",
                    kind="LOCAL",
                    owner_id="frame-v08",
                    current_revision=1,
                    schema_revision=1,
                    current_content_digest=digest,
                    acl_revision=0,
                    mutable=True,
                    tombstoned=False,
                )
            )


def test_integrity_reconstructs_shared_and_virtual_root_heads(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "head-integrity.sqlite")
    run_migrations(engine)
    live_value = b'{"schema_version":"spell.data.value/1","type":"INT64","value":"7"}'
    deleted_value = (
        b'{"schema_version":"spell.data.value/1","type":"STRING","value":"retired"}'
    )
    deleted_digest = _sha(deleted_value)
    shared_latest = [
        {
            "entry_id": "entry-live",
            "key": "alpha",
            "revision": 1,
            "tombstoned": False,
            "value_digest": _sha(live_value),
        },
        {
            "entry_id": "entry-deleted",
            "key": "retired",
            "revision": 2,
            "tombstoned": True,
            "value_digest": deleted_digest,
        },
    ]
    shared_digest = _sha(canonical_shared_namespace_state_bytes(shared_latest))
    root = {
        "root_id": "project-root",
        "root_kind": "PROJECT_DATA",
        "owner_id": "project-a",
        "acl_revision": 1,
        "quota_bytes": 1_048_576,
        "quota_nodes": 100,
    }
    root_configuration_digest = _sha(
        canonical_virtual_root_configuration_bytes(root)
    )
    root_content_digest = _sha(
        canonical_virtual_root_state_bytes("project-root", [])
    )
    with engine.begin() as connection:
        connection.execute(
            shared_namespaces.insert().values(
                namespace_id="shared-a",
                scope="PROJECT",
                owner_id="project-a",
                current_revision=4,
                current_content_digest=shared_digest,
                acl_revision=1,
                tombstoned=False,
            )
        )
        connection.execute(
            shared_entries.insert(),
            [
                {
                    "scope": "PROJECT",
                    "owner_id": "project-a",
                    "namespace_id": "shared-a",
                    "entry_id": "entry-live",
                    "revision": 1,
                    "key": "alpha",
                    "canonical_value": live_value,
                    "value_digest": _sha(live_value),
                    "tombstoned": False,
                    "updated_by_principal": "operator-a",
                },
                    {
                        "scope": "PROJECT",
                        "owner_id": "project-a",
                        "namespace_id": "shared-a",
                        "entry_id": "entry-deleted",
                        "revision": 1,
                        "key": "retired",
                        "canonical_value": deleted_value,
                        "value_digest": deleted_digest,
                        "tombstoned": False,
                        "updated_by_principal": "operator-a",
                    },
                    {
                        "scope": "PROJECT",
                        "owner_id": "project-a",
                        "namespace_id": "shared-a",
                        "entry_id": "entry-deleted",
                        "revision": 2,
                        "key": "retired",
                        "canonical_value": None,
                        "value_digest": deleted_digest,
                    "tombstoned": True,
                    "updated_by_principal": "operator-a",
                },
            ],
        )
        connection.execute(
            virtual_file_roots.insert().values(
                **root,
                current_revision=0,
                content_digest=root_content_digest,
                configuration_digest=root_configuration_digest,
                used_bytes=0,
                used_nodes=0,
                active=True,
            )
        )
        verify_data_integrity(connection)

    with engine.begin() as connection:
        connection.execute(
            shared_namespaces.update().values(current_content_digest="f" * 64)
        )
        assert any(
            "shared namespace head" in item
            for item in data_integrity_errors(connection)
        )
        connection.execute(
            shared_namespaces.update().values(current_content_digest=shared_digest)
        )
        connection.execute(
            virtual_file_roots.update().values(content_digest="e" * 64)
        )
        assert any(
            "virtual root head" in item for item in data_integrity_errors(connection)
        )


def test_v0007_requires_exact_predecessor_and_rejects_partial_objects(tmp_path: Path) -> None:
    empty = create_engine(f"sqlite:///{(tmp_path / 'empty.sqlite').as_posix()}")
    with empty.begin() as connection:
        with pytest.raises(RuntimeError, match="requires 0006"):
            v0007_data_local_service.upgrade(connection)

    engine = _sqlite_engine(tmp_path / "partial.sqlite")
    original = migration_runner.MIGRATIONS
    try:
        migration_runner.MIGRATIONS = original[:-1]
        run_migrations(engine)
    finally:
        migration_runner.MIGRATIONS = original
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE data_catalogs (id TEXT PRIMARY KEY)")
    with pytest.raises(RuntimeError, match="inventory differs"):
        run_migrations(engine)
    assert database_version(engine) == "0006_observation_conditions"
    with engine.connect() as connection:
        assert connection.scalar(
            select(schema_migrations.c.version).where(
                schema_migrations.c.version == "0007_data_local_service"
            )
        ) is None


def test_v0007_failure_rolls_back_all_new_objects_and_record(
    tmp_path: Path, monkeypatch
) -> None:
    engine = _sqlite_engine(tmp_path / "atomic.sqlite")
    original = migration_runner.MIGRATIONS
    monkeypatch.setattr(migration_runner, "MIGRATIONS", original[:-1])
    run_migrations(engine)

    def fail_after_schema(connection) -> None:
        v0007_data_local_service.upgrade(connection)
        raise RuntimeError("controlled v0007 failure")

    failing = SimpleNamespace(
        VERSION=v0007_data_local_service.VERSION, upgrade=fail_after_schema
    )
    monkeypatch.setattr(migration_runner, "MIGRATIONS", (*original[:-1], failing))
    with pytest.raises(RuntimeError, match="controlled v0007 failure"):
        run_migrations(engine)
    assert not EXPECTED_DATA_TABLES.intersection(inspect(engine).get_table_names())
    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM schema_migrations "
                "WHERE version='0007_data_local_service'"
            )
        ) == 0


def test_startup_rejects_physical_or_persisted_fingerprint_drift(tmp_path: Path) -> None:
    physical = _sqlite_engine(tmp_path / "physical-drift.sqlite")
    run_migrations(physical)
    with physical.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE data_catalogs ADD COLUMN unauthorized TEXT")
    with pytest.raises(DataSchemaError, match="column inventory"):
        run_migrations(physical)

    persisted = _sqlite_engine(tmp_path / "fingerprint-drift.sqlite")
    run_migrations(persisted)
    with persisted.begin() as connection:
        connection.execute(
            data_schema_fingerprints.update().values(
                canonical_schema_sha256="f" * 64
            )
        )
    with pytest.raises(DataSchemaError, match="persisted schema fingerprint"):
        run_migrations(persisted)


def test_startup_integrity_rejects_durable_pending_settlement(tmp_path: Path) -> None:
    database_path = tmp_path / "durable-pending-startup.sqlite"
    engine = _sqlite_engine(database_path)
    run_migrations(engine)
    with engine.begin() as connection:
        connection.execute(
            data_mutation_idempotency.insert().values(
                settlement_id="durable-pending",
                actor_principal_id="operator-a",
                caller_binding_kind="HTTP_MUTATION",
                caller_binding_digest="a" * 64,
                operation="SET",
                resource_identity_digest="b" * 64,
                idempotency_key="durable-pending",
                request_digest="c" * 64,
                state="PENDING",
            )
        )
    engine.dispose()

    procedures_dir = tmp_path / "pending-procedures"
    procedures_dir.mkdir()
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        procedures_dir=procedures_dir,
        websocket_replay_limit=100,
        websocket_queue_size=32,
        websocket_keepalive_seconds=0.1,
        data_dir=tmp_path / "pending-data",
    )
    auth_config = AuthConfig(
        issuer="openbexi-spell-tests",
        audience="openbexi-spell-api",
        signing_secret=b"test-only-secret-with-at-least-32-bytes",
        clock_skew_seconds=1,
        max_token_lifetime_seconds=900,
        allow_local_dev_issuance=True,
    )
    with pytest.raises(DataSchemaError, match="durably pending"):
        with TestClient(create_app(settings, auth_config=auth_config)):
            pass


def test_backup_rejects_durable_pending_settlement(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "durable-pending-backup.sqlite")
    run_migrations(engine)
    with engine.begin() as connection:
        connection.execute(
            data_mutation_idempotency.insert().values(
                settlement_id="durable-pending",
                actor_principal_id="operator-a",
                caller_binding_kind="HTTP_MUTATION",
                caller_binding_digest="a" * 64,
                operation="SET",
                resource_identity_digest="b" * 64,
                idempotency_key="durable-pending",
                request_digest="c" * 64,
                state="PENDING",
            )
        )
    with pytest.raises(DataSchemaError, match="durably pending"):
        create_sqlite_backup(engine, tmp_path / "durable-pending-backup")
    assert not (tmp_path / "durable-pending-backup").exists()


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("dictionary_state", "entry state is semantically invalid"),
        ("dictionary_content_digest", "content digest differs"),
        ("dictionary_source", "source provenance is semantically invalid"),
        ("container_state", "state is semantically invalid"),
        ("shared_value", "typed value is semantically invalid"),
    ],
)
def test_integrity_rejects_rehashed_invalid_semantic_state(
    tmp_path: Path, target: str, message: str
) -> None:
    engine = _sqlite_engine(tmp_path / f"semantic-{target}.sqlite")
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, target)
    with engine.connect() as connection:
        with pytest.raises(DataSchemaError, match=message):
            verify_data_integrity(connection)


def test_application_startup_rejects_rehashed_invalid_semantic_state(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "semantic-startup.sqlite"
    engine = _sqlite_engine(database_path)
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, "container_state")
    engine.dispose()

    procedures_dir = tmp_path / "procedures"
    procedures_dir.mkdir()
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        procedures_dir=procedures_dir,
        websocket_replay_limit=100,
        websocket_queue_size=32,
        websocket_keepalive_seconds=0.1,
        data_dir=tmp_path / "data",
    )
    auth_config = AuthConfig(
        issuer="openbexi-spell-tests",
        audience="openbexi-spell-api",
        signing_secret=b"test-only-secret-with-at-least-32-bytes",
        clock_skew_seconds=1,
        max_token_lifetime_seconds=900,
        allow_local_dev_issuance=True,
    )
    with pytest.raises(DataSchemaError, match="state is semantically invalid"):
        with TestClient(create_app(settings, auth_config=auth_config)):
            pass


def test_backup_rejects_rehashed_invalid_semantic_state(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "semantic-backup.sqlite")
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, "shared_value")
    destination = tmp_path / "semantic-corrupt-backup"
    with pytest.raises(DataSchemaError, match="typed value is semantically invalid"):
        create_sqlite_backup(engine, destination)
    assert not destination.exists()


@pytest.mark.parametrize(
    "target",
    ["dictionary_chain", "container_chain", "shared_chain"],
)
def test_integrity_rejects_rehashed_invalid_history(
    tmp_path: Path, target: str
) -> None:
    engine = _sqlite_engine(tmp_path / f"history-{target}.sqlite")
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, target)
    with engine.connect() as connection:
        with pytest.raises(DataSchemaError, match="history"):
            verify_data_integrity(connection)


def test_application_startup_rejects_rehashed_invalid_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "history-startup.sqlite"
    engine = _sqlite_engine(database_path)
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, "container_chain")
    engine.dispose()

    procedures_dir = tmp_path / "history-procedures"
    procedures_dir.mkdir()
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        procedures_dir=procedures_dir,
        websocket_replay_limit=100,
        websocket_queue_size=32,
        websocket_keepalive_seconds=0.1,
        data_dir=tmp_path / "history-data",
    )
    auth_config = AuthConfig(
        issuer="openbexi-spell-tests",
        audience="openbexi-spell-api",
        signing_secret=b"test-only-secret-with-at-least-32-bytes",
        clock_skew_seconds=1,
        max_token_lifetime_seconds=900,
        allow_local_dev_issuance=True,
    )
    with pytest.raises(DataSchemaError, match="container history"):
        with TestClient(create_app(settings, auth_config=auth_config)):
            pass


def test_backup_rejects_rehashed_invalid_history(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "history-backup.sqlite")
    run_migrations(engine)
    _seed_rehashed_semantic_corruption(engine, "shared_chain")
    destination = tmp_path / "history-corrupt-backup"
    with pytest.raises(DataSchemaError, match="shared entry history"):
        create_sqlite_backup(engine, destination)
    assert not destination.exists()


def test_schema_activation_is_exact_atomic_and_idempotent(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "activation.sqlite")
    run_migrations(engine)
    activate_data_schema(engine)
    activate_data_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(data_schema_fingerprints.c.activated)) is True

    corrupt = _sqlite_engine(tmp_path / "activation-corrupt.sqlite")
    run_migrations(corrupt)
    with corrupt.begin() as connection:
        connection.execute(
            data_schema_fingerprints.update().values(
                canonical_schema_sha256="f" * 64
            )
        )
    with pytest.raises(DataSchemaError, match="persisted schema fingerprint"):
        activate_data_schema(corrupt)
    with corrupt.connect() as connection:
        assert connection.scalar(select(data_schema_fingerprints.c.activated)) is False


def test_schema_verifier_rejects_extra_indexes_exactly(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "extra-index.sqlite")
    run_migrations(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX ix_unreviewed_catalog_owner "
            "ON data_catalogs(owner_id)"
        )
    assert "data_catalogs indexes differ" in schema_validation_errors(engine)
    with pytest.raises(DataSchemaError, match="indexes differ"):
        activate_data_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(data_schema_fingerprints.c.activated)) is False


@pytest.mark.parametrize(
    ("table_name", "old", "new", "message"),
    [
        (
            "data_catalogs",
            "current_revision BETWEEN 1 AND 9223372036854775807",
            "current_revision >= 1",
            "check constraints differ",
        ),
        (
            "data_schema_fingerprints",
            "DEFAULT FALSE",
            "DEFAULT TRUE",
            "server default differs",
        ),
    ],
)
def test_schema_verifier_binds_check_sql_and_default_expressions(
    tmp_path: Path, table_name: str, old: str, new: str, message: str
) -> None:
    engine = _sqlite_engine(tmp_path / f"{table_name}.sqlite")
    run_migrations(engine)
    _rewrite_sqlite_table_definition(engine, table_name, old, new)
    assert any(message in item for item in schema_validation_errors(engine))
    with pytest.raises(DataSchemaError, match=message):
        activate_data_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(data_schema_fingerprints.c.activated)) is False


def test_empty_unactivated_rollback_is_exact_and_reapplicable(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "rollback.sqlite")
    run_migrations(engine)
    dropped = rollback_data_local_service(engine)
    assert set(dropped) == EXPECTED_DATA_TABLES
    assert not EXPECTED_DATA_TABLES.intersection(inspect(engine).get_table_names())
    assert database_version(engine) == "0006_observation_conditions"
    assert run_migrations(engine) == ("0007_data_local_service",)


def test_data_rollback_rejects_activation_records_unknown_objects_and_drift(
    tmp_path: Path,
) -> None:
    activated = _sqlite_engine(tmp_path / "activated.sqlite")
    run_migrations(activated)
    with activated.begin() as connection:
        connection.execute(data_schema_fingerprints.update().values(activated=True))
    with pytest.raises(UnsafeDataRollbackError, match="activated"):
        rollback_data_local_service(activated)

    populated = _sqlite_engine(tmp_path / "populated.sqlite")
    run_migrations(populated)
    _seed_dictionary_revision(populated)
    with pytest.raises(UnsafeDataRollbackError, match="data or evidence"):
        rollback_data_local_service(populated)

    unknown = _sqlite_engine(tmp_path / "unknown.sqlite")
    run_migrations(unknown)
    with unknown.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE data_unreviewed (id TEXT PRIMARY KEY)")
    with pytest.raises(UnsafeDataRollbackError, match="unknown database objects"):
        rollback_data_local_service(unknown)

    drifted = _sqlite_engine(tmp_path / "drifted.sqlite")
    run_migrations(drifted)
    with drifted.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE data_catalogs ADD COLUMN drift TEXT")
    with pytest.raises(UnsafeDataRollbackError, match="fingerprint"):
        rollback_data_local_service(drifted)


def test_backup_round_trip_preserves_dictionary_state_source_provenance_and_files(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "source.sqlite")
    run_migrations(engine)
    expected_state, expected_source, expected_original = _seed_dictionary_revision(engine)
    payload = b"bounded virtual content\x00\xff"
    nfc_virtual_path = "r\u00e9sultats/caf\u00e9.bin"
    provider, virtual_member = _seed_virtual_reference(
        engine, payload, virtual_path=nfc_virtual_path
    )
    bundle = tmp_path / "backup"
    manifest = create_sqlite_backup(
        engine,
        bundle,
        virtual_file_provider=provider,
    )
    assert set(manifest) == {
        "schema_version",
        "migration_head",
        "database_backend",
        "created_at_database_time",
        "file_inventory",
        "file_sha256",
        "aggregate_sha256",
    }
    assert verify_backup_bundle(bundle) == manifest
    restored = tmp_path / "isolated-restore"
    assert restore_sqlite_backup(bundle, restored) == manifest
    assert verify_backup_bundle(restored) == manifest
    assert (restored / virtual_member).read_bytes() == payload
    restored_engine = _sqlite_engine(restored / "database.sqlite")
    try:
        with restored_engine.connect() as connection:
            row = connection.execute(select(data_dictionary_revisions)).mappings().one()
            assert row["canonical_entry_state"] == expected_state
            assert row["canonical_source_document"] == expected_source
            assert row["original_bytes"] == expected_original
            assert connection.execute(
                select(virtual_files.c.virtual_path)
            ).scalar_one() == nfc_virtual_path
            verify_data_integrity(connection)
    finally:
        restored_engine.dispose()
    with pytest.raises(UnsafeRestoreError, match="already exists"):
        restore_sqlite_backup(bundle, restored)


def test_backup_rejects_linked_roots_and_dangling_destination_links(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "linked-paths.sqlite")
    run_migrations(engine)
    bundle = tmp_path / "linked-paths-backup"
    create_sqlite_backup(engine, bundle)

    linked_bundle = tmp_path / "linked-bundle"
    dangling_backup = tmp_path / "dangling-backup"
    dangling_restore = tmp_path / "dangling-restore"
    try:
        os.symlink(bundle, linked_bundle, target_is_directory=True)
        os.symlink(
            tmp_path / "redirected-backup",
            dangling_backup,
            target_is_directory=True,
        )
        os.symlink(
            tmp_path / "redirected-restore",
            dangling_restore,
            target_is_directory=True,
        )
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(BackupCorruptionError, match="non-symlink directory"):
        verify_backup_bundle(linked_bundle)
    with pytest.raises(BackupCorruptionError, match="non-symlink directory"):
        restore_sqlite_backup(linked_bundle, tmp_path / "unused-restore")
    with pytest.raises(DataBackupError, match="already exists"):
        create_sqlite_backup(engine, dangling_backup)
    with pytest.raises(UnsafeRestoreError, match="already exists"):
        restore_sqlite_backup(bundle, dangling_restore)


def test_backup_virtual_limits_are_enforced_per_root_not_per_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(data_backup, "MAXIMUM_VIRTUAL_REFERENCES_PER_ROOT", 1)
    monkeypatch.setattr(data_backup, "MAXIMUM_VIRTUAL_ROOT_BYTES", 8)
    engine = _sqlite_engine(tmp_path / "multi-root.sqlite")
    run_migrations(engine)
    first, first_member = _seed_virtual_reference(
        engine,
        b"first!",
        root_id="root-alpha",
        owner_id="project-a",
        virtual_path="first/data.bin",
    )
    second, second_member = _seed_virtual_reference(
        engine,
        b"second",
        root_id="root-beta",
        root_kind="PROCEDURE_DATA",
        owner_id="procedure-library",
        virtual_path="second/data.bin",
    )
    provider = _VirtualBackupProvider({**first.objects, **second.objects})

    bundle = tmp_path / "multi-root-backup"
    manifest = create_sqlite_backup(
        engine, bundle, virtual_file_provider=provider
    )
    virtual_inventory = [
        item
        for item in manifest["file_inventory"]
        if item["path"].startswith("virtual-files/")
    ]
    assert {item["path"] for item in virtual_inventory} == {
        first_member,
        second_member,
    }
    assert sum(item["size"] for item in virtual_inventory) == 12
    assert verify_backup_bundle(bundle) == manifest
    assert restore_sqlite_backup(bundle, tmp_path / "multi-root-restore") == manifest
    engine.dispose()


def test_database_member_hashing_streams_past_the_legacy_256_mib_cap(
    tmp_path: Path,
) -> None:
    legacy_one_root_limit = 268_435_456
    size = legacy_one_root_limit + 4_097
    member = tmp_path / "large-database-member.sqlite"
    with member.open("xb") as stream:
        stream.truncate(size)

    tracemalloc.start()
    try:
        actual_size, actual_digest = data_backup._regular_file_metadata(
            member, "large database member"
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    expected = hashlib.sha256()
    zero_chunk = b"\0" * data_backup.BACKUP_STREAM_CHUNK_BYTES
    remaining = size
    while remaining:
        chunk_size = min(remaining, len(zero_chunk))
        expected.update(zero_chunk[:chunk_size])
        remaining -= chunk_size
    assert actual_size == size
    assert actual_digest == expected.hexdigest()
    assert peak < 8 * data_backup.BACKUP_STREAM_CHUNK_BYTES


@pytest.mark.parametrize("root_segment", [".", ".."])
def test_backup_archive_members_reject_lexical_root_traversal(
    root_segment: str,
) -> None:
    with pytest.raises(BackupCorruptionError, match="identity|member"):
        data_backup._virtual_member_identity(
            f"virtual-files/{root_segment}/{'a' * 64}"
        )


def test_backup_rejects_virtual_omissions_extras_changes_and_corrupt_objects(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "virtual-inventory.sqlite")
    run_migrations(engine)
    payload = b"database-referenced-object"
    provider, member = _seed_virtual_reference(engine, payload)

    omitted = _VirtualBackupProvider({})
    with pytest.raises(DataBackupError, match="inventory differs"):
        create_sqlite_backup(
            engine, tmp_path / "omitted-backup", virtual_file_provider=omitted
        )

    extra = _VirtualBackupProvider(provider.objects)
    extra.objects[("project-root", "e" * 64)] = ("extra.bin", b"extra")
    with pytest.raises(DataBackupError, match="inventory differs"):
        create_sqlite_backup(
            engine, tmp_path / "extra-backup", virtual_file_provider=extra
        )

    corrupt = _VirtualBackupProvider(provider.objects)
    identity = next(iter(corrupt.objects))
    corrupt.objects[identity] = (corrupt.objects[identity][0], b"corrupt")
    with pytest.raises(DataBackupError, match="differs from the database"):
        create_sqlite_backup(
            engine, tmp_path / "corrupt-backup-object", virtual_file_provider=corrupt
        )

    changing = _VirtualBackupProvider(provider.objects)
    changing.add_extra_after_read = True
    with pytest.raises(DataBackupError, match="changed during"):
        create_sqlite_backup(
            engine, tmp_path / "changing-backup", virtual_file_provider=changing
        )

    missing_bundle = tmp_path / "missing-member"
    create_sqlite_backup(
        engine, missing_bundle, virtual_file_provider=provider
    )
    (missing_bundle / member).unlink()
    with pytest.raises(BackupCorruptionError, match="inventory"):
        verify_backup_bundle(missing_bundle)

    extra_bundle = tmp_path / "extra-member"
    create_sqlite_backup(engine, extra_bundle, virtual_file_provider=provider)
    extra_path = extra_bundle / "virtual-files/project-root" / ("a" * 64)
    extra_path.write_bytes(b"extra")
    with pytest.raises(BackupCorruptionError, match="inventory"):
        verify_backup_bundle(extra_bundle)


def test_backup_owns_quiescence_and_rejects_rehashed_internal_corruption(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "source.sqlite")
    run_migrations(engine)
    _seed_dictionary_revision(engine)
    competing, _ = create_database(
        f"sqlite:///{(tmp_path / 'source.sqlite').as_posix()}",
        sqlite_busy_timeout_ms=50,
    )
    with engine.connect() as writer:
        writer.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(DataBackupError, match="write-quiescence"):
            create_sqlite_backup(competing, tmp_path / "not-created")
        writer.rollback()
    competing.dispose()

    bundle = tmp_path / "corrupt-backup"
    create_sqlite_backup(engine, bundle)
    database_path = bundle / "database.sqlite"
    corruption_connection = sqlite3.connect(database_path)
    try:
        connection = corruption_connection
        connection.execute(
            "UPDATE data_dictionary_revisions "
            "SET canonical_entry_state = replace(canonical_entry_state, 'alpha', 'ALPHA')"
        )
        connection.commit()
    finally:
        corruption_connection.close()

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    database_bytes = database_path.read_bytes()
    manifest["file_sha256"]["database.sqlite"] = _sha(database_bytes)
    for item in manifest["file_inventory"]:
        if item["path"] == "database.sqlite":
            item["size"] = len(database_bytes)
    aggregate = bytearray()
    for item in manifest["file_inventory"]:
        aggregate.extend(item["path"].encode("ascii"))
        aggregate.extend(b"\0")
        aggregate.extend(str(item["size"]).encode("ascii"))
        aggregate.extend(b"\0")
        aggregate.extend(manifest["file_sha256"][item["path"]].encode("ascii"))
        aggregate.extend(b"\n")
    manifest["aggregate_sha256"] = _sha(bytes(aggregate))
    manifest_path.write_bytes(canonical_backup_manifest_bytes(manifest))
    with pytest.raises(BackupCorruptionError, match="database verification"):
        verify_backup_bundle(bundle)


def test_postgresql_restore_contract_requires_a_separately_named_manual_target() -> None:
    result = validate_postgresql_restore_target(
        "postgresql+psycopg://spell@localhost/spell_live",
        "postgresql+psycopg://spell@localhost/spell_restore_verified",
    )
    assert result == {
        "active_database": "spell_live",
        "isolated_database": "spell_restore_verified",
        "manual_activation_required": True,
        "automatic_swap_authorized": False,
    }
    with pytest.raises(UnsafeRestoreError, match="separately named"):
        validate_postgresql_restore_target(
            "postgresql+psycopg://spell@localhost/spell_live",
            "postgresql+psycopg://spell@localhost/spell_live",
        )


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_v0007_postgresql_schema_and_fingerprint_match_sqlite_contract() -> None:
    from backend.tests.test_migrations import (
        postgresql_migration_engine,
        reset_migration_database,
    )

    engine = postgresql_migration_engine()
    reset_migration_database(engine)
    try:
        assert run_migrations(engine)[-1] == "0007_data_local_service"
        assert schema_validation_errors(engine) == []
        with engine.connect() as connection:
            row = connection.execute(select(data_schema_fingerprints)).mappings().one()
        assert row["backend_kind"] == "postgresql"
        assert row["canonical_schema_sha256"] == CANONICAL_SCHEMA_SHA256
    finally:
        reset_migration_database(engine)
        engine.dispose()


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_postgresql_backup_reconstructs_exact_isolated_manual_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.engine import make_url

    from backend.tests.test_migrations import (
        postgresql_migration_engine,
        reset_migration_database,
    )

    source_url = make_url(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    isolated_name = "spell_v08_backup_restore_test"
    isolated_url = source_url.set(database=isolated_name)
    admin_url = source_url.set(database="postgres")
    admin = create_engine(
        admin_url.render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
    )
    with admin.connect() as connection:
        connection.exec_driver_sql(
            f'DROP DATABASE IF EXISTS "{isolated_name}" WITH (FORCE)'
        )

    engine = postgresql_migration_engine()
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        expected_state, expected_source, expected_original = _seed_dictionary_revision(
            engine
        )
        monkeypatch.setattr(data_backup, "MAXIMUM_VIRTUAL_REFERENCES_PER_ROOT", 1)
        monkeypatch.setattr(data_backup, "MAXIMUM_VIRTUAL_ROOT_BYTES", 32)
        virtual_payload = b"postgresql-root-scoped-content"
        nfc_virtual_path = "r\u00e9sultats/caf\u00e9-postgresql.bin"
        first, virtual_member = _seed_virtual_reference(
            engine, virtual_payload, virtual_path=nfc_virtual_path
        )
        second_payload = b"postgresql-second-root-data"
        second_path = "donn\u00e9es/deuxi\u00e8me.bin"
        second, second_member = _seed_virtual_reference(
            engine,
            second_payload,
            root_id="procedure-root",
            root_kind="PROCEDURE_DATA",
            owner_id="procedure-library",
            virtual_path=second_path,
        )
        provider = _VirtualBackupProvider({**first.objects, **second.objects})
        bundle = tmp_path / "postgresql-backup"
        manifest = create_postgresql_backup(
            engine, bundle, virtual_file_provider=provider
        )
        assert manifest["database_backend"] == "postgresql"
        assert (bundle / virtual_member).read_bytes() == virtual_payload
        assert (bundle / second_member).read_bytes() == second_payload
        restored = restore_postgresql_backup(
            bundle,
            source_url.render_as_string(hide_password=False),
            isolated_url.render_as_string(hide_password=False),
        )
        assert restored["manual_activation_required"] is True
        assert restored["automatic_swap_authorized"] is False
        assert restored["manifest"] == manifest

        isolated = create_engine(
            isolated_url.render_as_string(hide_password=False)
        )
        try:
            with isolated.connect() as connection:
                row = connection.execute(
                    select(data_dictionary_revisions)
                ).mappings().one()
                assert row["canonical_entry_state"] == expected_state
                assert row["canonical_source_document"] == expected_source
                assert row["original_bytes"] == expected_original
                assert set(
                    connection.execute(select(virtual_files.c.virtual_path)).scalars()
                ) == {nfc_virtual_path, second_path}
                verify_data_integrity(connection)
        finally:
            isolated.dispose()
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.exec_driver_sql(
                f'DROP DATABASE IF EXISTS "{isolated_name}" WITH (FORCE)'
            )
        admin.dispose()
