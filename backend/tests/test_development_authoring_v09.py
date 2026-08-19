from __future__ import annotations

import hashlib
import io
import json
import stat
import threading
import zipfile

import pytest
from sqlalchemy import delete, func, select

from backend.data_values import make_typed_value, typed_value_digest
from backend.development_domain import (
    DevelopmentConflictError,
    DevelopmentError,
    DevelopmentLimitError,
    DevelopmentNotFoundError,
    canonical_json_bytes,
)
from backend.development_models import (
    DevelopmentAuditEvent,
    DevelopmentDictionaryArtifact,
    DevelopmentIdempotency,
    DevelopmentImportProvenance,
    DevelopmentResource,
)
from backend.development_service import (
    CATALOG_MEDIA_TYPE,
    MAX_CATALOG_ENTRIES,
    DevelopmentService,
)
from backend.dictionary_exchange import (
    DB_MEDIA_TYPE,
    IMP_MEDIA_TYPE,
    DictionaryEntry,
    DictionaryRecord,
    ImportOperation,
    build_db_document,
    build_imp_document,
    export_dictionary_document,
    parse_dictionary_document,
)
from backend.tests.test_development_service_v09 import (
    OPERATOR,
    _create_project,
    _service,
    _source,
)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _catalog(
    catalog_id: str,
    *,
    catalog_kind: str = "TM",
    dependencies: list[dict] | None = None,
    entry_id: str | None = None,
) -> tuple[str, str]:
    unsigned = {
        "schema_version": "spell.catalog.snapshot/1",
        "catalog_id": catalog_id,
        "catalog_revision": 1,
        "catalog_kind": catalog_kind,
        "entries": [
            {
                "entry_id": entry_id or f"{catalog_id.lower()}-entry",
                "qualified_name": f"{catalog_id}.value",
                "data": {"engineering_unit": "count"},
            }
        ],
        "dependencies": dependencies or [],
    }
    content_digest = _digest(canonical_json_bytes(unsigned))
    return canonical_json_bytes(
        {**unsigned, "content_digest": content_digest}
    ).decode(), content_digest


def _create_text_resource(
    service: DevelopmentService,
    project_id: str,
    *,
    revision: int,
    path: str,
    content: str,
    kind: str = "PROCEDURE",
    media_type: str = "text/x-python",
    key: str,
) -> dict:
    return service.create_resource(
        project_id,
        **OPERATOR,
        path=path,
        kind=kind,
        media_type=media_type,
        content=content,
        content_sha256=_digest(content.encode()),
        expected_workspace_revision=revision,
        idempotency_key=key,
    )["resource"]


def _check(
    service: DevelopmentService,
    project_id: str,
    revision: int,
    *,
    scope: str,
    path: str | None,
    reparse: bool,
    key: str,
) -> dict:
    queued = service.create_check(
        project_id,
        **OPERATOR,
        scope=scope,
        scope_path=path,
        expected_workspace_revision=revision,
        reparse_libraries=reparse,
        idempotency_key=key,
    )
    return service.run_check(queued["job"]["job_id"])["job"]


def test_pinned_catalog_manifest_scopes_changed_set_and_library_cache(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Scopes")
    catalog_content, catalog_digest = _catalog("CATALOG_A")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="catalog-a.json",
        content=catalog_content,
        kind="PROJECT_METADATA",
        media_type=CATALOG_MEDIA_TYPE,
        key="catalog-a",
    )
    first = _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/a.spell.py",
        content=_source("local/a"),
        key="procedure-a",
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=3,
        path="procedures/sub",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="folder-sub",
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=4,
        path="procedures/sub/b.spell.py",
        content=_source("local/b"),
        key="procedure-b",
    )
    manifest = {
        **project["manifest"],
        "catalog_dependencies": [
            {
                "catalog_id": "CATALOG_A",
                "catalog_revision": 1,
                "content_digest": catalog_digest,
            }
        ],
    }
    service.update_manifest(
        project["project_id"],
        **OPERATOR,
        manifest=manifest,
        expected_workspace_revision=5,
        idempotency_key="pin-catalog-a",
    )
    snapshot = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]
    assert snapshot["pinned_catalog_entries"] == [
        {
            "catalog_id": "CATALOG_A",
            "catalog_revision": 1,
            "content_digest": catalog_digest,
            "entry_id": "catalog_a-entry",
            "qualified_name": "CATALOG_A.value",
            "catalog_kind": "TM",
            "data": {"engineering_unit": "count"},
        }
    ]

    initial = _check(
        service,
        project["project_id"],
        6,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="project-cache-miss",
    )
    assert initial["report"]["outcome"] == "PASS"
    assert initial["report"]["library_cache_hit"] is False
    cached = _check(
        service,
        project["project_id"],
        6,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="project-cache-hit",
    )
    assert cached["report"]["library_cache_hit"] is True
    reparsed = _check(
        service,
        project["project_id"],
        6,
        scope="PROJECT",
        path=None,
        reparse=True,
        key="project-cache-reparse",
    )
    assert reparsed["report"]["library_cache_hit"] is False
    base = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=6,
        message="Scope base",
        selected_resource_ids=None,
        idempotency_key="scope-base-history",
    )["history_revision"]

    changed_source = _source("local/a", "changed")
    service.update_resource(
        project["project_id"],
        first["resource_id"],
        **OPERATOR,
        changes={
            "content": changed_source,
            "content_sha256": _digest(changed_source.encode()),
        },
        expected_workspace_revision=6,
        idempotency_key="change-a",
    )
    file_job = _check(
        service,
        project["project_id"],
        7,
        scope="FILE",
        path="procedures/a.spell.py",
        reparse=False,
        key="file-a",
    )
    assert set(file_job["report"]["input_digests"]) == {"procedures/a.spell.py"}
    folder_job = _check(
        service,
        project["project_id"],
        7,
        scope="FOLDER",
        path="procedures/sub",
        reparse=False,
        key="folder-sub",
    )
    assert set(folder_job["report"]["input_digests"]) == {
        "procedures/sub",
        "procedures/sub/b.spell.py"
    }
    changed = _check(
        service,
        project["project_id"],
        7,
        scope="CHANGED_SET",
        path=None,
        reparse=False,
        key="changed-set",
    )
    assert base["history_revision_id"]
    assert set(changed["report"]["input_digests"]) == {"procedures/a.spell.py"}


def test_catalog_dependency_cycle_and_dictionary_projection_are_strict(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Catalog cycle")
    a0, a0_digest = _catalog("CATALOG_A")
    a = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="catalog-a.json",
        content=a0,
        kind="PROJECT_METADATA",
        media_type=CATALOG_MEDIA_TYPE,
        key="cycle-a0",
    )
    b, b_digest = _catalog(
        "CATALOG_B",
        dependencies=[
            {
                "catalog_id": "CATALOG_A",
                "catalog_revision": 1,
                "content_digest": a0_digest,
            }
        ],
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="catalog-b.json",
        content=b,
        kind="PROJECT_METADATA",
        media_type=CATALOG_MEDIA_TYPE,
        key="cycle-b",
    )
    a1, a1_digest = _catalog(
        "CATALOG_A",
        dependencies=[
            {
                "catalog_id": "CATALOG_B",
                "catalog_revision": 1,
                "content_digest": b_digest,
            }
        ],
    )
    service.update_resource(
        project["project_id"],
        a["resource_id"],
        **OPERATOR,
        changes={"content": a1, "content_sha256": _digest(a1.encode())},
        expected_workspace_revision=3,
        idempotency_key="cycle-a1",
    )
    service.update_manifest(
        project["project_id"],
        **OPERATOR,
        manifest={
            **project["manifest"],
            "catalog_dependencies": [
                {
                    "catalog_id": "CATALOG_A",
                    "catalog_revision": 1,
                    "content_digest": a1_digest,
                }
            ],
        },
        expected_workspace_revision=4,
        idempotency_key="cycle-manifest",
    )
    cycle = _check(
        service,
        project["project_id"],
        5,
        scope="PROJECT",
        path=None,
        reparse=True,
        key="cycle-check",
    )
    assert "DEPENDENCY_CYCLE" in {
        item["code"] for item in cycle["report"]["diagnostics"]
    }

    envelope = make_typed_value("STRING", "{{ data-only }}")
    document = build_db_document(
        "dictionary-1",
        3,
        (
            DictionaryEntry(
                "entry-1",
                "scope.value",
                envelope,
                typed_value_digest(envelope),
            ),
        ),
    )
    dictionary = _create_text_resource(
        service,
        project["project_id"],
        revision=5,
        path="dictionary.db",
        content=document.canonical_bytes.decode(),
        kind="DICTIONARY",
        media_type=DB_MEDIA_TYPE,
        key="dictionary-db",
    )
    with service.factory() as session:
        projection = session.scalar(
            select(DevelopmentDictionaryArtifact).where(
                DevelopmentDictionaryArtifact.resource_id
                == dictionary["resource_id"]
            )
        )
        assert projection is not None
        assert projection.original_bytes == document.canonical_bytes
        assert projection.canonical_bytes == document.canonical_bytes
        assert projection.dictionary_id == "dictionary-1"
    with pytest.raises(DevelopmentError, match="dictionary document is invalid"):
        _create_text_resource(
            service,
            project["project_id"],
            revision=6,
            path="duplicate.db",
            content='{"schema_version":"x","schema_version":"y"}',
            kind="DICTIONARY",
            media_type=DB_MEDIA_TYPE,
            key="dictionary-duplicate",
        )


def test_dictionary_db_imp_and_all_pinned_catalog_kinds_round_trip_with_bounds(
    tmp_path, monkeypatch
) -> None:
    service = _service(tmp_path, "dictionary-catalog-proof.sqlite")
    project = _create_project(service, "Dictionary catalog proof")
    dependencies = []
    for revision, catalog_kind in enumerate(
        ("TM", "TC", "RESOURCE", "SCDB", "GDB", "PROC", "MMD"), start=1
    ):
        catalog_id = f"CATALOG_{catalog_kind}"
        content, digest = _catalog(catalog_id, catalog_kind=catalog_kind)
        _create_text_resource(
            service,
            project["project_id"],
            revision=revision,
            path=f"catalog-{catalog_kind.casefold()}.json",
            content=content,
            kind="PROJECT_METADATA",
            media_type=CATALOG_MEDIA_TYPE,
            key=f"catalog-kind-{catalog_kind.casefold()}",
        )
        dependencies.append(
            {
                "catalog_id": catalog_id,
                "catalog_revision": 1,
                "content_digest": digest,
            }
        )
    service.update_manifest(
        project["project_id"],
        **OPERATOR,
        manifest={**project["manifest"], "catalog_dependencies": dependencies},
        expected_workspace_revision=8,
        idempotency_key="pin-seven-catalog-kinds",
    )
    pinned = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["pinned_catalog_entries"]
    assert {item["catalog_kind"] for item in pinned} == {
        "TM",
        "TC",
        "RESOURCE",
        "SCDB",
        "GDB",
        "PROC",
        "MMD",
    }
    assert len(pinned) == 7

    value = make_typed_value("STRING", "data only")
    db_document = build_db_document(
        "dictionary-db",
        4,
        (
            DictionaryEntry(
                "entry-db", "scope.db", value, typed_value_digest(value)
            ),
        ),
    )
    db_original = json.dumps(
        db_document.as_payload(), indent=2, ensure_ascii=False
    ) + "\n"
    db_resource = _create_text_resource(
        service,
        project["project_id"],
        revision=9,
        path="dictionary.db",
        content=db_original,
        kind="DICTIONARY",
        media_type=DB_MEDIA_TYPE,
        key="dictionary-db-round-trip",
    )
    imp_document = build_imp_document(
        "dictionary-imp",
        5,
        (
            DictionaryRecord(
                ImportOperation.UPSERT,
                "entry-imp",
                0,
                "scope.imp",
                value,
                typed_value_digest(value),
            ),
            DictionaryRecord(ImportOperation.DELETE, "entry-old", 3),
        ),
    )
    imp_original = json.dumps(
        imp_document.as_payload(), indent=2, ensure_ascii=False
    ) + "\n"
    imp_resource = _create_text_resource(
        service,
        project["project_id"],
        revision=10,
        path="dictionary.imp",
        content=imp_original,
        kind="DICTIONARY",
        media_type=IMP_MEDIA_TYPE,
        key="dictionary-imp-round-trip",
    )
    with service.factory() as session:
        artifacts = {
            row.resource_id: row
            for row in session.scalars(
                select(DevelopmentDictionaryArtifact).where(
                    DevelopmentDictionaryArtifact.resource_id.in_(
                        [db_resource["resource_id"], imp_resource["resource_id"]]
                    )
                )
            ).all()
        }
        assert artifacts[db_resource["resource_id"]].source_format == "DB"
        assert artifacts[db_resource["resource_id"]].original_bytes == db_original.encode()
        assert artifacts[db_resource["resource_id"]].canonical_bytes == db_document.canonical_bytes
        assert artifacts[imp_resource["resource_id"]].source_format == "IMP"
        assert artifacts[imp_resource["resource_id"]].original_bytes == imp_original.encode()
        assert artifacts[imp_resource["resource_id"]].canonical_bytes == imp_document.canonical_bytes
    assert export_dictionary_document(
        parse_dictionary_document(db_original.encode(), media_type=DB_MEDIA_TYPE)
    ) == db_document.canonical_bytes
    assert export_dictionary_document(
        parse_dictionary_document(imp_original.encode(), media_type=IMP_MEDIA_TYPE)
    ) == imp_document.canonical_bytes

    assert MAX_CATALOG_ENTRIES == 100_000
    monkeypatch.setattr("backend.development_service.MAX_CATALOG_ENTRIES", 1)
    oversized_payload = json.loads(_catalog("CATALOG_LIMIT")[0])
    oversized_payload["entries"].append(
        {
            "entry_id": "second-entry",
            "qualified_name": "CATALOG_LIMIT.second",
            "data": {},
        }
    )
    unsigned = {key: item for key, item in oversized_payload.items() if key != "content_digest"}
    oversized_payload["content_digest"] = _digest(canonical_json_bytes(unsigned))
    with pytest.raises(DevelopmentLimitError, match="catalog entries exceed"):
        _create_text_resource(
            service,
            project["project_id"],
            revision=11,
            path="catalog-over-limit.json",
            content=canonical_json_bytes(oversized_payload).decode(),
            kind="PROJECT_METADATA",
            media_type=CATALOG_MEDIA_TYPE,
            key="catalog-entry-bound",
        )


def _zip(entries: list[tuple[str, bytes, bool]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content, directory in entries:
            info = zipfile.ZipInfo(
                name + ("/" if directory and not name.endswith("/") else ""),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.create_system = 3
            info.external_attr = (
                (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)
            ) << 16
            archive.writestr(info, b"" if directory else content)
    return stream.getvalue()


def _replace_zip_content(raw: bytes, path: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw), "r") as source, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED
    ) as target:
        for original in source.infolist():
            info = zipfile.ZipInfo(
                original.filename, date_time=(1980, 1, 1, 0, 0, 0)
            )
            info.create_system = original.create_system
            info.external_attr = original.external_attr
            info.compress_type = zipfile.ZIP_STORED
            info.comment = original.comment
            target.writestr(
                info,
                content if original.filename.rstrip("/") == path else source.read(original),
            )
    return output.getvalue()


def test_project_archive_round_trip_and_hostile_inputs(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Archive")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/archive.spell.py",
        content=_source("local/archive"),
        key="archive-source",
    )
    catalog_content, _ = _catalog("ARCHIVE_CATALOG")
    _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="catalog-without-special-suffix.data",
        content=catalog_content,
        kind="PROJECT_METADATA",
        media_type=CATALOG_MEDIA_TYPE,
        key="archive-catalog",
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=3,
        path="opaque.resource",
        content="metadata",
        kind="PROJECT_METADATA",
        media_type="application/vnd.example.metadata+text",
        key="archive-metadata",
    )
    raw, digest = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=4,
    )
    decoded = DevelopmentService._read_project_archive(
        raw, case_policy="CASE_INSENSITIVE"
    )
    decoded_by_path = {item["path"]: item for item in decoded}
    assert decoded_by_path["catalog-without-special-suffix.data"]["media_type"] == CATALOG_MEDIA_TYPE
    assert decoded_by_path["opaque.resource"]["kind"] == "PROJECT_METADATA"
    assert decoded_by_path["opaque.resource"]["media_type"] == "application/vnd.example.metadata+text"
    with zipfile.ZipFile(io.BytesIO(raw), "r") as exported_archive:
        assert all(
            info.is_dir() or ((info.external_attr >> 16) & 0o111) == 0
            for info in exported_archive.infolist()
        )
    imported = service.import_project(
        project["project_id"],
        **OPERATOR,
        original_filename="archive.spell-project.zip",
        original_media_type="application/vnd.openbexi.spell.project+zip",
        archive_bytes=raw,
        archive_sha256=digest,
        expected_workspace_revision=4,
        idempotency_key="archive-round-trip",
    )
    assert imported["import"]["added"] == 0
    assert imported["import"]["imported_tree_sha256"] == imported["import"]["canonical_tree_sha256"]
    replayed = service.import_project(
        project["project_id"],
        **OPERATOR,
        original_filename="archive.spell-project.zip",
        original_media_type="application/vnd.openbexi.spell.project+zip",
        archive_bytes=raw,
        archive_sha256=digest,
        expected_workspace_revision=4,
        idempotency_key="archive-round-trip",
    )
    assert replayed["replayed"] is True
    with service.factory() as session:
        provenance = session.get(
            DevelopmentImportProvenance, imported["import"]["operation_id"]
        )
        assert provenance is not None
        assert provenance.original_bytes == raw
        assert provenance.actor_subject == OPERATOR["subject"]
        assert provenance.original_filename == "archive.spell-project.zip"
        assert provenance.original_media_type == "application/vnd.openbexi.spell.project+zip"
        assert provenance.original_byte_length == len(raw)
        assert provenance.original_bytes_sha256 == digest
        assert provenance.base_workspace_revision == 4
        assert provenance.status == "NO_CHANGE"
        assert provenance.conflict_paths == []
        assert provenance.created_at_database_time is not None
        audit = session.get(DevelopmentAuditEvent, provenance.audit_id)
        assert audit is not None
        assert audit.action == "IMPORT_QUARANTINED"
        assert audit.payload["operation_id"] == provenance.operation_id
    reexported, reexported_digest = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=4,
    )
    assert reexported == raw
    assert reexported_digest == digest

    with pytest.raises(DevelopmentError, match="path contains a forbidden segment"):
        DevelopmentService._read_project_archive(
            _zip([("spell-project.yaml", b"{}", False), ("../escape", b"x", False)]),
            case_policy="CASE_INSENSITIVE",
        )
    duplicate_manifest = b'{"schema_version":"x","schema_version":"y"}'
    hostile = _zip(
        [
            ("procedures", b"", True),
            ("spell-project.yaml", duplicate_manifest, False),
        ]
    )
    with pytest.raises(DevelopmentError, match="duplicate key"):
        service.import_project(
            project["project_id"],
            **OPERATOR,
            original_filename="duplicate.zip",
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=hostile,
            archive_sha256=_digest(hostile),
            expected_workspace_revision=4,
            idempotency_key="archive-duplicate-manifest",
        )
    monkeypatch.setattr("backend.development_service.MAX_PROJECT_BYTES", 5)
    over_limit = _zip(
        [("spell-project.yaml", b"{}", False), ("extra.txt", b"1234", False)]
    )
    with pytest.raises(DevelopmentLimitError, match="uncompressed bytes"):
        DevelopmentService._read_project_archive(
            over_limit, case_policy="CASE_INSENSITIVE"
        )

    unknown = io.BytesIO()
    with zipfile.ZipFile(unknown, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("spell-project.yaml", date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 0
        info.external_attr = 0
        archive.writestr(info, b"{}")
    with pytest.raises(DevelopmentError, match="platform|non-regular"):
        DevelopmentService._read_project_archive(
            unknown.getvalue(), case_policy="CASE_INSENSITIVE"
        )


def test_project_archive_maps_crc_truncation_and_payload_directory_failures() -> None:
    valid = _zip(
        [
            ("spell-project.yaml", b"{}", False),
            ("crc-canary.txt", b"crc-payload-canary", False),
        ]
    )
    corrupted = bytearray(valid)
    position = valid.find(b"crc-payload-canary")
    assert position >= 0
    corrupted[position] ^= 0x01
    with pytest.raises(DevelopmentError, match="CRC"):
        DevelopmentService._read_project_archive(
            bytes(corrupted), case_policy="CASE_INSENSITIVE"
        )
    with pytest.raises(DevelopmentError, match="archive is invalid"):
        DevelopmentService._read_project_archive(
            valid[:-12], case_policy="CASE_INSENSITIVE"
        )

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        manifest = zipfile.ZipInfo(
            "spell-project.yaml", date_time=(1980, 1, 1, 0, 0, 0)
        )
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, b"{}")
        directory = zipfile.ZipInfo(
            "procedures/", date_time=(1980, 1, 1, 0, 0, 0)
        )
        directory.create_system = 3
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        archive.writestr(directory, b"unexpected-payload")
    with pytest.raises(DevelopmentError, match="directory entries must be empty"):
        DevelopmentService._read_project_archive(
            stream.getvalue(), case_policy="CASE_INSENSITIVE"
        )


def test_import_preparse_does_not_hold_sqlite_writer_lock(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path, "import-concurrency.sqlite")
    project = _create_project(service, "Slow Import")
    archive, digest = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=1,
    )
    entered = threading.Event()
    release = threading.Event()
    original = DevelopmentService._read_project_archive

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=3)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        DevelopmentService, "_read_project_archive", staticmethod(blocked)
    )
    result: dict = {}
    import_thread = threading.Thread(
        target=lambda: result.update(
            service.import_project(
                project["project_id"],
                **OPERATOR,
                original_filename="slow.zip",
                original_media_type="application/vnd.openbexi.spell.project+zip",
                archive_bytes=archive,
                archive_sha256=digest,
                expected_workspace_revision=1,
                idempotency_key="slow-import",
            )
        )
    )
    import_thread.start()
    assert entered.wait(timeout=1)
    unrelated: dict = {}
    writer = threading.Thread(
        target=lambda: unrelated.update(_create_project(service, "Unrelated"))
    )
    writer.start()
    try:
        writer.join(timeout=1)
        assert not writer.is_alive(), "archive parsing held the SQLite writer lock"
        assert unrelated["project_id"]
    finally:
        release.set()
    import_thread.join(timeout=5)
    assert not import_thread.is_alive()
    assert result["import"]["added"] == 0


def test_retained_import_apply_discard_race_and_idempotent_replay(
    tmp_path, monkeypatch
) -> None:
    service = _service(tmp_path, "retained-import.sqlite")
    project = _create_project(service, "Retained Import")
    resource = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="incoming.txt",
        content="workspace version",
        kind="PROJECT_METADATA",
        media_type="text/plain",
        key="retained-existing",
    )
    exported, _ = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=2,
    )
    incoming = _replace_zip_content(exported, "incoming.txt", b"retained version")
    with pytest.raises(DevelopmentConflictError) as caught:
        service.import_project(
            project["project_id"],
            **OPERATOR,
            original_filename="retained.zip",
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=incoming,
            archive_sha256=_digest(incoming),
            expected_workspace_revision=2,
            idempotency_key="retained-upload",
        )
    operation_id = caught.value.current["operation_id"]
    operation = service.get_import_operation(
        project["project_id"], operation_id, subject="viewer", role="viewer"
    )["import_operation"]
    assert operation["status"] == "CONFLICT"
    assert operation["original_bytes_available"] is True
    assert operation["conflict_paths"] == ["incoming.txt"]

    service.delete_resource(
        project["project_id"],
        resource["resource_id"],
        **OPERATOR,
        expected_workspace_revision=2,
        idempotency_key="retained-delete-existing",
    )
    entered = threading.Event()
    release = threading.Event()
    original_reader = DevelopmentService._read_project_archive

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=3)
        return original_reader(*args, **kwargs)

    monkeypatch.setattr(
        DevelopmentService, "_read_project_archive", staticmethod(blocked)
    )
    applied: dict = {}
    apply_thread = threading.Thread(
        target=lambda: applied.update(
            service.apply_import_operation(
                project["project_id"],
                operation_id,
                **OPERATOR,
                expected_workspace_revision=3,
                idempotency_key="retained-apply",
            )
        )
    )
    apply_thread.start()
    assert entered.wait(timeout=1)
    with pytest.raises(DevelopmentConflictError) as discard_race:
        service.discard_import_operation(
            project["project_id"],
            operation_id,
            **OPERATOR,
            expected_workspace_revision=3,
            reason="must not beat claimed apply",
            idempotency_key="retained-discard-race",
        )
    assert discard_race.value.code == "IMPORT_OPERATION_CLOSED"
    release.set()
    apply_thread.join(timeout=5)
    assert not apply_thread.is_alive()
    assert applied["source_operation_id"] == operation_id
    assert applied["import"]["added"] == 1
    assert service.get_import_operation(
        project["project_id"], operation_id, subject="viewer", role="viewer"
    )["import_operation"]["status"] == "APPLIED"
    imported = next(
        item
        for item in service.workspace_snapshot(
            project["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
        if item["path"] == "incoming.txt"
    )
    assert service.get_resource(
        project["project_id"], imported["resource_id"], subject="viewer", role="viewer"
    )["resource"]["content"] == "retained version"
    replay = service.apply_import_operation(
        project["project_id"],
        operation_id,
        **OPERATOR,
        expected_workspace_revision=3,
        idempotency_key="retained-apply",
    )
    assert replay["replayed"] is True
    with pytest.raises(DevelopmentConflictError) as resurrect:
        service.import_project(
            project["project_id"],
            **OPERATOR,
            original_filename="retained.zip",
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=incoming,
            archive_sha256=_digest(incoming),
            expected_workspace_revision=2,
            idempotency_key="retained-upload",
        )
    assert resurrect.value.code == "IMPORT_OPERATION_CLOSED"
    assert service.get_import_operation(
        project["project_id"], operation_id, subject="viewer", role="viewer"
    )["import_operation"]["status"] == "APPLIED"


def test_invalid_archive_manifests_create_no_invisible_quarantine_records(
    tmp_path,
) -> None:
    service = _service(tmp_path, "invalid-import-manifest.sqlite")
    project = _create_project(service, "Invalid import manifest")
    exported, _ = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=1,
    )
    with zipfile.ZipFile(io.BytesIO(exported), "r") as archive:
        manifest = json.loads(archive.read("spell-project.yaml"))
    missing = dict(manifest)
    missing.pop("owners")
    wrong_identity = {**manifest, "project_id": "dev-wrong-project"}
    variants = (
        b'{"schema_version":"first","schema_version":"duplicate"}',
        b"{}",
        canonical_json_bytes(missing),
        canonical_json_bytes(wrong_identity),
    )
    tracked_models = (
        DevelopmentImportProvenance,
        DevelopmentAuditEvent,
        DevelopmentIdempotency,
    )
    with service.factory() as session:
        before = {
            model: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in tracked_models
        }
    for index, invalid_manifest in enumerate(variants):
        hostile = _replace_zip_content(
            exported, "spell-project.yaml", invalid_manifest
        )
        with pytest.raises(DevelopmentError):
            service.import_project(
                project["project_id"],
                **OPERATOR,
                original_filename=f"invalid-manifest-{index}.zip",
                original_media_type="application/vnd.openbexi.spell.project+zip",
                archive_bytes=hostile,
                archive_sha256=_digest(hostile),
                expected_workspace_revision=1,
                idempotency_key=f"invalid-manifest-{index}",
            )
    with service.factory() as session:
        after = {
            model: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in tracked_models
        }
        assert after == before


def test_import_operation_unexpected_failure_and_startup_recovery_close_applying_state(
    tmp_path, monkeypatch
) -> None:
    service = _service(tmp_path, "retained-import-recovery.sqlite")
    project = _create_project(service, "Retained import recovery")
    resource = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="incoming.txt",
        content="workspace version",
        kind="PROJECT_METADATA",
        media_type="text/plain",
        key="recovery-existing",
    )
    exported, _ = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=2,
    )
    incoming = _replace_zip_content(exported, "incoming.txt", b"retained version")
    with pytest.raises(DevelopmentConflictError) as caught:
        service.import_project(
            project["project_id"],
            **OPERATOR,
            original_filename="recovery.zip",
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=incoming,
            archive_sha256=_digest(incoming),
            expected_workspace_revision=2,
            idempotency_key="recovery-upload",
        )
    operation_id = caught.value.current["operation_id"]
    service.delete_resource(
        project["project_id"],
        resource["resource_id"],
        **OPERATOR,
        expected_workspace_revision=2,
        idempotency_key="recovery-delete-existing",
    )

    def unexpected(*_args, **_kwargs):
        raise RuntimeError("injected retained import failure")

    monkeypatch.setattr(service, "import_project", unexpected)
    with pytest.raises(RuntimeError, match="injected retained import failure"):
        service.apply_import_operation(
            project["project_id"],
            operation_id,
            **OPERATOR,
            expected_workspace_revision=3,
            idempotency_key="recovery-apply-failure",
        )
    with service.factory() as session:
        operation = session.get(DevelopmentImportProvenance, operation_id)
        assert operation is not None
        assert operation.status == "CONFLICT"
    with service.factory.begin() as session:
        session.get(DevelopmentImportProvenance, operation_id).status = "APPLYING"
    assert service.recover_import_operations() == 1
    assert service.get_import_operation(
        project["project_id"], operation_id, subject="viewer", role="viewer"
    )["import_operation"]["status"] == "CONFLICT"


def test_project_archive_rejects_semantic_metadata_mismatch_and_time_overrun(
    tmp_path, monkeypatch
) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Archive semantics")
    source = _source("local/archive-semantics")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/archive-semantics.spell.py",
        content=source,
        key="archive-semantics-source",
    )
    raw, _ = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=2,
    )
    rewritten = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw), "r") as source_archive, zipfile.ZipFile(
        rewritten, "w", compression=zipfile.ZIP_STORED
    ) as target_archive:
        for original in source_archive.infolist():
            info = zipfile.ZipInfo(original.filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = original.external_attr
            info.compress_type = zipfile.ZIP_STORED
            metadata = json.loads(original.comment)
            if metadata["path"] == "procedures/archive-semantics.spell.py":
                metadata["kind"] = "PROJECT_METADATA"
                metadata["media_type"] = "text/x-python"
            info.comment = canonical_json_bytes(metadata)
            target_archive.writestr(info, source_archive.read(original))
    hostile = rewritten.getvalue()
    with pytest.raises(DevelopmentConflictError, match="conflicts") as caught:
        service.import_project(
            project["project_id"],
            **OPERATOR,
            original_filename="semantic-mismatch.zip",
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=hostile,
            archive_sha256=_digest(hostile),
            expected_workspace_revision=2,
            idempotency_key="archive-semantic-mismatch",
        )
    operation_id = caught.value.current["operation_id"]
    with service.factory() as session:
        provenance = session.get(DevelopmentImportProvenance, operation_id)
        assert provenance is not None
        assert provenance.status == "CONFLICT"
        assert provenance.original_bytes == hostile
        assert provenance.original_filename == "semantic-mismatch.zip"
        assert provenance.conflict_paths == [
            "procedures/archive-semantics.spell.py"
        ]
        actions = session.scalars(
            select(DevelopmentAuditEvent.action).where(
                DevelopmentAuditEvent.project_id == project["project_id"]
            )
        ).all()
        assert "IMPORT_QUARANTINED" in actions
        assert "IMPORT_PROJECT_CONFLICT" in actions

    ticks = iter((0.0, 31.0))
    monkeypatch.setattr("backend.development_service.time.monotonic", lambda: next(ticks))
    with pytest.raises(DevelopmentLimitError, match="processing-time"):
        DevelopmentService._read_project_archive(
            raw, case_policy="CASE_INSENSITIVE"
        )


@pytest.mark.parametrize(
    "hostile_path",
    [
        "/absolute.txt",
        "../parent.txt",
        "folder\\backslash.txt",
        "C:/drive.txt",
        "stream.txt:ads",
        "NUL",
        "con.txt",
        "folder/COM1.log",
        "folder/lpt9",
    ],
)
def test_project_archive_rejects_nonportable_and_device_paths(hostile_path) -> None:
    hostile = _zip(
        [
            ("spell-project.yaml", b"{}", False),
            (hostile_path, b"x", False),
        ]
    )
    with pytest.raises(DevelopmentError):
        DevelopmentService._read_project_archive(
            hostile, case_policy="CASE_INSENSITIVE"
        )


def test_project_archive_rejects_link_metadata_nested_archives_and_nfc_collisions() -> None:
    link_stream = io.BytesIO()
    with zipfile.ZipFile(link_stream, "w", compression=zipfile.ZIP_STORED) as archive:
        manifest = zipfile.ZipInfo(
            "spell-project.yaml", date_time=(1980, 1, 1, 0, 0, 0)
        )
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, b"{}")
        link = zipfile.ZipInfo("link", date_time=(1980, 1, 1, 0, 0, 0))
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, b"target")
    with pytest.raises(DevelopmentError, match="non-regular"):
        DevelopmentService._read_project_archive(
            link_stream.getvalue(), case_policy="CASE_INSENSITIVE"
        )

    nested = _zip(
        [("spell-project.yaml", b"{}", False), ("nested.zip", b"PK", False)]
    )
    with pytest.raises(DevelopmentError, match="nested"):
        DevelopmentService._read_project_archive(
            nested, case_policy="CASE_INSENSITIVE"
        )

    normalized_collision = _zip(
        [
            ("spell-project.yaml", b"{}", False),
            ("caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt", b"a", False),
            ("cafe\N{COMBINING ACUTE ACCENT}.txt", b"b", False),
        ]
    )
    with pytest.raises(DevelopmentConflictError, match="collide"):
        DevelopmentService._read_project_archive(
            normalized_collision, case_policy="CASE_INSENSITIVE"
        )


def test_folder_subtree_queries_treat_percent_and_underscore_literally(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Literal subtree")
    percent = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/foo%",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="folder-percent",
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/foox",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="folder-foox",
    )
    unrelated_percent = _create_text_resource(
        service,
        project["project_id"],
        revision=3,
        path="procedures/foox/item.spell.py",
        content=_source("local/foox"),
        key="file-foox",
    )
    service.copy_resource(
        project["project_id"],
        percent["resource_id"],
        **OPERATOR,
        destination_path="procedures/copied-percent",
        expected_workspace_revision=4,
        idempotency_key="copy-percent",
    )
    service.update_resource(
        project["project_id"],
        percent["resource_id"],
        **OPERATOR,
        changes={"path": "procedures/renamed-percent"},
        expected_workspace_revision=5,
        idempotency_key="rename-percent",
    )

    underscore = _create_text_resource(
        service,
        project["project_id"],
        revision=6,
        path="procedures/foo_",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="folder-underscore",
    )
    _create_text_resource(
        service,
        project["project_id"],
        revision=7,
        path="procedures/fooa",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="folder-fooa",
    )
    unrelated_underscore = _create_text_resource(
        service,
        project["project_id"],
        revision=8,
        path="procedures/fooa/item.spell.py",
        content=_source("local/fooa"),
        key="file-fooa",
    )
    service.delete_resource(
        project["project_id"],
        underscore["resource_id"],
        **OPERATOR,
        expected_workspace_revision=9,
        idempotency_key="delete-underscore",
    )
    workspace = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]
    by_id = {item["resource_id"]: item["path"] for item in workspace["resources"]}
    assert by_id[unrelated_percent["resource_id"]] == "procedures/foox/item.spell.py"
    assert by_id[unrelated_underscore["resource_id"]] == "procedures/fooa/item.spell.py"
    assert by_id[percent["resource_id"]] == "procedures/renamed-percent"
    assert underscore["resource_id"] not in by_id


def test_tree_manifest_invariants_and_check_scopes_fail_closed(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Tree invariants")
    with pytest.raises(DevelopmentConflictError) as orphan:
        _create_text_resource(
            service,
            project["project_id"],
            revision=1,
            path="procedures/missing/child.spell.py",
            content=_source("local/orphan"),
            key="tree-orphan",
        )
    assert orphan.value.code == "ORPHAN_RESOURCE"

    file_row = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/file.spell.py",
        content=_source("local/file"),
        key="tree-file",
    )
    with pytest.raises(DevelopmentConflictError) as below_file:
        _create_text_resource(
            service,
            project["project_id"],
            revision=2,
            path="procedures/file.spell.py/child.txt",
            content="child",
            kind="PROJECT_METADATA",
            media_type="text/plain",
            key="tree-below-file",
        )
    assert below_file.value.code == "RESOURCE_BELOW_FILE"

    root = next(
        item
        for item in service.workspace_snapshot(
            project["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
        if item["path"] == "procedures"
    )
    with pytest.raises(DevelopmentConflictError) as root_kind:
        service.update_resource(
            project["project_id"],
            root["resource_id"],
            **OPERATOR,
            changes={"kind": "PROJECT_METADATA", "media_type": "text/plain"},
            expected_workspace_revision=2,
            idempotency_key="tree-root-kind",
        )
    assert root_kind.value.code == "RESOURCE_HAS_CHILDREN"
    with pytest.raises(DevelopmentConflictError) as root_delete:
        service.apply_external_changes(
            project["project_id"],
            **OPERATOR,
            base_workspace_revision=2,
            changes=[
                {
                    "path": "procedures",
                    "delete": True,
                    "base_content_sha256": _digest(b""),
                }
            ],
            resolution="KEEP_AS_NEW_CHANGE",
            idempotency_key="tree-root-external-delete",
        )
    assert root_delete.value.code == "RESOURCE_HAS_CHILDREN"

    empty_project = _create_project(service, "Empty source root")
    empty_root = next(
        item
        for item in service.workspace_snapshot(
            empty_project["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
        if item["path"] == "procedures"
    )
    with pytest.raises(DevelopmentConflictError) as empty_root_kind:
        service.update_resource(
            empty_project["project_id"],
            empty_root["resource_id"],
            **OPERATOR,
            changes={"kind": "PROJECT_METADATA", "media_type": "text/plain"},
            expected_workspace_revision=1,
            idempotency_key="tree-empty-root-kind",
        )
    assert empty_root_kind.value.code == "MANIFEST_SOURCE_ROOT_NOT_FOLDER"
    with pytest.raises(DevelopmentConflictError) as missing_root:
        service.apply_external_changes(
            empty_project["project_id"],
            **OPERATOR,
            base_workspace_revision=1,
            changes=[
                {
                    "path": "procedures",
                    "delete": True,
                    "base_content_sha256": _digest(b""),
                }
            ],
            resolution="KEEP_AS_NEW_CHANGE",
            idempotency_key="tree-empty-root-external-delete",
        )
    assert missing_root.value.code == "MANIFEST_SOURCE_ROOT_MISSING"

    with pytest.raises(DevelopmentNotFoundError):
        service.create_check(
            project["project_id"],
            **OPERATOR,
            scope="FILE",
            scope_path="procedures/absent.spell.py",
            expected_workspace_revision=2,
            reparse_libraries=False,
            idempotency_key="scope-absent",
        )
    with pytest.raises(DevelopmentConflictError) as file_is_folder:
        service.create_check(
            project["project_id"],
            **OPERATOR,
            scope="FILE",
            scope_path="procedures",
            expected_workspace_revision=2,
            reparse_libraries=False,
            idempotency_key="scope-file-folder",
        )
    assert file_is_folder.value.code == "CHECK_SCOPE_KIND_INVALID"
    with pytest.raises(DevelopmentConflictError) as folder_is_file:
        service.create_check(
            project["project_id"],
            **OPERATOR,
            scope="FOLDER",
            scope_path=file_row["path"],
            expected_workspace_revision=2,
            reparse_libraries=False,
            idempotency_key="scope-folder-file",
        )
    assert folder_is_file.value.code == "CHECK_SCOPE_KIND_INVALID"

    with service.factory.begin() as session:
        session.execute(
            delete(DevelopmentResource).where(
                DevelopmentResource.resource_id == root["resource_id"]
            )
        )
    corrupted = _check(
        service,
        project["project_id"],
        2,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="tree-corruption-check",
    )
    assert corrupted["report"]["outcome"] == "FAILED"
    assert "MANIFEST_SOURCE_ROOT_MISSING" in {
        item["code"] for item in corrupted["report"]["diagnostics"]
    }
