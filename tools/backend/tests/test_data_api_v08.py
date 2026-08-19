from __future__ import annotations

import hashlib
import os

import pytest
from sqlalchemy import func, select

from backend.config import Settings
from backend.data_models import DataAuditOutbox, DataDictionary, DataMutationIdempotency
from backend.data_values import make_typed_value, typed_value_digest
from backend.dictionary_exchange import (
    DB_MEDIA_TYPE,
    DictionaryEntry,
    build_db_document,
)


SESSION_HEADERS = {
    "X-Spell-Session-Id": "pytest-session-0001",
    "X-Spell-Client-Instance-Key-Id": "pytest-client-key-0001",
}


def _settings_for_paths(procedures_dir, data_dir) -> Settings:
    return Settings(
        database_url="sqlite://",
        procedures_dir=procedures_dir,
        websocket_replay_limit=1000,
        websocket_queue_size=256,
        websocket_keepalive_seconds=5.0,
        data_dir=data_dir,
    )


def test_data_directory_rejects_both_directions_of_procedure_overlap(tmp_path) -> None:
    procedures = tmp_path / "workspace" / "procedures"
    with pytest.raises(ValueError, match="separate from executable procedures"):
        _settings_for_paths(procedures, procedures / "data")
    with pytest.raises(ValueError, match="separate from executable procedures"):
        _settings_for_paths(procedures, tmp_path / "workspace")


def test_data_directory_overlap_uses_resolved_symlink_paths(tmp_path) -> None:
    procedures = tmp_path / "real" / "procedures"
    procedures.mkdir(parents=True)
    alias = tmp_path / "procedure-alias"
    try:
        os.symlink(procedures, alias, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(ValueError, match="separate from executable procedures"):
        _settings_for_paths(procedures, alias / "data")


def _mutation_headers(
    authorization: dict[str, str],
    key: str,
    *,
    content_type: str,
) -> dict[str, str]:
    return {
        **authorization,
        **SESSION_HEADERS,
        "Idempotency-Key": key,
        "Content-Type": content_type,
    }


def test_file_api_streaming_lifecycle_and_replay(
    client, operator_headers, viewer_headers
) -> None:
    directory_headers = _mutation_headers(
        operator_headers, "api-create-reports", content_type="application/json"
    )
    created = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers=directory_headers,
        json={"virtual_path": "reports", "expected_revision": "0"},
    )
    assert created.status_code == 200, created.text
    assert created.json()["revision"] == "1"
    assert created.json()["replayed"] is False

    payload = b"v0.8 bounded content\n"
    digest = hashlib.sha256(payload).hexdigest()
    write_headers = {
        **_mutation_headers(
            operator_headers,
            "api-write-report",
            content_type="application/octet-stream",
        ),
        "Content-SHA256": digest,
    }
    url = (
        "/api/v1/data/files/PROJECT_DATA/content"
        "?virtual_path=reports/result.txt&expected_revision=0&encoding=UTF8_TEXT"
    )
    written = client.put(url, headers=write_headers, content=payload)
    assert written.status_code == 200, written.text
    assert written.json()["revision"] == "1"
    assert written.json()["replayed"] is False

    replay = client.put(url, headers=write_headers, content=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json() == {**written.json(), "replayed": True}

    read = client.get(
        "/api/v1/data/files/PROJECT_DATA/content",
        headers=viewer_headers,
        params={"virtual_path": "reports/result.txt", "revision": "1"},
    )
    assert read.status_code == 200, read.text
    assert read.content == payload
    assert read.headers["content-sha256"] == digest
    assert read.headers["x-spell-encoding"] == "UTF8_TEXT"
    assert read.headers["x-spell-revision"] == "1"

    listing = client.get(
        "/api/v1/data/files/PROJECT_DATA/directory",
        headers=viewer_headers,
        params={"virtual_path": "reports"},
    )
    assert listing.status_code == 200, listing.text
    assert [item["name"] for item in listing.json()["items"]] == ["result.txt"]

    deleted = client.request(
        "DELETE",
        "/api/v1/data/files/PROJECT_DATA/nodes",
        headers=_mutation_headers(
            operator_headers, "api-delete-report", content_type="application/json"
        ),
        json={"virtual_path": "reports/result.txt", "expected_revision": "1"},
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["deleted_revision"] == "1"


def test_data_api_authorizes_before_reading_mutation_body(
    client, viewer_headers
) -> None:
    response = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={
            **viewer_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "viewer-cannot-mutate",
            "Content-Type": "application/json",
        },
        content=b'{"not even":"the schema"}',
    )
    assert response.status_code == 403
    assert response.json()["code"] == "NOT_AUTHORIZED"

    catalog = client.post(
        "/api/v1/data/catalogs/catalog-unauthorized/revisions",
        params={"owner_id": "local-project", "acl_revision": "1"},
        headers={
            **viewer_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "viewer-catalog-mutation",
            "Content-Type": "application/json",
        },
        content=b"not-json",
    )
    assert catalog.status_code == 403
    assert catalog.json()["code"] == "NOT_AUTHORIZED"


def test_server_owned_policy_denies_cross_owner_stale_acl_and_read_only_root(
    client, operator_headers, viewer_headers
) -> None:
    cross_owner_read = client.get(
        "/api/v1/data/catalogs",
        params={"owner_id": "victim-project"},
        headers=viewer_headers,
    )
    assert cross_owner_read.status_code == 403
    assert cross_owner_read.json()["code"] == "NOT_AUTHORIZED"

    cross_owner_mutation = client.post(
        "/api/v1/data/shared/namespaces",
        params={
            "owner_id": "victim-project",
            "namespace_id": "victim-namespace",
            "acl_revision": "1",
        },
        headers={
            **operator_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "cross-owner-mutation",
            "Content-Type": "application/json",
        },
        content=b"not-json",
    )
    assert cross_owner_mutation.status_code == 403
    assert cross_owner_mutation.json()["code"] == "NOT_AUTHORIZED"

    stale_acl = client.post(
        "/api/v1/data/containers",
        params={
            "owner_id": "local-project",
            "container_id": "stale-acl-container",
            "acl_revision": "2",
        },
        headers={
            **operator_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "stale-acl-mutation",
            "Content-Type": "application/json",
        },
        content=b"not-json",
    )
    assert stale_acl.status_code == 403
    assert stale_acl.json()["code"] == "NOT_AUTHORIZED"

    read_only_root = client.post(
        "/api/v1/data/files/PROCEDURE_DATA/directories",
        headers={
            **operator_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "read-only-root-mutation",
            "Content-Type": "application/json",
        },
        content=b"not-json",
    )
    assert read_only_root.status_code == 403
    assert read_only_root.json()["code"] == "NOT_AUTHORIZED"


def test_mutations_require_exact_session_and_idempotency_bindings(
    client, operator_headers
) -> None:
    missing = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={
            **operator_headers,
            "Idempotency-Key": "missing-session",
            "Content-Type": "application/json",
        },
        json={"virtual_path": "missing", "expected_revision": "0"},
    )
    assert missing.status_code == 422
    assert missing.json()["code"] == "REJECTED"

    legacy_header_only = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={
            **operator_headers,
            **SESSION_HEADERS,
            "X-Idempotency-Key": "legacy-key",
            "Content-Type": "application/json",
        },
        json={"virtual_path": "legacy", "expected_revision": "0"},
    )
    assert legacy_header_only.status_code == 422
    assert legacy_header_only.json()["code"] == "REJECTED"


def test_json_mutations_reject_duplicates_unknown_fields_and_over_limit(
    client, operator_headers
) -> None:
    headers = _mutation_headers(
        operator_headers, "strict-json", content_type="application/json"
    )
    duplicate = b'{"virtual_path":"one","virtual_path":"two","expected_revision":"0"}'
    response = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={**headers, "Content-Length": str(len(duplicate))},
        content=duplicate,
    )
    assert response.status_code == 422
    assert response.json()["code"] == "REJECTED"

    unknown = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={**headers, "Idempotency-Key": "strict-json-unknown"},
        json={"virtual_path": "one", "expected_revision": "0", "extra": True},
    )
    assert unknown.status_code == 422

    numeric_revision = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={**headers, "Idempotency-Key": "strict-json-number-revision"},
        json={"virtual_path": "number-revision", "expected_revision": 0},
    )
    assert numeric_revision.status_code == 422

    oversized = b" " * 1_048_577
    too_large = client.post(
        "/api/v1/data/files/PROJECT_DATA/directories",
        headers={
            **headers,
            "Idempotency-Key": "strict-json-oversized",
            "Content-Length": str(len(oversized)),
        },
        content=oversized,
    )
    assert too_large.status_code == 413
    assert too_large.json()["code"] == "LIMIT_EXCEEDED"


def test_binary_write_rejects_encoding_length_digest_and_partial_visibility(
    client, operator_headers, viewer_headers
) -> None:
    payload = b"content"
    digest = hashlib.sha256(payload).hexdigest()
    base_headers = {
        **_mutation_headers(
            operator_headers,
            "bad-file-upload",
            content_type="application/octet-stream",
        ),
        "Content-SHA256": digest,
    }
    url = (
        "/api/v1/data/files/PROJECT_DATA/content"
        "?virtual_path=not-visible.bin&expected_revision=0&encoding=BINARY"
    )
    compressed = client.put(
        url,
        headers={**base_headers, "Content-Encoding": "gzip"},
        content=payload,
    )
    assert compressed.status_code == 422

    chunked = client.put(
        url,
        headers={**base_headers, "Transfer-Encoding": "chunked"},
        content=payload,
    )
    assert chunked.status_code == 422

    wrong_digest = client.put(
        url,
        headers={
            **base_headers,
            "Idempotency-Key": "bad-file-digest",
            "Content-SHA256": "0" * 64,
        },
        content=payload,
    )
    assert wrong_digest.status_code == 422
    missing = client.get(
        "/api/v1/data/files/PROJECT_DATA/content",
        headers=viewer_headers,
        params={"virtual_path": "not-visible.bin"},
    )
    assert missing.status_code == 404


def test_file_write_idempotency_binds_encoding_and_declared_length(
    client, operator_headers
) -> None:
    payload = b"same bytes"
    digest = hashlib.sha256(payload).hexdigest()
    headers = {
        **_mutation_headers(
            operator_headers,
            "api-write-semantic-binding",
            content_type="application/octet-stream",
        ),
        "Content-SHA256": digest,
    }
    base = (
        "/api/v1/data/files/PROJECT_DATA/content"
        "?virtual_path=semantic.bin&expected_revision=0"
    )
    created = client.put(f"{base}&encoding=BINARY", headers=headers, content=payload)
    assert created.status_code == 200, created.text

    changed_encoding = client.put(
        f"{base}&encoding=UTF8_TEXT", headers=headers, content=payload
    )
    assert changed_encoding.status_code == 409
    assert changed_encoding.json()["code"] == "IDEMPOTENCY_CONFLICT"


def test_catalog_container_and_shared_routes_are_closed_and_cursored(
    client, admin_headers, operator_headers, viewer_headers
) -> None:
    catalog_headers = _mutation_headers(
        admin_headers, "api-publish-catalog", content_type="application/json"
    )
    published = client.post(
        "/api/v1/data/catalogs/catalog-1/revisions",
        params={"owner_id": "local-project", "acl_revision": "1"},
        headers=catalog_headers,
        json={
            "dependencies": [],
            "entries": [
                {
                    "content": {"description": "bounded"},
                    "entry_id": "entry-1",
                    "qualified_name": "project.entry",
                }
            ],
            "expected_revision": "0",
            "kind": "MMD",
            "schema_version": "spell.catalog.test/1",
        },
    )
    assert published.status_code == 200, published.text
    assert published.json()["new_revision"] == "1"
    second_catalog = client.post(
        "/api/v1/data/catalogs/catalog-2/revisions",
        params={"owner_id": "local-project", "acl_revision": "1"},
        headers={**catalog_headers, "Idempotency-Key": "api-publish-catalog-2"},
        json={
            "dependencies": [
                {
                    "dependency_id": "catalog-2-imports-catalog-1",
                    "relationship": "IMPORTS",
                    "target_catalog_id": "catalog-1",
                    "target_content_digest": published.json()["content_digest"],
                    "target_revision": "1",
                }
            ],
            "entries": [],
            "expected_revision": "0",
            "kind": "MMD",
            "schema_version": "spell.catalog.test/1",
        },
    )
    assert second_catalog.status_code == 200, second_catalog.text

    catalogs = client.get(
        "/api/v1/data/catalogs",
        params={"owner_id": "local-project", "page_size": 1},
        headers=viewer_headers,
    )
    assert catalogs.status_code == 200, catalogs.text
    assert catalogs.json()["catalogs"][0]["revision"] == "1"
    assert catalogs.json()["next_cursor"]
    next_catalogs = client.get(
        "/api/v1/data/catalogs",
        params={
            "owner_id": "local-project",
            "page_size": 1,
            "cursor": catalogs.json()["next_cursor"],
        },
        headers=viewer_headers,
    )
    assert next_catalogs.status_code == 200, next_catalogs.text
    assert next_catalogs.json()["catalogs"][0]["catalog_id"] == "catalog-2"
    revision = client.get(
        "/api/v1/data/catalogs/catalog-1/revisions/1",
        params={"owner_id": "local-project", "acl_revision": "1"},
        headers=viewer_headers,
    )
    assert revision.status_code == 200, revision.text
    assert revision.json()["content"]["revision"] == "1"
    assert revision.json()["content"]["entries"][0]["content"] == {
        "description": "bounded"
    }

    mutation_headers = _mutation_headers(
        operator_headers, "api-create-container", content_type="application/json"
    )
    container = client.post(
        "/api/v1/data/containers",
        params={
            "owner_id": "local-project",
            "container_id": "container-1",
            "acl_revision": "1",
        },
        headers=mutation_headers,
        json={"expected_revision": "0", "schema_revision": "1"},
    )
    assert container.status_code == 200, container.text
    assert container.json()["new_revision"] == "1"
    containers = client.get(
        "/api/v1/data/containers",
        params={"owner_id": "local-project", "page_size": 1},
        headers=viewer_headers,
    )
    assert containers.status_code == 200, containers.text
    assert containers.json()["containers"] == [
        {
            "acl_revision": "1",
            "container_id": "container-1",
            "content_digest": container.json()["content_digest"],
            "kind": "DATA_CONTAINER",
            "revision": "1",
            "schema_revision": "1",
        }
    ]
    value = make_typed_value("STRING", "value")
    variable = client.put(
        "/api/v1/data/containers/container-1/variables/variable-1",
        params={"owner_id": "local-project", "acl_revision": "1"},
        headers={**mutation_headers, "Idempotency-Key": "api-set-variable"},
        json={
            "declared_type": "STRING",
            "expected_revision": "1",
            "expected_variable_revision": "0",
            "name": "variable",
            "value": value,
        },
    )
    assert variable.status_code == 200, variable.text
    assert variable.json()["new_revision"] == "2"
    enumerated = client.get(
        "/api/v1/data/containers/container-1/variables",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "page_size": 1,
        },
        headers=viewer_headers,
    )
    assert enumerated.status_code == 200, enumerated.text
    assert enumerated.json()["variables"][0]["revision"] == "1"

    namespace = client.post(
        "/api/v1/data/shared/namespaces",
        params={
            "owner_id": "local-project",
            "namespace_id": "shared-1",
            "acl_revision": "1",
        },
        headers={**mutation_headers, "Idempotency-Key": "api-create-namespace"},
        json={"expected_revision": "0", "scope": "PROJECT"},
    )
    assert namespace.status_code == 200, namespace.text
    context_namespace = client.post(
        "/api/v1/data/shared/namespaces",
        params={
            "owner_id": "local-project",
            "namespace_id": "shared-1",
            "acl_revision": "1",
        },
        headers={**mutation_headers, "Idempotency-Key": "api-create-context-namespace"},
        json={"expected_revision": "0", "scope": "CONTEXT"},
    )
    assert context_namespace.status_code == 403, context_namespace.text
    assert context_namespace.json()["code"] == "NOT_AUTHORIZED"
    execution_namespace = client.post(
        "/api/v1/data/shared/namespaces",
        params={
            "owner_id": "local-project",
            "namespace_id": "shared-execution",
            "acl_revision": "1",
        },
        headers={
            **mutation_headers,
            "Idempotency-Key": "api-create-execution-namespace",
        },
        json={"expected_revision": "0", "scope": "EXECUTION"},
    )
    assert execution_namespace.status_code == 403, execution_namespace.text
    assert execution_namespace.json()["code"] == "NOT_AUTHORIZED"
    shared = client.put(
        "/api/v1/data/shared/namespaces/shared-1/entries/key-one",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "scope": "PROJECT",
        },
        headers={**mutation_headers, "Idempotency-Key": "api-put-shared"},
        json={
            "expected_entry_revision": "0",
            "expected_namespace_revision": "1",
            "value": make_typed_value("INT64", 7),
        },
    )
    assert shared.status_code == 200, shared.text
    fetched = client.get(
        "/api/v1/data/shared/namespaces/shared-1/entries/key-one",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "scope": "PROJECT",
        },
        headers=viewer_headers,
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["value"] == make_typed_value("INT64", 7)
    context = client.get(
        "/api/v1/data/shared/namespaces/shared-1",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "scope": "CONTEXT",
        },
        headers=viewer_headers,
    )
    assert context.status_code == 403, context.text
    assert context.json()["code"] == "NOT_AUTHORIZED"


def test_dictionary_import_slow_stream_exhausts_one_end_to_end_deadline(
    client, operator_headers
) -> None:
    document = build_db_document("dictionary-timeout", 0, ())
    source = document.canonical_bytes

    class SlowStreamClock:
        calls = 0

        def __call__(self) -> float:
            self.calls += 1
            return 61.0 if self.calls >= 4 else 0.0

    client.app.state.data_import_monotonic = SlowStreamClock()
    try:
        response = client.post(
            "/api/v1/data/dictionaries/dictionary-timeout/imports",
            params={
                "owner_id": "local-project",
                "acl_revision": "1",
                "expected_revision": "0",
            },
            headers={
                **_mutation_headers(
                    operator_headers,
                    "api-import-dictionary-timeout",
                    content_type=DB_MEDIA_TYPE,
                ),
                "Content-SHA256": hashlib.sha256(source).hexdigest(),
            },
            content=source,
        )
    finally:
        del client.app.state.data_import_monotonic

    assert response.status_code == 413, response.text
    assert response.json()["code"] == "LIMIT_EXCEEDED"
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DataDictionary)) == 0
        assert (
            session.scalar(select(func.count()).select_from(DataMutationIdempotency))
            == 0
        )
    assert list(client.app.state.virtual_files._quarantine_dir.iterdir()) == []


def test_dictionary_import_crossing_deadline_after_commit_returns_success(
    client, operator_headers, monkeypatch
) -> None:
    document = build_db_document("dictionary-post-commit", 0, ())
    source = document.canonical_bytes

    class CommitBoundaryClock:
        committed = False

        def __call__(self) -> float:
            return 61.0 if self.committed else 0.0

    clock = CommitBoundaryClock()
    repository = client.app.state.data_repository
    create_dictionary = repository.create_dictionary

    def commit_then_advance_clock(*args, **kwargs):
        result = create_dictionary(*args, **kwargs)
        clock.committed = True
        return result

    monkeypatch.setattr(repository, "create_dictionary", commit_then_advance_clock)
    client.app.state.data_import_monotonic = clock
    try:
        response = client.post(
            "/api/v1/data/dictionaries/dictionary-post-commit/imports",
            params={
                "owner_id": "local-project",
                "acl_revision": "1",
                "expected_revision": "0",
            },
            headers={
                **_mutation_headers(
                    operator_headers,
                    "api-import-dictionary-post-commit",
                    content_type=DB_MEDIA_TYPE,
                ),
                "Content-SHA256": hashlib.sha256(source).hexdigest(),
            },
            content=source,
        )
    finally:
        del client.app.state.data_import_monotonic

    assert clock.committed is True
    assert response.status_code == 200, response.text
    assert response.json()["new_revision"] == "1"
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DataDictionary)) == 1
        assert (
            session.scalar(select(func.count()).select_from(DataMutationIdempotency))
            == 1
        )
        assert session.scalar(select(func.count()).select_from(DataAuditOutbox)) == 1


def test_dictionary_import_export_and_pagination_are_bounded(
    client, operator_headers, viewer_headers
) -> None:
    value = make_typed_value("STRING", "dictionary value")
    document = build_db_document(
        "dictionary-1",
        0,
        (
            DictionaryEntry(
                "entry-1",
                "scope.entry",
                value,
                typed_value_digest(value),
            ),
        ),
    )
    source = document.canonical_bytes
    imported = client.post(
        "/api/v1/data/dictionaries/dictionary-1/imports",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "expected_revision": "0",
        },
        headers={
            **_mutation_headers(
                operator_headers,
                "api-import-dictionary",
                content_type=DB_MEDIA_TYPE,
            ),
            "Content-SHA256": hashlib.sha256(source).hexdigest(),
        },
        content=source,
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["new_revision"] == "1"
    second_document = build_db_document("dictionary-2", 0, ())
    second_source = second_document.canonical_bytes
    second_import = client.post(
        "/api/v1/data/dictionaries/dictionary-2/imports",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "expected_revision": "0",
        },
        headers={
            **_mutation_headers(
                operator_headers,
                "api-import-dictionary-2",
                content_type=DB_MEDIA_TYPE,
            ),
            "Content-SHA256": hashlib.sha256(second_source).hexdigest(),
        },
        content=second_source,
    )
    assert second_import.status_code == 200, second_import.text

    listed = client.get(
        "/api/v1/data/dictionaries",
        params={"owner_id": "local-project", "page_size": 1},
        headers=viewer_headers,
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["dictionaries"][0]["revision"] == "1"
    assert listed.json()["next_cursor"]
    next_page = client.get(
        "/api/v1/data/dictionaries",
        params={
            "owner_id": "local-project",
            "page_size": 1,
            "cursor": listed.json()["next_cursor"],
        },
        headers=viewer_headers,
    )
    assert next_page.status_code == 200, next_page.text
    assert next_page.json()["dictionaries"][0]["dictionary_id"] == "dictionary-2"
    exported = client.get(
        "/api/v1/data/dictionaries/dictionary-1/revisions/1/exports",
        params={
            "owner_id": "local-project",
            "acl_revision": "1",
            "format": "DB",
        },
        headers=viewer_headers,
    )
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-sha256"] == hashlib.sha256(exported.content).hexdigest()


def test_public_api_has_no_virtual_root_provisioning_route(
    client, admin_headers
) -> None:
    response = client.post(
        "/api/v1/data/files/roots",
        headers={
            **admin_headers,
            **SESSION_HEADERS,
            "Idempotency-Key": "must-not-provision",
            "Content-Type": "application/json",
        },
        json={"root_id": "HOST", "path": "C:\\"},
    )
    assert response.status_code == 404
