from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import func, select

from backend.data_domain import (
    AuthorizationContext,
    DataPermission,
    HTTPCallerBinding,
    ResourceFamily,
    Role,
)
from backend.data_models import (
    DataDictionary,
    DataDictionaryRevision,
    activate_data_schema,
)
from backend.data_repository import DataRepository
from backend.data_values import make_typed_value, typed_value_digest
from backend.database import create_database
from backend.dictionary_exchange import (
    DB_MEDIA_TYPE,
    IMP_MEDIA_TYPE,
    DictionaryEntry,
    DictionaryExchangeError,
    DictionaryRecord,
    ImportOperation,
    build_db_document,
    build_imp_document,
    export_dictionary_document,
    parse_dictionary_document,
)
from backend.tests.migration_support import run_migrations


@pytest.fixture()
def repository(tmp_path: Path):
    engine, factory = create_database(
        f"sqlite:///{(tmp_path / 'dictionaries.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    repo = DataRepository(
        factory, cursor_secret=b"dictionary-owner-test-secret-00001"
    )
    try:
        yield repo, factory
    finally:
        engine.dispose()


def entry(identity: str, name: str, value: str) -> DictionaryEntry:
    envelope = make_typed_value("STRING", value)
    return DictionaryEntry(identity, name, envelope, typed_value_digest(envelope))


def test_db_snapshot_round_trips_as_stable_canonical_non_executing_bytes() -> None:
    document = build_db_document(
        "dictionary-1",
        4,
        (
            entry("z-entry", "module.z", "__import__('os').system('false')"),
            entry("a-entry", "module.a", "{{ dangerous_template() }}"),
        ),
    )
    encoded = export_dictionary_document(document)
    assert encoded == document.canonical_bytes
    assert [item.entry_id for item in document.entries] == ["a-entry", "z-entry"]
    parsed = parse_dictionary_document(encoded, media_type=DB_MEDIA_TYPE)
    assert parsed.entries == document.entries
    assert parsed.content_digest == document.content_digest
    assert parsed.original_bytes == encoded
    assert parsed.canonical_bytes == encoded


def test_import_retains_exact_source_bytes_but_normalizes_only_canonical_output() -> None:
    canonical = build_db_document(
        "dictionary-1", 0, (entry("entry-1", "scope.value", "value"),)
    )
    source = json.dumps(canonical.as_payload(), indent=2, ensure_ascii=False).encode("utf-8")
    parsed = parse_dictionary_document(source)
    assert parsed.original_bytes == source
    assert parsed.original_bytes_sha256 != parsed.canonical_document_sha256
    assert parsed.canonical_bytes == canonical.canonical_bytes
    assert parsed.content_digest == canonical.content_digest


def test_imp_has_explicit_ordered_upsert_and_delete_records_only() -> None:
    envelope = make_typed_value("INT64", 7)
    upsert = DictionaryRecord(
        ImportOperation.UPSERT,
        "entry-b",
        0,
        "scope.b",
        envelope,
        typed_value_digest(envelope),
    )
    delete = DictionaryRecord(ImportOperation.DELETE, "entry-a", 3)
    document = build_imp_document("dictionary-1", 8, (upsert, delete))
    assert [record.entry_id for record in document.records] == ["entry-a", "entry-b"]
    parsed = parse_dictionary_document(
        document.canonical_bytes, media_type=IMP_MEDIA_TYPE
    )
    assert parsed.records == document.records
    assert parsed.records[0].as_payload() == {
        "entry_id": "entry-a",
        "expected_entry_revision": 3,
        "operation": "DELETE",
    }


def test_strict_parser_rejects_duplicate_keys_bom_nonfinite_and_trailing_data() -> None:
    invalid = (
        b'{"format":"DB","format":"IMP"}',
        b"\xef\xbb\xbf{}",
        b'{"x":NaN}',
        b"{} trailing",
        b'"not an object"',
    )
    for payload in invalid:
        with pytest.raises(DictionaryExchangeError):
            parse_dictionary_document(payload)


def test_closed_world_documents_entries_and_records_reject_field_smuggling() -> None:
    db = build_db_document(
        "dictionary-1", 1, (entry("entry-1", "scope.value", "value"),)
    ).as_payload()
    db["unexpected"] = True
    with pytest.raises(DictionaryExchangeError) as unexpected:
        parse_dictionary_document(json.dumps(db, separators=(",", ":")).encode())
    assert unexpected.value.code == "CORRUPT_DOCUMENT"

    db = build_db_document(
        "dictionary-1", 1, (entry("entry-1", "scope.value", "value"),)
    ).as_payload()
    db["entries"][0]["callable"] = "builtins.eval"
    with pytest.raises(DictionaryExchangeError):
        parse_dictionary_document(json.dumps(db, separators=(",", ":")).encode())

    imp = build_imp_document(
        "dictionary-1", 1, (DictionaryRecord(ImportOperation.DELETE, "entry-1", 1),)
    ).as_payload()
    imp["records"][0]["value"] = make_typed_value("NULL", None)
    with pytest.raises(DictionaryExchangeError):
        parse_dictionary_document(json.dumps(imp, separators=(",", ":")).encode())


def test_value_and_document_digests_are_both_verified() -> None:
    document = build_db_document(
        "dictionary-1", 1, (entry("entry-1", "scope.value", "value"),)
    ).as_payload()
    document["entries"][0]["value_digest"] = "0" * 64
    with pytest.raises(DictionaryExchangeError) as value_digest:
        parse_dictionary_document(json.dumps(document, separators=(",", ":")).encode())
    assert value_digest.value.code == "CORRUPT_DOCUMENT"

    document = build_db_document(
        "dictionary-1", 1, (entry("entry-1", "scope.value", "value"),)
    ).as_payload()
    document["content_digest"] = "0" * 64
    with pytest.raises(DictionaryExchangeError) as document_digest:
        parse_dictionary_document(json.dumps(document, separators=(",", ":")).encode())
    assert document_digest.value.code == "CORRUPT_DOCUMENT"


def test_duplicate_identity_case_collision_and_duplicate_imp_target_fail_closed() -> None:
    with pytest.raises(DictionaryExchangeError) as duplicate:
        build_db_document(
            "dictionary-1",
            1,
            (
                entry("entry-1", "scope.one", "one"),
                entry("entry-1", "scope.two", "two"),
            ),
        )
    assert duplicate.value.code == "DUPLICATE_ENTRY"

    with pytest.raises(DictionaryExchangeError) as collision:
        build_db_document(
            "dictionary-1",
            1,
            (
                entry("Entry", "scope.one", "one"),
                entry("entry", "scope.two", "two"),
            ),
        )
    assert collision.value.code == "CASE_COLLISION"

    with pytest.raises(DictionaryExchangeError) as target:
        build_imp_document(
            "dictionary-1",
            1,
            (
                DictionaryRecord(ImportOperation.DELETE, "entry-1", 1),
                DictionaryRecord(ImportOperation.DELETE, "entry-1", 1),
            ),
        )
    assert target.value.code == "DUPLICATE_ENTRY_TARGET"


def test_delete_requires_a_live_revision_and_media_type_must_match() -> None:
    payload = {
        "base_revision": 1,
        "content_digest": "0" * 64,
        "dictionary_id": "dictionary-1",
        "format": "IMP",
        "records": [
            {
                "entry_id": "entry-1",
                "expected_entry_revision": 0,
                "operation": "DELETE",
            }
        ],
        "schema_version": "spell.dictionary.imp/1",
    }
    with pytest.raises(DictionaryExchangeError):
        parse_dictionary_document(json.dumps(payload, separators=(",", ":")).encode())

    document = build_db_document("dictionary-1", 0, ())
    with pytest.raises(DictionaryExchangeError) as media:
        parse_dictionary_document(document.canonical_bytes, media_type=IMP_MEDIA_TYPE)
    assert media.value.code == "FORMAT_UNSUPPORTED"


def _dictionary_authorization(
    operation: str, owner_id: str, dictionary_id: str
) -> AuthorizationContext:
    return AuthorizationContext(
        HTTPCallerBinding(
            "pytest-operator",
            Role.OPERATOR,
            "dictionary-session-0001",
            "dictionary-client-0001",
        ),
        (
            DataPermission(
                ResourceFamily.DICTIONARIES,
                operation,
                owner_id,
                dictionary_id,
                2,
            ),
        ),
    )


def _assert_two_owner_dictionary_identity(repo: DataRepository, factory) -> None:
    owners = ("dictionary-owner-a", "dictionary-owner-b")
    dictionary_id = "same-dictionary-id"
    document = build_db_document(
        dictionary_id,
        0,
        (entry("entry-1", "scope.value", "owner-specific"),),
    )
    for index, owner_id in enumerate(owners):
        created = repo.create_dictionary(
            _dictionary_authorization("IMPORT", owner_id, dictionary_id),
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=2,
            idempotency_key=f"create-same-dictionary-{index}",
            document=document,
        )
        assert created["revision"] == 1
        exported = repo.export_dictionary(
            _dictionary_authorization("EXPORT", owner_id, dictionary_id),
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=2,
        )
        assert parse_dictionary_document(exported).dictionary_id == dictionary_id
    with factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(DataDictionary)
            .where(DataDictionary.dictionary_id == dictionary_id)
        ) == 2
        assert session.scalar(
            select(func.count())
            .select_from(DataDictionaryRevision)
            .where(DataDictionaryRevision.dictionary_id == dictionary_id)
        ) == 2


def test_two_owners_can_use_the_same_dictionary_id_on_sqlite(repository) -> None:
    _assert_two_owner_dictionary_identity(*repository)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_two_owners_can_use_the_same_dictionary_id_on_postgresql() -> None:
    from backend.tests.test_migrations import reset_migration_database

    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        repo = DataRepository(
            factory, cursor_secret=b"postgres-dictionary-owner-test-01"
        )
        _assert_two_owner_dictionary_identity(repo, factory)
    finally:
        reset_migration_database(engine)
        engine.dispose()
