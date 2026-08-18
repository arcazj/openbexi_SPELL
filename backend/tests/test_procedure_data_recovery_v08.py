from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from backend.data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataNotFoundError,
    DataPermission,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    Role,
)
from backend.data_models import activate_data_schema
from backend.data_repository import DataRepository
from backend.data_mutations import EvidenceCorruptionError
from backend.data_values import make_typed_value, typed_value_digest
from backend.database import create_database
from backend.dictionary_exchange import DB_MEDIA_TYPE, DictionaryEntry, build_db_document
from backend.tests.migration_support import run_migrations
from backend.ir_v08 import file_handle_reference
from backend.virtual_file_service import ProcedureDataRuntime, VirtualFileService


EXECUTION_ID = "execution-recovery-0001"


def _request(
    operation: str,
    parameters: dict[str, object],
    *,
    request_id: str,
    generation: int,
    step_index: int,
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema_version": "spell.v08.data-request/1",
        "request_id": request_id,
        "execution_id": EXECUTION_ID,
        "step_index": step_index,
        "operation": operation,
        "parameters": parameters,
    }
    request["request_digest"] = hashlib.sha256(
        json.dumps(
            request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    ).hexdigest()
    request["service_principal_id"] = "procedure-runtime"
    request["worker_generation"] = generation
    return request


def _http_file_authorization(operation: str) -> AuthorizationContext:
    return AuthorizationContext(
        HTTPCallerBinding(
            "pytest-operator",
            Role.OPERATOR,
            "recovery-session-0001",
            "recovery-client-0001",
        ),
        (
            DataPermission(
                ResourceFamily.FILES,
                operation,
                "local-project",
                "PROJECT_DATA",
                1,
            ),
        ),
    )


@pytest.fixture()
def runtime(tmp_path: Path):
    engine, session_factory = create_database(
        f"sqlite:///{(tmp_path / 'procedure-recovery.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    generation = {"value": 1}

    def binding_check(_session, binding: ProcedureCallerBinding) -> None:
        if binding.worker_generation != generation["value"]:
            raise DataAuthorizationError("procedure generation is not admitted")

    files = VirtualFileService(tmp_path / "data")
    files.start()
    repository = DataRepository(
        session_factory,
        cursor_secret=files.cursor_secret,
        procedure_binding_check=binding_check,
        virtual_file_reader=files.read_physical_content,
    )
    files.attach_repository(repository)
    adapter = ProcedureDataRuntime(
        files,
        repository=repository,
        worker_generation=lambda _execution_id: generation["value"],
    )
    try:
        yield adapter, files, generation
    finally:
        files.close()
        engine.dispose()


def _recover_after_generation_advance(
    adapter: ProcedureDataRuntime,
    generation: dict[str, int],
    request: dict[str, object],
) -> dict[str, object]:
    original_generation = generation["value"]
    generation["value"] += 1
    retried = dict(request)
    retried["worker_generation"] = generation["value"]
    return dict(
        adapter.recover(
            retried,
            original_binding=ProcedureCallerBinding(
                "procedure-runtime",
                EXECUTION_ID,
                original_generation,
                str(request["request_id"]),
            ),
        )
    )


def test_recovery_contract_lists_every_procedure_mutator() -> None:
    assert set(ProcedureDataRuntime._MUTATION_RECOVERY) == {
        "CREATE_DICTIONARY",
        "LOAD_DICTIONARY",
        "SAVE_DICTIONARY",
        "CREATE_CONTAINER",
        "SET_VARIABLE",
        "DELETE_VARIABLE",
        "SHARED_CREATE_NAMESPACE",
        "SHARED_PUT",
        "SHARED_DELETE",
        "SHARED_CLEAR",
        "SHARED_DELETE_NAMESPACE",
        "WRITE_FILE",
        "DELETE_FILE",
        "CLOSE_FILE",
    }


def test_generic_recovery_rejects_different_operation_or_family(runtime) -> None:
    adapter, files, generation = runtime
    request = _request(
        "CREATE_DICTIONARY",
        {"dictionary_id": "DICT.IDENTITY", "format": "DB"},
        request_id="recovery-identity-create",
        generation=1,
        step_index=0,
    )
    assert adapter.resolve(request)["outcome"] == "OK"
    generation["value"] = 2
    original = ProcedureCallerBinding(
        "procedure-runtime", EXECUTION_ID, 1, "recovery-identity-create"
    )
    current = ProcedureCallerBinding(
        "procedure-runtime", EXECUTION_ID, 2, "recovery-identity-create"
    )
    with pytest.raises(DataNotFoundError):
        files._repository.recover_procedure_mutation(
            original,
            current,
            resource_family=ResourceFamily.DICTIONARIES,
            operations=("CREATE",),
        )
    with pytest.raises(EvidenceCorruptionError):
        files._repository.recover_procedure_mutation(
            original,
            current,
            resource_family=ResourceFamily.CONTAINERS,
            operations=("IMPORT",),
        )


def test_dictionary_mutations_recover_without_reimport_or_rewrite(runtime) -> None:
    adapter, files, generation = runtime
    create = _request(
        "CREATE_DICTIONARY",
        {"dictionary_id": "DICT.RECOVERY", "format": "DB"},
        request_id="recovery-dictionary-create",
        generation=1,
        step_index=1,
    )
    created = dict(adapter.resolve(create))
    assert created["outcome"] == "OK"
    recovered_create = _recover_after_generation_advance(adapter, generation, create)
    assert recovered_create["outcome"] == "OK"
    assert recovered_create["revision"] == created["revision"] == 1
    assert recovered_create["value"] != created["value"]

    value = make_typed_value("STRING", "recovered")
    document = build_db_document(
        "DICT.RECOVERY",
        1,
        (DictionaryEntry("entry-1", "recovery.value", value, typed_value_digest(value)),),
    )
    source = document.canonical_bytes
    files.write_file(
        _http_file_authorization("WRITE"),
        "PROJECT_DATA",
        "dictionary-recovery.db",
        source,
        expected_revision=0,
        encoding="UTF8_TEXT",
        content_sha256=hashlib.sha256(source).hexdigest(),
        idempotency_key="seed-dictionary-recovery",
    )
    load = _request(
        "LOAD_DICTIONARY",
        {
            "dictionary_id": "DICT.RECOVERY",
            "expected_revision": 1,
            "format": "DB",
            "root_id": "PROJECT_DATA",
            "source_revision": 1,
            "virtual_path": "dictionary-recovery.db",
        },
        request_id="recovery-dictionary-load",
        generation=generation["value"],
        step_index=2,
    )
    loaded = dict(adapter.resolve(load))
    recovered_load = _recover_after_generation_advance(adapter, generation, load)
    assert recovered_load["outcome"] == "OK"
    assert recovered_load["revision"] == loaded["revision"] == 2
    assert recovered_load["value"] != loaded["value"]

    save = _request(
        "SAVE_DICTIONARY",
        {
            "dictionary_id": "DICT.RECOVERY",
            "dictionary_revision": 2,
            "expected_file_revision": 0,
            "format": "DB",
            "root_id": "PROJECT_DATA",
            "virtual_path": "dictionary-recovery-saved.db",
        },
        request_id="recovery-dictionary-save",
        generation=generation["value"],
        step_index=3,
    )
    saved = dict(adapter.resolve(save))
    recovered_save = _recover_after_generation_advance(adapter, generation, save)
    assert saved == recovered_save == {"outcome": "OK", "revision": 1}


def test_container_mutations_recover_without_reexecution(runtime) -> None:
    adapter, _files, generation = runtime
    create = _request(
        "CREATE_CONTAINER",
        {"container_id": "container-recovery", "schema_revision": 1},
        request_id="recovery-container-create",
        generation=1,
        step_index=10,
    )
    created = dict(adapter.resolve(create))
    recovered_create = _recover_after_generation_advance(adapter, generation, create)
    assert recovered_create["revision"] == created["revision"] == 1
    assert recovered_create["value"] != created["value"]

    set_variable = _request(
        "SET_VARIABLE",
        {
            "container_id": "container-recovery",
            "declared_type": "LONG",
            "expected_revision": 1,
            "name": "count",
            "value": 7,
            "variable_id": "count-variable",
        },
        request_id="recovery-container-set",
        generation=generation["value"],
        step_index=11,
    )
    updated = dict(adapter.resolve(set_variable))
    assert _recover_after_generation_advance(adapter, generation, set_variable) == updated

    delete_variable = _request(
        "DELETE_VARIABLE",
        {
            "container_id": "container-recovery",
            "expected_revision": 2,
            "variable_id": "count-variable",
        },
        request_id="recovery-container-delete",
        generation=generation["value"],
        step_index=12,
    )
    deleted = dict(adapter.resolve(delete_variable))
    assert _recover_after_generation_advance(adapter, generation, delete_variable) == deleted


def test_shared_mutation_families_recover_each_committed_revision(runtime) -> None:
    adapter, _files, generation = runtime

    def settle(
        operation: str,
        parameters: dict[str, object],
        request_id: str,
        step_index: int,
    ) -> dict[str, object]:
        request = _request(
            operation,
            parameters,
            request_id=request_id,
            generation=generation["value"],
            step_index=step_index,
        )
        result = dict(adapter.resolve(request))
        assert result["outcome"] == "OK", result
        assert _recover_after_generation_advance(adapter, generation, request) == result
        return result

    settle(
        "SHARED_CREATE_NAMESPACE",
        {
            "acl_revision": 0,
            "namespace_id": "shared-recovery",
            "scope": "EXECUTION",
        },
        "recovery-shared-create",
        20,
    )
    settle(
        "SHARED_PUT",
        {
            "expected_entry_revision": 0,
            "expected_namespace_revision": 1,
            "key": "one",
            "namespace_id": "shared-recovery",
            "value": 1,
        },
        "recovery-shared-put-one",
        21,
    )
    settle(
        "SHARED_DELETE",
        {
            "expected_entry_revision": 1,
            "expected_namespace_revision": 2,
            "key": "one",
            "namespace_id": "shared-recovery",
        },
        "recovery-shared-delete",
        22,
    )
    settle(
        "SHARED_PUT",
        {
            "expected_entry_revision": 0,
            "expected_namespace_revision": 3,
            "key": "two",
            "namespace_id": "shared-recovery",
            "value": 2,
        },
        "recovery-shared-put-two",
        23,
    )
    settle(
        "SHARED_CLEAR",
        {"expected_namespace_revision": 4, "namespace_id": "shared-recovery"},
        "recovery-shared-clear",
        24,
    )
    settle(
        "SHARED_DELETE_NAMESPACE",
        {"expected_namespace_revision": 5, "namespace_id": "shared-recovery"},
        "recovery-shared-delete-namespace",
        25,
    )


def test_file_mutations_recover_and_transient_handles_are_generation_stale(runtime) -> None:
    adapter, _files, generation = runtime
    write = _request(
        "WRITE_FILE",
        {
            "content": "committed",
            "content_sha256": hashlib.sha256(b"committed").hexdigest(),
            "encoding": "UTF8_TEXT",
            "expected_revision": 0,
            "root_id": "PROJECT_DATA",
            "virtual_path": "recovery.txt",
        },
        request_id="recovery-file-write",
        generation=1,
        step_index=30,
    )
    written = dict(adapter.resolve(write))
    assert _recover_after_generation_advance(adapter, generation, write) == written

    delete = _request(
        "DELETE_FILE",
        {
            "expected_revision": 1,
            "root_id": "PROJECT_DATA",
            "virtual_path": "recovery.txt",
        },
        request_id="recovery-file-delete",
        generation=generation["value"],
        step_index=31,
    )
    deleted = dict(adapter.resolve(delete))
    assert _recover_after_generation_advance(adapter, generation, delete) == deleted

    open_write = _request(
        "OPEN_FILE",
        {
            "mode": "WRITE",
            "revision": 0,
            "root_id": "PROJECT_DATA",
            "virtual_path": "handle-recovery.txt",
        },
        request_id="recovery-handle-open",
        generation=generation["value"],
        step_index=32,
    )
    opened = dict(adapter.resolve(open_write))
    assert opened["outcome"] == "OK"
    handle_reference = file_handle_reference(
        opened["value"],
        execution_id=EXECUTION_ID,
        worker_generation=generation["value"],
        creator_request_id=str(open_write["request_id"]),
    )
    write_handle = _request(
        "WRITE_FILE",
        {
            "content": "through handle",
            "content_sha256": hashlib.sha256(b"through handle").hexdigest(),
            "encoding": "UTF8_TEXT",
            "handle": handle_reference,
        },
        request_id="recovery-handle-write",
        generation=generation["value"],
        step_index=33,
    )
    assert adapter.resolve(write_handle)["outcome"] == "OK"
    close = _request(
        "CLOSE_FILE",
        {"handle": handle_reference},
        request_id="recovery-handle-close",
        generation=generation["value"],
        step_index=34,
    )
    closed = dict(adapter.resolve(close))
    assert _recover_after_generation_advance(adapter, generation, close) == closed

    transient_open = _request(
        "OPEN_FILE",
        {
            "mode": "READ",
            "revision": 1,
            "root_id": "PROJECT_DATA",
            "virtual_path": "handle-recovery.txt",
        },
        request_id="recovery-transient-open",
        generation=generation["value"],
        step_index=35,
    )
    assert adapter.resolve(transient_open)["outcome"] == "OK"
    stale = _recover_after_generation_advance(adapter, generation, transient_open)
    assert stale["outcome"] == "STALE_HANDLE"
