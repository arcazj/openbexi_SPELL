from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import backend.worker as worker_module
import backend.secure_filesystem as secure_filesystem_module
import backend.virtual_file_service as virtual_file_module

from backend.data_domain import (
    AuthorizationContext,
    DataPermission,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    Role,
)
from backend.data_models import (
    DataAuditOutbox,
    DataMutationIdempotency,
    SharedNamespace,
    VirtualFile,
    VirtualFileRoot,
    activate_data_schema,
    canonical_virtual_root_configuration_bytes,
)
from backend.data_repository import DataRepository
from backend.data_values import make_typed_value, typed_value_digest
from backend.database import create_database
from backend.dictionary_exchange import (
    DB_MEDIA_TYPE,
    DictionaryEntry,
    build_db_document,
    parse_dictionary_document,
)
from backend.tests.migration_support import run_migrations
from backend.ir_v08 import (
    canonicalize_data_result,
    file_handle_reference,
    validate_data_request,
)
from backend.procedure_parser import ProcedureCatalog
from backend.virtual_file_service import (
    MAXIMUM_FILE_BYTES,
    PreparedWrite,
    ProcedureDataRuntime,
    VirtualFileError,
    VirtualFileService,
    validate_virtual_path,
)


def _http_authorization(operation: str) -> AuthorizationContext:
    caller = HTTPCallerBinding(
        "pytest-operator",
        Role.OPERATOR,
        "session-binding-0001",
        "client-key-bind-0001",
    )
    return AuthorizationContext(
        caller,
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


def _procedure_authorization(operation: str, request_id: str = "request-0001") -> AuthorizationContext:
    caller = ProcedureCallerBinding(
        "procedure-runtime", "execution-0001", 1, request_id
    )
    return AuthorizationContext(
        caller,
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


@pytest.fixture
def files(tmp_path: Path):
    service, engine, _ = _open_service(tmp_path)
    try:
        yield service
    finally:
        service.close()
        engine.dispose()


def _open_service(tmp_path: Path):
    engine, session_factory = create_database(
        f"sqlite:///{(tmp_path / 'virtual-files.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    service = VirtualFileService(tmp_path / "data")
    service.start()
    repository = DataRepository(
        session_factory,
        cursor_secret=service.cursor_secret,
        procedure_binding_check=lambda _session, _binding: None,
        virtual_file_reader=service.read_physical_content,
    )
    try:
        service.attach_repository(repository)
    except Exception:
        service.close()
        engine.dispose()
        raise
    return service, engine, session_factory


def _set_project_quota(
    files: VirtualFileService, *, quota_bytes: int, quota_nodes: int
) -> None:
    with files._repository.session_factory() as session:
        root = session.get(VirtualFileRoot, "PROJECT_DATA")
        assert root is not None
        root.quota_bytes = quota_bytes
        root.quota_nodes = quota_nodes
        root.configuration_digest = hashlib.sha256(
            canonical_virtual_root_configuration_bytes(
                {
                    "acl_revision": root.acl_revision,
                    "owner_id": root.owner_id,
                    "quota_bytes": quota_bytes,
                    "quota_nodes": quota_nodes,
                    "root_id": root.root_id,
                    "root_kind": root.root_kind,
                }
            )
        ).hexdigest()
        session.commit()


def _make_directory_link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("directory symlinks are unavailable")
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not link.exists():
        pytest.skip("directory junctions are unavailable")


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "../escape",
        "a/../escape",
        "a//b",
        "a\\b",
        "C:drive",
        "encoded/%2e%2e/path",
        "NUL",
        "aux.txt",
        "trailing/",
        "control\x00value",
        ".spell-write-owned",
    ],
)
def test_virtual_paths_reject_host_ambiguous_forms(path: str) -> None:
    with pytest.raises(VirtualFileError) as raised:
        validate_virtual_path(path)
    assert raised.value.code in {"REJECTED", "LIMIT_EXCEEDED"}


def test_activation_rejects_preexisting_ancestor_link_without_creating_outside(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "activation-outside"
    outside.mkdir()
    linked_ancestor = tmp_path / "activation-link"
    _make_directory_link(linked_ancestor, outside)
    requested_base = linked_ancestor / "must-not-be-created"
    service = VirtualFileService(requested_base)

    with pytest.raises(VirtualFileError) as failed:
        service.start()
    assert failed.value.code == "REJECTED"
    assert not (outside / "must-not-be-created").exists()


def test_activation_ancestor_swap_is_blocked_or_remains_parent_handle_relative(
    tmp_path: Path, monkeypatch
) -> None:
    activation_parent = tmp_path / "activation-race"
    ancestor = activation_parent / "owned-ancestor"
    ancestor.mkdir(parents=True)
    parked = activation_parent / "owned-ancestor-parked"
    outside = tmp_path / "activation-race-outside"
    outside.mkdir()
    outcome: list[str] = []

    def attempt_swap() -> None:
        try:
            os.replace(ancestor, parked)
        except OSError:
            outcome.append("blocked")
            return
        outcome.append("retained")
        try:
            _make_directory_link(ancestor, outside)
        except pytest.skip.Exception:
            ancestor.mkdir()

    if os.name == "nt":
        original_open = secure_filesystem_module._win_nt_open

        def raced_open(root_handle, name, **kwargs):
            handle = original_open(root_handle, name, **kwargs)
            if name == ancestor.name and not outcome:
                attempt_swap()
            return handle

        monkeypatch.setattr(secure_filesystem_module, "_win_nt_open", raced_open)
    else:
        original_open = secure_filesystem_module.os.open

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == ancestor.name and dir_fd is not None and not outcome:
                attempt_swap()
            return descriptor

        monkeypatch.setattr(secure_filesystem_module.os, "open", raced_open)

    opened = secure_filesystem_module.open_owned_directory(
        ancestor / "created-relative", create=True
    )
    opened.close()

    assert outcome in (["blocked"], ["retained"])
    if outcome == ["blocked"]:
        assert (ancestor / "created-relative").is_dir()
    else:
        assert (parked / "created-relative").is_dir()
        assert not (outside / "created-relative").exists()


def test_verified_owned_directory_flush_preserves_file_fsync_portability(
    tmp_path: Path,
) -> None:
    directory = secure_filesystem_module.open_owned_directory(tmp_path)
    try:
        secure_filesystem_module.fsync_directory(directory)
    finally:
        directory.close()


def test_revisioned_atomic_file_lifecycle_and_idempotency(
    files: VirtualFileService,
) -> None:
    created = files.create_directory(
        _http_authorization("CREATE_DIRECTORY"),
        "PROJECT_DATA",
        "reports",
        expected_revision=0,
        idempotency_key="mkdir-reports",
    )
    assert created["revision"] == 1

    payload = b"qualified\n"
    digest = hashlib.sha256(payload).hexdigest()
    written = files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "reports/result.txt",
        payload,
        expected_revision=0,
        encoding="UTF8_TEXT",
        content_sha256=digest,
        idempotency_key="write-result",
    )
    assert written["revision"] == 1
    replay = files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "reports/result.txt",
        payload,
        expected_revision=0,
        encoding="UTF8_TEXT",
        content_sha256=digest,
        idempotency_key="write-result",
    )
    assert replay == {**written, "replayed": True}

    read = files.read_file(
        _http_authorization("READ"), "PROJECT_DATA", "reports/result.txt"
    )
    assert read["content"] == payload
    assert read["content_sha256"] == digest
    listing = files.list_directory(
        _http_authorization("LIST"), "PROJECT_DATA", "reports"
    )
    assert [item["name"] for item in listing["items"]] == ["result.txt"]

    with pytest.raises(VirtualFileError) as conflict:
        files.write_file(
            _http_authorization("WRITE"),
            "PROJECT_DATA",
            "reports/result.txt",
            b"different",
            expected_revision=0,
            encoding="BINARY",
            content_sha256=hashlib.sha256(b"different").hexdigest(),
            idempotency_key="write-result",
        )
    assert conflict.value.code == "IDEMPOTENCY_CONFLICT"

    deleted = files.delete_node(
        _http_authorization("DELETE"),
        "PROJECT_DATA",
        "reports/result.txt",
        expected_revision=1,
        idempotency_key="delete-result",
    )
    assert deleted["deleted_revision"] == 1
    with pytest.raises(VirtualFileError) as missing:
        files.read_file(
            _http_authorization("READ"), "PROJECT_DATA", "reports/result.txt"
        )
    assert missing.value.code == "NOT_FOUND"


def test_prepared_write_is_not_visible_before_commit(files: VirtualFileService) -> None:
    payload = b"atomic"
    digest = hashlib.sha256(payload).hexdigest()
    prepared = files.prepare_write(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "atomic.bin",
        expected_revision=0,
        encoding="BINARY",
        idempotency_key="atomic-write",
        request_digest=hashlib.sha256(b"request").hexdigest(),
        declared_length=len(payload),
        content_sha256=digest,
    )
    assert not isinstance(prepared, dict)
    prepared.write(payload)
    with pytest.raises(VirtualFileError) as missing:
        files.read_file(_http_authorization("READ"), "PROJECT_DATA", "atomic.bin")
    assert missing.value.code == "NOT_FOUND"
    result = files.commit_write(
        _http_authorization("WRITE"),
        prepared,
        declared_length=len(payload),
        content_sha256=digest,
    )
    assert result["content_sha256"] == digest


def test_concurrent_near_quota_preparation_admits_only_one_durable_reservation(
    tmp_path: Path,
) -> None:
    first, first_engine, _ = _open_service(tmp_path)
    second, second_engine, _ = _open_service(tmp_path)
    _set_project_quota(first, quota_bytes=6, quota_nodes=1)
    barrier = threading.Barrier(2)

    def reserve(service: VirtualFileService, name: str) -> PreparedWrite | VirtualFileError:
        payload = b"four"
        digest = hashlib.sha256(payload).hexdigest()
        barrier.wait(timeout=5)
        try:
            return service.prepare_write(
                _http_authorization("WRITE"),
                "PROJECT_DATA",
                name,
                expected_revision=0,
                encoding="BINARY",
                idempotency_key=f"reserve-{name}",
                request_digest=hashlib.sha256(name.encode("ascii")).hexdigest(),
                declared_length=len(payload),
                content_sha256=digest,
            )
        except VirtualFileError as exc:
            return exc

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = tuple(
                pool.map(
                    lambda item: reserve(*item),
                    ((first, "first.bin"), (second, "second.bin")),
                )
            )
        admitted = [item for item in outcomes if isinstance(item, PreparedWrite)]
        rejected = [item for item in outcomes if isinstance(item, VirtualFileError)]
        assert len(admitted) == 1
        assert len(rejected) == 1
        assert rejected[0].code in {"REVISION_CONFLICT", "SERVICE_CAPACITY_EXHAUSTED"}
        with first._repository.session_factory() as session:
            root = session.get(VirtualFileRoot, "PROJECT_DATA")
            assert root is not None
            assert root.used_bytes == 0 and root.used_nodes == 0
            assert root.reserved_bytes == 4 and root.reserved_nodes == 1
            assert root.reservation_id == admitted[0].reservation_id
        assert len(list((first._base / "project-data").glob(".spell-write-*"))) == 1

        admitted[0].abort()
        with first._repository.session_factory() as session:
            root = session.get(VirtualFileRoot, "PROJECT_DATA")
            assert root is not None
            assert root.reservation_id is None
            assert root.reservation_binding_digest is None
            assert root.reserved_bytes == 0 and root.reserved_nodes == 0
    finally:
        first.close()
        second.close()
        first_engine.dispose()
        second_engine.dispose()


def test_restart_releases_abandoned_reservation_before_removing_stage(
    tmp_path: Path,
) -> None:
    crashed, crashed_engine, _ = _open_service(tmp_path)
    payload = b"reserved-before-crash"
    digest = hashlib.sha256(payload).hexdigest()
    prepared = crashed.prepare_write(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "crash.bin",
        expected_revision=0,
        encoding="BINARY",
        idempotency_key="crash-reservation",
        request_digest=hashlib.sha256(b"crash-reservation-request").hexdigest(),
        declared_length=len(payload),
        content_sha256=digest,
    )
    assert isinstance(prepared, PreparedWrite)
    prepared.write(payload[:7])
    prepared.finish()
    stage_path = prepared.temporary_path
    assert stage_path.exists()
    with crashed._repository.session_factory() as session:
        root = session.get(VirtualFileRoot, "PROJECT_DATA")
        assert root is not None
        assert root.reservation_id == prepared.reservation_id
        assert root.reserved_bytes == len(payload) and root.reserved_nodes == 1

    restarted, restarted_engine, _ = _open_service(tmp_path)
    try:
        assert not stage_path.exists()
        with restarted._repository.session_factory() as session:
            root = session.get(VirtualFileRoot, "PROJECT_DATA")
            assert root is not None
            assert root.reservation_id is None
            assert root.reservation_binding_digest is None
            assert root.reserved_bytes == 0 and root.reserved_nodes == 0
    finally:
        restarted.close()
        restarted_engine.dispose()
        crashed.close()
        crashed_engine.dispose()


def test_virtual_metadata_settlement_and_evidence_are_database_authoritative(
    files: VirtualFileService,
) -> None:
    payload = b"database authority"
    digest = hashlib.sha256(payload).hexdigest()
    result = files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "authority.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="database-authority-write",
    )
    with files._repository.session_factory() as session:
        root = session.get(VirtualFileRoot, "PROJECT_DATA")
        assert root is not None and root.current_revision == result["root_revision"]
        rows = session.query(VirtualFile).filter_by(
            root_id="PROJECT_DATA", virtual_path="authority.bin"
        ).all()
        assert [(row.revision, row.content_digest) for row in rows] == [(1, digest)]
        assert session.query(DataMutationIdempotency).count() == 1
        assert session.query(DataAuditOutbox).count() == 1
    assert not list((files._base / ".spell-control").glob("*.json"))


def test_post_finalize_failure_leaves_no_visible_head_and_recovery_quarantines(
    files: VirtualFileService, monkeypatch
) -> None:
    payload = b"orphan after rollback"
    digest = hashlib.sha256(payload).hexdigest()
    original = files._repository.commit_virtual_file

    def fail_after_finalize(*args, finalize_bytes, **kwargs):
        finalize_bytes()
        raise RuntimeError("injected database failure")

    monkeypatch.setattr(files._repository, "commit_virtual_file", fail_after_finalize)
    with pytest.raises(RuntimeError, match="injected database failure"):
        files.write_file(
            _http_authorization("WRITE"),
            "PROJECT_DATA",
            "rolled-back.bin",
            payload,
            expected_revision=0,
            encoding="BINARY",
            content_sha256=digest,
            idempotency_key="rollback-write",
        )
    monkeypatch.setattr(files._repository, "commit_virtual_file", original)
    with pytest.raises(VirtualFileError) as missing:
        files.read_file(
            _http_authorization("READ"), "PROJECT_DATA", "rolled-back.bin"
        )
    assert missing.value.code == "NOT_FOUND"
    assert (files._base / "project-data" / ".spell-objects" / digest).exists()
    assert files.recover()["quarantined_orphans"] == 1


def test_file_handles_are_opaque_bound_and_restart_stale(
    tmp_path: Path,
) -> None:
    service, engine, _ = _open_service(tmp_path)
    payload = b"handle-data"
    service.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "handle.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=hashlib.sha256(payload).hexdigest(),
        idempotency_key="seed-handle",
    )
    authorization = _procedure_authorization("READ")
    opened = service.open_file(
        authorization,
        "PROJECT_DATA",
        "handle.bin",
        execution_id="execution-0001",
        mode="READ",
        revision=1,
    )
    token = opened["handle"]
    assert token not in repr(service._handles)
    assert service.read_handle(
        authorization, token, execution_id="execution-0001"
    )["content"] == payload
    with pytest.raises(VirtualFileError) as different_request:
        service.read_handle(
            _procedure_authorization("READ", "request-0002"),
            token,
            execution_id="execution-0001",
        )
    assert different_request.value.code == "STALE_HANDLE"
    service.close()
    engine.dispose()

    restarted, restarted_engine, _ = _open_service(tmp_path)
    try:
        with pytest.raises(VirtualFileError) as stale:
            restarted.read_handle(
                authorization, token, execution_id="execution-0001"
            )
        assert stale.value.code == "STALE_HANDLE"
    finally:
        restarted.close()
        restarted_engine.dispose()


def test_writable_handle_reserves_worst_case_quota_before_stage_and_consumes(
    files: VirtualFileService, monkeypatch
) -> None:
    def authorization(request_id: str) -> AuthorizationContext:
        caller = ProcedureCallerBinding(
            "procedure-runtime", "execution-0001", 1, request_id
        )
        return AuthorizationContext(
            caller,
            tuple(
                DataPermission(
                    ResourceFamily.FILES,
                    operation,
                    "local-project",
                    "PROJECT_DATA",
                    1,
                )
                for operation in ("READ", "WRITE")
            ),
        )

    original_open = virtual_file_module.open_regular_file
    reservation_observed_before_stage: list[bool] = []

    def guarded_open(directory, name, *args, **kwargs):
        if name.startswith(".spell-handle-"):
            with files._repository.session_factory() as session:
                root = session.get(VirtualFileRoot, "PROJECT_DATA")
                reservation_observed_before_stage.append(
                    root is not None
                    and root.reservation_id is not None
                    and root.reserved_bytes == MAXIMUM_FILE_BYTES
                    and root.reserved_nodes == 1
                )
        return original_open(directory, name, *args, **kwargs)

    monkeypatch.setattr(virtual_file_module, "open_regular_file", guarded_open)
    handle_authorization = authorization("handle-open-reservation")
    opened = files.open_file(
        handle_authorization,
        "PROJECT_DATA",
        "reserved-handle.bin",
        execution_id="execution-0001",
        mode="WRITE",
        revision=0,
    )
    assert reservation_observed_before_stage == [True]
    payload = b"handle quota"
    files.write_handle(
        handle_authorization,
        opened["handle"],
        payload,
        execution_id="execution-0001",
        encoding="BINARY",
        content_sha256=hashlib.sha256(payload).hexdigest(),
    )
    closed = files.close_file(
        handle_authorization,
        opened["handle"],
        execution_id="execution-0001",
    )
    assert closed == {"closed": True, "revision": 1}
    with files._repository.session_factory() as session:
        root = session.get(VirtualFileRoot, "PROJECT_DATA")
        assert root is not None
        assert root.used_bytes == len(payload) and root.used_nodes == 1
        assert root.reservation_id is None
        assert root.reservation_binding_digest is None
        assert root.reserved_bytes == 0 and root.reserved_nodes == 0


def test_recovery_removes_temporary_and_quarantines_orphan(tmp_path: Path) -> None:
    service, engine, _ = _open_service(tmp_path)
    root = tmp_path / "data" / "project-data"
    (root / ".spell-write-abandoned").write_bytes(b"partial")
    (root / "host-added.bin").write_bytes(b"orphan")
    result = service.recover()
    assert result == {"removed_temporary": 1, "quarantined_orphans": 1}
    assert not (root / ".spell-write-abandoned").exists()
    assert not (root / "host-added.bin").exists()
    service.close()
    engine.dispose()


def test_restart_fails_when_committed_content_is_missing(tmp_path: Path) -> None:
    service, engine, _ = _open_service(tmp_path)
    payload = b"must remain present"
    digest = hashlib.sha256(payload).hexdigest()
    service.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "missing-on-restart.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="missing-content-write",
    )
    (service._base / "project-data" / ".spell-objects" / digest).unlink()
    service.close()
    engine.dispose()

    with pytest.raises(VirtualFileError) as failed:
        _open_service(tmp_path)
    assert failed.value.code == "CORRUPT_FILE"


def test_restart_does_not_accept_same_digest_from_wrong_root(tmp_path: Path) -> None:
    service, engine, _ = _open_service(tmp_path)
    payload = b"root-bound content"
    digest = hashlib.sha256(payload).hexdigest()
    service.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "root-bound.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="root-bound-write",
    )
    project_object = service._base / "project-data" / ".spell-objects" / digest
    procedure_object = service._base / "procedure-data" / ".spell-objects" / digest
    project_object.unlink()
    procedure_object.write_bytes(payload)
    service.close()
    engine.dispose()

    with pytest.raises(VirtualFileError) as failed:
        _open_service(tmp_path)
    assert failed.value.code == "CORRUPT_FILE"
    assert not procedure_object.exists()
    quarantine = tmp_path / "data" / ".spell-quarantine"
    assert any(item.name.endswith(digest) for item in quarantine.iterdir())


def test_corrupt_referenced_content_blocks_followup_mutation(
    files: VirtualFileService,
) -> None:
    payload = b"committed before corruption"
    digest = hashlib.sha256(payload).hexdigest()
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "corrupt-before-mutation.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="corrupt-before-mutation-write",
    )
    object_path = files._base / "project-data" / ".spell-objects" / digest
    object_path.write_bytes(b"corrupt")

    with pytest.raises(VirtualFileError) as failed:
        files.create_directory(
            _http_authorization("CREATE_DIRECTORY"),
            "PROJECT_DATA",
            "must-not-settle",
            expected_revision=0,
            idempotency_key="blocked-by-integrity",
        )
    assert failed.value.code == "CORRUPT_FILE"


def test_physical_reader_rejects_unprovisioned_storage_root(
    files: VirtualFileService,
) -> None:
    with pytest.raises(VirtualFileError) as failed:
        files.read_physical_content("HOST", "path.bin", "0" * 64)
    assert failed.value.code == "CORRUPT_FILE"


def test_committed_object_link_substitution_never_reaches_outside_content(
    files: VirtualFileService, tmp_path: Path
) -> None:
    payload = b"inside-object"
    digest = hashlib.sha256(payload).hexdigest()
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "linked.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="seed-linked-object",
    )
    outside = tmp_path / "outside-secret.bin"
    outside.write_bytes(b"must-not-be-read")
    object_path = files._base / "project-data" / ".spell-objects" / digest
    object_path.unlink()
    try:
        os.symlink(outside, object_path)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are unavailable")

    with pytest.raises(VirtualFileError) as api_read:
        files.read_file(
            _http_authorization("READ"), "PROJECT_DATA", "linked.bin", revision=1
        )
    assert api_read.value.code == "CORRUPT_FILE"
    with pytest.raises(VirtualFileError) as physical_read:
        files.read_physical_content("PROJECT_DATA", "linked.bin", digest)
    assert physical_read.value.code == "CORRUPT_FILE"
    assert outside.read_bytes() == b"must-not-be-read"


def test_hard_link_substitution_is_rejected_by_final_handle_link_count(
    files: VirtualFileService, tmp_path: Path
) -> None:
    payload = b"hard-link-content"
    digest = hashlib.sha256(payload).hexdigest()
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "hard-linked.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="seed-hard-linked-object",
    )
    outside = tmp_path / "outside-hard-link.bin"
    outside.write_bytes(payload)
    object_path = files._base / "project-data" / ".spell-objects" / digest
    object_path.unlink()
    try:
        os.link(outside, object_path)
    except OSError:
        pytest.skip("hard links are unavailable")

    with pytest.raises(VirtualFileError) as failed:
        files.read_file(
            _http_authorization("READ"),
            "PROJECT_DATA",
            "hard-linked.bin",
            revision=1,
        )
    assert failed.value.code == "CORRUPT_FILE"
    assert outside.read_bytes() == payload


def test_stage_name_symlink_swap_cannot_finalize_outside_or_wrong_identity(
    files: VirtualFileService, tmp_path: Path, monkeypatch
) -> None:
    outside = tmp_path / "outside-stage-target.bin"
    outside.write_bytes(b"outside-stays-unchanged")
    original_rename = virtual_file_module.rename_open_file
    swap_observed: list[bool] = []

    def swap_then_rename(
        source_directory, source_name, source_stream, target_directory, target_name
    ):
        held = source_directory.path / f"attacker-held-{source_name}"
        stage = source_directory.path / source_name
        os.replace(stage, held)
        try:
            os.symlink(outside, stage)
        except (OSError, NotImplementedError):
            try:
                os.link(outside, stage)
            except OSError:
                os.replace(held, stage)
                pytest.skip("link substitution is unavailable")
        swap_observed.append(True)
        return original_rename(
            source_directory,
            source_name,
            source_stream,
            target_directory,
            target_name,
        )

    monkeypatch.setattr(virtual_file_module, "rename_open_file", swap_then_rename)
    payload = b"authoritative-stage"
    digest = hashlib.sha256(payload).hexdigest()
    try:
        result = files.write_file(
            _http_authorization("WRITE"),
            "PROJECT_DATA",
            "stage-swap.bin",
            payload,
            expected_revision=0,
            encoding="BINARY",
            content_sha256=digest,
            idempotency_key="stage-name-swap",
        )
    except VirtualFileError as exc:
        assert exc.code == "CORRUPT_FILE"
        with pytest.raises(VirtualFileError) as missing:
            files.read_file(
                _http_authorization("READ"), "PROJECT_DATA", "stage-swap.bin"
            )
        assert missing.value.code == "NOT_FOUND"
        files.recover()
    else:
        assert result["content_sha256"] == digest
        assert files.read_file(
            _http_authorization("READ"),
            "PROJECT_DATA",
            "stage-swap.bin",
            revision=1,
        )["content"] == payload
    assert swap_observed == [True]
    assert outside.read_bytes() == b"outside-stays-unchanged"
    object_path = files._base / "project-data" / ".spell-objects" / digest
    assert not object_path.is_symlink()


def test_retained_root_handle_blocks_or_survives_root_path_replacement(
    files: VirtualFileService, tmp_path: Path
) -> None:
    payload = b"root-handle-content"
    digest = hashlib.sha256(payload).hexdigest()
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "root-bound.bin",
        payload,
        expected_revision=0,
        encoding="BINARY",
        content_sha256=digest,
        idempotency_key="root-handle-seed",
    )
    root_path = files._base / "project-data"
    parked = files._base / "project-data-parked"
    outside = tmp_path / "outside-root"
    outside.mkdir()
    try:
        os.replace(root_path, parked)
    except OSError:
        # Windows retains directory handles without delete sharing, so a path
        # replacement is rejected before it can alter the root identity.
        assert files.read_physical_content(
            "PROJECT_DATA", "root-bound.bin", digest
        ) == payload
        return

    root_path.mkdir()
    try:
        os.symlink(outside, root_path / ".spell-objects", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")
    (parked / "host-added-after-root-swap.bin").write_bytes(b"orphan")
    recovered = files.recover()
    assert recovered["quarantined_orphans"] >= 1
    assert files.read_physical_content(
        "PROJECT_DATA", "root-bound.bin", digest
    ) == payload
    assert list(outside.iterdir()) == []


def _runtime_request(
    *, generation: int, content: str = "committed"
) -> dict[str, object]:
    parameters = {
        "root_id": "PROJECT_DATA",
        "virtual_path": "runtime.txt",
        "encoding": "UTF8_TEXT",
        "content": content,
        "expected_revision": 0,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }
    request: dict[str, object] = {
        "schema_version": "spell.v08.data-request/1",
        "request_id": "request-runtime-0001",
        "execution_id": "execution-runtime-0001",
        "step_index": 0,
        "operation": "WRITE_FILE",
        "parameters": parameters,
    }
    request["request_digest"] = hashlib.sha256(
        json.dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    request["service_principal_id"] = "procedure-runtime"
    request["worker_generation"] = generation
    return request


def _operation_request(
    operation: str,
    parameters: dict[str, object],
    *,
    request_id: str,
    step_index: int,
    generation: int = 1,
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema_version": "spell.v08.data-request/1",
        "request_id": request_id,
        "execution_id": "execution-runtime-0001",
        "step_index": step_index,
        "operation": operation,
        "parameters": parameters,
    }
    request["request_digest"] = hashlib.sha256(
        json.dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    request["service_principal_id"] = "procedure-runtime"
    request["worker_generation"] = generation
    return request


def test_runtime_file_results_are_primitive_and_properties_are_executable(
    files: VirtualFileService,
) -> None:
    payload = b"runtime text"
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "runtime-property.txt",
        payload,
        expected_revision=0,
        encoding="UTF8_TEXT",
        content_sha256=hashlib.sha256(payload).hexdigest(),
        idempotency_key="runtime-property-seed",
    )
    generation = 1
    runtime = ProcedureDataRuntime(
        files, worker_generation=lambda _execution_id: generation
    )
    file_value = runtime.resolve(
        _operation_request(
            "FILE_VALUE",
            {"root_id": "PROJECT_DATA", "virtual_path": "runtime-property.txt"},
            request_id="runtime-file-value",
            step_index=1,
        )
    )
    assert isinstance(file_value["value"], str)
    assert file_value["value"].startswith("spell-file-v1.")

    opened = runtime.resolve(
        _operation_request(
            "OPEN_FILE",
            {
                "root_id": "PROJECT_DATA",
                "virtual_path": "runtime-property.txt",
                "mode": "READ",
                "revision": 1,
            },
            request_id="runtime-open-file",
            step_index=2,
        )
    )
    assert isinstance(opened["value"], str)
    handle = file_handle_reference(
        opened["value"],
        execution_id="execution-runtime-0001",
        worker_generation=1,
        creator_request_id="runtime-open-file",
    )
    stored_handle = next(
        item for item in files._handles.values() if item.origin_request_id == "runtime-open-file"
    )
    stored_handle.origin_request_id = "tampered-creator-request"
    tampered = runtime.resolve(
        _operation_request(
            "READ_FILE",
            {"handle": handle},
            request_id="runtime-read-tampered-origin",
            step_index=3,
        )
    )
    assert tampered["outcome"] == "STALE_HANDLE"
    stored_handle.origin_request_id = "runtime-open-file"
    generation = 2
    cross_generation = runtime.resolve(
        _operation_request(
            "READ_FILE",
            {"handle": handle},
            request_id="runtime-read-new-generation",
            step_index=3,
            generation=2,
        )
    )
    assert cross_generation["outcome"] == "STALE_HANDLE"
    generation = 1
    is_open = runtime.resolve(
        _operation_request(
            "FILE_PROPERTY",
            {"handle": handle, "property": "isOpen"},
            request_id="runtime-file-property-open",
            step_index=3,
        )
    )
    assert is_open == {"outcome": "OK", "value": True}
    basename = runtime.resolve(
        _operation_request(
            "FILE_PROPERTY",
            {
                "root_id": "PROJECT_DATA",
                "virtual_path": "runtime-property.txt",
                "property": "basename",
            },
            request_id="runtime-file-property-basename",
            step_index=4,
        )
    )
    assert basename == {"outcome": "OK", "value": "runtime-property.txt"}
    read = runtime.resolve(
        _operation_request(
            "READ_FILE",
            {"handle": handle},
            request_id="runtime-read-file",
            step_index=5,
        )
    )
    assert read["value"] == "runtime text"
    listing = runtime.resolve(
        _operation_request(
            "READ_DIRECTORY",
            {"root_id": "PROJECT_DATA", "virtual_path": ""},
            request_id="runtime-read-directory",
            step_index=6,
        )
    )
    assert isinstance(listing["value"], str)
    assert json.loads(listing["value"])["items"][0]["name"] == "runtime-property.txt"
    closed = runtime.resolve(
        _operation_request(
            "CLOSE_FILE",
            {"handle": handle},
            request_id="runtime-close-file",
            step_index=7,
        )
    )
    assert closed == {"outcome": "OK", "revision": 1}
    deleted = runtime.resolve(
        _operation_request(
            "DELETE_FILE",
            {
                "root_id": "PROJECT_DATA",
                "virtual_path": "runtime-property.txt",
                "expected_revision": 1,
            },
            request_id="runtime-delete-file",
            step_index=8,
        )
    )
    assert deleted == {"outcome": "OK", "revision": 1}

    writable = runtime.resolve(
        _operation_request(
            "OPEN_FILE",
            {
                "root_id": "PROJECT_DATA",
                "virtual_path": "runtime-write-handle.txt",
                "mode": "WRITE",
                "revision": 0,
            },
            request_id="runtime-open-write-file",
            step_index=9,
        )
    )
    write_handle = file_handle_reference(
        writable["value"],
        execution_id="execution-runtime-0001",
        worker_generation=1,
        creator_request_id="runtime-open-write-file",
    )
    write_payload = "through handle"
    written = runtime.resolve(
        _operation_request(
            "WRITE_FILE",
            {
                "handle": write_handle,
                "encoding": "UTF8_TEXT",
                "content": write_payload,
                "content_sha256": hashlib.sha256(write_payload.encode("utf-8")).hexdigest(),
            },
            request_id="runtime-write-handle",
            step_index=10,
        )
    )
    assert written == {"outcome": "OK"}
    committed = runtime.resolve(
        _operation_request(
            "CLOSE_FILE",
            {"handle": write_handle},
            request_id="runtime-close-write-file",
            step_index=11,
        )
    )
    assert committed == {"outcome": "OK", "revision": 1}


def test_compiled_file_handle_workflow_executes_through_worker_and_runtime(
    files: VirtualFileService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "handle: str = ''\n"
        "OpenFile('PROJECT_DATA', 'worker-runtime.txt', mode='WRITE', revision=0, target=handle)\n"
        "WriteFile(handle=handle, content='end to end')\n"
        "CloseFile(handle)\n",
        "file-workflow.spell.py",
    )
    runtime = ProcedureDataRuntime(
        files,
        repository=files._repository,
        worker_generation=lambda _execution_id: 1,
    )
    control: queue.Queue[dict[str, object]] = queue.Queue()
    output: queue.Queue[dict[str, object]] = queue.Queue()
    monkeypatch.setattr(worker_module, "_replace_worker_environment", lambda: None)
    thread = threading.Thread(
        target=worker_module.worker_main,
        args=(
            "execution-runtime-0001",
            1,
            procedure.ir_version,
            list(procedure.steps),
            0,
            "start-file-workflow",
            None,
            {},
            control,
            output,
            None,
            None,
            False,
        ),
        daemon=True,
    )
    thread.start()
    operations: list[str] = []
    terminal: dict[str, object] | None = None
    while terminal is None:
        message = output.get(timeout=5)
        if message.get("kind") == "terminal":
            terminal = message
            continue
        if message.get("kind") != "data_requested":
            continue
        request = {
            key: value
            for key, value in message.items()
            if key not in {"kind", "generation"}
        }
        step_index = request["step_index"]
        assert type(step_index) is int
        handle_parameter = request["parameters"].get("handle")
        authoritative_variables = (
            {"handle": handle_parameter} if handle_parameter is not None else {}
        )
        request = validate_data_request(
            procedure.steps[step_index],
            request,
            execution_id="execution-runtime-0001",
            authoritative_variables=authoritative_variables,
            worker_generation=1,
        )
        operations.append(request["operation"])
        raw = runtime.resolve(
            {**request, "service_principal_id": "procedure-runtime", "worker_generation": 1}
        )
        assert raw["outcome"] == "OK"
        control.put(
            {"type": "data_result", **canonicalize_data_result(request, raw)}
        )

    assert terminal["state"] == "completed"
    assert operations == ["OPEN_FILE", "WRITE_FILE", "CLOSE_FILE"]
    thread.join(timeout=1)
    assert not thread.is_alive()
    persisted = files.read_file(
        _http_authorization("READ"),
        "PROJECT_DATA",
        "worker-runtime.txt",
        revision=1,
    )
    assert persisted["content"] == b"end to end"


def test_runtime_dictionary_load_and_save_are_revision_pinned_file_round_trips(
    files: VirtualFileService,
) -> None:
    generation = 1
    runtime = ProcedureDataRuntime(
        files,
        repository=files._repository,
        worker_generation=lambda _execution_id: generation,
    )
    created = runtime.resolve(
        _operation_request(
            "CREATE_DICTIONARY",
            {"dictionary_id": "DICT.RUNTIME", "format": "DB"},
            request_id="runtime-create-dictionary",
            step_index=20,
        )
    )
    assert created["outcome"] == "OK"
    assert created["revision"] == 1

    value = make_typed_value("STRING", "round-trip")
    source_document = build_db_document(
        "DICT.RUNTIME",
        1,
        (
            DictionaryEntry(
                "entry-1",
                "runtime.value",
                value,
                typed_value_digest(value),
            ),
        ),
    )
    source_bytes = source_document.canonical_bytes
    files.create_directory(
        _http_authorization("CREATE_DIRECTORY"),
        "PROJECT_DATA",
        "dictionary",
        expected_revision=0,
        idempotency_key="dictionary-directory",
    )
    files.write_file(
        _http_authorization("WRITE"),
        "PROJECT_DATA",
        "dictionary/source.db",
        source_bytes,
        expected_revision=0,
        encoding="UTF8_TEXT",
        content_sha256=hashlib.sha256(source_bytes).hexdigest(),
        idempotency_key="dictionary-source",
    )

    load_request = _operation_request(
            "LOAD_DICTIONARY",
            {
                "dictionary_id": "DICT.RUNTIME",
                "expected_revision": 1,
                "format": "DB",
                "root_id": "PROJECT_DATA",
                "source_revision": 1,
                "virtual_path": "dictionary/source.db",
            },
            request_id="runtime-load-dictionary",
            step_index=21,
        )
    loaded = runtime.resolve(load_request)
    assert loaded["outcome"] == "OK"
    assert loaded["revision"] == 2
    assert isinstance(loaded["value"], str)
    assert len(loaded["value"]) > 64

    generation = 2
    recovered_load = runtime.recover(
        _operation_request(
            "LOAD_DICTIONARY",
            load_request["parameters"],
            request_id="runtime-load-dictionary",
            step_index=21,
            generation=2,
        ),
        original_binding=ProcedureCallerBinding(
            "procedure-runtime",
            "execution-runtime-0001",
            1,
            "runtime-load-dictionary",
        ),
    )
    assert recovered_load["outcome"] == "OK"
    assert recovered_load["revision"] == loaded["revision"]
    assert recovered_load["value"] != loaded["value"]

    saved = runtime.resolve(
        _operation_request(
            "SAVE_DICTIONARY",
            {
                "dictionary_id": "DICT.RUNTIME",
                "dictionary_revision": 2,
                "expected_file_revision": 0,
                "format": "DB",
                "root_id": "PROJECT_DATA",
                "virtual_path": "dictionary/saved.db",
            },
            request_id="runtime-save-dictionary",
            step_index=22,
            generation=2,
        )
    )
    assert saved == {"outcome": "OK", "revision": 1}
    saved_file = files.read_file(
        _http_authorization("READ"),
        "PROJECT_DATA",
        "dictionary/saved.db",
        revision=1,
    )
    parsed = parse_dictionary_document(saved_file["content"], media_type=DB_MEDIA_TYPE)
    assert parsed.base_revision == 2
    assert [(item.entry_id, item.value) for item in parsed.entries] == [
        ("entry-1", value)
    ]


def test_runtime_shared_create_and_list_derive_execution_owner(
    files: VirtualFileService,
) -> None:
    runtime = ProcedureDataRuntime(
        files,
        repository=files._repository,
        worker_generation=lambda _execution_id: 1,
    )
    created = runtime.resolve(
        _operation_request(
            "SHARED_CREATE_NAMESPACE",
            {
                "acl_revision": 1,
                "namespace_id": "runtime-shared",
                "scope": "EXECUTION",
            },
            request_id="runtime-create-shared",
            step_index=30,
        )
    )
    assert created == {"outcome": "OK", "revision": 1}
    listed = runtime.resolve(
        _operation_request(
            "SHARED_LIST_NAMESPACES",
            {},
            request_id="runtime-list-shared",
            step_index=31,
        )
    )
    assert listed["outcome"] == "OK"
    assert "runtime-shared" in listed["value"]
    with files._repository.session_factory() as session:
        head = session.get(
            SharedNamespace,
            {
                "scope": "EXECUTION",
                "owner_id": "execution-runtime-0001",
                "namespace_id": "runtime-shared",
            },
        )
        assert head is not None
        assert head.owner_id == "execution-runtime-0001"

    fabricated = runtime.resolve(
        _operation_request(
            "SHARED_LIST_NAMESPACES",
            {"owner_id": "fabricated-execution"},
            request_id="runtime-list-shared-fabricated",
            step_index=32,
        )
    )
    assert fabricated["outcome"] == "REJECTED"


def test_runtime_does_not_conflate_settlements_across_worker_generations(
    tmp_path: Path,
) -> None:
    generation = 1
    service, engine, _ = _open_service(tmp_path)
    runtime = ProcedureDataRuntime(
        service, worker_generation=lambda _execution_id: generation
    )
    first = runtime.resolve(_runtime_request(generation=1))
    assert first == {"outcome": "OK", "revision": 1}
    service.close()
    engine.dispose()

    generation = 2
    recovered, recovered_engine, _ = _open_service(tmp_path)
    runtime = ProcedureDataRuntime(
        recovered, worker_generation=lambda _execution_id: generation
    )
    recovered_result = runtime.recover(
        _runtime_request(generation=2),
        original_binding=ProcedureCallerBinding(
            "procedure-runtime",
            "execution-runtime-0001",
            1,
            "request-runtime-0001",
        ),
    )
    assert recovered_result == first
    generation_two = runtime.resolve(_runtime_request(generation=2))
    assert generation_two["outcome"] == "REVISION_CONFLICT"
    stale = runtime.resolve(_runtime_request(generation=1))
    assert stale["outcome"] == "NOT_AUTHORIZED"
    mismatch = runtime.resolve(_runtime_request(generation=2, content="changed"))
    assert mismatch["outcome"] == "REVISION_CONFLICT"
    recovered.close()
    recovered_engine.dispose()
