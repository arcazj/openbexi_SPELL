from __future__ import annotations

import ast
import base64
import hashlib
import json
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.development_bundle_broker import (
    DualContainerBundleBroker,
    READY_SCHEMA,
    RESPONSE_SCHEMA,
)
from backend.development_bundle_builder import build_request_payload, make_build_request
from backend.development_bundle_protocol import atomic_protocol_write
from backend.development_bundle_provenance import (
    BASE_IMAGE_REFERENCE,
    toolchain_descriptor,
    toolchain_digest,
    toolchain_files,
)
from backend.development_bundle_worker import (
    _write_ready,
    process_pending_once,
)
from backend.development_domain import (
    DevelopmentConflictError,
    DevelopmentCorruptionError,
    DevelopmentLimitError,
    canonical_json_bytes,
    canonical_tree,
)
from backend.development_service import (
    CATALOG_MEDIA_TYPE,
    MAX_BUNDLE_CATALOG_SNAPSHOTS,
    MAX_BUNDLE_ENTRIES,
    DevelopmentService,
)


def _request() -> dict:
    project_id = "dev-builder-test"
    manifest = DevelopmentService._manifest(
        None,
        project_id=project_id,
        display_name="Builder Test",
        case_policy="CASE_INSENSITIVE",
        owner="author@example.com",
    )
    source = "\n".join(
        (
            "# @procedure local/builder-test",
            "# @display-name Builder Test",
            "# @description Isolated builder test",
            "# @language-profile spell-restricted-ast/0.9",
            '"""Isolated builder test."""',
            "ARGS()",
            'DataContainer("LOCAL.BUILDER")',
            'Log("ready")',
            "",
        )
    ).encode("utf-8")
    resources = [
        {
            "content": canonical_json_bytes(manifest),
            "content_sha256": hashlib.sha256(canonical_json_bytes(manifest)).hexdigest(),
            "kind": "PROJECT",
            "media_type": "application/yaml",
            "path": "spell-project.yaml",
            "resource_id": "resource-manifest",
        },
        {
            "content": b"",
            "content_sha256": hashlib.sha256(b"").hexdigest(),
            "kind": "SOURCE_FOLDER",
            "media_type": "inode/directory",
            "path": "procedures",
            "resource_id": "resource-folder",
        },
        {
            "content": source,
            "content_sha256": hashlib.sha256(source).hexdigest(),
            "kind": "PROCEDURE",
            "media_type": "text/x-python",
            "path": "procedures/builder.spell.py",
            "resource_id": "resource-procedure",
        },
    ]
    snapshot = DevelopmentService._snapshot_bytes_from_entries(resources)
    _, tree_digest = canonical_tree(resources, case_policy="CASE_INSENSITIVE")
    return make_build_request(
        history_revision_id="history-builder-test",
        project_id=project_id,
        tree_digest=tree_digest,
        snapshot_bytes=snapshot,
        workspace_revision=3,
        created_at_database_time="2026-08-18T12:00:00Z",
        validation_summary_digest=hashlib.sha256(b"validation").hexdigest(),
        review_subject="reviewer@example.com",
    )


def _directories(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    request = tmp_path / "requests"
    responses = {
        "builder-a": tmp_path / "responses-a",
        "builder-b": tmp_path / "responses-b",
    }
    request.mkdir()
    for worker, path in responses.items():
        path.mkdir()
        _write_ready(worker, path)
    return request, responses


def _worker_once(worker: str, request: Path, response: Path) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process_pending_once(worker, request, response):
            return
        time.sleep(0.005)
    raise AssertionError(f"{worker} did not observe a request")


def test_two_independent_workers_reproduce_exact_bundle_bytes(tmp_path: Path) -> None:
    request_directory, response_directories = _directories(tmp_path)
    broker = DualContainerBundleBroker(
        request_directory=request_directory,
        response_directories=response_directories,
        timeout_seconds=5,
        poll_seconds=0.005,
    )

    results = []
    for _ in range(2):
        threads = [
            threading.Thread(
                target=_worker_once,
                args=(worker, request_directory, response_directories[worker]),
            )
            for worker in ("builder-a", "builder-b")
        ]
        for thread in threads:
            thread.start()
        results.append(broker.build(_request()))
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()

    assert results[0] == results[1]
    assert hashlib.sha256(results[0].bundle_bytes).hexdigest()
    assert list(request_directory.iterdir()) == []
    assert sorted(path.name for path in response_directories["builder-a"].iterdir()) == [
        "ready.json"
    ]


def test_timeout_and_late_worker_leave_no_protocol_or_bundle_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_directory, response_directories = _directories(tmp_path)
    broker = DualContainerBundleBroker(
        request_directory=request_directory,
        response_directories=response_directories,
        timeout_seconds=0.1,
        poll_seconds=0.005,
    )
    entered = threading.Event()
    release = threading.Event()
    from backend import development_bundle_worker as worker_module

    original = worker_module.build_request_payload

    def delayed(request):
        entered.set()
        release.wait(timeout=2)
        return original(request)

    monkeypatch.setattr(worker_module, "build_request_payload", delayed)
    thread = threading.Thread(
        target=_worker_once,
        args=("builder-a", request_directory, response_directories["builder-a"]),
    )
    thread.start()
    with pytest.raises(DevelopmentConflictError, match="did not respond") as caught:
        broker.build(_request())
    assert caught.value.code == "BUILDER_UNAVAILABLE"
    assert entered.wait(timeout=1)
    release.set()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert list(request_directory.iterdir()) == []
    for path in response_directories.values():
        assert sorted(item.name for item in path.iterdir()) == ["ready.json"]


def test_broker_rejects_tampered_worker_response_and_cleans_protocol_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_directory, response_directories = _directories(tmp_path)
    broker = DualContainerBundleBroker(
        request_directory=request_directory,
        response_directories=response_directories,
        timeout_seconds=5,
        poll_seconds=0.005,
    )
    from backend import development_bundle_worker as worker_module

    original_response = worker_module._response
    original_atomic_write = worker_module.atomic_protocol_write
    late_publish_entered = threading.Event()
    release_late_publish = threading.Event()

    def delayed_atomic_write(path: Path, raw: bytes, **kwargs) -> None:
        if (
            path.parent == response_directories["builder-a"]
            and path.name.endswith(".response.json")
        ):
            late_publish_entered.set()
            assert release_late_publish.wait(timeout=5)
        original_atomic_write(path, raw, **kwargs)

    def tampered_response(**kwargs):
        value = original_response(**kwargs)
        if kwargs["worker_id"] == "builder-b" and value.get("status") == "OK":
            assert late_publish_entered.wait(timeout=5)
            value["bundle_sha256"] = "0" * 64
        return value

    monkeypatch.setattr(worker_module, "atomic_protocol_write", delayed_atomic_write)
    monkeypatch.setattr(worker_module, "_response", tampered_response)
    threads = [
        threading.Thread(
            target=_worker_once,
            args=(worker, request_directory, response_directories[worker]),
        )
        for worker in ("builder-a", "builder-b")
    ]
    for thread in threads:
        thread.start()
    with pytest.raises(DevelopmentCorruptionError, match="byte digest differs"):
        broker.build(_request())
    assert list(request_directory.iterdir()) == []
    release_late_publish.set()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert list(request_directory.iterdir()) == []
    for path in response_directories.values():
        assert sorted(item.name for item in path.iterdir()) == ["ready.json"]


def test_two_workers_finishing_after_deadline_are_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_directory, response_directories = _directories(tmp_path)
    broker = DualContainerBundleBroker(
        request_directory=request_directory,
        response_directories=response_directories,
        timeout_seconds=0.1,
        poll_seconds=0.005,
    )
    entered = threading.Barrier(3)
    release = threading.Event()
    from backend import development_bundle_worker as worker_module

    original = worker_module.build_request_payload

    def delayed(request):
        entered.wait(timeout=3)
        release.wait(timeout=2)
        return original(request)

    monkeypatch.setattr(worker_module, "build_request_payload", delayed)
    threads = [
        threading.Thread(
            target=_worker_once,
            args=(worker, request_directory, response_directories[worker]),
        )
        for worker in ("builder-a", "builder-b")
    ]
    for thread in threads:
        thread.start()

    outcome: dict[str, Exception] = {}

    def build() -> None:
        try:
            broker.build(_request())
        except Exception as exc:
            outcome["error"] = exc

    broker_thread = threading.Thread(target=build)
    broker_thread.start()
    entered.wait(timeout=3)
    time.sleep(0.15)
    release.set()
    broker_thread.join(timeout=5)
    assert not broker_thread.is_alive()
    assert isinstance(outcome.get("error"), DevelopmentConflictError)
    assert outcome["error"].code == "BUILDER_UNAVAILABLE"
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert list(request_directory.iterdir()) == []
    for path in response_directories.values():
        assert sorted(item.name for item in path.iterdir()) == ["ready.json"]


def test_worker_restart_removes_only_expired_schema_valid_orphan(tmp_path: Path) -> None:
    request_directory, response_directories = _directories(tmp_path)
    response = response_directories["builder-a"] / ("0" * 32 + ".response.json")
    atomic_protocol_write(
        response,
        canonical_json_bytes(
            {
                "error_code": "BUILDER_FAILED",
                "expires_at_epoch_ms": 0,
                "request_id": "0" * 32,
                "request_sha256": "0" * 64,
                "schema_version": RESPONSE_SCHEMA,
                "status": "ERROR",
                "worker_id": "builder-a",
            }
        ),
        label="test orphan",
    )
    assert not process_pending_once(
        "builder-a", request_directory, response_directories["builder-a"]
    )
    assert sorted(item.name for item in response_directories["builder-a"].iterdir()) == [
        "ready.json"
    ]


def test_worker_orphan_cleanup_tolerates_only_delete_after_enumeration(
    tmp_path: Path, monkeypatch
) -> None:
    from backend import development_bundle_worker as worker_module

    request_directory, response_directories = _directories(tmp_path)
    response_directory = response_directories["builder-a"]
    response = response_directory / ("1" * 32 + ".response.json")
    raw = canonical_json_bytes(
        {
            "error_code": "BUILDER_FAILED",
            "expires_at_epoch_ms": 0,
            "request_id": "1" * 32,
            "request_sha256": "1" * 64,
            "schema_version": RESPONSE_SCHEMA,
            "status": "ERROR",
            "worker_id": "builder-a",
        }
    )
    atomic_protocol_write(response, raw, label="racing orphan")
    original_read = worker_module.read_protocol_file

    def delete_then_read(path: Path, **kwargs) -> bytes:
        if path == response:
            path.unlink()
        return original_read(path, **kwargs)

    monkeypatch.setattr(worker_module, "read_protocol_file", delete_then_read)
    assert not process_pending_once("builder-a", request_directory, response_directory)
    assert not response.exists()

    monkeypatch.setattr(worker_module, "read_protocol_file", original_read)
    atomic_protocol_write(response, b"{}", label="tampered orphan")
    with pytest.raises(RuntimeError, match="orphaned bundle builder response is invalid"):
        process_pending_once("builder-a", request_directory, response_directory)
    assert response.read_bytes() == b"{}"


def test_toolchain_descriptor_binds_runtime_lock_dockerfile_and_regular_files(
    tmp_path: Path,
) -> None:
    descriptor = toolchain_descriptor()
    assert descriptor["base_image"] == BASE_IMAGE_REFERENCE
    assert descriptor["runtime"]["python"] == {
        "abi_tag": "cpython-313",
        "implementation": "cpython",
        "version": "3.13.14",
    }
    assert descriptor["runtime"]["os_release"] == {"ID": "debian", "VERSION_ID": "13"}
    assert descriptor["runtime"]["installed_requirements"]
    assert hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest() == toolchain_digest()

    repository = Path(__file__).resolve().parents[2]
    assert {
        "contracts/v10/language_reference_example_matrix.json",
        "contracts/v11/telecommand_catalog.json",
        "contracts/v11/telecommand_execution.json",
    } <= set(toolchain_files(repository))
    copied = tmp_path / "repository"
    for relative in toolchain_files(repository):
        destination = copied.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository.joinpath(*relative.split("/")), destination)
    baseline_digest = toolchain_digest(copied)
    formerly_omitted = copied / "backend" / "ir_v03.py"
    formerly_omitted.write_text(
        formerly_omitted.read_text(encoding="utf-8") + "\n# provenance mutation proof\n",
        encoding="utf-8",
    )
    assert toolchain_digest(copied) != baseline_digest
    shutil.copyfile(repository / "backend" / "ir_v03.py", formerly_omitted)
    dockerfile = copied / "backend" / "Dockerfile"
    dockerfile.write_text(
        dockerfile.read_text(encoding="utf-8").replace(BASE_IMAGE_REFERENCE, "python:latest", 1),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="base image differs"):
        toolchain_descriptor(copied)

    shutil.copyfile(repository / "backend" / "Dockerfile", dockerfile)
    source = copied / "backend" / "development_bundle_worker.py"
    source.unlink()
    source.symlink_to(repository / "backend" / "development_bundle_worker.py")
    with pytest.raises(RuntimeError, match="source path is invalid"):
        toolchain_descriptor(copied)


def test_builder_boundary_has_no_network_process_or_driver_imports() -> None:
    repository = Path(__file__).resolve().parents[2]
    forbidden = {"socket", "subprocess", "multiprocessing", "driver_host", "grpc"}
    for name in (
        "development_bundle_builder.py",
        "development_bundle_broker.py",
        "development_bundle_protocol.py",
        "development_bundle_worker.py",
    ):
        tree = ast.parse((repository / "backend" / name).read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert forbidden.isdisjoint(imports), name


def test_bundle_generation_and_verifier_enforce_entry_and_actual_catalog_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    history_value = request["history"]
    history = SimpleNamespace(
        history_revision_id=history_value["history_revision_id"],
        project_id=history_value["project_id"],
        tree_digest=history_value["tree_digest"],
        snapshot_bytes=base64.b64decode(history_value["snapshot_bytes"]),
        workspace_revision=history_value["workspace_revision"],
        created_at_database_time=datetime.fromisoformat(
            history_value["created_at_database_time"].replace("Z", "+00:00")
        ),
        validation_summary_digest=history_value["validation_summary_digest"],
    )
    review = SimpleNamespace(reviewer_subject=request["review"]["reviewer_subject"])
    original_snapshot_resources = DevelopmentService._snapshot_resources
    monkeypatch.setattr(
        DevelopmentService,
        "_snapshot_resources",
        staticmethod(lambda _raw: [{}] * (MAX_BUNDLE_ENTRIES + 1)),
    )
    with pytest.raises(DevelopmentLimitError, match="entry count"):
        DevelopmentService._bundle_payload(history, review)

    base_resources = original_snapshot_resources(history.snapshot_bytes)
    catalog_resources = []
    for index in range(MAX_BUNDLE_CATALOG_SNAPSHOTS + 1):
        unsigned = {
            "schema_version": "spell.catalog.snapshot/1",
            "catalog_id": f"CATALOG_{index:03d}",
            "catalog_revision": 1,
            "catalog_kind": "TM",
            "entries": [],
            "dependencies": [],
        }
        content_digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        content = canonical_json_bytes(
            {**unsigned, "content_digest": content_digest}
        )
        catalog_resources.append(
            {
                "content": content,
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "kind": "PROJECT_METADATA",
                "media_type": CATALOG_MEDIA_TYPE,
                "path": f"catalogs/{index:03d}.json",
                "resource_id": f"catalog-resource-{index:03d}",
            }
        )
    monkeypatch.setattr(
        DevelopmentService,
        "_snapshot_resources",
        staticmethod(lambda _raw: [*base_resources, *catalog_resources]),
    )
    with pytest.raises(DevelopmentLimitError, match="catalog snapshot count"):
        DevelopmentService._bundle_payload(history, review)

    monkeypatch.setattr(
        DevelopmentService,
        "_snapshot_resources",
        staticmethod(original_snapshot_resources),
    )
    built = build_request_payload(request)

    def row_for(payload: dict) -> SimpleNamespace:
        raw = canonical_json_bytes(payload)
        digest = hashlib.sha256(raw).hexdigest()
        manifest = payload["manifest"]
        return SimpleNamespace(
            bundle_digest=digest,
            project_id=manifest["project_id"],
            history_revision_id=manifest["history_revision_id"],
            bundle_bytes=raw,
            byte_length=len(raw),
            manifest={"bundle_digest": digest, **manifest},
            source_tree_digest=manifest["source_tree_digest"],
            validation_report_digest=manifest["validation_report_digest"],
            review_subject=manifest["review_subject"],
            builder_identity=manifest["builder_identity"],
        )

    entry_overflow = json.loads(built.bundle_bytes)
    entry_overflow["entries"] = [{}] * (MAX_BUNDLE_ENTRIES + 1)
    with pytest.raises(DevelopmentCorruptionError, match="entries are invalid"):
        DevelopmentService._verify_bundle_row(row_for(entry_overflow))

    catalog_overflow = json.loads(built.bundle_bytes)
    catalog_entry = {
        "content": base64.b64encode(catalog_resources[0]["content"]).decode("ascii"),
        "content_sha256": catalog_resources[0]["content_sha256"],
        "kind": "PROJECT_METADATA",
        "media_type": CATALOG_MEDIA_TYPE,
    }
    catalog_overflow["entries"].extend(
        {**catalog_entry, "path": f"catalogs/{index:03d}.json"}
        for index in range(MAX_BUNDLE_CATALOG_SNAPSHOTS + 1)
    )
    catalog_overflow["entries"].sort(key=lambda item: item["path"].encode("utf-8"))
    with pytest.raises(
        DevelopmentCorruptionError, match="catalog snapshot count"
    ):
        DevelopmentService._verify_bundle_row(row_for(catalog_overflow))


def test_compose_workers_use_same_image_and_separate_response_volumes() -> None:
    compose = (Path(__file__).resolve().parents[2] / "compose.yaml").read_text(
        encoding="utf-8"
    )
    assert compose.count("image: openbexi-spell-backend:${SPELL_IMAGE_TAG:-local}") == 3
    assert "bundle-builder-a:" in compose and "bundle-builder-b:" in compose
    assert compose.count("network_mode: none") >= 3
    assert "spell-bundle-builder-response-a" in compose
    assert "spell-bundle-builder-response-b" in compose
    assert READY_SCHEMA == "spell.bundle-builder-ready/1"
