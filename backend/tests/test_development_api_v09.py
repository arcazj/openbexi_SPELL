from __future__ import annotations

import ast
import base64
import hashlib
import io
import stat
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.requests import Request

from backend.auth import AuthConfig, issue_local_dev_token
from backend.development_analysis import analyze_source
from backend.development_schemas import DEVELOPMENT_API_CONTRACT
from backend.procedure_parser import MAX_SOURCE_BYTES
from backend.tests.test_development_service_v09 import (
    ADMIN,
    OPERATOR,
    _candidate_bundle,
    _create_procedure,
    _create_project,
)


def _headers(config: AuthConfig, subject: str, role: str) -> dict[str, str]:
    token = issue_local_dev_token(
        config,
        subject=subject,
        role=role,
        peer_host="127.0.0.1",
        lifetime_seconds=600,
    )
    return {"Authorization": f"Bearer {token}"}


def _replace_archive_member(raw: bytes, path: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw), "r") as source, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED
    ) as target:
        for original in source.infolist():
            info = zipfile.ZipInfo(
                original.filename, date_time=(1980, 1, 1, 0, 0, 0)
            )
            info.create_system = 3
            info.external_attr = original.external_attr or (
                (stat.S_IFREG | 0o644) << 16
            )
            info.compress_type = zipfile.ZIP_STORED
            info.comment = original.comment
            target.writestr(
                info,
                content if original.filename.rstrip("/") == path else source.read(original),
            )
    return output.getvalue()


def test_development_route_contract_auth_strict_payload_and_idempotency(
    client: TestClient,
    auth_config: AuthConfig,
    viewer_headers: dict[str, str],
) -> None:
    actual = {
        f"{method.upper()} {path}"
        for path, operations in client.app.openapi()["paths"].items()
        if path.startswith("/api/v1/development")
        for method in operations
    }
    assert actual == set(DEVELOPMENT_API_CONTRACT)
    assert client.get("/api/v1/development/projects").status_code == 401

    body = {
        "name": "API contract",
        "case_policy": "CASE_INSENSITIVE",
        "manifest": None,
        "idempotency_key": "api-project-1",
    }
    denied = client.post(
        "/api/v1/development/projects", headers=viewer_headers, json=body
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "FORBIDDEN"

    operator = _headers(
        auth_config, "author name@example.com", "operator"
    )
    created = client.post(
        "/api/v1/development/projects", headers=operator, json=body
    )
    assert created.status_code == 200, created.text
    assert created.json()["replayed"] is False
    replay = client.post(
        "/api/v1/development/projects", headers=operator, json=body
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["project"] == created.json()["project"]

    conflict = client.post(
        "/api/v1/development/projects",
        headers=operator,
        json={**body, "case_policy": "CASE_SENSITIVE"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "IDEMPOTENCY_CONFLICT"
    extra = client.post(
        "/api/v1/development/projects",
        headers=operator,
        json={**body, "idempotency_key": "api-project-2", "unexpected": True},
    )
    assert extra.status_code == 422

    admin = _headers(auth_config, "admin@example.com", "admin")
    project_id = created.json()["project"]["project_id"]
    admin_edit = client.post(
        f"/api/v1/development/projects/{project_id}/resources",
        headers=admin,
        json={
            "path": "procedures/admin.spell.py",
            "kind": "PROCEDURE",
            "media_type": "text/x-python",
            "content": "# @procedure local/admin\nLog('no')\n",
            "content_sha256": hashlib.sha256(
                b"# @procedure local/admin\nLog('no')\n"
            ).hexdigest(),
            "expected_workspace_revision": 1,
            "idempotency_key": "admin-edit",
        },
    )
    assert admin_edit.status_code == 403


def test_catalog_decision_route_forwards_operation_body_field(
    client: TestClient,
    auth_config: AuthConfig,
) -> None:
    service = client.app.state.development_service
    project = _create_project(service, "API catalog decision")
    _create_procedure(
        service,
        project,
        procedure_id="api-catalog-decision",
        path="procedures/api-catalog-decision.spell.py",
    )
    bundle = _candidate_bundle(service, {**project, "workspace_revision": 2})
    admin_headers = _headers(auth_config, ADMIN["subject"], ADMIN["role"])
    approval = client.post(
        f"/api/v1/development/bundles/{bundle['bundle_digest']}/approve",
        headers=admin_headers,
        json={
            "expected_state_revision": 1,
            "reason": "Approve API route bundle",
            "idempotency_key": "api-catalog-approve",
        },
    )
    assert approval.status_code == 200, approval.text

    body = {
        "operation": "PROMOTE",
        "bundle_digest": bundle["bundle_digest"],
        "expected_registry_revision": 0,
        "reason": "Promote through the real catalog decision route",
        "idempotency_key": "api-catalog-promote",
    }
    response = client.post(
        "/api/v1/development/catalog/api-catalog-decision/decisions",
        headers=admin_headers,
        json=body,
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"]["operation"] == "PROMOTE"
    entry = response.json()["catalog_entry"]
    assert {
        key: entry[key]
        for key in (
            "procedure_id",
            "registry_revision",
            "current_bundle_digest",
            "previous_bundle_digest",
            "state",
            "updated_by_subject",
        )
    } == {
        "procedure_id": "api-catalog-decision",
        "registry_revision": 1,
        "current_bundle_digest": bundle["bundle_digest"],
        "previous_bundle_digest": None,
        "state": "PROMOTED",
        "updated_by_subject": ADMIN["subject"],
    }

    replay = client.post(
        "/api/v1/development/catalog/api-catalog-decision/decisions",
        headers=admin_headers,
        json=body,
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True


def test_analysis_module_is_non_executing_and_bounds_before_ast_parse(
    monkeypatch,
) -> None:
    source_path = Path(__file__).parents[1] / "development_analysis.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    prohibited_modules = {
        "asyncio",
        "ctypes",
        "http",
        "importlib",
        "multiprocessing",
        "os",
        "pathlib",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(item.name.split(".")[0] not in prohibited_modules for item in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in prohibited_modules
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}

    def forbidden_parse(*_args, **_kwargs):
        raise AssertionError("ast.parse must not receive oversized source")

    monkeypatch.setattr("backend.development_analysis.ast.parse", forbidden_parse)
    oversized = "# @procedure local/large\n" + "x" * MAX_SOURCE_BYTES
    result = analyze_source(
        oversized, "procedures/large.spell.py", workspace_revision=1
    )
    assert [item["code"] for item in result.diagnostics] == ["SPELL005"]


def test_completed_analysis_report_download_is_exact_and_digest_bound(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    service = client.app.state.development_service
    project = _create_project(service, "Report download")
    _create_procedure(service, project)
    queued = service.create_check(
        project["project_id"],
        **OPERATOR,
        scope="PROJECT",
        scope_path=None,
        expected_workspace_revision=2,
        reparse_libraries=False,
        idempotency_key="report-check",
    )
    completed = service.run_check(queued["job"]["job_id"])["job"]
    polled = client.get(
        f"/api/v1/development/checks/{completed['job_id']}",
        headers=viewer_headers,
    )
    assert polled.status_code == 200
    assert "report" not in polled.json()["job"]
    assert polled.json()["job"]["report_sha256"] == completed["report_sha256"]
    response = client.get(
        f"/api/v1/development/checks/{completed['job_id']}/report",
        headers=viewer_headers,
    )
    assert response.status_code == 200
    assert response.content == service.download_check_report(
        completed["job_id"], subject="viewer", role="viewer"
    )[0]
    assert response.headers["content-sha256"] == hashlib.sha256(response.content).hexdigest()


def test_raw_import_auth_precedes_body_and_stream_contract_is_digest_bound(
    client: TestClient,
    auth_config: AuthConfig,
    monkeypatch,
) -> None:
    original_stream = Request.stream

    async def forbidden_stream(_request):
        raise AssertionError("unauthenticated import body was consumed")
        yield b""

    monkeypatch.setattr(Request, "stream", forbidden_stream)
    raw = b"not-consumed-before-auth"
    denied = client.post(
        "/api/v1/development/projects/not-authorized/imports",
        content=raw,
        headers={
            "Content-Type": "application/vnd.openbexi.spell.project+zip",
            "Content-SHA256": hashlib.sha256(raw).hexdigest(),
            "Idempotency-Key": "unauthorized-import",
            "X-Spell-Filename-Base64url": base64.urlsafe_b64encode(
                "unauthorized.zip".encode()
            ).rstrip(b"=").decode(),
            "X-Spell-Workspace-Revision": "0",
        },
    )
    assert denied.status_code == 401
    monkeypatch.setattr(Request, "stream", original_stream)

    service = client.app.state.development_service
    project = _create_project(service, "Raw import API")
    archive, archive_digest = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=1,
    )
    operator = _headers(auth_config, OPERATOR["subject"], "operator")
    response = client.post(
        f"/api/v1/development/projects/{project['project_id']}/imports",
        content=archive,
        headers={
            **operator,
            "Content-Type": "application/vnd.openbexi.spell.project+zip",
            "Content-SHA256": archive_digest,
            "Idempotency-Key": "raw-import-api",
            "X-Spell-Filename-Base64url": base64.urlsafe_b64encode(
                "résumé-import.zip".encode("utf-8")
            ).rstrip(b"=").decode("ascii"),
            "X-Spell-Workspace-Revision": "1",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["import"]["added"] == 0
    assert response.json()["import"]["original_bytes_sha256"] == archive_digest
    operation = service.get_import_operation(
        project["project_id"],
        response.json()["import"]["operation_id"],
        subject="viewer",
        role="viewer",
    )["import_operation"]
    assert operation["original_filename"] == "résumé-import.zip"

    wrong_digest = client.post(
        f"/api/v1/development/projects/{project['project_id']}/imports",
        content=archive,
        headers={
            **operator,
            "Content-Type": "application/vnd.openbexi.spell.project+zip",
            "Content-SHA256": "0" * 64,
            "Idempotency-Key": "raw-import-wrong-digest",
            "X-Spell-Filename-Base64url": base64.urlsafe_b64encode(
                "raw-import.zip".encode()
            ).rstrip(b"=").decode(),
            "X-Spell-Workspace-Revision": "1",
        },
    )
    assert wrong_digest.status_code == 422


def test_retained_import_routes_enforce_actor_and_idempotency(
    client: TestClient,
    auth_config: AuthConfig,
    viewer_headers: dict[str, str],
) -> None:
    service = client.app.state.development_service
    project = _create_project(service, "Retained API")
    content = b"workspace"
    resource = service.create_resource(
        project["project_id"],
        **OPERATOR,
        path="incoming.txt",
        kind="PROJECT_METADATA",
        media_type="text/plain",
        content=content.decode(),
        content_sha256=hashlib.sha256(content).hexdigest(),
        expected_workspace_revision=1,
        idempotency_key="retained-api-resource",
    )["resource"]
    archive, _ = service.export_project(
        project["project_id"],
        subject="viewer",
        role="viewer",
        expected_workspace_revision=2,
    )
    incoming = _replace_archive_member(archive, "incoming.txt", b"retained")
    operator = _headers(auth_config, OPERATOR["subject"], "operator")
    other_operator = _headers(auth_config, "other-author@example.com", "operator")
    admin = _headers(auth_config, "admin@example.com", "admin")

    def upload(key: str):
        return client.post(
            f"/api/v1/development/projects/{project['project_id']}/imports",
            content=incoming,
            headers={
                **operator,
                "Content-Type": "application/vnd.openbexi.spell.project+zip",
                "Content-SHA256": hashlib.sha256(incoming).hexdigest(),
                "Idempotency-Key": key,
                "X-Spell-Filename-Base64url": base64.urlsafe_b64encode(
                    b"retained.zip"
                ).rstrip(b"=").decode("ascii"),
                "X-Spell-Workspace-Revision": "2",
            },
        )

    first = upload("retained-api-upload-discard")
    assert first.status_code == 409
    operation_id = first.json()["detail"]["current"]["operation_id"]
    path = f"/api/v1/development/projects/{project['project_id']}/imports/{operation_id}"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=viewer_headers).json()["import_operation"]["status"] == "CONFLICT"
    discard_body = {
        "expected_workspace_revision": 2,
        "reason": "reject incoming archive",
        "idempotency_key": "retained-api-discard",
    }
    assert client.post(f"{path}/discard", headers=admin, json=discard_body).status_code == 403
    assert client.post(f"{path}/discard", headers=other_operator, json=discard_body).status_code == 403
    discarded = client.post(f"{path}/discard", headers=operator, json=discard_body)
    assert discarded.status_code == 200, discarded.text
    assert discarded.json()["import_operation"]["status"] == "DISCARDED"
    replay = client.post(f"{path}/discard", headers=operator, json=discard_body)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    conflict = client.post(
        f"{path}/discard",
        headers=operator,
        json={**discard_body, "reason": "different request"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "IDEMPOTENCY_CONFLICT"

    closed_retry = upload("retained-api-upload-discard")
    assert closed_retry.status_code == 409
    assert closed_retry.json()["detail"]["code"] == "IMPORT_OPERATION_CLOSED"
    assert client.get(path, headers=viewer_headers).json()["import_operation"]["status"] == "DISCARDED"

    second = upload("retained-api-upload-apply")
    assert second.status_code == 409
    second_id = second.json()["detail"]["current"]["operation_id"]
    second_path = (
        f"/api/v1/development/projects/{project['project_id']}/imports/{second_id}"
    )
    service.delete_resource(
        project["project_id"],
        resource["resource_id"],
        **OPERATOR,
        expected_workspace_revision=2,
        idempotency_key="retained-api-delete",
    )
    apply_body = {
        "expected_workspace_revision": 3,
        "idempotency_key": "retained-api-apply",
    }
    assert client.post(f"{second_path}/apply", headers=admin, json=apply_body).status_code == 403
    assert client.post(f"{second_path}/apply", headers=other_operator, json=apply_body).status_code == 403
    applied = client.post(f"{second_path}/apply", headers=operator, json=apply_body)
    assert applied.status_code == 200, applied.text
    assert applied.json()["source_operation_id"] == second_id
    replay = client.post(f"{second_path}/apply", headers=operator, json=apply_body)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True


def test_deeply_nested_json_is_bounded_validation_error(
    client: TestClient, operator_headers: dict[str, str]
) -> None:
    deeply_nested = "[" * 1200 + "0" + "]" * 1200
    response = client.post(
        "/api/v1/development/projects",
        content=deeply_nested,
        headers={**operator_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "json_invalid"
