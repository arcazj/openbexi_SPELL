"""Authenticated REST boundary for the bounded v0.9 development environment."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import unicodedata
from typing import Annotated, Any, Callable

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from .development_domain import (
    DevelopmentAuthorizationError,
    DevelopmentConflictError,
    DevelopmentCorruptionError,
    DevelopmentError,
    DevelopmentLimitError,
    DevelopmentNotFoundError,
)
from .development_schemas import (
    BundleApprove,
    BundleBuild,
    CancelRequest,
    CatalogDecision,
    CheckCreate,
    ConflictDismiss,
    ConflictResolve,
    ExternalChanges,
    HistoryCommit,
    HistorySelectedCommit,
    HistoryReview,
    HistoryRevert,
    ImportDiscard,
    ManifestUpdate,
    PresenceUpdate,
    ProjectCreate,
    ProjectExport,
    ResourceCopy,
    ResourceCreate,
    ResourceUpdate,
    RefreshBase,
    RevisionMutation,
)
from .development_service import DevelopmentService, MAX_ARCHIVE_BYTES


def _identity(caller: Any) -> dict[str, str]:
    return {"subject": caller.actor, "role": caller.role}


def _status(exc: DevelopmentError) -> int:
    if isinstance(exc, DevelopmentAuthorizationError):
        return 403
    if isinstance(exc, DevelopmentNotFoundError):
        return 404
    if isinstance(exc, DevelopmentConflictError):
        return 409
    if isinstance(exc, DevelopmentCorruptionError):
        return 500
    if isinstance(exc, DevelopmentLimitError):
        return 413
    return 422


def _raise(exc: DevelopmentError) -> None:
    raise HTTPException(
        status_code=_status(exc),
        detail={
            "code": exc.code,
            "message": str(exc)[:512],
            "current": getattr(exc, "current", None),
        },
    ) from exc


def _call(handler: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return handler(*args, **kwargs)
    except DevelopmentError as exc:
        _raise(exc)


def install_development_api(
    app: Any,
    *,
    service: DevelopmentService,
    identity_dependency: Callable[..., Any],
) -> None:
    router = APIRouter(prefix="/api/v1/development", tags=["development"])

    @router.get("/projects")
    def list_projects(caller: Any = Depends(identity_dependency)):
        return _call(service.list_projects, **_identity(caller))

    @router.post("/projects")
    def create_project(body: ProjectCreate, caller: Any = Depends(identity_dependency)):
        return _call(service.create_project, **_identity(caller), **body.model_dump())

    @router.get("/projects/{project_id}/workspace")
    def workspace(project_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.workspace_snapshot, project_id, **_identity(caller))

    @router.get("/projects/{project_id}/properties")
    def properties(project_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.project_properties, project_id, **_identity(caller))

    @router.post("/projects/{project_id}/open")
    def open_project(
        project_id: str,
        body: RevisionMutation,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.set_project_open,
            project_id,
            **_identity(caller),
            opened=True,
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/close")
    def close_project(
        project_id: str,
        body: RevisionMutation,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.set_project_open,
            project_id,
            **_identity(caller),
            opened=False,
            **body.model_dump(),
        )

    @router.put("/projects/{project_id}/manifest")
    def update_manifest(
        project_id: str,
        body: ManifestUpdate,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.update_manifest,
            project_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.get("/projects/{project_id}/resources/{resource_id}")
    def get_resource(
        project_id: str,
        resource_id: str,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(service.get_resource, project_id, resource_id, **_identity(caller))

    @router.post("/projects/{project_id}/resources")
    def create_resource(
        project_id: str,
        body: ResourceCreate,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.create_resource, project_id, **_identity(caller), **body.model_dump()
        )

    @router.put("/projects/{project_id}/resources/{resource_id}")
    def update_resource(
        project_id: str,
        resource_id: str,
        body: ResourceUpdate,
        caller: Any = Depends(identity_dependency),
    ):
        values = body.model_dump()
        expected = values.pop("expected_workspace_revision")
        key = values.pop("idempotency_key")
        changes = {name: value for name, value in values.items() if value is not None}
        return _call(
            service.update_resource,
            project_id,
            resource_id,
            **_identity(caller),
            changes=changes,
            expected_workspace_revision=expected,
            idempotency_key=key,
        )

    @router.delete("/projects/{project_id}/resources/{resource_id}")
    def delete_resource(
        project_id: str,
        resource_id: str,
        body: RevisionMutation,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.delete_resource,
            project_id,
            resource_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/resources/{resource_id}/copy")
    def copy_resource(
        project_id: str,
        resource_id: str,
        body: ResourceCopy,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.copy_resource,
            project_id,
            resource_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.put("/projects/{project_id}/presence")
    def update_presence(
        project_id: str,
        body: PresenceUpdate,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.update_presence, project_id, **_identity(caller), **body.model_dump()
        )

    @router.post("/projects/{project_id}/checks")
    def create_check(
        project_id: str,
        body: CheckCreate,
        background: BackgroundTasks,
        caller: Any = Depends(identity_dependency),
    ):
        result = _call(
            service.create_check, project_id, **_identity(caller), **body.model_dump()
        )
        background.add_task(service.run_check, result["job"]["job_id"])
        return result

    @router.get("/checks/{job_id}")
    def get_check(job_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.get_check, job_id, **_identity(caller))

    @router.get("/checks/{job_id}/report")
    def download_check_report(job_id: str, caller: Any = Depends(identity_dependency)):
        raw, digest = _call(
            service.download_check_report,
            job_id,
            **_identity(caller),
        )
        return Response(
            raw,
            media_type="application/json",
            headers={"Content-SHA256": digest},
        )

    @router.post("/checks/{job_id}/cancel")
    def cancel_check(
        job_id: str,
        body: CancelRequest,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.cancel_check, job_id, **_identity(caller), **body.model_dump()
        )

    @router.post("/projects/{project_id}/problems/clean")
    def clean_problems(
        project_id: str,
        body: RevisionMutation,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.clean_problems, project_id, **_identity(caller), **body.model_dump()
        )

    @router.get("/projects/{project_id}/history")
    def list_history(project_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.list_history, project_id, **_identity(caller))

    @router.get("/projects/{project_id}/status")
    def workspace_status(project_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.workspace_status, project_id, **_identity(caller))

    @router.get("/projects/{project_id}/diff")
    def diff_workspace_to_base(
        project_id: str, caller: Any = Depends(identity_dependency)
    ):
        return _call(service.diff_workspace_to_base, project_id, **_identity(caller))

    @router.post("/projects/{project_id}/history")
    def commit_history(
        project_id: str,
        body: HistoryCommit,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.commit_history, project_id, **_identity(caller), **body.model_dump()
        )

    @router.post("/projects/{project_id}/history/commit-selected")
    def commit_selected_history(
        project_id: str,
        body: HistorySelectedCommit,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.commit_history,
            project_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/history/refresh-base")
    def refresh_base(
        project_id: str,
        body: RefreshBase,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.refresh_base,
            project_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.get("/history/{history_revision_id}")
    def get_history(history_revision_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.get_history, history_revision_id, **_identity(caller))

    @router.get("/history/{history_revision_id}/diff")
    def diff_history(
        history_revision_id: str,
        against_revision_id: str = Query(..., min_length=1, max_length=128),
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.diff_history,
            history_revision_id,
            **_identity(caller),
            against_revision_id=against_revision_id,
        )

    @router.post("/history/{history_revision_id}/review")
    def review_history(
        history_revision_id: str,
        body: HistoryReview,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.review_history,
            history_revision_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/history/{history_revision_id}/revert")
    def revert_history(
        history_revision_id: str,
        body: HistoryRevert,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.revert_history,
            history_revision_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/conflicts/resolve")
    def resolve_conflict(
        project_id: str,
        body: ConflictResolve,
        caller: Any = Depends(identity_dependency),
    ):
        values = body.model_dump()
        if values["resolution"] != "MERGED":
            values["resolved_content"] = None
        return _call(
            service.resolve_conflict, project_id, **_identity(caller), **values
        )

    @router.post("/projects/{project_id}/conflicts/{conflict_id}/dismiss")
    def dismiss_conflict(
        project_id: str,
        conflict_id: str,
        body: ConflictDismiss,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.dismiss_conflict,
            project_id,
            conflict_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/imports")
    async def import_project(
        project_id: str,
        request: Request,
        content_sha256: Annotated[
            str, Header(alias="Content-SHA256", pattern=r"^[0-9a-f]{64}$")
        ],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=200)
        ],
        original_filename_base64url: Annotated[
            str,
            Header(
                alias="X-Spell-Filename-Base64url",
                min_length=1,
                max_length=683,
                pattern=r"^[A-Za-z0-9_-]+$",
            ),
        ],
        expected_workspace_revision: Annotated[
            int, Header(alias="X-Spell-Workspace-Revision", ge=0)
        ],
        caller: Any = Depends(identity_dependency),
    ):
        try:
            encoded_filename = original_filename_base64url.encode("ascii")
            padding = b"=" * ((4 - len(encoded_filename) % 4) % 4)
            filename_bytes = base64.b64decode(
                encoded_filename + padding, altchars=b"-_", validate=True
            )
            original_filename = filename_bytes.decode("utf-8")
        except (UnicodeError, ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "REJECTED", "message": "filename header is invalid", "current": None},
            ) from exc
        if (
            not filename_bytes
            or len(filename_bytes) > 512
            or base64.urlsafe_b64encode(filename_bytes).rstrip(b"=") != encoded_filename
            or original_filename != unicodedata.normalize("NFC", original_filename)
            or original_filename in {".", ".."}
            or "\x00" in original_filename
            or "/" in original_filename
            or "\\" in original_filename
        ):
            raise HTTPException(
                status_code=422,
                detail={"code": "REJECTED", "message": "filename header is not canonical", "current": None},
            )
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/vnd.openbexi.spell.project+zip":
            raise HTTPException(
                status_code=415,
                detail={"code": "REJECTED", "message": "project archive media type is required", "current": None},
            )
        if request.headers.get("content-encoding"):
            raise HTTPException(
                status_code=415,
                detail={"code": "REJECTED", "message": "encoded import bodies are not allowed", "current": None},
            )
        declared_length = request.headers.get("content-length")
        if declared_length is not None:
            try:
                declared = int(declared_length)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "REJECTED", "message": "Content-Length is invalid", "current": None},
                ) from exc
            if declared < 0 or declared > MAX_ARCHIVE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail={"code": "LIMIT_EXCEEDED", "message": "archive is too large", "current": None},
                )
        stream = io.BytesIO()
        length = 0
        digest = hashlib.sha256()
        async for chunk in request.stream():
            length += len(chunk)
            if length > MAX_ARCHIVE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail={"code": "LIMIT_EXCEEDED", "message": "archive is too large", "current": None},
                )
            digest.update(chunk)
            stream.write(chunk)
        if digest.hexdigest() != content_sha256:
            raise HTTPException(
                status_code=422,
                detail={"code": "REJECTED", "message": "archive SHA-256 differs", "current": None},
            )
        archive = stream.getvalue()
        return await run_in_threadpool(
            _call,
            service.import_project,
            project_id,
            **_identity(caller),
            original_filename=original_filename,
            original_media_type="application/vnd.openbexi.spell.project+zip",
            archive_bytes=archive,
            archive_sha256=content_sha256,
            expected_workspace_revision=expected_workspace_revision,
            idempotency_key=idempotency_key,
        )

    @router.get("/projects/{project_id}/imports/{operation_id}")
    def get_import_operation(
        project_id: str,
        operation_id: str,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.get_import_operation,
            project_id,
            operation_id,
            **_identity(caller),
        )

    @router.post("/projects/{project_id}/imports/{operation_id}/apply")
    def apply_import_operation(
        project_id: str,
        operation_id: str,
        body: RevisionMutation,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.apply_import_operation,
            project_id,
            operation_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/imports/{operation_id}/discard")
    def discard_import_operation(
        project_id: str,
        operation_id: str,
        body: ImportDiscard,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.discard_import_operation,
            project_id,
            operation_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/projects/{project_id}/exports")
    def export_project(
        project_id: str,
        body: ProjectExport,
        caller: Any = Depends(identity_dependency),
    ):
        raw, digest = _call(
            service.export_project, project_id, **_identity(caller), **body.model_dump()
        )
        return Response(
            raw,
            media_type="application/vnd.openbexi.spell.project+zip",
            headers={"Content-SHA256": digest},
        )

    @router.post("/projects/{project_id}/external-changes")
    def external_changes(
        project_id: str,
        body: ExternalChanges,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.apply_external_changes,
            project_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.post("/history/{history_revision_id}/bundles")
    def build_bundle(
        history_revision_id: str,
        body: BundleBuild,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.build_bundle,
            history_revision_id,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.get("/bundles/{bundle_digest}")
    def get_bundle(bundle_digest: str, caller: Any = Depends(identity_dependency)):
        return _call(service.get_bundle, bundle_digest, **_identity(caller))

    @router.get("/bundles/{bundle_digest}/download")
    def download_bundle(bundle_digest: str, caller: Any = Depends(identity_dependency)):
        result = _call(
            service.get_bundle,
            bundle_digest,
            **_identity(caller),
            include_bytes=True,
        )
        return Response(
            result["bundle_bytes"],
            media_type="application/vnd.openbexi.spell.bundle+json",
            headers={"Content-SHA256": bundle_digest},
        )

    @router.post("/bundles/{bundle_digest}/approve")
    def approve_bundle(
        bundle_digest: str,
        body: BundleApprove,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.approve_bundle,
            bundle_digest,
            **_identity(caller),
            **body.model_dump(),
        )

    @router.get("/catalog/{procedure_id}")
    def get_catalog(procedure_id: str, caller: Any = Depends(identity_dependency)):
        return _call(service.get_catalog_entry, procedure_id, **_identity(caller))

    @router.post("/catalog/{procedure_id}/decisions")
    def catalog_decision(
        procedure_id: str,
        body: CatalogDecision,
        caller: Any = Depends(identity_dependency),
    ):
        return _call(
            service.catalog_decision,
            procedure_id,
            **_identity(caller),
            **body.model_dump(),
        )

    app.include_router(router)


__all__ = ["install_development_api"]
