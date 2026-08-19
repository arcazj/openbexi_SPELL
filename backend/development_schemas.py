"""Strict request contracts for the bounded v0.9 development API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class StrictDevelopmentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IdempotentRequest(StrictDevelopmentModel):
    idempotency_key: StrictStr = Field(min_length=1, max_length=200)


class RevisionMutation(IdempotentRequest):
    expected_workspace_revision: StrictInt = Field(ge=0)


class ProjectCreate(IdempotentRequest):
    name: StrictStr = Field(min_length=1, max_length=256)
    case_policy: Literal["CASE_SENSITIVE", "CASE_INSENSITIVE"]
    manifest: dict[str, Any] | None = None


class ResourceCreate(RevisionMutation):
    path: StrictStr = Field(min_length=1, max_length=512)
    kind: Literal[
        "SOURCE_FOLDER", "FOLDER", "PROCEDURE", "LIBRARY", "DICTIONARY", "PROJECT_METADATA"
    ]
    media_type: StrictStr = Field(min_length=1, max_length=160)
    content: StrictStr
    content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class ResourceUpdate(RevisionMutation):
    path: StrictStr | None = Field(default=None, min_length=1, max_length=512)
    kind: Literal[
        "SOURCE_FOLDER", "FOLDER", "PROCEDURE", "LIBRARY", "DICTIONARY", "PROJECT_METADATA"
    ] | None = None
    media_type: StrictStr | None = Field(default=None, min_length=1, max_length=160)
    content: StrictStr | None = None
    content_sha256: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ResourceCopy(RevisionMutation):
    destination_path: StrictStr = Field(min_length=1, max_length=512)


class ManifestUpdate(RevisionMutation):
    manifest: dict[str, Any]


class PresenceUpdate(RevisionMutation):
    resource_id: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    client_instance_id: StrictStr = Field(min_length=1, max_length=128)
    status: Literal["ACTIVE", "IDLE", "EDITING", "VIEWING", "OFFLINE"]


class CheckCreate(RevisionMutation):
    scope: Literal["FILE", "FOLDER", "PROJECT", "CHANGED_SET"]
    scope_path: StrictStr | None = Field(default=None, min_length=1, max_length=512)
    reparse_libraries: StrictBool = False


class CancelRequest(IdempotentRequest):
    pass


class HistoryCommit(RevisionMutation):
    message: StrictStr = Field(min_length=1, max_length=4096)
    selected_resource_ids: list[StrictStr] | None = Field(default=None, max_length=10_000)


class HistorySelectedCommit(RevisionMutation):
    message: StrictStr = Field(min_length=1, max_length=4096)
    selected_resource_ids: list[StrictStr] = Field(min_length=1, max_length=10_000)


class RefreshBase(RevisionMutation):
    history_revision_id: StrictStr = Field(min_length=1, max_length=128)


class HistoryReview(IdempotentRequest):
    decision: Literal["APPROVE"]
    reason: StrictStr = Field(min_length=1, max_length=4096)
    expected_review_revision: StrictInt = Field(ge=0)


class HistoryRevert(RevisionMutation):
    reason: StrictStr = Field(min_length=1, max_length=4096)


class ConflictResolve(RevisionMutation):
    path: StrictStr = Field(min_length=1, max_length=512)
    resolution: Literal["OURS", "THEIRS", "MERGED", "DELETE"]
    resolved_content: StrictStr | None = None
    expected_conflict_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class ConflictDismiss(RevisionMutation):
    expected_conflict_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    reason: StrictStr = Field(min_length=1, max_length=4096)


class ProjectImportHeaders(RevisionMutation):
    original_filename_base64url: StrictStr = Field(
        min_length=1, max_length=683, pattern=r"^[A-Za-z0-9_-]+$"
    )
    archive_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class ImportDiscard(RevisionMutation):
    reason: StrictStr = Field(min_length=1, max_length=4096)


class ProjectExport(StrictDevelopmentModel):
    expected_workspace_revision: StrictInt = Field(ge=0)


class ExternalChanges(IdempotentRequest):
    base_workspace_revision: StrictInt = Field(ge=0)
    base_history_revision_id: StrictStr | None = Field(
        default=None, min_length=1, max_length=128
    )
    changes: list[dict[str, Any]] = Field(max_length=10_000)
    resolution: Literal["RELOAD", "KEEP_AS_NEW_CHANGE", "THREE_WAY_MERGE"]


class BundleBuild(IdempotentRequest):
    pass


class BundleApprove(IdempotentRequest):
    expected_state_revision: StrictInt = Field(ge=0)
    reason: StrictStr = Field(min_length=1, max_length=4096)


class CatalogDecision(IdempotentRequest):
    operation: Literal["PROMOTE", "SUPERSEDE", "WITHDRAW", "ROLLBACK_PROMOTE"]
    bundle_digest: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    expected_registry_revision: StrictInt = Field(ge=0)
    reason: StrictStr = Field(min_length=1, max_length=4096)


# Kept next to the request types so backend tests and the generated OpenAPI document
# can assert that the browser client contract has not drifted.
DEVELOPMENT_API_CONTRACT = {
    "GET /api/v1/development/projects": None,
    "POST /api/v1/development/projects": ProjectCreate,
    "GET /api/v1/development/projects/{project_id}/workspace": None,
    "GET /api/v1/development/projects/{project_id}/properties": None,
    "POST /api/v1/development/projects/{project_id}/open": RevisionMutation,
    "POST /api/v1/development/projects/{project_id}/close": RevisionMutation,
    "PUT /api/v1/development/projects/{project_id}/manifest": ManifestUpdate,
    "GET /api/v1/development/projects/{project_id}/resources/{resource_id}": None,
    "POST /api/v1/development/projects/{project_id}/resources": ResourceCreate,
    "PUT /api/v1/development/projects/{project_id}/resources/{resource_id}": ResourceUpdate,
    "DELETE /api/v1/development/projects/{project_id}/resources/{resource_id}": RevisionMutation,
    "POST /api/v1/development/projects/{project_id}/resources/{resource_id}/copy": ResourceCopy,
    "PUT /api/v1/development/projects/{project_id}/presence": PresenceUpdate,
    "POST /api/v1/development/projects/{project_id}/checks": CheckCreate,
    "GET /api/v1/development/checks/{job_id}": None,
    "GET /api/v1/development/checks/{job_id}/report": None,
    "POST /api/v1/development/checks/{job_id}/cancel": CancelRequest,
    "POST /api/v1/development/projects/{project_id}/problems/clean": RevisionMutation,
    "GET /api/v1/development/projects/{project_id}/history": None,
    "GET /api/v1/development/projects/{project_id}/status": None,
    "GET /api/v1/development/projects/{project_id}/diff": None,
    "POST /api/v1/development/projects/{project_id}/history": HistoryCommit,
    "POST /api/v1/development/projects/{project_id}/history/commit-selected": HistorySelectedCommit,
    "POST /api/v1/development/projects/{project_id}/history/refresh-base": RefreshBase,
    "GET /api/v1/development/history/{history_revision_id}": None,
    "GET /api/v1/development/history/{history_revision_id}/diff": None,
    "POST /api/v1/development/history/{history_revision_id}/review": HistoryReview,
    "POST /api/v1/development/history/{history_revision_id}/revert": HistoryRevert,
    "POST /api/v1/development/projects/{project_id}/conflicts/resolve": ConflictResolve,
    "POST /api/v1/development/projects/{project_id}/conflicts/{conflict_id}/dismiss": ConflictDismiss,
    "POST /api/v1/development/projects/{project_id}/imports": ProjectImportHeaders,
    "GET /api/v1/development/projects/{project_id}/imports/{operation_id}": None,
    "POST /api/v1/development/projects/{project_id}/imports/{operation_id}/apply": RevisionMutation,
    "POST /api/v1/development/projects/{project_id}/imports/{operation_id}/discard": ImportDiscard,
    "POST /api/v1/development/projects/{project_id}/exports": ProjectExport,
    "POST /api/v1/development/projects/{project_id}/external-changes": ExternalChanges,
    "POST /api/v1/development/history/{history_revision_id}/bundles": BundleBuild,
    "GET /api/v1/development/bundles/{bundle_digest}": None,
    "GET /api/v1/development/bundles/{bundle_digest}/download": None,
    "POST /api/v1/development/bundles/{bundle_digest}/approve": BundleApprove,
    "GET /api/v1/development/catalog/{procedure_id}": None,
    "POST /api/v1/development/catalog/{procedure_id}/decisions": CatalogDecision,
}


__all__ = [
    name
    for name in globals()
    if name[0].isupper() and name not in {"Any", "BaseModel", "ConfigDict", "Field"}
] + ["DEVELOPMENT_API_CONTRACT"]
