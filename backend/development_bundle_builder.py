"""Deterministic request/result contract for isolated v0.9 bundle builders."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Mapping, Protocol

from .development_bundle_provenance import (
    BUILDER_IDENTITY,
    toolchain_descriptor,
    toolchain_digest,
)
from .development_domain import (
    DevelopmentCorruptionError,
    DevelopmentError,
    canonical_json_bytes,
    require_digest,
    require_identifier,
    require_revision,
)


REQUEST_SCHEMA = "spell.bundle-build-request/1"
MAX_BUILD_REQUEST_BYTES = 96 * 1024 * 1024


@dataclass(frozen=True)
class BundleBuildResult:
    bundle_bytes: bytes
    manifest_without_digest: dict[str, Any]
    procedure_ids: tuple[str, ...]
    toolchain_descriptor: dict[str, Any]
    toolchain_digest: str


class BundleBuilder(Protocol):
    def build(self, request: Mapping[str, Any]) -> BundleBuildResult: ...


def canonical_request_bytes(request: Mapping[str, Any]) -> bytes:
    raw = canonical_json_bytes(dict(request))
    if len(raw) > MAX_BUILD_REQUEST_BYTES:
        raise DevelopmentError("bundle build request exceeds its byte limit")
    return raw


def make_build_request(
    *,
    history_revision_id: str,
    project_id: str,
    tree_digest: str,
    snapshot_bytes: bytes,
    workspace_revision: int,
    created_at_database_time: str,
    validation_summary_digest: str,
    review_subject: str,
) -> dict[str, Any]:
    return {
        "expected_toolchain_digest": toolchain_digest(),
        "history": {
            "created_at_database_time": created_at_database_time,
            "history_revision_id": history_revision_id,
            "project_id": project_id,
            "snapshot_bytes": base64.b64encode(snapshot_bytes).decode("ascii"),
            "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
            "tree_digest": tree_digest,
            "validation_summary_digest": validation_summary_digest,
            "workspace_revision": workspace_revision,
        },
        "review": {"reviewer_subject": review_subject},
        "schema_version": REQUEST_SCHEMA,
    }


def build_request_payload(request: Mapping[str, Any]) -> BundleBuildResult:
    if type(request) is not dict or set(request) != {
        "expected_toolchain_digest",
        "history",
        "review",
        "schema_version",
    }:
        raise DevelopmentError("bundle build request fields differ")
    if request["schema_version"] != REQUEST_SCHEMA:
        raise DevelopmentError("bundle build request version differs")
    expected_toolchain = require_digest(
        request["expected_toolchain_digest"], "expected_toolchain_digest"
    )
    actual_descriptor = toolchain_descriptor()
    actual_toolchain = hashlib.sha256(canonical_json_bytes(actual_descriptor)).hexdigest()
    if expected_toolchain != actual_toolchain:
        raise DevelopmentCorruptionError("builder toolchain digest differs")
    history_value = request["history"]
    if type(history_value) is not dict or set(history_value) != {
        "created_at_database_time",
        "history_revision_id",
        "project_id",
        "snapshot_bytes",
        "snapshot_sha256",
        "tree_digest",
        "validation_summary_digest",
        "workspace_revision",
    }:
        raise DevelopmentError("bundle build history fields differ")
    try:
        snapshot = base64.b64decode(history_value["snapshot_bytes"], validate=True)
    except (TypeError, ValueError) as exc:
        raise DevelopmentError("bundle build snapshot bytes are invalid") from exc
    if len(snapshot) > MAX_BUILD_REQUEST_BYTES:
        raise DevelopmentError("bundle build snapshot exceeds its byte limit")
    if hashlib.sha256(snapshot).hexdigest() != require_digest(
        history_value["snapshot_sha256"], "snapshot_sha256"
    ):
        raise DevelopmentCorruptionError("bundle build snapshot digest differs")
    created = history_value["created_at_database_time"]
    if type(created) is not str or not created.endswith("Z"):
        raise DevelopmentError("bundle build database time is invalid")
    try:
        created_time = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DevelopmentError("bundle build database time is invalid") from exc
    review_value = request["review"]
    if type(review_value) is not dict or set(review_value) != {"reviewer_subject"}:
        raise DevelopmentError("bundle build review fields differ")
    reviewer_subject = review_value["reviewer_subject"]
    if type(reviewer_subject) is not str or not reviewer_subject or len(
        reviewer_subject.encode("utf-8")
    ) > 200:
        raise DevelopmentError("bundle build reviewer subject is invalid")
    history = SimpleNamespace(
        history_revision_id=require_identifier(
            history_value["history_revision_id"], "history_revision_id"
        ),
        project_id=require_identifier(history_value["project_id"], "project_id"),
        tree_digest=require_digest(history_value["tree_digest"], "tree_digest"),
        snapshot_bytes=snapshot,
        workspace_revision=require_revision(
            history_value["workspace_revision"], "workspace_revision"
        ),
        created_at_database_time=created_time,
        validation_summary_digest=require_digest(
            history_value["validation_summary_digest"],
            "validation_summary_digest",
        ),
    )
    review = SimpleNamespace(reviewer_subject=reviewer_subject)

    # Delayed import avoids a module cycle. The isolated worker executes the exact
    # production parser/compiler path without acquiring a database or network handle.
    from .development_service import DevelopmentService

    raw, manifest, procedure_ids = DevelopmentService._bundle_payload(history, review)
    if manifest.get("builder_identity") != BUILDER_IDENTITY:
        raise DevelopmentCorruptionError("bundle builder identity differs")
    if manifest.get("toolchain_digest") != actual_toolchain:
        raise DevelopmentCorruptionError("bundle toolchain manifest differs")
    return BundleBuildResult(
        bundle_bytes=raw,
        manifest_without_digest=manifest,
        procedure_ids=tuple(procedure_ids),
        toolchain_descriptor=actual_descriptor,
        toolchain_digest=actual_toolchain,
    )


class InProcessDualBundleBuilder:
    """Explicit test adapter; production app configuration never selects this."""

    def build(self, request: Mapping[str, Any]) -> BundleBuildResult:
        first = build_request_payload(dict(request))
        second = build_request_payload(dict(request))
        if first != second:
            raise DevelopmentCorruptionError("independent test bundle builds differ")
        return first


__all__ = [
    "BundleBuildResult",
    "BundleBuilder",
    "InProcessDualBundleBuilder",
    "MAX_BUILD_REQUEST_BYTES",
    "REQUEST_SCHEMA",
    "build_request_payload",
    "canonical_request_bytes",
    "make_build_request",
]
