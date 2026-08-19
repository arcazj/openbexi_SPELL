"""Transactional service for bounded v0.9 project authoring and promotion."""

from __future__ import annotations

import base64
import difflib
import hashlib
import io
import json
import stat
import time
import uuid
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .database import begin_mutation_write, session_scope, utc_now
from .development_bundle_builder import BundleBuilder, make_build_request
from .development_bundle_provenance import BUILDER_IDENTITY, toolchain_digest
from .development_analysis import (
    AnalysisResult,
    LANGUAGE_PROFILE,
    TOOL_VERSION,
    analyze_library_source,
    analyze_resources,
    analyze_source,
)
from .development_domain import (
    CHECK_SCOPES,
    MAX_PROJECT_BYTES,
    MAX_RESOURCE_BYTES,
    MAX_RESOURCES,
    PROMOTION_OPERATIONS,
    RESOURCE_KINDS,
    Actor,
    DevelopmentAuthorizationError,
    DevelopmentConflictError,
    DevelopmentCorruptionError,
    DevelopmentError,
    DevelopmentLimitError,
    DevelopmentNotFoundError,
    canonical_json_bytes,
    canonical_request_digest,
    canonical_tree,
    normalize_path,
    path_identity,
    require_actor,
    require_admin,
    require_case_policy,
    require_digest,
    require_idempotency_key,
    require_identifier,
    require_mutation_actor,
    require_revision,
    require_text,
    sha256_bytes,
    strict_json_bytes,
)
from .development_models import (
    DevelopmentAnalysisJob,
    DevelopmentAuditEvent,
    DevelopmentBundle,
    DevelopmentCatalogEntry,
    DevelopmentConflict,
    DevelopmentDictionaryArtifact,
    DevelopmentHistoryReview,
    DevelopmentHistoryRevision,
    DevelopmentIdempotency,
    DevelopmentImportProvenance,
    DevelopmentLibraryCache,
    DevelopmentCatalogSnapshot,
    DevelopmentOutbox,
    DevelopmentPresence,
    DevelopmentProblem,
    DevelopmentProject,
    DevelopmentPromotionDecision,
    DevelopmentResource,
    DevelopmentRuntimePin,
)
from .procedure_parser import (
    IR_VERSION,
    MAX_SOURCE_BYTES,
    V06_IR_VERSION,
    V07_IR_VERSION,
    V08_IR_VERSION,
    Procedure,
    ProcedureCatalog,
)
from .dictionary_exchange import (
    DB_MEDIA_TYPE,
    IMP_MEDIA_TYPE,
    DictionaryExchangeError,
    export_dictionary_document,
    parse_dictionary_document,
)


PROJECT_SCHEMA_VERSION = "spell.project/0.9"
BUNDLE_SCHEMA_VERSION = "spell.bundle/1"
COMPATIBILITY_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
CATALOG_MEDIA_TYPE = "application/vnd.openbexi.spell.catalog-snapshot+json"
MAX_ARCHIVE_BYTES = 67_108_864
MAX_ARCHIVE_ENTRIES = 10_000
MAX_COMPRESSION_RATIO = 100
MAX_CATALOG_ENTRIES = 100_000
MAX_BUNDLE_ENTRIES = 20_000
MAX_BUNDLE_CATALOG_SNAPSHOTS = 128
MAX_MANIFEST_BYTES = 262_144
MAX_IMPORT_SECONDS = 30.0
MAX_IMPORT_PROVENANCE_PER_PROJECT = 128
MAX_PROJECTS_PER_SUBJECT = 32
MAX_OPEN_WORKSPACES_PER_SUBJECT = 8
MAX_PROMOTION_CATALOG_ENTRIES = 10_000
MAX_PROMOTION_DECISIONS_PER_ENTRY = 100_000
MAX_STORED_MUTATION_RESPONSE_BYTES = 1_048_576
MAX_DURABLE_RECORDS_PER_SCOPE = 100_000
SUPPORTED_BUNDLE_IR_SCHEMA_VERSIONS = frozenset(
    {IR_VERSION, V06_IR_VERSION, V07_IR_VERSION, V08_IR_VERSION}
)
_MISSING = object()


def _id() -> str:
    return str(uuid.uuid4())


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _project_diagnostic(
    *,
    workspace_revision: int,
    source_digest: str,
    code: str,
    message: str,
) -> dict[str, Any]:
    identity = canonical_json_bytes(
        {
            "code": code,
            "source_digest": source_digest,
            "source_path": "spell-project.yaml",
            "span": [1, 1, 1, 1],
            "tool_version": TOOL_VERSION,
            "workspace_revision": workspace_revision,
        }
    )
    return {
        "diagnostic_id": sha256_bytes(identity),
        "code": code,
        "severity": "ERROR",
        "source_path": "spell-project.yaml",
        "start_line": 1,
        "start_column": 1,
        "end_line": 1,
        "end_column": 1,
        "language_profile": LANGUAGE_PROFILE,
        "message": message[:2000],
        "remediation_ref": f"spell://diagnostics/{code}",
        "tool_version": TOOL_VERSION,
    }


def _resource_diagnostic(
    *,
    workspace_revision: int,
    source_digest: str,
    source_path: str,
    code: str,
    message: str,
) -> dict[str, Any]:
    item = _project_diagnostic(
        workspace_revision=workspace_revision,
        source_digest=source_digest,
        code=code,
        message=message,
    )
    item["source_path"] = source_path
    item["diagnostic_id"] = sha256_bytes(
        canonical_json_bytes(
            {
                "code": code,
                "source_digest": source_digest,
                "source_path": source_path,
                "span": [1, 1, 1, 1],
                "tool_version": TOOL_VERSION,
                "workspace_revision": workspace_revision,
            }
        )
    )
    return item


def _content(value: Any) -> bytes:
    if type(value) is not str:
        raise DevelopmentError("content must be UTF-8 text")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DevelopmentError("content must be UTF-8 text") from exc
    if len(raw) > MAX_RESOURCE_BYTES:
        raise DevelopmentLimitError("resource content exceeds its byte limit")
    if "\x00" in value:
        raise DevelopmentError("resource content contains a NUL character")
    return raw


def _descendant_pattern(path: str) -> str:
    escaped = path.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped + "/%"


def _strict_json_document(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise DevelopmentError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DevelopmentError(f"{label} contains a non-finite number")
            ),
        )
    except DevelopmentError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise DevelopmentError(f"{label} is not strict UTF-8 JSON") from exc


def _tree_integrity_issues(
    entries: Iterable[Mapping[str, Any]], *, case_policy: str
) -> list[tuple[str, str]]:
    rows = list(entries)
    by_identity: dict[str, Mapping[str, Any]] = {}
    issues: list[tuple[str, str]] = []
    for row in rows:
        path = row.get("path")
        kind = row.get("kind")
        content = row.get("content")
        try:
            normalized = normalize_path(path)
            identity = path_identity(normalized, case_policy)
        except DevelopmentError as exc:
            issues.append(("PATH_INVALID", str(exc)))
            continue
        if normalized != path:
            issues.append(("PATH_NOT_CANONICAL", f"resource path {path!r} is not canonical"))
        if identity in by_identity:
            issues.append(("CASE_CONFLICT", f"resource path {path!r} collides"))
        else:
            by_identity[identity] = row
        if kind not in RESOURCE_KINDS:
            issues.append(("RESOURCE_KIND_INVALID", f"resource {path!r} has an invalid kind"))
        if kind in {"SOURCE_FOLDER", "FOLDER"} and content != b"" and content != "":
            issues.append(("FOLDER_CONTENT_INVALID", f"folder {path!r} contains bytes"))

    manifest_row = by_identity.get(path_identity("spell-project.yaml", case_policy))
    manifest: Any = None
    if manifest_row is None or manifest_row.get("path") != "spell-project.yaml":
        issues.append(("MANIFEST_MISSING", "project manifest resource is missing"))
    elif manifest_row.get("kind") != "PROJECT":
        issues.append(("MANIFEST_KIND_INVALID", "project manifest resource kind is invalid"))
    else:
        raw_manifest = manifest_row.get("content")
        if type(raw_manifest) is str:
            raw_manifest = raw_manifest.encode("utf-8")
        if type(raw_manifest) is not bytes:
            issues.append(("MANIFEST_INVALID", "project manifest bytes are invalid"))
        else:
            try:
                manifest = _strict_json_document(raw_manifest, "project manifest")
            except DevelopmentError as exc:
                issues.append(("MANIFEST_INVALID", str(exc)))
    source_roots = manifest.get("source_roots") if type(manifest) is dict else None
    if type(source_roots) is not list:
        issues.append(("MANIFEST_SOURCE_ROOTS_INVALID", "manifest source_roots are invalid"))
        source_roots = []
    for source_root in source_roots:
        try:
            root_path = normalize_path(source_root, allow_manifest=False)
            root = by_identity.get(path_identity(root_path, case_policy))
        except DevelopmentError as exc:
            issues.append(("MANIFEST_SOURCE_ROOT_INVALID", str(exc)))
            continue
        if root is None:
            issues.append(
                ("MANIFEST_SOURCE_ROOT_MISSING", f"source root {root_path!r} is missing")
            )
        elif root.get("kind") not in {"SOURCE_FOLDER", "FOLDER"}:
            issues.append(
                (
                    "MANIFEST_SOURCE_ROOT_NOT_FOLDER",
                    f"source root {root_path!r} is not a folder",
                )
            )

    for identity, row in by_identity.items():
        path = str(row.get("path"))
        if path == "spell-project.yaml" or "/" not in path:
            continue
        parent_path = path.rsplit("/", 1)[0]
        parent = by_identity.get(path_identity(parent_path, case_policy))
        if parent is None:
            issues.append(("ORPHAN_RESOURCE", f"resource {path!r} has no parent folder"))
        elif parent.get("kind") not in {"SOURCE_FOLDER", "FOLDER"}:
            issues.append(
                (
                    "RESOURCE_BELOW_FILE",
                    f"resource {path!r} is below non-folder {parent_path!r}",
                )
            )
    return sorted(set(issues))


def _require_tree_integrity(
    entries: Iterable[Mapping[str, Any]], *, case_policy: str
) -> None:
    issues = _tree_integrity_issues(entries, case_policy=case_policy)
    if issues:
        code, message = issues[0]
        raise DevelopmentConflictError(message, code=code)


def _validate_resource_document(
    *,
    kind: str,
    media_type: str,
    raw: bytes,
) -> dict[str, Any]:
    if kind in {"PROCEDURE", "LIBRARY"}:
        if media_type != "text/x-python":
            raise DevelopmentError(f"{kind.casefold()} media type is unsupported")
        if len(raw) > MAX_SOURCE_BYTES:
            raise DevelopmentLimitError(
                f"{kind.casefold()} source exceeds the {MAX_SOURCE_BYTES}-byte limit"
            )
    if kind == "DICTIONARY":
        if media_type not in {DB_MEDIA_TYPE, IMP_MEDIA_TYPE}:
            raise DevelopmentError("dictionary media type is unsupported")
        try:
            document = parse_dictionary_document(raw, media_type=media_type)
            canonical = export_dictionary_document(document)
        except DictionaryExchangeError as exc:
            raise DevelopmentError(
                f"dictionary document is invalid: {exc.code}"
            ) from exc
        return {
            "dictionary": {
                "dictionary_id": document.dictionary_id,
                "source_format": document.format.value,
                "base_revision": int(document.base_revision),
                "original_bytes": raw,
                "original_bytes_sha256": sha256_bytes(raw),
                "canonical_bytes": canonical,
                "canonical_bytes_sha256": sha256_bytes(canonical),
                "canonical_state": document.as_payload(),
            }
        }
    if media_type == CATALOG_MEDIA_TYPE:
        if kind != "PROJECT_METADATA":
            raise DevelopmentError("catalog snapshots must be project metadata")
        value = _strict_json_document(raw, "catalog snapshot")
        expected_fields = {
            "schema_version",
            "catalog_id",
            "catalog_revision",
            "catalog_kind",
            "entries",
            "dependencies",
            "content_digest",
        }
        if type(value) is not dict or set(value) != expected_fields:
            raise DevelopmentError("catalog snapshot fields differ")
        if value["schema_version"] != "spell.catalog.snapshot/1":
            raise DevelopmentError("catalog snapshot version is unsupported")
        catalog_id = require_identifier(value["catalog_id"], "catalog_id")
        catalog_revision = require_revision(value["catalog_revision"], "catalog_revision")
        if catalog_revision < 1:
            raise DevelopmentError("catalog_revision must be positive")
        if value["catalog_kind"] not in {"TM", "TC", "RESOURCE", "SCDB", "GDB", "PROC", "MMD"}:
            raise DevelopmentError("catalog kind is invalid")
        entries = value["entries"]
        if type(entries) is not list:
            raise DevelopmentError("catalog entries are invalid")
        if len(entries) > MAX_CATALOG_ENTRIES:
            raise DevelopmentLimitError("catalog entries exceed their limit")
        identities: set[str] = set()
        names: set[str] = set()
        canonical_entries = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {"entry_id", "qualified_name", "data"}:
                raise DevelopmentError("catalog entry fields differ")
            entry_id = require_identifier(entry["entry_id"], "entry_id")
            qualified_name = require_text(entry["qualified_name"], "qualified_name", 256)
            if entry_id.casefold() in identities or qualified_name.casefold() in names:
                raise DevelopmentConflictError("catalog entry has a case collision", code="CASE_CONFLICT")
            identities.add(entry_id.casefold())
            names.add(qualified_name.casefold())
            if type(entry["data"]) is not dict:
                raise DevelopmentError("catalog entry data must be an object")
            data_bytes = canonical_json_bytes(entry["data"])
            if len(data_bytes) > MAX_MANIFEST_BYTES:
                raise DevelopmentLimitError("catalog entry data exceeds its byte limit")
            canonical_entries.append(
                {"entry_id": entry_id, "qualified_name": qualified_name, "data": entry["data"]}
            )
        dependencies = value["dependencies"]
        if type(dependencies) is not list or len(dependencies) > 128:
            raise DevelopmentError("catalog dependencies are invalid")
        canonical_dependencies: list[dict[str, Any]] = []
        dependency_keys: set[tuple[str, int]] = set()
        for dependency in dependencies:
            if type(dependency) is not dict or set(dependency) != {
                "catalog_id",
                "catalog_revision",
                "content_digest",
            }:
                raise DevelopmentError("catalog dependency fields differ")
            dependency_id = require_identifier(dependency["catalog_id"], "catalog_id")
            dependency_revision = require_revision(
                dependency["catalog_revision"], "catalog_revision"
            )
            if dependency_revision < 1:
                raise DevelopmentError("catalog_revision must be positive")
            dependency_digest = require_digest(
                dependency["content_digest"], "content_digest"
            )
            dependency_key = (dependency_id.casefold(), dependency_revision)
            if dependency_key in dependency_keys:
                raise DevelopmentConflictError(
                    "catalog dependencies collide", code="CASE_CONFLICT"
                )
            dependency_keys.add(dependency_key)
            canonical_dependencies.append(
                {
                    "catalog_id": dependency_id,
                    "catalog_revision": dependency_revision,
                    "content_digest": dependency_digest,
                }
            )
        unsigned = {
            "schema_version": value["schema_version"],
            "catalog_id": catalog_id,
            "catalog_revision": catalog_revision,
            "catalog_kind": value["catalog_kind"],
            "entries": canonical_entries,
            "dependencies": sorted(
                canonical_dependencies,
                key=lambda item: (
                    item["catalog_id"].casefold(),
                    item["catalog_revision"],
                ),
            ),
        }
        digest = require_digest(value["content_digest"], "content_digest")
        if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
            raise DevelopmentError("catalog snapshot digest differs")
        return {
            "catalog": {
                **unsigned,
                "content_digest": digest,
                "canonical_snapshot": canonical_json_bytes({**unsigned, "content_digest": digest}),
            }
        }
    return {}


def _project_dict(row: DevelopmentProject) -> dict[str, Any]:
    return {
        "project_id": row.project_id,
        "workspace_id": row.workspace_id,
        "display_name": row.display_name,
        "owner_subject": row.owner_subject,
        "author_subject": row.author_subject,
        "case_policy": row.case_policy,
        "workspace_revision": int(row.workspace_revision),
        "base_history_revision_id": row.base_history_revision_id,
        "base_bundle_digest": row.base_bundle_digest,
        "manifest": row.manifest,
        "closed": bool(row.closed),
        "created_at": _iso(row.created_at_database_time),
        "updated_at": _iso(row.updated_at_database_time),
    }


def _resource_dict(
    row: DevelopmentResource,
    *,
    include_content: bool = True,
) -> dict[str, Any]:
    result = {
        "resource_id": row.resource_id,
        "project_id": row.project_id,
        "path": row.path,
        "kind": row.kind,
        "media_type": row.media_type,
        "content_sha256": row.content_sha256,
        "byte_length": int(row.byte_length),
        "revision": int(row.revision),
        "created_by_subject": row.created_by_subject,
        "updated_by_subject": row.updated_by_subject,
        "created_at": _iso(row.created_at_database_time),
        "updated_at": _iso(row.updated_at_database_time),
    }
    if include_content:
        try:
            result["content"] = row.content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DevelopmentCorruptionError("stored resource is not UTF-8") from exc
    return result


def _job_dict(row: DevelopmentAnalysisJob, *, include_report: bool = True) -> dict[str, Any]:
    result = {
        "job_id": row.job_id,
        "project_id": row.project_id,
        "workspace_revision": int(row.workspace_revision),
        "scope": row.scope,
        "scope_path": row.scope_path,
        "reparse_libraries": bool(row.reparse_libraries),
        "state": row.state,
        "progress": int(row.progress),
        "tool_version": row.tool_version,
        "input_digest": row.input_digest,
        "report_sha256": row.report_sha256,
        "failure_code": row.failure_code,
        "created_at": _iso(row.created_at_database_time),
        "started_at": _iso(row.started_at_database_time),
        "completed_at": _iso(row.completed_at_database_time),
    }
    if include_report and row.report is not None:
        result["report"] = strict_json_bytes(row.report, "analysis report")
    return result


def _problem_dict(row: DevelopmentProblem) -> dict[str, Any]:
    return {
        "problem_id": row.problem_id,
        "diagnostic_id": row.diagnostic_id,
        "job_id": row.job_id,
        "project_id": row.project_id,
        "workspace_revision": int(row.workspace_revision),
        "source_path": row.source_path,
        "start_line": int(row.start_line),
        "start_column": int(row.start_column),
        "end_line": int(row.end_line),
        "end_column": int(row.end_column),
        "severity": row.severity,
        "code": row.code,
        "message": row.message,
        "remediation_ref": row.remediation_ref,
        "tool_version": row.tool_version,
        "language_profile": row.language_profile,
    }


def _history_dict(row: DevelopmentHistoryRevision) -> dict[str, Any]:
    return {
        "history_revision_id": row.history_revision_id,
        "project_id": row.project_id,
        "ordinal": int(row.ordinal),
        "parent_revision_ids": list(row.parent_revision_ids),
        "tree_digest": row.tree_digest,
        "author_subject": row.author_subject,
        "message": row.message,
        "validation_job_id": row.validation_job_id,
        "validation_summary_digest": row.validation_summary_digest,
        "workspace_revision": int(row.workspace_revision),
        "created_at": _iso(row.created_at_database_time),
    }


def _review_dict(row: DevelopmentHistoryReview | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "review_id": row.review_id,
        "history_revision_id": row.history_revision_id,
        "review_revision": int(row.review_revision),
        "reviewer_subject": row.reviewer_subject,
        "decision": row.decision,
        "reason": row.reason,
        "created_at": _iso(row.created_at_database_time),
    }


def _bundle_dict(row: DevelopmentBundle) -> dict[str, Any]:
    return {
        "bundle_digest": row.bundle_digest,
        "project_id": row.project_id,
        "history_revision_id": row.history_revision_id,
        "byte_length": int(row.byte_length),
        "manifest": row.manifest,
        "source_tree_digest": row.source_tree_digest,
        "validation_report_digest": row.validation_report_digest,
        "author_subject": row.author_subject,
        "review_subject": row.review_subject,
        "builder_identity": row.builder_identity,
        "state": row.state,
        "state_revision": int(row.state_revision),
        "approved_by_subject": row.approved_by_subject,
        "approval_reason": row.approval_reason,
        "created_at": _iso(row.created_at_database_time),
        "updated_at": _iso(row.updated_at_database_time),
    }


def _catalog_dict(row: DevelopmentCatalogEntry) -> dict[str, Any]:
    return {
        "procedure_id": row.procedure_id,
        "registry_revision": int(row.registry_revision),
        "current_bundle_digest": row.current_bundle_digest,
        "previous_bundle_digest": row.previous_bundle_digest,
        "state": row.state,
        "updated_by_subject": row.updated_by_subject,
        "created_at": _iso(row.created_at_database_time),
        "updated_at": _iso(row.updated_at_database_time),
    }


class DevelopmentService:
    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        reserved_procedure_ids: Iterable[str] = (),
        bundle_builder: BundleBuilder | None = None,
    ):
        self.factory = factory
        self.bundle_builder = bundle_builder
        self.reserved_procedure_ids = frozenset(
            item.casefold() for item in reserved_procedure_ids
        )

    @staticmethod
    def _actor(subject: Any, role: Any, *, admin: bool = False, mutation: bool = False) -> Actor:
        if admin:
            return require_admin(subject, role)
        if mutation:
            return require_mutation_actor(subject, role)
        return require_actor(subject, role)

    @staticmethod
    def _project(session: Session, project_id: Any) -> DevelopmentProject:
        identifier = require_identifier(project_id, "project_id")
        row = session.get(DevelopmentProject, identifier)
        if row is None:
            raise DevelopmentNotFoundError("project was not found")
        return row

    @staticmethod
    def _author(
        project: DevelopmentProject,
        actor: Actor,
        *,
        allow_closed: bool = False,
    ) -> None:
        if actor.role != "operator" or project.author_subject != actor.subject:
            raise DevelopmentAuthorizationError(
                "only the operator author may mutate this workspace"
            )
        if project.closed and not allow_closed:
            raise DevelopmentConflictError(
                "project workspace is closed",
                code="PROJECT_CLOSED",
                current={"workspace_revision": int(project.workspace_revision)},
            )

    @staticmethod
    def _lock_subject_limit(session: Session, subject: str) -> None:
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            lock_key = int.from_bytes(
                hashlib.sha256(subject.encode("utf-8")).digest()[:8],
                "big",
                signed=True,
            )
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})

    @staticmethod
    def _translate_transaction_error(exc: Exception) -> DevelopmentConflictError | None:
        if not isinstance(exc, (DBAPIError, IntegrityError, OperationalError)):
            return None
        original = getattr(exc, "orig", exc)
        sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
        message = str(original).casefold()
        if sqlstate in {"40001", "40P01", "55P03"} or any(
            token in message
            for token in (
                "database is locked",
                "database is busy",
                "could not serialize",
                "deadlock detected",
                "lock not available",
            )
        ):
            return DevelopmentConflictError(
                "transaction could not be completed; retry with the same idempotency key",
                code="RETRYABLE_TRANSACTION_CONFLICT",
            )
        if isinstance(exc, IntegrityError):
            return DevelopmentConflictError(
                "concurrent mutation conflicts with current state",
                code="CONCURRENT_MUTATION_CONFLICT",
            )
        return None

    @staticmethod
    def _check_revision(project: DevelopmentProject, expected: Any) -> int:
        expected_revision = require_revision(expected)
        if int(project.workspace_revision) != expected_revision:
            raise DevelopmentConflictError(
                "workspace revision differs",
                code="WORKSPACE_REVISION_CONFLICT",
                current={"workspace_revision": int(project.workspace_revision)},
            )
        return expected_revision

    def _mutate(
        self,
        actor: Actor,
        *,
        scope: str,
        idempotency_key: Any,
        request: Mapping[str, Any],
        apply: Callable[[Session, str], dict[str, Any]],
    ) -> dict[str, Any]:
        key = require_idempotency_key(idempotency_key)
        request_sha256 = canonical_request_digest(request)
        try:
            with session_scope(self.factory) as session:
                begin_mutation_write(session)
                existing = session.scalar(
                    select(DevelopmentIdempotency).where(
                        DevelopmentIdempotency.actor_subject == actor.subject,
                        DevelopmentIdempotency.operation_scope == scope,
                        DevelopmentIdempotency.idempotency_key == key,
                    )
                )
                if existing is not None:
                    if existing.request_sha256 != request_sha256:
                        raise DevelopmentConflictError(
                            "idempotency key was used for another request",
                            code="IDEMPOTENCY_CONFLICT",
                        )
                    return {**existing.response, "replayed": True}
                record_count = session.scalar(
                    select(func.count()).select_from(DevelopmentIdempotency).where(
                        DevelopmentIdempotency.actor_subject == actor.subject,
                        DevelopmentIdempotency.operation_scope == scope,
                    )
                )
                if int(record_count or 0) >= MAX_DURABLE_RECORDS_PER_SCOPE:
                    raise DevelopmentLimitError("idempotency record limit is reached")
                correlation_id = _id()
                response = apply(session, correlation_id)
                stored = {**response, "replayed": False}
                if len(canonical_json_bytes(stored)) > MAX_STORED_MUTATION_RESPONSE_BYTES:
                    raise DevelopmentLimitError("mutation response exceeds its durable bound")
                session.add(
                    DevelopmentIdempotency(
                        record_id=_id(),
                        actor_subject=actor.subject,
                        operation_scope=scope,
                        idempotency_key=key,
                        request_sha256=request_sha256,
                        response=stored,
                    )
                )
                return stored
        except DevelopmentError:
            raise
        except Exception as exc:
            translated = self._translate_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise

    @staticmethod
    def _audit(
        session: Session,
        actor: Actor,
        *,
        project_id: str | None,
        action: str,
        correlation_id: str,
        idempotency_key: str,
        previous_revision: int | None,
        new_revision: int | None,
        payload: Mapping[str, Any],
        outbox_topic: str | None = None,
        aggregate_id: str | None = None,
    ) -> str:
        audit_id = _id()
        session.add(
            DevelopmentAuditEvent(
                audit_id=audit_id,
                project_id=project_id,
                actor_subject=actor.subject,
                actor_role=actor.role,
                action=action,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
                previous_revision=previous_revision,
                new_revision=new_revision,
                payload=dict(payload),
            )
        )
        if outbox_topic is not None:
            session.add(
                DevelopmentOutbox(
                    event_id=_id(),
                    topic=outbox_topic,
                    aggregate_id=aggregate_id or project_id or correlation_id,
                    aggregate_revision=int(new_revision or 0),
                    payload={
                        **dict(payload),
                        "actor_subject": actor.subject,
                        "correlation_id": correlation_id,
                    },
                    published=False,
                )
            )
        return audit_id

    @staticmethod
    def _replace_resource_projection(
        session: Session,
        resource: DevelopmentResource,
        projection: Mapping[str, Any],
    ) -> None:
        session.execute(
            delete(DevelopmentDictionaryArtifact).where(
                DevelopmentDictionaryArtifact.resource_id == resource.resource_id
            )
        )
        session.execute(
            delete(DevelopmentCatalogSnapshot).where(
                DevelopmentCatalogSnapshot.resource_id == resource.resource_id
            )
        )
        dictionary = projection.get("dictionary")
        if dictionary is not None:
            session.add(
                DevelopmentDictionaryArtifact(
                    resource_id=resource.resource_id,
                    project_id=resource.project_id,
                    dictionary_id=dictionary["dictionary_id"],
                    source_format=dictionary["source_format"],
                    base_revision=dictionary["base_revision"],
                    original_bytes=dictionary["original_bytes"],
                    original_bytes_sha256=dictionary["original_bytes_sha256"],
                    canonical_bytes=dictionary["canonical_bytes"],
                    canonical_bytes_sha256=dictionary["canonical_bytes_sha256"],
                    canonical_state=dictionary["canonical_state"],
                )
            )
        catalog = projection.get("catalog")
        if catalog is not None:
            session.add(
                DevelopmentCatalogSnapshot(
                    snapshot_id=_id(),
                    resource_id=resource.resource_id,
                    project_id=resource.project_id,
                    catalog_id=catalog["catalog_id"],
                    catalog_revision=catalog["catalog_revision"],
                    catalog_kind=catalog["catalog_kind"],
                    content_digest=catalog["content_digest"],
                    canonical_snapshot=catalog["canonical_snapshot"],
                    entries=catalog["entries"],
                    dependencies=catalog["dependencies"],
                )
            )

    @staticmethod
    def _manifest(
        value: Any,
        *,
        project_id: str,
        display_name: str,
        case_policy: str,
        owner: str,
    ) -> dict[str, Any]:
        supplied = {} if value is None else value
        if type(supplied) is not dict:
            raise DevelopmentError("manifest must be an object")
        allowed = {
            "schema_version",
            "project_id",
            "display_name",
            "language_profile",
            "source_roots",
            "case_policy",
            "catalog_dependencies",
            "owners",
            "policy_labels",
        }
        if set(supplied).difference(allowed):
            raise DevelopmentError("manifest contains unknown fields")
        manifest = {
            "schema_version": supplied.get("schema_version", PROJECT_SCHEMA_VERSION),
            "project_id": supplied.get("project_id", project_id),
            "display_name": supplied.get("display_name", display_name),
            "language_profile": supplied.get("language_profile", "spell-restricted-ast/0.9"),
            "source_roots": supplied.get("source_roots", ["procedures"]),
            "case_policy": supplied.get("case_policy", case_policy),
            "catalog_dependencies": supplied.get("catalog_dependencies", []),
            "owners": supplied.get("owners", [owner]),
            "policy_labels": supplied.get("policy_labels", ["LOCAL_SYNTHETIC_NON_CUI_ONLY"]),
        }
        if manifest["schema_version"] != PROJECT_SCHEMA_VERSION:
            raise DevelopmentError("manifest schema_version is unsupported")
        manifest["project_id"] = require_identifier(manifest["project_id"], "project_id")
        manifest["display_name"] = require_text(
            manifest["display_name"], "display_name", 256
        )
        if manifest["project_id"] != project_id or manifest["display_name"] != display_name:
            raise DevelopmentError("manifest project identity differs")
        if manifest["case_policy"] != case_policy:
            raise DevelopmentError("manifest case policy differs")
        if manifest["language_profile"] != "spell-restricted-ast/0.9":
            raise DevelopmentError("manifest language profile is unsupported")
        roots = manifest["source_roots"]
        if type(roots) is not list or not roots or len(roots) > 32:
            raise DevelopmentError("manifest source_roots are invalid")
        manifest["source_roots"] = [normalize_path(item) for item in roots]
        root_identities = [
            path_identity(item, case_policy) for item in manifest["source_roots"]
        ]
        if len(root_identities) != len(set(root_identities)):
            raise DevelopmentConflictError(
                "manifest source roots collide under the case policy",
                code="CASE_CONFLICT",
            )
        dependencies = manifest["catalog_dependencies"]
        if type(dependencies) is not list or len(dependencies) > 128:
            raise DevelopmentError("manifest catalog_dependencies is invalid")
        normalized_dependencies: list[dict[str, Any]] = []
        dependency_identities: set[str] = set()
        for dependency in dependencies:
            if type(dependency) is not dict or set(dependency) != {
                "catalog_id",
                "catalog_revision",
                "content_digest",
            }:
                raise DevelopmentError("catalog dependency fields differ")
            catalog_id = require_identifier(dependency["catalog_id"], "catalog_id")
            catalog_revision = require_revision(
                dependency["catalog_revision"], "catalog_revision"
            )
            if catalog_revision < 1:
                raise DevelopmentError("catalog_revision must be positive")
            content_digest = require_digest(
                dependency["content_digest"], "content_digest"
            )
            identity = catalog_id.casefold()
            if identity in dependency_identities:
                raise DevelopmentConflictError(
                    "manifest catalog dependencies collide",
                    code="CASE_CONFLICT",
                )
            dependency_identities.add(identity)
            normalized_dependencies.append(
                {
                    "catalog_id": catalog_id,
                    "catalog_revision": catalog_revision,
                    "content_digest": content_digest,
                }
            )
        manifest["catalog_dependencies"] = sorted(
            normalized_dependencies,
            key=lambda item: (item["catalog_id"].casefold(), item["catalog_id"]),
        )
        owners = manifest["owners"]
        if type(owners) is not list or not owners or len(owners) > 32:
            raise DevelopmentError("manifest owners is invalid")
        manifest["owners"] = [require_text(item, "owner", 200) for item in owners]
        if len({item.casefold() for item in manifest["owners"]}) != len(manifest["owners"]):
            raise DevelopmentConflictError("manifest owners collide", code="CASE_CONFLICT")
        if owner not in manifest["owners"]:
            raise DevelopmentError("manifest must include the project owner")
        labels = manifest["policy_labels"]
        if type(labels) is not list or not labels or len(labels) > 32:
            raise DevelopmentError("manifest policy_labels is invalid")
        manifest["policy_labels"] = [
            require_identifier(item, "policy_label") for item in labels
        ]
        if len(set(manifest["policy_labels"])) != len(manifest["policy_labels"]):
            raise DevelopmentError("manifest policy_labels contain duplicates")
        if "LOCAL_SYNTHETIC_NON_CUI_ONLY" not in manifest["policy_labels"]:
            raise DevelopmentError("manifest lacks the required local-synthetic policy label")
        manifest_bytes = canonical_json_bytes(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise DevelopmentLimitError("manifest exceeds its byte limit")
        return manifest

    def create_project(
        self,
        *,
        subject: Any,
        role: Any,
        name: Any,
        case_policy: Any,
        manifest: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        if actor.role != "operator":
            raise DevelopmentAuthorizationError("operator role is required to author a project")
        display_name = require_text(name, "name", 256)
        policy = require_case_policy(case_policy)
        normalized_name = display_name.casefold()
        project_id = "dev-" + hashlib.sha256(
            canonical_json_bytes({"name": normalized_name, "owner": actor.subject})
        ).hexdigest()[:24]
        request = {"name": display_name, "case_policy": policy, "manifest": manifest}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            self._lock_subject_limit(session, actor.subject)
            project_count = session.scalar(
                select(func.count()).select_from(DevelopmentProject).where(
                    DevelopmentProject.owner_subject == actor.subject
                )
            )
            open_count = session.scalar(
                select(func.count()).select_from(DevelopmentProject).where(
                    DevelopmentProject.owner_subject == actor.subject,
                    DevelopmentProject.closed == False,  # noqa: E712
                )
            )
            if int(project_count) >= MAX_PROJECTS_PER_SUBJECT:
                raise DevelopmentConflictError(
                    "project count limit is reached", code="PROJECT_LIMIT_REACHED"
                )
            if int(open_count) >= MAX_OPEN_WORKSPACES_PER_SUBJECT:
                raise DevelopmentConflictError(
                    "open workspace limit is reached", code="OPEN_WORKSPACE_LIMIT_REACHED"
                )
            if session.scalar(
                select(DevelopmentProject).where(
                    DevelopmentProject.owner_subject == actor.subject,
                    DevelopmentProject.normalized_name == normalized_name,
                )
            ) is not None:
                raise DevelopmentConflictError("project name already exists")
            bounded_manifest = self._manifest(
                manifest,
                project_id=project_id,
                display_name=display_name,
                case_policy=policy,
                owner=actor.subject,
            )
            project = DevelopmentProject(
                project_id=project_id,
                workspace_id=_id(),
                display_name=display_name,
                normalized_name=normalized_name,
                owner_subject=actor.subject,
                author_subject=actor.subject,
                case_policy=policy,
                workspace_revision=1,
                base_history_revision_id=None,
                base_bundle_digest=None,
                manifest=bounded_manifest,
                closed=False,
            )
            session.add(project)
            manifest_bytes = canonical_json_bytes(bounded_manifest)
            session.add(
                DevelopmentResource(
                    resource_id=_id(),
                    project_id=project_id,
                    path="spell-project.yaml",
                    path_identity=path_identity("spell-project.yaml", policy),
                    kind="PROJECT",
                    media_type="application/yaml",
                    content=manifest_bytes,
                    content_sha256=sha256_bytes(manifest_bytes),
                    byte_length=len(manifest_bytes),
                    revision=1,
                    created_by_subject=actor.subject,
                    updated_by_subject=actor.subject,
                )
            )
            folder_paths: dict[str, tuple[str, str]] = {}
            root_identities = {
                path_identity(source_root, policy)
                for source_root in bounded_manifest["source_roots"]
            }
            for source_root in bounded_manifest["source_roots"]:
                parts = source_root.split("/")
                for depth in range(1, len(parts) + 1):
                    folder_path = "/".join(parts[:depth])
                    identity = path_identity(folder_path, policy)
                    folder_paths[identity] = (
                        folder_path,
                        "SOURCE_FOLDER" if identity in root_identities else "FOLDER",
                    )
            for folder_path, folder_kind in sorted(
                folder_paths.values(), key=lambda item: item[0].encode("utf-8")
            ):
                session.add(
                    DevelopmentResource(
                        resource_id=_id(),
                        project_id=project_id,
                        path=folder_path,
                        path_identity=path_identity(folder_path, policy),
                        kind=folder_kind,
                    media_type="application/x-directory",
                    content=b"",
                    content_sha256=sha256_bytes(b""),
                    byte_length=0,
                    revision=1,
                    created_by_subject=actor.subject,
                    updated_by_subject=actor.subject,
                    )
                )
            session.flush()
            self._require_project_tree(
                project, self._resource_rows(session, project_id)
            )
            self._audit(
                session,
                actor,
                project_id=project_id,
                action="CREATE_PROJECT",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=0,
                new_revision=1,
                payload={"project_id": project_id},
                outbox_topic="development.workspace.changed",
                aggregate_id=project_id,
            )
            session.flush()
            return {"project": _project_dict(project)}

        return self._mutate(
            actor,
            scope=f"project:create:{normalized_name}",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def list_projects(self, *, subject: Any, role: Any) -> dict[str, Any]:
        self._actor(subject, role)
        with self.factory() as session:
            rows = session.scalars(
                select(DevelopmentProject).order_by(
                    DevelopmentProject.normalized_name,
                    DevelopmentProject.project_id,
                )
            ).all()
            return {"items": [_project_dict(row) for row in rows]}

    def project_properties(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        with self.factory() as session:
            project = self._project(session, identifier)
            grouped = session.execute(
                select(
                    DevelopmentResource.kind,
                    func.count(),
                    func.coalesce(func.sum(DevelopmentResource.byte_length), 0),
                )
                .where(DevelopmentResource.project_id == identifier)
                .group_by(DevelopmentResource.kind)
            ).all()
            return {
                "project": _project_dict(project),
                "resource_counts": {
                    str(kind): int(count) for kind, count, _ in sorted(grouped)
                },
                "byte_length": sum(int(size) for _, _, size in grouped),
            }

    def update_manifest(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        manifest: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        expected = require_revision(expected_workspace_revision)
        request = {
            "manifest": manifest,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            bounded = self._manifest(
                manifest,
                project_id=project.project_id,
                display_name=project.display_name,
                case_policy=project.case_policy,
                owner=project.owner_subject,
            )
            resources = self._resource_rows(session, identifier)
            identities = {
                row.path_identity
                for row in resources
                if row.kind in {"SOURCE_FOLDER", "FOLDER"}
            }
            missing_roots = [
                root
                for root in bounded["source_roots"]
                if path_identity(root, project.case_policy) not in identities
            ]
            if missing_roots:
                raise DevelopmentConflictError(
                    "manifest source roots must be existing folders",
                    code="DEPENDENCY_MISSING",
                    current={"paths": missing_roots},
                )
            row = next(item for item in resources if item.path == "spell-project.yaml")
            raw = canonical_json_bytes(bounded)
            row.content = raw
            row.content_sha256 = sha256_bytes(raw)
            row.byte_length = len(raw)
            row.revision += 1
            row.updated_by_subject = actor.subject
            row.updated_at_database_time = utc_now()
            project.manifest = bounded
            self._require_project_tree(project, resources)
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="UPDATE_PROJECT_MANIFEST",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={"content_sha256": row.content_sha256},
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project), "resource": _resource_dict(row)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:manifest:update",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def set_project_open(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        opened: bool,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        expected = require_revision(expected_workspace_revision)
        request = {
            "opened": opened,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor, allow_closed=True)
            self._check_revision(project, expected)
            self._lock_subject_limit(session, actor.subject)
            target_closed = not opened
            if bool(project.closed) == target_closed:
                raise DevelopmentConflictError(
                    "project lifecycle state already matches the request",
                    code="PROJECT_STATE_CONFLICT",
                    current={"closed": bool(project.closed)},
                )
            if opened:
                open_count = session.scalar(
                    select(func.count()).select_from(DevelopmentProject).where(
                        DevelopmentProject.owner_subject == actor.subject,
                        DevelopmentProject.closed == False,  # noqa: E712
                    )
                )
                if int(open_count or 0) >= MAX_OPEN_WORKSPACES_PER_SUBJECT:
                    raise DevelopmentConflictError(
                        "open workspace limit is reached",
                        code="OPEN_WORKSPACE_LIMIT_REACHED",
                    )
            project.closed = target_closed
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            action = "OPEN_PROJECT" if opened else "CLOSE_PROJECT"
            self._audit(
                session,
                actor,
                project_id=identifier,
                action=action,
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={"closed": target_closed},
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:{'open' if opened else 'close'}",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def copy_resource(
        self,
        project_id: Any,
        resource_id: Any,
        *,
        subject: Any,
        role: Any,
        destination_path: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        source_id = require_identifier(resource_id, "resource_id")
        destination = normalize_path(destination_path, allow_manifest=False)
        expected = require_revision(expected_workspace_revision)
        request = {
            "destination_path": destination,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            source = session.get(DevelopmentResource, source_id)
            if source is None or source.project_id != identifier:
                raise DevelopmentNotFoundError("resource was not found")
            if source.path == "spell-project.yaml":
                raise DevelopmentAuthorizationError("project manifest cannot be copied")
            if source.kind in {"SOURCE_FOLDER", "FOLDER"} and session.scalar(
                select(DevelopmentResource.resource_id).where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.path.like(
                        _descendant_pattern(source.path), escape="\\"
                    ),
                )
            ) is not None:
                raise DevelopmentConflictError(
                    "copy of a non-empty folder is not supported",
                    code="RESOURCE_HAS_CHILDREN",
                )
            destination_identity = path_identity(destination, project.case_policy)
            collision = session.scalar(
                select(DevelopmentResource.resource_id).where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.path_identity == destination_identity,
                )
            )
            if collision is not None:
                raise DevelopmentConflictError(
                    "resource path already exists", code="CASE_CONFLICT"
                )
            count, total = self._resource_totals(session, identifier)
            if count >= MAX_RESOURCES or total + int(source.byte_length) > MAX_PROJECT_BYTES:
                raise DevelopmentLimitError("project resource limits would be exceeded")
            projection = _validate_resource_document(
                kind=source.kind,
                media_type=source.media_type,
                raw=bytes(source.content),
            )
            row = DevelopmentResource(
                resource_id=_id(),
                project_id=identifier,
                path=destination,
                path_identity=destination_identity,
                kind=source.kind,
                media_type=source.media_type,
                content=bytes(source.content),
                content_sha256=source.content_sha256,
                byte_length=int(source.byte_length),
                revision=1,
                created_by_subject=actor.subject,
                updated_by_subject=actor.subject,
            )
            session.add(row)
            self._replace_resource_projection(session, row, projection)
            session.flush()
            self._require_project_tree(project, self._resource_rows(session, identifier))
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="COPY_RESOURCE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={
                    "source_resource_id": source_id,
                    "resource_id": row.resource_id,
                    "destination_path": destination,
                },
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project), "resource": _resource_dict(row)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:resource:{source_id}:copy",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def get_resource(
        self,
        project_id: Any,
        resource_id: Any,
        *,
        subject: Any,
        role: Any,
        include_language: bool = True,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        project_identifier = require_identifier(project_id, "project_id")
        resource_identifier = require_identifier(resource_id, "resource_id")
        with self.factory() as session:
            project = self._project(session, project_identifier)
            row = session.get(DevelopmentResource, resource_identifier)
            if row is None or row.project_id != project.project_id:
                raise DevelopmentNotFoundError("resource was not found")
            result = _resource_dict(row)
            if include_language and row.kind in {"PROCEDURE", "LIBRARY"}:
                analysis = (
                    analyze_library_source(
                        result["content"],
                        row.path,
                        workspace_revision=int(project.workspace_revision),
                    )
                    if row.kind == "LIBRARY"
                    else analyze_source(
                        result["content"],
                        row.path,
                        workspace_revision=int(project.workspace_revision),
                    )
                )
                result["language"] = {
                    "diagnostics": list(analysis.diagnostics),
                    "outline": list(analysis.outline),
                    "completions": list(analysis.completions),
                }
                compiled = analysis.compiled.get(row.path)
                metadata = analysis.metadata
                if metadata is not None:
                    display_name = metadata.get(
                        "display-name",
                        metadata["procedure"].replace("_", " ").title(),
                    )
                    description = metadata.get("description", "")
                    procedure_id = metadata["procedure"]
                    arguments: dict[str, str] = {}
                    if compiled is not None:
                        display_name = compiled["display_name"]
                        description = compiled["description"]
                        procedure_id = compiled["procedure_id"]
                        steps = list(compiled["steps"])
                        arguments = (
                            dict(steps[0].get("argument_declarations", {}))
                            if steps
                            else {}
                        )
                    result["metadata"] = {
                        "procedure_id": procedure_id,
                        "display_name": display_name,
                        "description": description,
                        "language_profile": LANGUAGE_PROFILE,
                        "arguments": arguments,
                        "catalog_dependencies": list(
                            project.manifest.get("catalog_dependencies", [])
                        ),
                    }
            return {"resource": result}

    def _resource_totals(self, session: Session, project_id: str) -> tuple[int, int]:
        count, size = session.execute(
            select(func.count(), func.coalesce(func.sum(DevelopmentResource.byte_length), 0)).where(
                DevelopmentResource.project_id == project_id
            )
        ).one()
        return int(count), int(size)

    def create_resource(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        path: Any,
        kind: Any,
        media_type: Any,
        content: Any,
        content_sha256: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        bounded_path = normalize_path(path, allow_manifest=False)
        if kind not in RESOURCE_KINDS or kind == "PROJECT":
            raise DevelopmentError("resource kind is invalid")
        bounded_kind = str(kind)
        bounded_media = require_text(media_type, "media_type", 160)
        raw = _content(content)
        if bounded_kind in {"SOURCE_FOLDER", "FOLDER"} and raw:
            raise DevelopmentError("folder resources cannot contain bytes")
        expected_digest = require_digest(content_sha256, "content_sha256")
        if sha256_bytes(raw) != expected_digest:
            raise DevelopmentError("content SHA-256 differs")
        projection = _validate_resource_document(
            kind=bounded_kind,
            media_type=bounded_media,
            raw=raw,
        )
        expected = require_revision(expected_workspace_revision)
        request = {
            "path": bounded_path,
            "kind": bounded_kind,
            "media_type": bounded_media,
            "content_sha256": expected_digest,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            identity = path_identity(bounded_path, project.case_policy)
            if session.scalar(
                select(DevelopmentResource.resource_id).where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.path_identity == identity,
                )
            ) is not None:
                raise DevelopmentConflictError(
                    "resource path already exists", code="CASE_CONFLICT"
                )
            count, total = self._resource_totals(session, identifier)
            if count >= MAX_RESOURCES or total + len(raw) > MAX_PROJECT_BYTES:
                raise DevelopmentLimitError("project resource limits would be exceeded")
            row = DevelopmentResource(
                resource_id=_id(),
                project_id=identifier,
                path=bounded_path,
                path_identity=identity,
                kind=bounded_kind,
                media_type=bounded_media,
                content=raw,
                content_sha256=expected_digest,
                byte_length=len(raw),
                revision=1,
                created_by_subject=actor.subject,
                updated_by_subject=actor.subject,
            )
            session.add(row)
            self._replace_resource_projection(session, row, projection)
            session.flush()
            self._require_project_tree(project, self._resource_rows(session, identifier))
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="CREATE_RESOURCE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={"resource_id": row.resource_id, "path": bounded_path},
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {
                "project": _project_dict(project),
                "resource": _resource_dict(row),
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:resource:create",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def update_resource(
        self,
        project_id: Any,
        resource_id: Any,
        *,
        subject: Any,
        role: Any,
        changes: Mapping[str, Any],
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        resource_identifier = require_identifier(resource_id, "resource_id")
        expected = require_revision(expected_workspace_revision)
        allowed = {"path", "kind", "media_type", "content", "content_sha256"}
        if not changes or set(changes).difference(allowed):
            raise DevelopmentError("resource update fields are invalid")
        request = {
            "changes": dict(changes),
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            row = session.get(DevelopmentResource, resource_identifier)
            if row is None or row.project_id != identifier:
                raise DevelopmentNotFoundError("resource was not found")
            if row.path == "spell-project.yaml":
                raise DevelopmentAuthorizationError(
                    "project manifest updates require the project manifest operation"
                )
            descendants = session.scalars(
                select(DevelopmentResource)
                .where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.path.like(
                        _descendant_pattern(row.path), escape="\\"
                    ),
                )
                .order_by(DevelopmentResource.path)
            ).all()
            new_path = (
                normalize_path(changes["path"], allow_manifest=False)
                if "path" in changes
                else row.path
            )
            new_kind = changes.get("kind", row.kind)
            if new_kind not in RESOURCE_KINDS or new_kind == "PROJECT":
                raise DevelopmentError("resource kind is invalid")
            if descendants and new_kind not in {"SOURCE_FOLDER", "FOLDER"}:
                raise DevelopmentConflictError(
                    "a non-empty folder cannot change resource kind",
                    code="RESOURCE_HAS_CHILDREN",
                )
            new_media = (
                require_text(changes["media_type"], "media_type", 160)
                if "media_type" in changes
                else row.media_type
            )
            new_content = _content(changes["content"]) if "content" in changes else row.content
            if new_kind in {"SOURCE_FOLDER", "FOLDER"} and new_content:
                raise DevelopmentError("folder resources cannot contain bytes")
            new_digest = sha256_bytes(new_content)
            if "content_sha256" in changes:
                if require_digest(changes["content_sha256"], "content_sha256") != new_digest:
                    raise DevelopmentError("content SHA-256 differs")
            elif "content" in changes:
                raise DevelopmentError("content_sha256 is required with content")
            projection = _validate_resource_document(
                kind=str(new_kind),
                media_type=new_media,
                raw=new_content,
            )
            new_identity = path_identity(new_path, project.case_policy)
            old_identity = path_identity(row.path, project.case_policy)
            if new_path != row.path and (
                new_identity.startswith(old_identity + "/")
                or old_identity.startswith(new_identity + "/")
            ):
                raise DevelopmentConflictError(
                    "folder cannot move into itself or one of its descendants",
                    code="PATH_CONFLICT",
                )
            subtree_ids = {resource_identifier, *(item.resource_id for item in descendants)}
            planned_paths = {resource_identifier: new_path}
            for child in descendants:
                planned_paths[child.resource_id] = normalize_path(
                    new_path + child.path[len(row.path) :], allow_manifest=False
                )
            planned_identities = {
                resource_key: path_identity(value, project.case_policy)
                for resource_key, value in planned_paths.items()
            }
            if len(set(planned_identities.values())) != len(planned_identities):
                raise DevelopmentConflictError(
                    "moved subtree collides under the project case policy",
                    code="CASE_CONFLICT",
                )
            outside_rows = session.scalars(
                select(DevelopmentResource).where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.resource_id.not_in(subtree_ids),
                )
            ).all()
            outside_by_identity = {item.path_identity: item for item in outside_rows}
            collision_identity = next(
                (
                    identity
                    for identity in planned_identities.values()
                    if identity in outside_by_identity
                ),
                None,
            )
            if collision_identity is not None:
                collision = outside_by_identity[collision_identity]
                raise DevelopmentConflictError(
                    "resource path collides under the project case policy",
                    code="CASE_CONFLICT",
                    current={"resource_id": collision.resource_id, "path": collision.path},
                )
            _, total = self._resource_totals(session, identifier)
            if total - int(row.byte_length) + len(new_content) > MAX_PROJECT_BYTES:
                raise DevelopmentLimitError("project byte limit would be exceeded")
            old_path = row.path
            case_only_two_phase = (
                new_path != old_path and new_path.casefold() == old_path.casefold()
            )
            if case_only_two_phase:
                for item in [row, *descendants]:
                    temporary_path = normalize_path(
                        f"case-rename-{item.resource_id}", allow_manifest=False
                    )
                    item.path = temporary_path
                    item.path_identity = path_identity(
                        temporary_path, project.case_policy
                    )
                session.flush()
            row.path = new_path
            row.path_identity = new_identity
            row.kind = str(new_kind)
            row.media_type = new_media
            row.content = new_content
            row.content_sha256 = new_digest
            row.byte_length = len(new_content)
            row.revision += 1
            row.updated_by_subject = actor.subject
            row.updated_at_database_time = utc_now()
            for child in descendants:
                child.path = planned_paths[child.resource_id]
                child.path_identity = planned_identities[child.resource_id]
                child.revision += 1
                child.updated_by_subject = actor.subject
                child.updated_at_database_time = utc_now()
            if old_path in project.manifest.get("source_roots", []) and new_path != old_path:
                updated_manifest = {
                    **project.manifest,
                    "source_roots": [
                        new_path if item == old_path else item
                        for item in project.manifest["source_roots"]
                    ],
                }
                project.manifest = self._manifest(
                    updated_manifest,
                    project_id=project.project_id,
                    display_name=project.display_name,
                    case_policy=project.case_policy,
                    owner=project.owner_subject,
                )
                manifest_row = session.scalar(
                    select(DevelopmentResource).where(
                        DevelopmentResource.project_id == identifier,
                        DevelopmentResource.path == "spell-project.yaml",
                    )
                )
                if manifest_row is None:
                    raise DevelopmentCorruptionError("project manifest resource is missing")
                manifest_bytes = canonical_json_bytes(project.manifest)
                manifest_row.content = manifest_bytes
                manifest_row.content_sha256 = sha256_bytes(manifest_bytes)
                manifest_row.byte_length = len(manifest_bytes)
                manifest_row.revision += 1
                manifest_row.updated_by_subject = actor.subject
                manifest_row.updated_at_database_time = utc_now()
            self._replace_resource_projection(session, row, projection)
            self._require_project_tree(project, self._resource_rows(session, identifier))
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="UPDATE_RESOURCE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={
                    "resource_id": resource_identifier,
                    "old_path": old_path,
                    "path": new_path,
                    "content_sha256": new_digest,
                    "descendant_count": len(descendants),
                    "case_only_two_phase": case_only_two_phase,
                },
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project), "resource": _resource_dict(row)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:resource:{resource_identifier}:update",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def delete_resource(
        self,
        project_id: Any,
        resource_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        resource_identifier = require_identifier(resource_id, "resource_id")
        expected = require_revision(expected_workspace_revision)
        request = {"expected_workspace_revision": expected}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            row = session.get(DevelopmentResource, resource_identifier)
            if row is None or row.project_id != identifier:
                raise DevelopmentNotFoundError("resource was not found")
            if row.path == "spell-project.yaml":
                raise DevelopmentAuthorizationError("project manifest cannot be deleted")
            if row.kind in {"SOURCE_FOLDER", "FOLDER"} and session.scalar(
                select(DevelopmentResource.resource_id).where(
                    DevelopmentResource.project_id == identifier,
                    DevelopmentResource.path.like(
                        _descendant_pattern(row.path), escape="\\"
                    ),
                )
            ) is not None:
                raise DevelopmentConflictError(
                    "non-empty folder cannot be deleted",
                    code="RESOURCE_HAS_CHILDREN",
                )
            deleted = _resource_dict(row, include_content=False)
            session.execute(
                delete(DevelopmentDictionaryArtifact).where(
                    DevelopmentDictionaryArtifact.resource_id == resource_identifier
                )
            )
            session.execute(
                delete(DevelopmentCatalogSnapshot).where(
                    DevelopmentCatalogSnapshot.resource_id == resource_identifier
                )
            )
            remaining = [
                item
                for item in self._resource_rows(session, identifier)
                if item.resource_id != resource_identifier
            ]
            self._require_project_tree(project, remaining)
            session.delete(row)
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="DELETE_RESOURCE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload=deleted,
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project), "deleted_resource": deleted}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:resource:{resource_identifier}:delete",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def workspace_snapshot(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        now = utc_now()
        with session_scope(self.factory) as session:
            project = self._project(session, identifier)
            session.execute(
                delete(DevelopmentPresence).where(
                    DevelopmentPresence.project_id == identifier,
                    DevelopmentPresence.expires_at_database_time <= now,
                )
            )
            resources = session.scalars(
                select(DevelopmentResource)
                .where(DevelopmentResource.project_id == identifier)
                .order_by(DevelopmentResource.path, DevelopmentResource.resource_id)
            ).all()
            problems = session.scalars(
                select(DevelopmentProblem)
                .where(
                    DevelopmentProblem.project_id == identifier,
                    DevelopmentProblem.workspace_revision == project.workspace_revision,
                )
                .order_by(
                    DevelopmentProblem.source_path,
                    DevelopmentProblem.start_line,
                    DevelopmentProblem.start_column,
                    DevelopmentProblem.severity,
                    DevelopmentProblem.code,
                    DevelopmentProblem.diagnostic_id,
                )
            ).all()
            jobs = session.scalars(
                select(DevelopmentAnalysisJob)
                .where(DevelopmentAnalysisJob.project_id == identifier)
                .order_by(DevelopmentAnalysisJob.created_at_database_time.desc())
                .limit(100)
            ).all()
            history = session.scalars(
                select(DevelopmentHistoryRevision)
                .where(DevelopmentHistoryRevision.project_id == identifier)
                .order_by(DevelopmentHistoryRevision.ordinal.desc())
                .limit(100)
            ).all()
            reviews = (
                session.scalars(
                    select(DevelopmentHistoryReview).where(
                        DevelopmentHistoryReview.history_revision_id.in_(
                            [item.history_revision_id for item in history]
                        )
                    )
                ).all()
                if history
                else []
            )
            reviews_by_history = {
                item.history_revision_id: item for item in reviews
            }
            bundles = session.scalars(
                select(DevelopmentBundle)
                .where(DevelopmentBundle.project_id == identifier)
                .order_by(DevelopmentBundle.created_at_database_time.desc())
            ).all()
            bundle_digests = {item.bundle_digest for item in bundles}
            catalogs = (
                session.scalars(
                    select(DevelopmentCatalogEntry).where(
                        DevelopmentCatalogEntry.current_bundle_digest.in_(bundle_digests)
                    )
                ).all()
                if bundle_digests
                else []
            )
            presence = session.scalars(
                select(DevelopmentPresence)
                .where(DevelopmentPresence.project_id == identifier)
                .order_by(DevelopmentPresence.subject, DevelopmentPresence.client_instance_id)
            ).all()
            dependency_keys = {
                (
                    item["catalog_id"],
                    int(item["catalog_revision"]),
                    item["content_digest"],
                )
                for item in project.manifest.get("catalog_dependencies", [])
            }
            snapshots = session.scalars(
                select(DevelopmentCatalogSnapshot).where(
                    DevelopmentCatalogSnapshot.project_id == identifier
                )
            ).all()
            pinned_catalog_entries: list[dict[str, Any]] = []
            for snapshot in sorted(
                snapshots,
                key=lambda item: (
                    item.catalog_id.casefold(),
                    int(item.catalog_revision),
                    item.content_digest,
                ),
            ):
                key = (
                    snapshot.catalog_id,
                    int(snapshot.catalog_revision),
                    snapshot.content_digest,
                )
                if key not in dependency_keys:
                    continue
                for entry in snapshot.entries:
                    pinned_catalog_entries.append(
                        {
                            "catalog_id": snapshot.catalog_id,
                            "catalog_revision": int(snapshot.catalog_revision),
                            "content_digest": snapshot.content_digest,
                            "entry_id": entry["entry_id"],
                            "qualified_name": entry["qualified_name"],
                            "catalog_kind": snapshot.catalog_kind,
                            "data": entry["data"],
                        }
                    )
                    if len(pinned_catalog_entries) > 100_000:
                        raise DevelopmentCorruptionError(
                            "pinned catalog projection exceeds its bound"
                        )
            conflicts = session.scalars(
                select(DevelopmentConflict)
                .where(
                    DevelopmentConflict.project_id == identifier,
                    DevelopmentConflict.resolved == False,  # noqa: E712
                )
                .order_by(DevelopmentConflict.path, DevelopmentConflict.conflict_id)
            ).all()
            return {
                "workspace": {
                    "project": _project_dict(project),
                    "workspace_revision": int(project.workspace_revision),
                    "resources": [
                        _resource_dict(row, include_content=False) for row in resources
                    ],
                    "problems": [_problem_dict(row) for row in problems],
                    "jobs": [_job_dict(row, include_report=False) for row in jobs],
                    "history": [
                        {
                            **_history_dict(row),
                            "review": _review_dict(
                                reviews_by_history.get(row.history_revision_id)
                            ),
                            "review_revision": int(
                                reviews_by_history[row.history_revision_id].review_revision
                            )
                            if row.history_revision_id in reviews_by_history
                            else 0,
                        }
                        for row in history
                    ],
                    "bundles": [_bundle_dict(row) for row in bundles],
                    "promotion_catalog_entries": [_catalog_dict(row) for row in catalogs],
                    "pinned_catalog_entries": pinned_catalog_entries,
                    "presence": [
                        {
                            "presence_id": row.presence_id,
                            "project_id": row.project_id,
                            "resource_id": row.resource_id,
                            "subject": row.subject,
                            "client_instance_id": row.client_instance_id,
                            "status": row.status,
                            "updated_at": _iso(row.updated_at_database_time),
                            "expires_at": _iso(row.expires_at_database_time),
                        }
                        for row in presence
                    ],
                    "conflicts": [
                        {
                            "conflict_id": row.conflict_id,
                            "project_id": row.project_id,
                            "path": row.path,
                            "base_path": row.base_path,
                            "kind": row.kind,
                            "conflict_digest": row.conflict_digest,
                            "detected_workspace_revision": int(
                                row.detected_workspace_revision
                            ),
                            "ours_resource_id": row.ours_resource_id,
                            "ours_path": row.ours_path,
                            "base_kind": row.base_kind,
                            "base_media_type": row.base_media_type,
                            "ours_kind": row.ours_kind,
                            "ours_media_type": row.ours_media_type,
                            "theirs_kind": row.theirs_kind,
                            "theirs_media_type": row.theirs_media_type,
                            "base_content_sha256": (
                                sha256_bytes(row.base_content)
                                if row.base_content is not None
                                else None
                            ),
                            "ours_content_sha256": (
                                sha256_bytes(row.ours_content)
                                if row.ours_content is not None
                                else None
                            ),
                            "theirs_content_sha256": (
                                sha256_bytes(row.theirs_content)
                                if row.theirs_content is not None
                                else None
                            ),
                            "created_at": _iso(row.created_at_database_time),
                        }
                        for row in conflicts
                    ],
                }
            }

    def update_presence(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        resource_id: Any,
        client_instance_id: Any,
        status: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        client = require_identifier(client_instance_id, "client_instance_id")
        bounded_status = require_text(status, "status", 32).upper()
        if bounded_status not in {"ACTIVE", "IDLE", "EDITING", "VIEWING", "OFFLINE"}:
            raise DevelopmentError("presence status is invalid")
        resource = (
            require_identifier(resource_id, "resource_id") if resource_id is not None else None
        )
        expected = require_revision(expected_workspace_revision)
        request = {
            "resource_id": resource,
            "client_instance_id": client,
            "status": bounded_status,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            self._lock_subject_limit(session, f"presence:{identifier}")
            if resource is not None:
                target = session.get(DevelopmentResource, resource)
                if target is None or target.project_id != identifier:
                    raise DevelopmentNotFoundError("presence resource was not found")
            row = session.scalar(
                select(DevelopmentPresence).where(
                    DevelopmentPresence.project_id == identifier,
                    DevelopmentPresence.subject == actor.subject,
                    DevelopmentPresence.client_instance_id == client,
                )
            )
            now = utc_now()
            if row is None:
                count = session.scalar(
                    select(func.count()).select_from(DevelopmentPresence).where(
                        DevelopmentPresence.project_id == identifier
                    )
                )
                if int(count or 0) >= 1000:
                    raise DevelopmentLimitError("presence record limit is reached")
                row = DevelopmentPresence(
                    presence_id=_id(),
                    project_id=identifier,
                    resource_id=resource,
                    subject=actor.subject,
                    client_instance_id=client,
                    status=bounded_status,
                    updated_at_database_time=now,
                    expires_at_database_time=now + timedelta(minutes=2),
                )
                session.add(row)
            else:
                row.resource_id = resource
                row.status = bounded_status
                row.updated_at_database_time = now
                row.expires_at_database_time = now + timedelta(minutes=2)
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="UPDATE_PRESENCE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={"presence_id": row.presence_id, "status": bounded_status},
            )
            session.flush()
            return {
                "presence": {
                    "presence_id": row.presence_id,
                    "project_id": row.project_id,
                    "resource_id": row.resource_id,
                    "subject": row.subject,
                    "client_instance_id": row.client_instance_id,
                    "status": row.status,
                    "updated_at": _iso(row.updated_at_database_time),
                    "expires_at": _iso(row.expires_at_database_time),
                },
                "workspace_revision": expected,
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:presence:{client}",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    @staticmethod
    def _resource_rows(session: Session, project_id: str) -> list[DevelopmentResource]:
        return list(
            session.scalars(
                select(DevelopmentResource)
                .where(DevelopmentResource.project_id == project_id)
                .order_by(DevelopmentResource.path, DevelopmentResource.resource_id)
            ).all()
        )

    @staticmethod
    def _analysis_inputs(rows: Iterable[DevelopmentResource]) -> list[dict[str, Any]]:
        return [
            {
                "path": row.path,
                "kind": row.kind,
                "media_type": row.media_type,
                "content": bytes(row.content),
            }
            for row in rows
        ]

    @classmethod
    def _project_tree_issues(
        cls,
        project: DevelopmentProject,
        rows: Iterable[DevelopmentResource],
    ) -> list[tuple[str, str]]:
        materialized = list(rows)
        issues = _tree_integrity_issues(
            cls._analysis_inputs(materialized), case_policy=project.case_policy
        )
        manifest_row = next(
            (row for row in materialized if row.path == "spell-project.yaml"), None
        )
        expected = canonical_json_bytes(project.manifest)
        if manifest_row is None or bytes(manifest_row.content) != expected:
            issues.append(
                (
                    "MANIFEST_PROJECTION_MISMATCH",
                    "project manifest row differs from the authoritative manifest",
                )
            )
        return sorted(set(issues))

    @classmethod
    def _require_project_tree(
        cls,
        project: DevelopmentProject,
        rows: Iterable[DevelopmentResource],
    ) -> None:
        issues = cls._project_tree_issues(project, rows)
        if issues:
            code, message = issues[0]
            raise DevelopmentConflictError(message, code=code)

    @staticmethod
    def _dependency_validation(
        session: Session,
        project: DevelopmentProject,
        *,
        reparse_libraries: bool,
    ) -> tuple[list[tuple[str, str]], list[str], str, bool]:
        dependencies = list(project.manifest.get("catalog_dependencies", []))
        snapshots = session.scalars(
            select(DevelopmentCatalogSnapshot).where(
                DevelopmentCatalogSnapshot.project_id == project.project_id
            )
        ).all()
        snapshot_index: dict[tuple[str, int], DevelopmentCatalogSnapshot] = {}
        for snapshot in snapshots:
            key = (snapshot.catalog_id.casefold(), int(snapshot.catalog_revision))
            if key in snapshot_index:
                raise DevelopmentCorruptionError(
                    "catalog snapshots collide under casefold identity"
                )
            if sha256_bytes(snapshot.canonical_snapshot) != snapshot.content_digest:
                # The declared digest covers the unsigned canonical document, while the
                # stored canonical bytes also contain that digest. Reparse it below.
                parsed = strict_json_bytes(snapshot.canonical_snapshot, "catalog snapshot")
                unsigned = {key: value for key, value in parsed.items() if key != "content_digest"}
                if sha256_bytes(canonical_json_bytes(unsigned)) != snapshot.content_digest:
                    raise DevelopmentCorruptionError("stored catalog snapshot digest differs")
            snapshot_index[key] = snapshot
        cache_input = {
            "dependencies": dependencies,
            "snapshots": [
                {
                    "catalog_id": item.catalog_id,
                    "catalog_revision": int(item.catalog_revision),
                    "content_digest": item.content_digest,
                    "dependencies": item.dependencies,
                }
                for item in sorted(
                    snapshots,
                    key=lambda item: (
                        item.catalog_id.casefold(),
                        int(item.catalog_revision),
                    ),
                )
            ],
        }
        content_digest = sha256_bytes(canonical_json_bytes(cache_input))
        if reparse_libraries:
            session.execute(
                delete(DevelopmentLibraryCache).where(
                    DevelopmentLibraryCache.project_id == project.project_id
                )
            )
        else:
            cached = session.scalar(
                select(DevelopmentLibraryCache).where(
                    DevelopmentLibraryCache.project_id == project.project_id,
                    DevelopmentLibraryCache.cache_kind == "CATALOG_GRAPH",
                    DevelopmentLibraryCache.content_digest == content_digest,
                    DevelopmentLibraryCache.language_profile == LANGUAGE_PROFILE,
                    DevelopmentLibraryCache.tool_version == TOOL_VERSION,
                )
            )
            if cached is not None:
                raw = bytes(cached.canonical_result)
                if sha256_bytes(raw) == cached.result_sha256:
                    value = strict_json_bytes(raw, "library cache")
                    if type(value) is dict and set(value) == {"closure", "issues"}:
                        return (
                            [(str(item[0]), str(item[1])) for item in value["issues"]],
                            [str(item) for item in value["closure"]],
                            content_digest,
                            True,
                        )
                session.delete(cached)
        issues: list[tuple[str, str]] = []
        closure: list[str] = []
        visiting: set[tuple[str, int]] = set()
        visited: set[tuple[str, int]] = set()

        def visit(dependency: Mapping[str, Any]) -> None:
            key = (
                str(dependency["catalog_id"]).casefold(),
                int(dependency["catalog_revision"]),
            )
            if key in visiting:
                issues.append(("DEPENDENCY_CYCLE", "catalog dependency graph contains a cycle"))
                return
            if key in visited:
                return
            if len(visited) >= 1024:
                issues.append(("DEPENDENCY_LIMIT", "catalog dependency graph exceeds 1024 nodes"))
                return
            snapshot = snapshot_index.get(key)
            if snapshot is None:
                issues.append(
                    (
                        "DEPENDENCY_MISSING",
                        f"pinned catalog {dependency['catalog_id']} revision {dependency['catalog_revision']} is missing",
                    )
                )
                return
            if snapshot.content_digest != dependency["content_digest"]:
                issues.append(
                    (
                        "DEPENDENCY_DIGEST_MISMATCH",
                        f"pinned catalog {dependency['catalog_id']} digest differs",
                    )
                )
                return
            visiting.add(key)
            for child in snapshot.dependencies:
                visit(child)
            visiting.remove(key)
            visited.add(key)
            closure.append(snapshot.content_digest)

        for dependency in dependencies:
            visit(dependency)
        issues = sorted(set(issues))
        closure = sorted(set(closure))
        cache_bytes = canonical_json_bytes(
            {"closure": closure, "issues": [list(item) for item in issues]}
        )
        session.add(
            DevelopmentLibraryCache(
                cache_id=_id(),
                project_id=project.project_id,
                cache_kind="CATALOG_GRAPH",
                content_digest=content_digest,
                language_profile=LANGUAGE_PROFILE,
                tool_version=TOOL_VERSION,
                canonical_result=cache_bytes,
                result_sha256=sha256_bytes(cache_bytes),
            )
        )
        return issues, closure, content_digest, False

    def _library_analysis(
        self,
        *,
        project_id: str,
        resource: Mapping[str, Any],
        workspace_revision: int,
        reparse: bool,
    ) -> tuple[AnalysisResult, bool]:
        path = str(resource["path"])
        raw = bytes(resource["content"])
        content_digest = sha256_bytes(raw)
        if not reparse:
            with self.factory() as session:
                cached = session.scalar(
                    select(DevelopmentLibraryCache).where(
                        DevelopmentLibraryCache.project_id == project_id,
                        DevelopmentLibraryCache.cache_kind == "LIBRARY_INDEX",
                        DevelopmentLibraryCache.content_digest == content_digest,
                        DevelopmentLibraryCache.language_profile == LANGUAGE_PROFILE,
                        DevelopmentLibraryCache.tool_version == TOOL_VERSION,
                    )
                )
                if cached is not None:
                    result_bytes = bytes(cached.canonical_result)
                    if sha256_bytes(result_bytes) == cached.result_sha256:
                        parsed = strict_json_bytes(result_bytes, "library analysis cache")
                        if type(parsed) is dict and set(parsed) == {
                            "completions",
                            "diagnostics",
                            "input_digests",
                            "outline",
                        }:
                            return (
                                AnalysisResult(
                                    diagnostics=tuple(parsed["diagnostics"]),
                                    outline=tuple(parsed["outline"]),
                                    completions=tuple(parsed["completions"]),
                                    compiled={},
                                    input_digests=dict(parsed["input_digests"]),
                                ),
                                True,
                            )

        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            result = analyze_resources(
                [resource],
                workspace_revision=workspace_revision,
                scope="FILE",
                scope_path=path,
            )
        else:
            result = analyze_library_source(
                source,
                path,
                workspace_revision=workspace_revision,
            )
        result_bytes = canonical_json_bytes(
            {
                "completions": list(result.completions),
                "diagnostics": list(result.diagnostics),
                "input_digests": result.input_digests,
                "outline": list(result.outline),
            }
        )
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            existing = session.scalar(
                select(DevelopmentLibraryCache).where(
                    DevelopmentLibraryCache.project_id == project_id,
                    DevelopmentLibraryCache.cache_kind == "LIBRARY_INDEX",
                    DevelopmentLibraryCache.content_digest == content_digest,
                    DevelopmentLibraryCache.language_profile == LANGUAGE_PROFILE,
                    DevelopmentLibraryCache.tool_version == TOOL_VERSION,
                )
            )
            if existing is None:
                session.add(
                    DevelopmentLibraryCache(
                        cache_id=_id(),
                        project_id=project_id,
                        cache_kind="LIBRARY_INDEX",
                        content_digest=content_digest,
                        language_profile=LANGUAGE_PROFILE,
                        tool_version=TOOL_VERSION,
                        canonical_result=result_bytes,
                        result_sha256=sha256_bytes(result_bytes),
                    )
                )
            else:
                existing.canonical_result = result_bytes
                existing.result_sha256 = sha256_bytes(result_bytes)
        return result, False

    def enqueue_check(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        scope: Any,
        scope_path: Any,
        expected_workspace_revision: Any,
        reparse_libraries: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        if scope not in CHECK_SCOPES:
            raise DevelopmentError("analysis scope is invalid")
        bounded_scope = str(scope)
        bounded_path = normalize_path(scope_path) if scope_path is not None else None
        if bounded_scope in {"FILE", "FOLDER"} and bounded_path is None:
            raise DevelopmentError("scope_path is required for file or folder checks")
        if bounded_scope in {"PROJECT", "CHANGED_SET"} and bounded_path is not None:
            raise DevelopmentError("scope_path is not allowed for this check scope")
        if type(reparse_libraries) is not bool:
            raise DevelopmentError("reparse_libraries must be boolean")
        expected = require_revision(expected_workspace_revision)
        request = {
            "scope": bounded_scope,
            "scope_path": bounded_path,
            "expected_workspace_revision": expected,
            "reparse_libraries": reparse_libraries,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            self._lock_subject_limit(session, f"analysis:{actor.subject}")
            active = session.scalar(
                select(func.count()).select_from(DevelopmentAnalysisJob).where(
                    DevelopmentAnalysisJob.actor_subject == actor.subject,
                    DevelopmentAnalysisJob.state.in_(("QUEUED", "RUNNING", "CANCEL_REQUESTED")),
                )
            )
            if int(active or 0) >= 2:
                raise DevelopmentConflictError("concurrent analysis job limit is reached")
            rows = self._resource_rows(session, identifier)
            if bounded_scope in {"FILE", "FOLDER"}:
                target = next(
                    (
                        row
                        for row in rows
                        if row.path_identity
                        == path_identity(str(bounded_path), project.case_policy)
                    ),
                    None,
                )
                if target is None:
                    raise DevelopmentNotFoundError("analysis scope resource was not found")
                if bounded_scope == "FILE" and target.kind in {
                    "SOURCE_FOLDER",
                    "FOLDER",
                }:
                    raise DevelopmentConflictError(
                        "file analysis scope refers to a folder",
                        code="CHECK_SCOPE_KIND_INVALID",
                    )
                if bounded_scope == "FOLDER" and target.kind not in {
                    "SOURCE_FOLDER",
                    "FOLDER",
                }:
                    raise DevelopmentConflictError(
                        "folder analysis scope refers to a file",
                        code="CHECK_SCOPE_KIND_INVALID",
                    )
            _, tree_digest = canonical_tree(
                self._analysis_inputs(rows), case_policy=project.case_policy
            )
            job = DevelopmentAnalysisJob(
                job_id=_id(),
                project_id=identifier,
                workspace_revision=expected,
                scope=bounded_scope,
                scope_path=bounded_path,
                reparse_libraries=reparse_libraries,
                state="QUEUED",
                progress=0,
                actor_subject=actor.subject,
                tool_version=TOOL_VERSION,
                input_digest=tree_digest,
                report=None,
                report_sha256=None,
                failure_code=None,
            )
            session.add(job)
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="QUEUE_SEMANTIC_CHECK",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={"job_id": job.job_id, "scope": bounded_scope},
            )
            session.flush()
            return {"job": _job_dict(job)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:check",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def _run_check(self, job_id: Any) -> dict[str, Any]:
        identifier = require_identifier(job_id, "job_id")
        inputs: list[dict[str, Any]]
        job_scope: str
        job_scope_path: str | None
        job_revision: int
        project_id: str
        started: datetime
        dependency_issues: list[tuple[str, str]]
        dependency_closure: list[str]
        library_cache_digest: str
        library_cache_hit: bool
        covered_paths: set[str]
        manifest_digest: str
        tree_issues: list[tuple[str, str]]
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            job = session.get(DevelopmentAnalysisJob, identifier)
            if job is None:
                raise DevelopmentNotFoundError("analysis job was not found")
            if job.state in {"COMPLETED", "FAILED", "CANCELLED"}:
                return {"job": _job_dict(job)}
            now = utc_now()
            if job.state == "CANCEL_REQUESTED":
                job.state = "CANCELLED"
                job.progress = 100
                job.completed_at_database_time = now
                return {"job": _job_dict(job)}
            if job.state != "QUEUED":
                raise DevelopmentConflictError("analysis job state is invalid")
            job.state = "RUNNING"
            job.progress = 10
            job.started_at_database_time = now
            project = self._project(session, job.project_id)
            rows = self._resource_rows(session, job.project_id)
            job_scope = job.scope
            job_scope_path = job.scope_path
            job_revision = int(job.workspace_revision)
            project_id = job.project_id
            started = now
            if int(project.workspace_revision) != job_revision:
                job.state = "FAILED"
                job.progress = 100
                job.failure_code = "STALE_WORKSPACE_RESULT"
                job.completed_at_database_time = utc_now()
                return {"job": _job_dict(job)}
            manifest_row = next(
                (row for row in rows if row.path == "spell-project.yaml"), None
            )
            manifest_digest = (
                manifest_row.content_sha256
                if manifest_row is not None
                else sha256_bytes(b"")
            )
            tree_issues = self._project_tree_issues(project, rows)
            all_inputs = self._analysis_inputs(rows)
            covered_paths = set()
            if job_scope == "FILE":
                inputs = [item for item in all_inputs if item["path"] == job_scope_path]
                covered_paths.add(str(job_scope_path))
            elif job_scope == "FOLDER":
                prefix = str(job_scope_path) + "/"
                inputs = [
                    item
                    for item in all_inputs
                    if item["path"] == job_scope_path or item["path"].startswith(prefix)
                ]
                covered_paths.update(str(item["path"]) for item in inputs)
            elif job_scope == "CHANGED_SET" and project.base_history_revision_id is not None:
                base = session.get(
                    DevelopmentHistoryRevision, project.base_history_revision_id
                )
                base_map = self._snapshot_map(base) if base is not None else {}
                current_map = {str(item["path"]): item for item in all_inputs}
                changed_paths = {
                    path
                    for path in set(base_map) | set(current_map)
                    if path not in base_map
                    or path not in current_map
                    or base_map[path]["content_sha256"]
                    != sha256_bytes(current_map[path]["content"])
                    or base_map[path]["kind"] != current_map[path]["kind"]
                    or base_map[path]["media_type"] != current_map[path]["media_type"]
                }
                inputs = [item for item in all_inputs if item["path"] in changed_paths]
                covered_paths.update(changed_paths)
            else:
                inputs = all_inputs
                covered_paths.update(str(item["path"]) for item in inputs)
            covered_paths.add("spell-project.yaml")
            (
                dependency_issues,
                dependency_closure,
                library_cache_digest,
                library_cache_hit,
            ) = self._dependency_validation(
                session,
                project,
                reparse_libraries=bool(job.reparse_libraries),
            )

        diagnostics: list[dict[str, Any]] = [
            _project_diagnostic(
                workspace_revision=job_revision,
                source_digest=manifest_digest,
                code=code,
                message=message,
            )
            for code, message in [*tree_issues, *dependency_issues]
        ]
        outline: list[dict[str, Any]] = []
        completions: dict[str, dict[str, Any]] = {}
        compiled: dict[str, dict[str, Any]] = {}
        input_digests: dict[str, str] = {}
        library_resource_cache: dict[str, bool] = {}
        input_count = max(1, len(inputs))
        for input_index, resource in enumerate(inputs, 1):
            with session_scope(self.factory) as progress_session:
                begin_mutation_write(progress_session)
                current_job = progress_session.get(DevelopmentAnalysisJob, identifier)
                if current_job is None:
                    raise DevelopmentNotFoundError("analysis job was not found")
                if current_job.state in {"CANCEL_REQUESTED", "CANCELLED"}:
                    current_job.state = "CANCELLED"
                    current_job.progress = 100
                    current_job.completed_at_database_time = utc_now()
                    return {"job": _job_dict(current_job)}
                if current_job.state != "RUNNING":
                    return {"job": _job_dict(current_job)}
                current_job.progress = max(
                    int(current_job.progress),
                    min(95, 10 + (input_index - 1) * 80 // input_count),
                )
            if resource["kind"] not in {"PROCEDURE", "LIBRARY"}:
                input_digests[str(resource["path"])] = sha256_bytes(
                    bytes(resource["content"])
                )
                try:
                    _validate_resource_document(
                        kind=str(resource["kind"]),
                        media_type=str(resource["media_type"]),
                        raw=bytes(resource["content"]),
                    )
                except DevelopmentError as exc:
                    diagnostics.append(
                        _resource_diagnostic(
                            workspace_revision=job_revision,
                            source_digest=sha256_bytes(bytes(resource["content"])),
                            source_path=str(resource["path"]),
                            code="SCHEMA_INVALID",
                            message=str(exc),
                        )
                    )
            elif resource["kind"] == "LIBRARY":
                result, cache_hit = self._library_analysis(
                    project_id=project_id,
                    resource=resource,
                    workspace_revision=job_revision,
                    reparse=bool(job.reparse_libraries),
                )
                diagnostics.extend(result.diagnostics)
                outline.extend(
                    {**item, "source_path": str(resource["path"])}
                    for item in result.outline
                )
                completions.update({item["label"]: item for item in result.completions})
                input_digests.update(result.input_digests)
                library_resource_cache[str(resource["path"])] = cache_hit
            else:
                result = analyze_resources(
                    [resource],
                    workspace_revision=job_revision,
                    scope=job_scope,
                    scope_path=job_scope_path,
                )
                diagnostics.extend(result.diagnostics)
                outline.extend(result.outline)
                completions.update({item["label"]: item for item in result.completions})
                compiled.update(result.compiled)
                input_digests.update(result.input_digests)
            if len(diagnostics) > 100_000:
                raise DevelopmentLimitError("project diagnostic limit is exceeded")

        if library_resource_cache:
            library_cache_hit = library_cache_hit and all(
                library_resource_cache.values()
            )

        diagnostics.sort(
            key=lambda item: (
                item["source_path"],
                item["start_line"],
                item["start_column"],
                item["severity"],
                item["code"],
                item["diagnostic_id"],
            )
        )
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            job = session.get(DevelopmentAnalysisJob, identifier)
            if job is None:
                raise DevelopmentNotFoundError("analysis job was not found")
            if job.state in {"CANCEL_REQUESTED", "CANCELLED"}:
                if job.state != "CANCELLED":
                    job.state = "CANCELLED"
                    job.progress = 100
                    job.completed_at_database_time = utc_now()
                return {"job": _job_dict(job)}
            if job.state != "RUNNING":
                return {"job": _job_dict(job)}
            project = self._project(session, project_id)
            if int(project.workspace_revision) != job_revision:
                job.state = "FAILED"
                job.progress = 100
                job.failure_code = "STALE_WORKSPACE_RESULT"
                job.completed_at_database_time = utc_now()
                return {"job": _job_dict(job)}
            current_resources = {
                row.path: row for row in self._resource_rows(session, project_id)
            }
            if job_scope != "PROJECT":
                prior_revision = session.scalar(
                    select(func.max(DevelopmentProblem.workspace_revision)).where(
                        DevelopmentProblem.project_id == project_id,
                        DevelopmentProblem.workspace_revision < job_revision,
                    )
                )
                if prior_revision is not None:
                    prior_problems = session.scalars(
                        select(DevelopmentProblem).where(
                            DevelopmentProblem.project_id == project_id,
                            DevelopmentProblem.workspace_revision == prior_revision,
                        )
                    ).all()
                    reports: dict[str, dict[str, Any]] = {}
                    for problem in prior_problems:
                        if problem.source_path in covered_paths:
                            continue
                        resource = current_resources.get(problem.source_path)
                        if resource is None:
                            continue
                        report = reports.get(problem.job_id)
                        if report is None:
                            prior_job = session.get(
                                DevelopmentAnalysisJob, problem.job_id
                            )
                            if prior_job is None or prior_job.report is None:
                                continue
                            try:
                                parsed = json.loads(prior_job.report)
                            except (TypeError, ValueError):
                                continue
                            if type(parsed) is not dict:
                                continue
                            report = parsed
                            reports[problem.job_id] = report
                        prior_inputs = report.get("input_digests")
                        if (
                            type(prior_inputs) is not dict
                            or prior_inputs.get(problem.source_path)
                            != resource.content_sha256
                        ):
                            continue
                        diagnostic_id = sha256_bytes(
                            canonical_json_bytes(
                                {
                                    "code": problem.code,
                                    "source_digest": resource.content_sha256,
                                    "source_path": problem.source_path,
                                    "span": [
                                        problem.start_line,
                                        problem.start_column,
                                        problem.end_line,
                                        problem.end_column,
                                    ],
                                    "tool_version": problem.tool_version,
                                    "workspace_revision": job_revision,
                                }
                            )
                        )
                        session.add(
                            DevelopmentProblem(
                                problem_id=_id(),
                                diagnostic_id=diagnostic_id,
                                job_id=problem.job_id,
                                project_id=project_id,
                                workspace_revision=job_revision,
                                source_path=problem.source_path,
                                start_line=problem.start_line,
                                start_column=problem.start_column,
                                end_line=problem.end_line,
                                end_column=problem.end_column,
                                severity=problem.severity,
                                code=problem.code,
                                message=problem.message,
                                remediation_ref=problem.remediation_ref,
                                tool_version=problem.tool_version,
                                language_profile=problem.language_profile,
                            )
                        )
                    session.flush()
            existing_problems = session.scalars(
                select(DevelopmentProblem).where(
                    DevelopmentProblem.project_id == project_id,
                    DevelopmentProblem.workspace_revision == job_revision,
                )
            ).all()
            replaced_problem_ids = [
                problem.problem_id
                for problem in existing_problems
                if job_scope == "PROJECT" or problem.source_path in covered_paths
            ]
            if replaced_problem_ids:
                session.execute(
                    delete(DevelopmentProblem).where(
                        DevelopmentProblem.problem_id.in_(replaced_problem_ids)
                    )
                )
            for diagnostic in diagnostics:
                session.add(
                    DevelopmentProblem(
                        problem_id=_id(),
                        diagnostic_id=diagnostic["diagnostic_id"],
                        job_id=job.job_id,
                        project_id=job.project_id,
                        workspace_revision=job.workspace_revision,
                        source_path=diagnostic["source_path"],
                        start_line=diagnostic["start_line"],
                        start_column=diagnostic["start_column"],
                        end_line=diagnostic["end_line"],
                        end_column=diagnostic["end_column"],
                        severity=diagnostic["severity"],
                        code=diagnostic["code"],
                        message=diagnostic["message"],
                        remediation_ref=diagnostic["remediation_ref"],
                        tool_version=diagnostic["tool_version"],
                        language_profile=diagnostic["language_profile"],
                    )
                )
            completed = utc_now()
            report = canonical_json_bytes(
                {
                    "project_id": project_id,
                    "workspace_revision": job_revision,
                    "scope": job_scope,
                    "scope_path": job_scope_path,
                    "started_at": _iso(started),
                    "completed_at": _iso(completed),
                    "tool_version": job.tool_version,
                    "input_digests": input_digests,
                    "dependency_closure": dependency_closure,
                    "library_cache_digest": library_cache_digest,
                    "library_cache_hit": library_cache_hit,
                    "library_resource_cache": {
                        path: library_resource_cache[path]
                        for path in sorted(library_resource_cache)
                    },
                    "diagnostics": diagnostics,
                    "outline": outline[:5000],
                    "completions": [completions[key] for key in sorted(completions)[:500]],
                    "outcome": "PASS" if not diagnostics else "FAILED",
                }
            )
            job.report = report
            job.report_sha256 = sha256_bytes(report)
            job.state = "COMPLETED"
            job.progress = 100
            job.completed_at_database_time = completed
            session.flush()
            return {"job": _job_dict(job)}

    def run_check(self, job_id: Any) -> dict[str, Any]:
        identifier = require_identifier(job_id, "job_id")
        try:
            return self._run_check(identifier)
        except Exception as exc:
            with session_scope(self.factory) as session:
                begin_mutation_write(session)
                job = session.get(DevelopmentAnalysisJob, identifier)
                if job is None:
                    raise
                if job.state in {"CANCEL_REQUESTED", "CANCELLED"}:
                    job.state = "CANCELLED"
                    job.failure_code = None
                elif job.state not in {"COMPLETED", "FAILED"}:
                    job.state = "FAILED"
                    job.failure_code = (
                        exc.code[:80]
                        if isinstance(exc, DevelopmentError)
                        else "ANALYSIS_INTERNAL_FAILURE"
                    )
                job.progress = 100
                job.completed_at_database_time = utc_now()
                session.flush()
                return {"job": _job_dict(job)}

    def create_check(self, project_id: Any, **kwargs: Any) -> dict[str, Any]:
        return self.enqueue_check(project_id, **kwargs)

    def get_check(
        self,
        job_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(job_id, "job_id")
        with self.factory() as session:
            row = session.get(DevelopmentAnalysisJob, identifier)
            if row is None:
                raise DevelopmentNotFoundError("analysis job was not found")
            problems = session.scalars(
                select(DevelopmentProblem)
                .where(DevelopmentProblem.job_id == identifier)
                .order_by(
                    DevelopmentProblem.source_path,
                    DevelopmentProblem.start_line,
                    DevelopmentProblem.start_column,
                    DevelopmentProblem.severity,
                    DevelopmentProblem.code,
                    DevelopmentProblem.diagnostic_id,
                )
            ).all()
            return {
                "job": _job_dict(row, include_report=False),
                "problems": [_problem_dict(item) for item in problems],
            }

    def download_check_report(
        self,
        job_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> tuple[bytes, str]:
        self._actor(subject, role)
        identifier = require_identifier(job_id, "job_id")
        with self.factory() as session:
            row = session.get(DevelopmentAnalysisJob, identifier)
            if row is None:
                raise DevelopmentNotFoundError("analysis job was not found")
            if row.state != "COMPLETED" or row.report is None or row.report_sha256 is None:
                raise DevelopmentConflictError(
                    "completed analysis report is unavailable",
                    code="REPORT_UNAVAILABLE",
                )
            raw = bytes(row.report)
            digest = require_digest(row.report_sha256, "report_sha256")
            if sha256_bytes(raw) != digest:
                raise DevelopmentCorruptionError("analysis report digest differs")
            parsed = strict_json_bytes(raw, "analysis report")
            if canonical_json_bytes(parsed) != raw:
                raise DevelopmentCorruptionError("analysis report is not canonical")
            return raw, digest

    def cancel_check(
        self,
        job_id: Any,
        *,
        subject: Any,
        role: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(job_id, "job_id")
        request = {"job_id": identifier}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            row = session.get(DevelopmentAnalysisJob, identifier)
            if row is None:
                raise DevelopmentNotFoundError("analysis job was not found")
            project = self._project(session, row.project_id)
            self._author(project, actor)
            if row.state == "QUEUED":
                row.state = "CANCELLED"
                row.progress = 100
                row.completed_at_database_time = utc_now()
            elif row.state == "RUNNING":
                row.state = "CANCEL_REQUESTED"
            elif row.state not in {"CANCEL_REQUESTED", "CANCELLED"}:
                raise DevelopmentConflictError("analysis job can no longer be cancelled")
            self._audit(
                session,
                actor,
                project_id=row.project_id,
                action="CANCEL_SEMANTIC_CHECK",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=int(project.workspace_revision),
                new_revision=int(project.workspace_revision),
                payload={"job_id": row.job_id, "state": row.state},
            )
            session.flush()
            return {"job": _job_dict(row)}

        return self._mutate(
            actor,
            scope=f"check:{identifier}:cancel",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def clean_problems(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        expected = require_revision(expected_workspace_revision)
        request = {"expected_workspace_revision": expected}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            deleted_count = session.execute(
                delete(DevelopmentProblem).where(
                    DevelopmentProblem.project_id == identifier,
                    DevelopmentProblem.workspace_revision == expected,
                )
            ).rowcount
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="CLEAN_PROBLEMS",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={"deleted": int(deleted_count or 0)},
            )
            return {"deleted": int(deleted_count or 0), "workspace_revision": expected}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:problems:clean",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def recover_analysis_jobs(self) -> int:
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            rows = session.scalars(
                select(DevelopmentAnalysisJob).where(
                    DevelopmentAnalysisJob.state.in_(("QUEUED", "RUNNING", "CANCEL_REQUESTED"))
                )
            ).all()
            completed = utc_now()
            for row in rows:
                row.state = "FAILED"
                row.progress = 100
                row.failure_code = "FAILED_RETRYABLE"
                row.completed_at_database_time = completed
            return len(rows)

    @staticmethod
    def _snapshot_bytes(rows: Iterable[DevelopmentResource]) -> bytes:
        return canonical_json_bytes(
            {
                "resources": [
                    {
                        "content": base64.b64encode(row.content).decode("ascii"),
                        "content_sha256": row.content_sha256,
                        "kind": row.kind,
                        "media_type": row.media_type,
                        "path": row.path,
                        "resource_id": row.resource_id,
                    }
                    for row in sorted(rows, key=lambda item: item.path.encode("utf-8"))
                ],
                "schema_version": "spell.development.snapshot/1",
            }
        )

    @staticmethod
    def _snapshot_resources(raw: bytes) -> list[dict[str, Any]]:
        value = strict_json_bytes(raw, "history snapshot")
        if type(value) is not dict or set(value) != {"resources", "schema_version"}:
            raise DevelopmentCorruptionError("history snapshot schema differs")
        if value["schema_version"] != "spell.development.snapshot/1":
            raise DevelopmentCorruptionError("history snapshot version differs")
        entries = value["resources"]
        if type(entries) is not list or len(entries) > MAX_RESOURCES:
            raise DevelopmentCorruptionError("history snapshot resources are invalid")
        result: list[dict[str, Any]] = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {
                "content",
                "content_sha256",
                "kind",
                "media_type",
                "path",
                "resource_id",
            }:
                raise DevelopmentCorruptionError("history snapshot resource schema differs")
            try:
                content = base64.b64decode(entry["content"], validate=True)
            except (TypeError, ValueError) as exc:
                raise DevelopmentCorruptionError("history snapshot content is invalid") from exc
            if sha256_bytes(content) != entry["content_sha256"]:
                raise DevelopmentCorruptionError("history snapshot content digest differs")
            require_identifier(entry["resource_id"], "resource_id")
            result.append({**entry, "content": content})
        return result

    @staticmethod
    def _snapshot_bytes_from_entries(entries: Iterable[Mapping[str, Any]]) -> bytes:
        return canonical_json_bytes(
            {
                "resources": [
                    {
                        "content": base64.b64encode(bytes(entry["content"])).decode("ascii"),
                        "content_sha256": entry["content_sha256"],
                        "kind": entry["kind"],
                        "media_type": entry["media_type"],
                        "path": entry["path"],
                        "resource_id": entry["resource_id"],
                    }
                    for entry in sorted(
                        entries, key=lambda item: str(item["path"]).encode("utf-8")
                    )
                ],
                "schema_version": "spell.development.snapshot/1",
            }
        )

    @staticmethod
    def _validation_summary_digest(report: Mapping[str, Any]) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "diagnostics": report["diagnostics"],
                    "input_digests": report["input_digests"],
                    "outcome": report["outcome"],
                    "tool_version": report["tool_version"],
                }
            )
        )

    def _validate_frozen_entries(
        self,
        project: DevelopmentProject,
        entries: Sequence[Mapping[str, Any]],
        *,
        workspace_revision: int,
    ) -> tuple[bytes, str, bytes]:
        materialized = [dict(entry) for entry in entries]
        _require_tree_integrity(materialized, case_policy=project.case_policy)
        manifest_entry = next(
            (entry for entry in materialized if entry["path"] == "spell-project.yaml"),
            None,
        )
        if manifest_entry is None:
            raise DevelopmentConflictError("project manifest is missing", code="MANIFEST_MISSING")
        parsed_manifest = _strict_json_document(
            bytes(manifest_entry["content"]), "project manifest"
        )
        manifest = self._manifest(
            parsed_manifest,
            project_id=project.project_id,
            display_name=project.display_name,
            case_policy=project.case_policy,
            owner=project.owner_subject,
        )
        if canonical_json_bytes(manifest) != bytes(manifest_entry["content"]):
            raise DevelopmentConflictError(
                "project manifest is not canonical", code="MANIFEST_INVALID"
            )
        tree_bytes, tree_digest = canonical_tree(
            materialized, case_policy=project.case_policy
        )
        diagnostics: list[dict[str, Any]] = []
        catalog_index: dict[tuple[str, int], dict[str, Any]] = {}
        input_digests = {
            str(entry["path"]): sha256_bytes(bytes(entry["content"]))
            for entry in materialized
        }
        for entry in materialized:
            try:
                projection = _validate_resource_document(
                    kind=str(entry["kind"]),
                    media_type=str(entry["media_type"]),
                    raw=bytes(entry["content"]),
                )
            except DevelopmentError as exc:
                diagnostics.append(
                    _resource_diagnostic(
                        workspace_revision=workspace_revision,
                        source_digest=input_digests[str(entry["path"])],
                        source_path=str(entry["path"]),
                        code="SCHEMA_INVALID",
                        message=str(exc),
                    )
                )
                continue
            catalog = projection.get("catalog")
            if catalog is not None:
                key = (catalog["catalog_id"].casefold(), int(catalog["catalog_revision"]))
                if key in catalog_index:
                    diagnostics.append(
                        _resource_diagnostic(
                            workspace_revision=workspace_revision,
                            source_digest=input_digests[str(entry["path"])],
                            source_path=str(entry["path"]),
                            code="DEPENDENCY_DUPLICATE",
                            message="catalog snapshot identity is duplicated",
                        )
                    )
                else:
                    catalog_index[key] = catalog

        analysis = analyze_resources(
            materialized,
            workspace_revision=workspace_revision,
            scope="PROJECT",
        )
        diagnostics.extend(analysis.diagnostics)
        procedure_ids: dict[str, str] = {}
        for compiled in analysis.compiled.values():
            procedure_id = str(compiled["procedure_id"])
            identity = procedure_id.casefold()
            if identity in procedure_ids:
                diagnostics.append(
                    _project_diagnostic(
                        workspace_revision=workspace_revision,
                        source_digest=tree_digest,
                        code="PROCEDURE_ID_COLLISION",
                        message=f"procedure id {procedure_id!r} is duplicated",
                    )
                )
            procedure_ids[identity] = procedure_id

        closure: list[str] = []
        visiting: set[tuple[str, int]] = set()
        visited: set[tuple[str, int]] = set()

        def visit(dependency: Mapping[str, Any]) -> None:
            key = (
                str(dependency["catalog_id"]).casefold(),
                int(dependency["catalog_revision"]),
            )
            if key in visiting:
                diagnostics.append(
                    _project_diagnostic(
                        workspace_revision=workspace_revision,
                        source_digest=tree_digest,
                        code="DEPENDENCY_CYCLE",
                        message="catalog dependency graph contains a cycle",
                    )
                )
                return
            if key in visited:
                return
            if len(visited) >= 1024:
                raise DevelopmentLimitError("catalog dependency graph exceeds 1024 nodes")
            snapshot = catalog_index.get(key)
            if snapshot is None:
                diagnostics.append(
                    _project_diagnostic(
                        workspace_revision=workspace_revision,
                        source_digest=tree_digest,
                        code="DEPENDENCY_MISSING",
                        message=(
                            f"pinned catalog {dependency['catalog_id']} revision "
                            f"{dependency['catalog_revision']} is missing"
                        ),
                    )
                )
                return
            if snapshot["content_digest"] != dependency["content_digest"]:
                diagnostics.append(
                    _project_diagnostic(
                        workspace_revision=workspace_revision,
                        source_digest=tree_digest,
                        code="DEPENDENCY_DIGEST_MISMATCH",
                        message=f"pinned catalog {dependency['catalog_id']} digest differs",
                    )
                )
                return
            visiting.add(key)
            for child in snapshot["dependencies"]:
                visit(child)
            visiting.remove(key)
            visited.add(key)
            closure.append(snapshot["content_digest"])

        for dependency in manifest["catalog_dependencies"]:
            visit(dependency)
        if len(diagnostics) > 100_000:
            raise DevelopmentLimitError("project diagnostic limit is exceeded")
        diagnostics.sort(
            key=lambda item: (
                item["source_path"],
                item["start_line"],
                item["start_column"],
                item["severity"],
                item["code"],
                item["diagnostic_id"],
            )
        )
        completed = utc_now()
        report = canonical_json_bytes(
            {
                "project_id": project.project_id,
                "workspace_revision": workspace_revision,
                "scope": "PROJECT",
                "scope_path": None,
                "started_at": _iso(completed),
                "completed_at": _iso(completed),
                "tool_version": TOOL_VERSION,
                "input_digests": input_digests,
                "dependency_closure": sorted(set(closure)),
                "library_cache_digest": None,
                "library_cache_hit": False,
                "library_resource_cache": {},
                "diagnostics": diagnostics,
                "outline": list(analysis.outline)[:5000],
                "completions": list(analysis.completions)[:500],
                "outcome": "PASS" if not diagnostics else "FAILED",
            }
        )
        return tree_bytes, tree_digest, report

    @staticmethod
    def _latest_completed_job(
        session: Session,
        project_id: str,
        workspace_revision: int,
        *,
        expected_inputs: Mapping[str, str],
        expected_tree_digest: str,
    ) -> DevelopmentAnalysisJob:
        row = session.scalar(
            select(DevelopmentAnalysisJob)
            .where(
                DevelopmentAnalysisJob.project_id == project_id,
                DevelopmentAnalysisJob.workspace_revision == workspace_revision,
                DevelopmentAnalysisJob.state == "COMPLETED",
                DevelopmentAnalysisJob.scope == "PROJECT",
            )
            .order_by(DevelopmentAnalysisJob.completed_at_database_time.desc())
        )
        if row is None or row.report is None:
            raise DevelopmentConflictError(
                "a completed project semantic check is required",
                code="VALIDATION_REQUIRED",
            )
        raw_report = bytes(row.report)
        if row.report_sha256 is None or sha256_bytes(raw_report) != row.report_sha256:
            raise DevelopmentCorruptionError("analysis report digest differs")
        report = strict_json_bytes(raw_report, "analysis report")
        if canonical_json_bytes(report) != raw_report:
            raise DevelopmentCorruptionError("analysis report is not canonical")
        if report.get("outcome") != "PASS":
            raise DevelopmentConflictError(
                "project semantic check has blocking diagnostics",
                code="VALIDATION_FAILED",
            )
        if report.get("input_digests") != dict(expected_inputs):
            raise DevelopmentConflictError(
                "project semantic check does not cover the exact workspace tree",
                code="VALIDATION_STALE",
            )
        if row.input_digest != expected_tree_digest:
            raise DevelopmentConflictError(
                "project semantic check tree digest differs",
                code="VALIDATION_STALE",
            )
        return row

    def commit_history(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        message: Any,
        selected_resource_ids: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        expected = require_revision(expected_workspace_revision)
        bounded_message = require_text(message, "message", 4096)
        selected: list[str] | None
        if selected_resource_ids is None:
            selected = None
        elif type(selected_resource_ids) is list and selected_resource_ids:
            selected = [require_identifier(item, "selected_resource_id") for item in selected_resource_ids]
            if len(selected) != len(set(selected)):
                raise DevelopmentError("selected_resource_ids contain duplicates")
        else:
            raise DevelopmentError("selected_resource_ids are invalid")
        request = {
            "expected_workspace_revision": expected,
            "message": bounded_message,
            "selected_resource_ids": selected,
        }
        with self.factory() as observation_session:
            observed_project = self._project(observation_session, identifier)
            self._author(observed_project, actor)
            self._check_revision(observed_project, expected)
            observed_base_history_revision_id = (
                observed_project.base_history_revision_id
            )

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            if (
                project.base_history_revision_id
                != observed_base_history_revision_id
            ):
                raise DevelopmentConflictError(
                    "workspace history base changed after the request was observed",
                    code="HISTORY_BASE_CONFLICT",
                    current={
                        "workspace_revision": int(project.workspace_revision),
                        "base_history_revision_id": project.base_history_revision_id,
                    },
                )
            rows = self._resource_rows(session, identifier)
            parent = (
                session.get(
                    DevelopmentHistoryRevision, project.base_history_revision_id
                )
                if project.base_history_revision_id is not None
                else None
            )
            if selected is not None:
                if parent is None:
                    raise DevelopmentConflictError(
                        "initial history commit must include the full workspace",
                        code="HISTORY_SELECTION_INVALID",
                    )
                current_by_id = {row.resource_id: row for row in rows}
                base_entries = self._snapshot_resources(parent.snapshot_bytes)
                base_by_id = {entry["resource_id"]: entry for entry in base_entries}
                if not set(selected).issubset(set(current_by_id) | set(base_by_id)):
                    raise DevelopmentNotFoundError("selected history resource was not found")
                merged_by_id = dict(base_by_id)
                for resource_id in selected:
                    current_resource = current_by_id.get(resource_id)
                    if current_resource is None:
                        merged_by_id.pop(resource_id, None)
                    else:
                        merged_by_id[resource_id] = {
                            "content": bytes(current_resource.content),
                            "content_sha256": current_resource.content_sha256,
                            "kind": current_resource.kind,
                            "media_type": current_resource.media_type,
                            "path": current_resource.path,
                            "resource_id": current_resource.resource_id,
                        }
                selected_entries = list(merged_by_id.values())
                identities = [
                    path_identity(str(entry["path"]), project.case_policy)
                    for entry in selected_entries
                ]
                if len(identities) != len(set(identities)):
                    raise DevelopmentConflictError(
                        "selected history changes create a path collision",
                        code="CASE_CONFLICT",
                    )
                tree_bytes, tree_digest, selected_report = self._validate_frozen_entries(
                    project,
                    selected_entries,
                    workspace_revision=expected,
                )
                snapshot = self._snapshot_bytes_from_entries(selected_entries)
                parsed_selected_report = strict_json_bytes(
                    selected_report, "selected history validation report"
                )
                if parsed_selected_report["outcome"] != "PASS":
                    raise DevelopmentConflictError(
                        "selected history tree has blocking diagnostics",
                        code="VALIDATION_FAILED",
                        current={"diagnostics": parsed_selected_report["diagnostics"][:100]},
                    )
                completed = utc_now()
                job = DevelopmentAnalysisJob(
                    job_id=_id(),
                    project_id=identifier,
                    workspace_revision=expected,
                    scope="PROJECT",
                    scope_path=None,
                    reparse_libraries=True,
                    state="COMPLETED",
                    progress=100,
                    actor_subject=actor.subject,
                    tool_version=TOOL_VERSION,
                    input_digest=tree_digest,
                    report=selected_report,
                    report_sha256=sha256_bytes(selected_report),
                    failure_code=None,
                    started_at_database_time=completed,
                    completed_at_database_time=completed,
                )
                session.add(job)
                report = parsed_selected_report
            else:
                analysis_entries = self._analysis_inputs(rows)
                self._require_project_tree(project, rows)
                tree_bytes, tree_digest = canonical_tree(
                    analysis_entries, case_policy=project.case_policy
                )
                snapshot = self._snapshot_bytes(rows)
                job = self._latest_completed_job(
                    session,
                    identifier,
                    expected,
                    expected_inputs={
                        str(entry["path"]): sha256_bytes(bytes(entry["content"]))
                        for entry in analysis_entries
                    },
                    expected_tree_digest=tree_digest,
                )
                report = strict_json_bytes(job.report or b"{}", "analysis report")
            parent_ids = (
                [project.base_history_revision_id]
                if project.base_history_revision_id is not None
                else []
            )
            ordinal = int(
                session.scalar(
                    select(func.coalesce(func.max(DevelopmentHistoryRevision.ordinal), 0)).where(
                        DevelopmentHistoryRevision.project_id == identifier
                    )
                )
                or 0
            ) + 1
            validation_summary_digest = self._validation_summary_digest(report)
            history_id = "hist-" + sha256_bytes(
                canonical_json_bytes(
                    {
                        "author_subject": actor.subject,
                        "message": bounded_message,
                        "parents": parent_ids,
                        "project_id": identifier,
                        "tree_digest": tree_digest,
                        "validation_summary_digest": validation_summary_digest,
                    }
                )
            )[:40]
            existing = session.get(DevelopmentHistoryRevision, history_id)
            if existing is not None:
                return {"history_revision": _history_dict(existing)}
            row = DevelopmentHistoryRevision(
                history_revision_id=history_id,
                project_id=identifier,
                ordinal=ordinal,
                parent_revision_ids=parent_ids,
                tree_digest=tree_digest,
                tree_bytes=tree_bytes,
                snapshot_bytes=snapshot,
                author_subject=actor.subject,
                message=bounded_message,
                message_digest=sha256_bytes(bounded_message.encode("utf-8")),
                validation_job_id=job.job_id,
                validation_summary_digest=validation_summary_digest,
                workspace_revision=expected,
            )
            session.add(row)
            project.base_history_revision_id = history_id
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="COMMIT_HISTORY",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={"history_revision_id": history_id, "tree_digest": tree_digest},
                outbox_topic="development.history.committed",
                aggregate_id=history_id,
            )
            session.flush()
            return {"history_revision": _history_dict(row)}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:history:commit",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def list_history(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        with self.factory() as session:
            self._project(session, identifier)
            rows = session.scalars(
                select(DevelopmentHistoryRevision)
                .where(DevelopmentHistoryRevision.project_id == identifier)
                .order_by(DevelopmentHistoryRevision.ordinal.desc())
            ).all()
            reviews = (
                session.scalars(
                    select(DevelopmentHistoryReview).where(
                        DevelopmentHistoryReview.history_revision_id.in_(
                            [item.history_revision_id for item in rows]
                        )
                    )
                ).all()
                if rows
                else []
            )
            review_map = {item.history_revision_id: item for item in reviews}
            return {
                "items": [
                    {
                        **_history_dict(row),
                        "review": _review_dict(
                            review_map.get(row.history_revision_id)
                        ),
                        "review_revision": int(
                            review_map[row.history_revision_id].review_revision
                        )
                        if row.history_revision_id in review_map
                        else 0,
                    }
                    for row in rows
                ]
            }

    def get_history(
        self,
        history_revision_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(history_revision_id, "history_revision_id")
        with self.factory() as session:
            row = session.get(DevelopmentHistoryRevision, identifier)
            if row is None:
                raise DevelopmentNotFoundError("history revision was not found")
            review = session.scalar(
                select(DevelopmentHistoryReview).where(
                    DevelopmentHistoryReview.history_revision_id == identifier
                )
            )
            return {
                "history_revision": _history_dict(row),
                "review": _review_dict(review),
            }

    @staticmethod
    def _snapshot_map(row: DevelopmentHistoryRevision) -> dict[str, dict[str, Any]]:
        return {item["path"]: item for item in DevelopmentService._snapshot_resources(row.snapshot_bytes)}

    @staticmethod
    def _diff_maps(
        left: Mapping[str, dict[str, Any]],
        right: Mapping[str, dict[str, Any]],
        *,
        history_revision_id: str | None,
        against_revision_id: str | None,
        before_validation_digest: str | None,
        after_validation_digest: str | None,
    ) -> dict[str, Any]:
        left_ids = {str(item["resource_id"]): path for path, item in left.items()}
        right_ids = {str(item["resource_id"]): path for path, item in right.items()}
        if len(left_ids) != len(left) or len(right_ids) != len(right):
            raise DevelopmentCorruptionError("history resource identities are duplicated")
        work: list[tuple[str | None, str | None, str]] = []
        for resource_id in sorted(set(left_ids) & set(right_ids)):
            before_path = left_ids[resource_id]
            after_path = right_ids[resource_id]
            before = left[before_path]
            after = right[after_path]
            same_content = before["content_sha256"] == after["content_sha256"]
            same_metadata = (
                before["kind"] == after["kind"]
                and before["media_type"] == after["media_type"]
            )
            if before_path != after_path:
                status = (
                    "CASE_CHANGED"
                    if before_path.casefold() == after_path.casefold()
                    else "RENAMED"
                )
            elif not same_content:
                status = "MODIFIED"
            elif not same_metadata:
                status = "MODIFIED"
            else:
                continue
            work.append((before_path, after_path, status))
        work.extend(
            (left_ids[resource_id], None, "DELETED")
            for resource_id in sorted(set(left_ids) - set(right_ids))
        )
        work.extend(
            (None, right_ids[resource_id], "ADDED")
            for resource_id in sorted(set(right_ids) - set(left_ids))
        )
        work.sort(
            key=lambda item: (
                str(item[1] or item[0]).encode("utf-8"),
                item[2],
                str(item[0]).encode("utf-8"),
            )
        )
        changes: list[dict[str, Any]] = []
        total_bytes = 0
        for before_path, after_path, status in work:
            before = left.get(before_path) if before_path is not None else None
            after = right.get(after_path) if after_path is not None else None
            display_path = str(after_path or before_path)
            try:
                before_text = (
                    before["content"].decode("utf-8") if before is not None else ""
                ).splitlines(keepends=True)
                after_text = (
                    after["content"].decode("utf-8") if after is not None else ""
                ).splitlines(keepends=True)
            except UnicodeDecodeError as exc:
                raise DevelopmentCorruptionError(
                    "history snapshot resource is not UTF-8"
                ) from exc
            patch = "".join(
                difflib.unified_diff(
                    before_text,
                    after_text,
                    fromfile=f"a/{before_path or display_path}",
                    tofile=f"b/{after_path or display_path}",
                    n=20,
                )
            )
            total_bytes += len(patch.encode("utf-8"))
            if len(changes) >= MAX_RESOURCES or total_bytes > 16_777_216:
                raise DevelopmentLimitError("history diff exceeds its bound")
            changes.append(
                {
                    "resource_id": str((after or before)["resource_id"]),
                    "path": display_path,
                    "old_path": before_path if before_path != after_path else None,
                    "before_path": before_path,
                    "after_path": after_path,
                    "status": status,
                    "content_changed": bool(
                        before is None
                        or after is None
                        or before["content_sha256"] != after["content_sha256"]
                    ),
                    "before_sha256": before["content_sha256"] if before else None,
                    "after_sha256": after["content_sha256"] if after else None,
                    "metadata_delta": {
                        "before": (
                            {"kind": before["kind"], "media_type": before["media_type"]}
                            if before
                            else None
                        ),
                        "after": (
                            {"kind": after["kind"], "media_type": after["media_type"]}
                            if after
                            else None
                        ),
                    },
                    "dependency_impact": bool(
                        display_path == "spell-project.yaml"
                        or (before or after or {}).get("kind")
                        in {"PROCEDURE", "LIBRARY", "DICTIONARY", "PROJECT_METADATA"}
                    ),
                    "patch": patch,
                }
            )

        def manifest_dependencies(values: Mapping[str, dict[str, Any]]) -> list[Any]:
            manifest = values.get("spell-project.yaml")
            if manifest is None:
                return []
            parsed = _strict_json_document(manifest["content"], "project manifest")
            dependencies = parsed.get("catalog_dependencies", [])
            return list(dependencies) if type(dependencies) is list else []

        return {
            "history_revision_id": history_revision_id,
            "against_revision_id": against_revision_id,
            "changes": changes,
            "dependency_delta": {
                "before": manifest_dependencies(left),
                "after": manifest_dependencies(right),
            },
            "validation_delta": {
                "before_digest": before_validation_digest,
                "after_digest": after_validation_digest,
                "changed": before_validation_digest != after_validation_digest,
            },
        }

    def diff_history(
        self,
        history_revision_id: Any,
        *,
        subject: Any,
        role: Any,
        against_revision_id: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(history_revision_id, "history_revision_id")
        against = require_identifier(against_revision_id, "against_revision_id")
        with self.factory() as session:
            current = session.get(DevelopmentHistoryRevision, identifier)
            base = session.get(DevelopmentHistoryRevision, against)
            if current is None or base is None or current.project_id != base.project_id:
                raise DevelopmentNotFoundError("history revision was not found")
            left = self._snapshot_map(base)
            right = self._snapshot_map(current)
            return {
                "diff": self._diff_maps(
                    left,
                    right,
                    history_revision_id=identifier,
                    against_revision_id=against,
                    before_validation_digest=base.validation_summary_digest,
                    after_validation_digest=current.validation_summary_digest,
                )
            }

    @staticmethod
    def _workspace_map(rows: Iterable[DevelopmentResource]) -> dict[str, dict[str, Any]]:
        return {
            row.path: {
                "content": bytes(row.content),
                "content_sha256": row.content_sha256,
                "kind": row.kind,
                "media_type": row.media_type,
                "path": row.path,
                "resource_id": row.resource_id,
            }
            for row in rows
        }

    def _workspace_diff(
        self,
        session: Session,
        project: DevelopmentProject,
    ) -> dict[str, Any]:
        rows = self._resource_rows(session, project.project_id)
        right = self._workspace_map(rows)
        base = (
            session.get(DevelopmentHistoryRevision, project.base_history_revision_id)
            if project.base_history_revision_id is not None
            else None
        )
        if project.base_history_revision_id is not None and base is None:
            raise DevelopmentCorruptionError("workspace base history revision is missing")
        left = self._snapshot_map(base) if base is not None else {}
        analysis_entries = self._analysis_inputs(rows)
        _, tree_digest = canonical_tree(
            analysis_entries, case_policy=project.case_policy
        )
        after_validation_digest: str | None = None
        try:
            job = self._latest_completed_job(
                session,
                project.project_id,
                int(project.workspace_revision),
                expected_inputs={
                    str(entry["path"]): sha256_bytes(bytes(entry["content"]))
                    for entry in analysis_entries
                },
                expected_tree_digest=tree_digest,
            )
        except DevelopmentConflictError:
            pass
        else:
            report = strict_json_bytes(job.report or b"{}", "analysis report")
            after_validation_digest = self._validation_summary_digest(report)
        return self._diff_maps(
            left,
            right,
            history_revision_id=None,
            against_revision_id=(base.history_revision_id if base is not None else None),
            before_validation_digest=(
                base.validation_summary_digest if base is not None else None
            ),
            after_validation_digest=after_validation_digest,
        )

    def workspace_status(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        with self.factory() as session:
            project = self._project(session, identifier)
            diff = self._workspace_diff(session, project)
            return {
                "status": {
                    "project_id": identifier,
                    "workspace_revision": int(project.workspace_revision),
                    "base_history_revision_id": project.base_history_revision_id,
                    "clean": not diff["changes"],
                    "change_count": len(diff["changes"]),
                    "changes": [
                        {
                            "resource_id": item["resource_id"],
                            "path": item["path"],
                            "old_path": item["old_path"],
                            "status": item["status"],
                            "before_sha256": item["before_sha256"],
                            "after_sha256": item["after_sha256"],
                        }
                        for item in diff["changes"]
                    ],
                }
            }

    def diff_workspace_to_base(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        with self.factory() as session:
            project = self._project(session, identifier)
            return {
                "diff": {
                    **self._workspace_diff(session, project),
                    "project_id": identifier,
                    "workspace_revision": int(project.workspace_revision),
                }
            }

    def refresh_base(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        history_revision_id: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        history_id = require_identifier(
            history_revision_id, "history_revision_id"
        )
        expected = require_revision(expected_workspace_revision)
        request = {
            "history_revision_id": history_id,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            target = session.get(DevelopmentHistoryRevision, history_id)
            if target is None or target.project_id != identifier:
                raise DevelopmentNotFoundError("history revision was not found")
            current_diff = self._workspace_diff(session, project)
            if current_diff["changes"]:
                raise DevelopmentConflictError(
                    "workspace has local changes and cannot refresh its base",
                    code="WORKSPACE_DIRTY",
                    current={"change_count": len(current_diff["changes"])},
                )
            entries = self._snapshot_resources(target.snapshot_bytes)
            self._validate_frozen_entries(
                project,
                entries,
                workspace_revision=expected,
            )
            session.execute(
                delete(DevelopmentProblem).where(
                    DevelopmentProblem.project_id == identifier
                )
            )
            session.execute(
                delete(DevelopmentDictionaryArtifact).where(
                    DevelopmentDictionaryArtifact.project_id == identifier
                )
            )
            session.execute(
                delete(DevelopmentCatalogSnapshot).where(
                    DevelopmentCatalogSnapshot.project_id == identifier
                )
            )
            session.execute(
                delete(DevelopmentResource).where(
                    DevelopmentResource.project_id == identifier
                )
            )
            for entry in entries:
                resource = DevelopmentResource(
                    resource_id=entry["resource_id"],
                    project_id=identifier,
                    path=entry["path"],
                    path_identity=path_identity(entry["path"], project.case_policy),
                    kind=entry["kind"],
                    media_type=entry["media_type"],
                    content=entry["content"],
                    content_sha256=entry["content_sha256"],
                    byte_length=len(entry["content"]),
                    revision=1,
                    created_by_subject=actor.subject,
                    updated_by_subject=actor.subject,
                )
                session.add(resource)
                self._replace_resource_projection(
                    session,
                    resource,
                    _validate_resource_document(
                        kind=resource.kind,
                        media_type=resource.media_type,
                        raw=bytes(resource.content),
                    ),
                )
            manifest_entry = next(
                entry for entry in entries if entry["path"] == "spell-project.yaml"
            )
            project.manifest = self._manifest(
                _strict_json_document(manifest_entry["content"], "project manifest"),
                project_id=project.project_id,
                display_name=project.display_name,
                case_policy=project.case_policy,
                owner=project.owner_subject,
            )
            project.base_history_revision_id = history_id
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            session.flush()
            self._require_project_tree(
                project, self._resource_rows(session, identifier)
            )
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="REFRESH_BASE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={"history_revision_id": history_id},
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {
                "project": _project_dict(project),
                "base_history_revision": _history_dict(target),
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:history:refresh-base",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def review_history(
        self,
        history_revision_id: Any,
        *,
        subject: Any,
        role: Any,
        decision: Any,
        reason: Any,
        expected_review_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, admin=True)
        identifier = require_identifier(history_revision_id, "history_revision_id")
        if decision != "APPROVE":
            raise DevelopmentError("history review decision is invalid")
        bounded_reason = require_text(reason, "reason", 4096)
        expected = require_revision(expected_review_revision, "expected_review_revision")
        request = {
            "decision": decision,
            "reason": bounded_reason,
            "expected_review_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            history = session.get(DevelopmentHistoryRevision, identifier)
            if history is None:
                raise DevelopmentNotFoundError("history revision was not found")
            if history.author_subject == actor.subject:
                raise DevelopmentAuthorizationError("history author cannot review the same revision")
            existing = session.scalar(
                select(DevelopmentHistoryReview).where(
                    DevelopmentHistoryReview.history_revision_id == identifier
                )
            )
            current_revision = int(existing.review_revision) if existing is not None else 0
            if current_revision != expected:
                raise DevelopmentConflictError(
                    "history review revision differs",
                    code="REVISION_CONFLICT",
                    current={"review_revision": current_revision},
                )
            if existing is not None:
                raise DevelopmentConflictError("history revision is already reviewed")
            review = DevelopmentHistoryReview(
                review_id=_id(),
                history_revision_id=identifier,
                review_revision=1,
                reviewer_subject=actor.subject,
                decision="APPROVED",
                reason=bounded_reason,
            )
            session.add(review)
            self._audit(
                session,
                actor,
                project_id=history.project_id,
                action="REVIEW_HISTORY",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=0,
                new_revision=1,
                payload={"history_revision_id": identifier, "decision": "APPROVED"},
                outbox_topic="development.history.reviewed",
                aggregate_id=identifier,
            )
            session.flush()
            return {"history_revision": _history_dict(history), "review": _review_dict(review)}

        return self._mutate(
            actor,
            scope=f"history:{identifier}:review",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def revert_history(
        self,
        history_revision_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        reason: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(history_revision_id, "history_revision_id")
        expected = require_revision(expected_workspace_revision)
        bounded_reason = require_text(reason, "reason", 4096)
        request = {"expected_workspace_revision": expected, "reason": bounded_reason}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            history = session.get(DevelopmentHistoryRevision, identifier)
            if history is None:
                raise DevelopmentNotFoundError("history revision was not found")
            project = self._project(session, history.project_id)
            self._author(project, actor)
            self._check_revision(project, expected)
            entries = self._snapshot_resources(history.snapshot_bytes)
            _require_tree_integrity(entries, case_policy=project.case_policy)
            session.execute(
                delete(DevelopmentProblem).where(DevelopmentProblem.project_id == project.project_id)
            )
            session.execute(
                delete(DevelopmentDictionaryArtifact).where(
                    DevelopmentDictionaryArtifact.project_id == project.project_id
                )
            )
            session.execute(
                delete(DevelopmentCatalogSnapshot).where(
                    DevelopmentCatalogSnapshot.project_id == project.project_id
                )
            )
            session.execute(
                delete(DevelopmentResource).where(DevelopmentResource.project_id == project.project_id)
            )
            for entry in entries:
                resource = DevelopmentResource(
                        resource_id=entry["resource_id"],
                        project_id=project.project_id,
                        path=entry["path"],
                        path_identity=path_identity(entry["path"], project.case_policy),
                        kind=entry["kind"],
                        media_type=entry["media_type"],
                        content=entry["content"],
                        content_sha256=entry["content_sha256"],
                        byte_length=len(entry["content"]),
                        revision=1,
                        created_by_subject=actor.subject,
                        updated_by_subject=actor.subject,
                    )
                session.add(resource)
                self._replace_resource_projection(
                    session,
                    resource,
                    _validate_resource_document(
                        kind=resource.kind,
                        media_type=resource.media_type,
                        raw=bytes(resource.content),
                    ),
                )
            manifest_entry = next(
                (entry for entry in entries if entry["path"] == "spell-project.yaml"),
                None,
            )
            if manifest_entry is None:
                raise DevelopmentCorruptionError("history snapshot lacks project manifest")
            project.manifest = self._manifest(
                _strict_json_document(manifest_entry["content"], "project manifest"),
                project_id=project.project_id,
                display_name=project.display_name,
                case_policy=project.case_policy,
                owner=project.owner_subject,
            )
            session.flush()
            self._require_project_tree(
                project, self._resource_rows(session, project.project_id)
            )
            project.workspace_revision += 1
            project.base_history_revision_id = identifier
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=project.project_id,
                action="REVERT_AS_NEW_CHANGE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={"history_revision_id": identifier, "reason": bounded_reason},
                outbox_topic="development.workspace.changed",
                aggregate_id=project.project_id,
            )
            session.flush()
            return {"project": _project_dict(project), "reverted_to": identifier}

        return self._mutate(
            actor,
            scope=f"history:{identifier}:revert",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def resolve_conflict(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        path: Any,
        resolution: Any,
        resolved_content: Any,
        expected_conflict_digest: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        bounded_path = normalize_path(path, allow_manifest=False)
        if resolution not in {"OURS", "THEIRS", "MERGED", "DELETE"}:
            raise DevelopmentError("conflict resolution is invalid")
        digest = require_digest(expected_conflict_digest, "expected_conflict_digest")
        expected = require_revision(expected_workspace_revision)
        merged = _content(resolved_content) if resolution == "MERGED" else None
        request = {
            "path": bounded_path,
            "resolution": resolution,
            "resolved_content_sha256": sha256_bytes(merged) if merged is not None else None,
            "expected_conflict_digest": digest,
            "expected_workspace_revision": expected,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            conflict = session.scalar(
                select(DevelopmentConflict)
                .where(
                    DevelopmentConflict.project_id == identifier,
                    DevelopmentConflict.path == bounded_path,
                    DevelopmentConflict.conflict_digest == digest,
                    DevelopmentConflict.resolved.is_(False),
                )
                .with_for_update()
            )
            if conflict is None:
                raise DevelopmentNotFoundError("conflict was not found")
            if int(project.workspace_revision) != int(conflict.detected_workspace_revision):
                raise DevelopmentConflictError(
                    "conflict is stale for the current workspace",
                    code="STALE_CONFLICT",
                    current={"workspace_revision": int(project.workspace_revision)},
                )

            resource = None
            if conflict.ours_resource_id is not None:
                resource = session.scalar(
                    select(DevelopmentResource)
                    .where(
                        DevelopmentResource.resource_id == conflict.ours_resource_id,
                        DevelopmentResource.project_id == identifier,
                    )
                    .with_for_update()
                )
                if (
                    resource is None
                    or int(resource.revision)
                    != int(conflict.ours_resource_revision or -1)
                    or resource.path != conflict.ours_path
                    or resource.kind != conflict.ours_kind
                    or resource.media_type != conflict.ours_media_type
                    or bytes(resource.content) != bytes(conflict.ours_content or b"")
                ):
                    raise DevelopmentConflictError(
                        "conflict resource has changed since detection",
                        code="STALE_CONFLICT",
                        current={"workspace_revision": int(project.workspace_revision)},
                    )
            else:
                unexpected = session.scalar(
                    select(DevelopmentResource.resource_id).where(
                        DevelopmentResource.project_id == identifier,
                        DevelopmentResource.path_identity
                        == path_identity(conflict.base_path, project.case_policy),
                    )
                )
                if unexpected is not None:
                    raise DevelopmentConflictError(
                        "conflict resource has changed since detection",
                        code="STALE_CONFLICT",
                        current={"workspace_revision": int(project.workspace_revision)},
                    )

            descendants: list[DevelopmentResource] = []
            if resource is not None:
                descendants = list(
                    session.scalars(
                        select(DevelopmentResource)
                        .where(
                            DevelopmentResource.project_id == identifier,
                            DevelopmentResource.path.like(
                                _descendant_pattern(resource.path), escape="\\"
                            ),
                        )
                        .order_by(DevelopmentResource.path)
                        .with_for_update()
                    ).all()
                )

            if resolution == "OURS":
                selected_exists = conflict.ours_resource_id is not None
                selected_path = conflict.ours_path
                selected_kind = conflict.ours_kind
                selected_media = conflict.ours_media_type
                selected_content = conflict.ours_content
            elif resolution == "THEIRS":
                selected_exists = conflict.theirs_content is not None
                selected_path = conflict.path
                selected_kind = conflict.theirs_kind
                selected_media = conflict.theirs_media_type
                selected_content = conflict.theirs_content
            elif resolution == "MERGED":
                selected_exists = True
                selected_path = conflict.path
                selected_kind = conflict.theirs_kind or conflict.ours_kind or conflict.base_kind
                selected_media = (
                    conflict.theirs_media_type
                    or conflict.ours_media_type
                    or conflict.base_media_type
                )
                selected_content = merged
            else:
                selected_exists = False
                selected_path = conflict.ours_path or conflict.base_path
                selected_kind = None
                selected_media = None
                selected_content = None

            resolved_resource: DevelopmentResource | None = None
            if not selected_exists:
                subtree = [resource, *descendants] if resource is not None else []
                subtree_ids = [item.resource_id for item in subtree]
                if subtree_ids:
                    session.execute(
                        delete(DevelopmentDictionaryArtifact).where(
                            DevelopmentDictionaryArtifact.resource_id.in_(subtree_ids)
                        )
                    )
                    session.execute(
                        delete(DevelopmentCatalogSnapshot).where(
                            DevelopmentCatalogSnapshot.resource_id.in_(subtree_ids)
                        )
                    )
                    for item in reversed(subtree):
                        session.delete(item)
            else:
                if (
                    selected_path is None
                    or selected_kind not in RESOURCE_KINDS
                    or selected_kind == "PROJECT"
                    or selected_media is None
                    or selected_content is None
                ):
                    raise DevelopmentCorruptionError("conflict selection is incomplete")
                selected_path = normalize_path(selected_path, allow_manifest=False)
                selected_content = bytes(selected_content)
                if selected_kind in {"SOURCE_FOLDER", "FOLDER"} and selected_content:
                    raise DevelopmentError("folder resources cannot contain bytes")
                if descendants and selected_kind not in {"SOURCE_FOLDER", "FOLDER"}:
                    raise DevelopmentConflictError(
                        "a non-empty folder cannot change resource kind",
                        code="RESOURCE_HAS_CHILDREN",
                    )
                projection = _validate_resource_document(
                    kind=selected_kind,
                    media_type=selected_media,
                    raw=selected_content,
                )
                content_digest = sha256_bytes(selected_content)
                count, total = self._resource_totals(session, identifier)
                resulting_total = total + len(selected_content) - (
                    int(resource.byte_length) if resource is not None else 0
                )
                if (
                    (resource is None and count >= MAX_RESOURCES)
                    or resulting_total > MAX_PROJECT_BYTES
                ):
                    raise DevelopmentLimitError("project resource limits would be exceeded")

                target_identity = path_identity(selected_path, project.case_policy)
                if resource is None:
                    target_collision = session.scalar(
                        select(DevelopmentResource.resource_id).where(
                            DevelopmentResource.project_id == identifier,
                            DevelopmentResource.path_identity == target_identity,
                        )
                    )
                    if target_collision is not None:
                        raise DevelopmentConflictError(
                            "resolved resource path collides", code="CASE_CONFLICT"
                        )
                    resource = DevelopmentResource(
                        resource_id=_id(),
                        project_id=identifier,
                        path=selected_path,
                        path_identity=target_identity,
                        kind=selected_kind,
                        media_type=selected_media,
                        content=selected_content,
                        content_sha256=content_digest,
                        byte_length=len(selected_content),
                        revision=1,
                        created_by_subject=actor.subject,
                        updated_by_subject=actor.subject,
                    )
                    session.add(resource)
                else:
                    old_path = resource.path
                    planned_paths = {resource.resource_id: selected_path}
                    for child in descendants:
                        planned_paths[child.resource_id] = normalize_path(
                            selected_path + child.path[len(old_path) :],
                            allow_manifest=False,
                        )
                    planned_identities = {
                        resource_id: path_identity(value, project.case_policy)
                        for resource_id, value in planned_paths.items()
                    }
                    if len(set(planned_identities.values())) != len(planned_identities):
                        raise DevelopmentConflictError(
                            "resolved subtree collides under the project case policy",
                            code="CASE_CONFLICT",
                        )
                    subtree_ids = set(planned_paths)
                    outside_rows = session.scalars(
                        select(DevelopmentResource).where(
                            DevelopmentResource.project_id == identifier,
                            DevelopmentResource.resource_id.not_in(subtree_ids),
                        )
                    ).all()
                    outside_identities = {item.path_identity for item in outside_rows}
                    if any(
                        identity in outside_identities
                        for identity in planned_identities.values()
                    ):
                        raise DevelopmentConflictError(
                            "resolved resource path collides", code="CASE_CONFLICT"
                        )
                    if (
                        selected_path != old_path
                        and selected_path.casefold() == old_path.casefold()
                    ):
                        for item in [resource, *descendants]:
                            temporary_path = normalize_path(
                                f"case-rename-{item.resource_id}",
                                allow_manifest=False,
                            )
                            item.path = temporary_path
                            item.path_identity = path_identity(
                                temporary_path, project.case_policy
                            )
                        session.flush()
                    resource.path = selected_path
                    resource.path_identity = target_identity
                    resource.kind = selected_kind
                    resource.media_type = selected_media
                    resource.content = selected_content
                    resource.content_sha256 = content_digest
                    resource.byte_length = len(selected_content)
                    resource.revision += 1
                    resource.updated_by_subject = actor.subject
                    resource.updated_at_database_time = utc_now()
                    for child in descendants:
                        child.path = planned_paths[child.resource_id]
                        child.path_identity = planned_identities[child.resource_id]
                        child.revision += 1
                        child.updated_by_subject = actor.subject
                        child.updated_at_database_time = utc_now()
                    if old_path in project.manifest.get("source_roots", []) and selected_path != old_path:
                        project.manifest = self._manifest(
                            {
                                **project.manifest,
                                "source_roots": [
                                    selected_path if item == old_path else item
                                    for item in project.manifest["source_roots"]
                                ],
                            },
                            project_id=project.project_id,
                            display_name=project.display_name,
                            case_policy=project.case_policy,
                            owner=project.owner_subject,
                        )
                        manifest_row = session.scalar(
                            select(DevelopmentResource).where(
                                DevelopmentResource.project_id == identifier,
                                DevelopmentResource.path == "spell-project.yaml",
                            )
                        )
                        if manifest_row is None:
                            raise DevelopmentCorruptionError(
                                "project manifest resource is missing"
                            )
                        manifest_bytes = canonical_json_bytes(project.manifest)
                        manifest_row.content = manifest_bytes
                        manifest_row.content_sha256 = sha256_bytes(manifest_bytes)
                        manifest_row.byte_length = len(manifest_bytes)
                        manifest_row.revision += 1
                        manifest_row.updated_by_subject = actor.subject
                        manifest_row.updated_at_database_time = utc_now()
                self._replace_resource_projection(session, resource, projection)
                resolved_resource = resource

            session.flush()
            resolved_rows = self._resource_rows(session, project.project_id)
            self._require_project_tree(project, resolved_rows)
            _, _, validation_report = self._validate_frozen_entries(
                project,
                [
                    {
                        "content": bytes(item.content),
                        "content_sha256": item.content_sha256,
                        "kind": item.kind,
                        "media_type": item.media_type,
                        "path": item.path,
                        "resource_id": item.resource_id,
                    }
                    for item in resolved_rows
                ],
                workspace_revision=expected + 1,
            )
            validation = strict_json_bytes(
                validation_report, "conflict resolution validation report"
            )
            if validation["outcome"] != "PASS":
                raise DevelopmentConflictError(
                    "conflict resolution has blocking diagnostics",
                    code="VALIDATION_FAILED",
                    current={"diagnostics": validation["diagnostics"][:100]},
                )
            resolution_digest = sha256_bytes(
                canonical_json_bytes(
                    {
                        "conflict_digest": conflict.conflict_digest,
                        "content_sha256": (
                            sha256_bytes(bytes(selected_content))
                            if selected_content is not None
                            else None
                        ),
                        "kind": selected_kind,
                        "media_type": selected_media,
                        "path": selected_path,
                        "resolution": resolution,
                    }
                )
            )
            conflict.resolved = True
            conflict.resolution_digest = resolution_digest
            conflict.resolved_at_database_time = utc_now()
            project.workspace_revision += 1
            project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="RESOLVE_CONFLICT",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={
                    "conflict_id": conflict.conflict_id,
                    "resolution": resolution,
                    "resolved_path": selected_path,
                    "descendant_count": len(descendants),
                },
                outbox_topic="development.workspace.changed",
                aggregate_id=identifier,
            )
            session.flush()
            return {
                "project": _project_dict(project),
                "resource": (
                    _resource_dict(resolved_resource)
                    if resolved_resource is not None
                    else None
                ),
                "conflict": {
                    "conflict_id": conflict.conflict_id,
                    "conflict_digest": conflict.conflict_digest,
                    "resolved": True,
                    "resolution_digest": resolution_digest,
                },
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:conflict:{digest}",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def dismiss_conflict(
        self,
        project_id: Any,
        conflict_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_conflict_digest: Any,
        expected_workspace_revision: Any,
        reason: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        bounded_conflict_id = require_identifier(conflict_id, "conflict_id")
        digest = require_digest(expected_conflict_digest, "expected_conflict_digest")
        expected = require_revision(expected_workspace_revision)
        bounded_reason = require_text(reason, "reason", 4096)
        request = {
            "expected_conflict_digest": digest,
            "expected_workspace_revision": expected,
            "reason": bounded_reason,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            conflict = session.scalar(
                select(DevelopmentConflict)
                .where(
                    DevelopmentConflict.conflict_id == bounded_conflict_id,
                    DevelopmentConflict.project_id == identifier,
                    DevelopmentConflict.conflict_digest == digest,
                    DevelopmentConflict.resolved.is_(False),
                )
                .with_for_update()
            )
            if conflict is None:
                raise DevelopmentNotFoundError("conflict was not found")
            if int(conflict.detected_workspace_revision) == int(project.workspace_revision):
                raise DevelopmentConflictError(
                    "a current conflict must be resolved rather than dismissed",
                    code="CONFLICT_NOT_STALE",
                    current={"workspace_revision": int(project.workspace_revision)},
                )
            resolution_digest = sha256_bytes(
                canonical_json_bytes(
                    {
                        "conflict_digest": conflict.conflict_digest,
                        "reason": bounded_reason,
                        "resolution": "DISMISSED_STALE",
                        "workspace_revision": int(project.workspace_revision),
                    }
                )
            )
            conflict.resolved = True
            conflict.resolution_digest = resolution_digest
            conflict.resolved_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="DISMISS_STALE_CONFLICT",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={
                    "conflict_id": bounded_conflict_id,
                    "conflict_digest": digest,
                    "reason": bounded_reason,
                },
            )
            session.flush()
            return {
                "project": _project_dict(project),
                "conflict": {
                    "conflict_id": bounded_conflict_id,
                    "conflict_digest": digest,
                    "resolved": True,
                    "resolution": "DISMISSED_STALE",
                    "resolution_digest": resolution_digest,
                },
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:conflict:{bounded_conflict_id}:dismiss",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    @staticmethod
    def _archive_kind(path: str, is_directory: bool) -> tuple[str, str]:
        if path == "spell-project.yaml":
            return "PROJECT", "application/yaml"
        if is_directory:
            return "FOLDER", "application/x-directory"
        if path.endswith(".library.py"):
            return "LIBRARY", "text/x-python"
        if path.endswith(".spell.py"):
            return "PROCEDURE", "text/x-python"
        if path.endswith(".db"):
            return "DICTIONARY", DB_MEDIA_TYPE
        if path.endswith(".imp"):
            return "DICTIONARY", IMP_MEDIA_TYPE
        return "PROJECT_METADATA", "text/plain"

    @staticmethod
    def _read_project_archive(
        raw: bytes,
        *,
        case_policy: str,
        deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise DevelopmentLimitError("project archive exceeds its byte limit")
        operation_deadline = (
            time.monotonic() + MAX_IMPORT_SECONDS if deadline is None else deadline
        )
        try:
            archive = zipfile.ZipFile(io.BytesIO(raw), "r")
        except (OSError, zipfile.BadZipFile) as exc:
            raise DevelopmentError("project archive is invalid") from exc
        entries: list[dict[str, Any]] = []
        identities: set[str] = set()
        total = 0
        with archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise DevelopmentLimitError("project archive has too many entries")
            for info in infos:
                if time.monotonic() > operation_deadline:
                    raise DevelopmentLimitError(
                        "project import exceeded its processing-time bound"
                    )
                if info.flag_bits & 0x1:
                    raise DevelopmentError("encrypted archive entries are not allowed")
                if info.create_system != 3 or info.extra:
                    raise DevelopmentError(
                        "archive entry platform or link metadata is not allowed"
                    )
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise DevelopmentError("archive compression method is not allowed")
                name = info.filename[:-1] if info.is_dir() and info.filename.endswith("/") else info.filename
                path = normalize_path(name)
                identity = path_identity(path, case_policy)
                if identity in identities:
                    raise DevelopmentConflictError(
                        "archive paths collide", code="CASE_CONFLICT", current={"path": path}
                    )
                identities.add(identity)
                file_type = (info.external_attr >> 16) & 0o170000
                expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
                if file_type != expected_type:
                    raise DevelopmentError("archive contains a non-regular entry")
                if path.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".7z")):
                    raise DevelopmentError("nested archives are not allowed")
                if info.file_size > MAX_RESOURCE_BYTES:
                    raise DevelopmentLimitError("archive entry exceeds its byte limit")
                if info.compress_size == 0:
                    ratio = info.file_size if info.file_size else 1
                else:
                    ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise DevelopmentError("archive entry compression ratio is excessive")
                total += int(info.file_size)
                if total > MAX_PROJECT_BYTES:
                    raise DevelopmentLimitError(
                        "archive uncompressed bytes exceed the project limit"
                    )
                try:
                    content = archive.read(info)
                except (EOFError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
                    raise DevelopmentError(
                        "archive entry bytes or CRC are invalid"
                    ) from exc
                if len(content) != int(info.file_size):
                    raise DevelopmentError("archive entry byte length differs")
                if info.is_dir() and content:
                    raise DevelopmentError("archive directory entries must be empty")
                try:
                    content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise DevelopmentError("archive resources must be UTF-8 text") from exc
                if len(info.comment) > 1024:
                    raise DevelopmentLimitError("archive entry metadata exceeds its bound")
                if info.comment:
                    metadata = _strict_json_document(info.comment, "archive entry metadata")
                    if type(metadata) is not dict or set(metadata) != {
                        "kind",
                        "media_type",
                        "path",
                        "schema_version",
                    }:
                        raise DevelopmentError("archive entry metadata fields differ")
                    if (
                        metadata["schema_version"] != "spell.archive-resource/1"
                        or metadata["path"] != path
                        or canonical_json_bytes(metadata) != info.comment
                    ):
                        raise DevelopmentError("archive entry metadata identity differs")
                    kind = metadata["kind"]
                    media_type = metadata["media_type"]
                    if kind not in RESOURCE_KINDS or type(media_type) is not str:
                        raise DevelopmentError("archive entry metadata is invalid")
                    if path == "spell-project.yaml" and kind != "PROJECT":
                        raise DevelopmentError("archive manifest kind differs")
                    if path != "spell-project.yaml" and kind == "PROJECT":
                        raise DevelopmentError("archive resource kind is invalid")
                    if info.is_dir() != (kind in {"SOURCE_FOLDER", "FOLDER"}):
                        raise DevelopmentError("archive entry type differs from its metadata")
                    media_type = require_text(media_type, "media_type", 160)
                else:
                    kind, media_type = DevelopmentService._archive_kind(
                        path, info.is_dir()
                    )
                _validate_resource_document(
                    kind=kind,
                    media_type=media_type,
                    raw=content,
                )
                entries.append(
                    {
                        "path": path,
                        "path_identity": identity,
                        "kind": kind,
                        "media_type": media_type,
                        "content": content,
                        "content_sha256": sha256_bytes(content),
                    }
                )
        if "spell-project.yaml" not in {entry["path"] for entry in entries}:
            raise DevelopmentError("project archive manifest is missing")
        if time.monotonic() > operation_deadline:
            raise DevelopmentLimitError("project import exceeded its processing-time bound")
        return sorted(entries, key=lambda item: item["path"].encode("utf-8"))

    def import_project(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        original_filename: Any,
        original_media_type: Any,
        archive_bytes: bytes,
        archive_sha256: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
        retained_operation_id: Any = None,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        filename = require_text(original_filename, "original_filename", 512)
        media_type = require_text(original_media_type, "original_media_type", 160)
        if media_type != "application/vnd.openbexi.spell.project+zip":
            raise DevelopmentError("project archive media type is invalid")
        if type(archive_bytes) is not bytes:
            raise DevelopmentError("archive bytes are invalid")
        digest = require_digest(archive_sha256, "archive_sha256")
        if sha256_bytes(archive_bytes) != digest:
            raise DevelopmentError("archive SHA-256 differs")
        deadline = time.monotonic() + MAX_IMPORT_SECONDS
        expected = require_revision(expected_workspace_revision)
        key = require_idempotency_key(idempotency_key)
        retained_identifier = (
            require_identifier(retained_operation_id, "retained_operation_id")
            if retained_operation_id is not None
            else None
        )
        request = {
            "original_filename": filename,
            "original_media_type": media_type,
            "archive_sha256": digest,
            "expected_workspace_revision": expected,
            "retained_operation_id": retained_identifier,
        }
        scope = f"project:{identifier}:import"
        operation_id = retained_identifier or (
            "import-"
            + sha256_bytes(
                canonical_json_bytes(
                    {
                        "actor_subject": actor.subject,
                        "idempotency_key": key,
                        "project_id": identifier,
                    }
                )
            )[:48]
        )

        # Archive parsing, CRC/decompression, document validation, and tree
        # hashing happen before any write transaction is acquired.
        with self.factory() as read_session:
            observed_project = self._project(read_session, identifier)
            self._author(observed_project, actor)
            observed_case_policy = observed_project.case_policy
            observed_display_name = observed_project.display_name
            observed_owner_subject = observed_project.owner_subject
            observed_manifest = dict(observed_project.manifest)
            observed_rows = self._resource_rows(read_session, identifier)
            _, observed_tree_digest = canonical_tree(
                self._analysis_inputs(observed_rows),
                case_policy=observed_case_policy,
            )
        entries = self._read_project_archive(
            archive_bytes,
            case_policy=observed_case_policy,
            deadline=deadline,
        )
        manifest_entry = next(
            item for item in entries if item["path"] == "spell-project.yaml"
        )
        if len(manifest_entry["content"]) > MAX_MANIFEST_BYTES:
            raise DevelopmentLimitError("project manifest exceeds its byte limit")
        imported_manifest = _strict_json_document(
            manifest_entry["content"], "project manifest"
        )
        required_manifest_fields = {
            "schema_version",
            "project_id",
            "display_name",
            "language_profile",
            "source_roots",
            "case_policy",
            "catalog_dependencies",
            "owners",
            "policy_labels",
        }
        if type(imported_manifest) is not dict or set(imported_manifest) != required_manifest_fields:
            raise DevelopmentError("imported project manifest fields differ")
        bounded_imported_manifest = self._manifest(
            imported_manifest,
            project_id=identifier,
            display_name=observed_display_name,
            case_policy=observed_case_policy,
            owner=observed_owner_subject,
        )
        if (
            bounded_imported_manifest != imported_manifest
            or bounded_imported_manifest != observed_manifest
        ):
            raise DevelopmentConflictError(
                "imported project manifest differs from the target project",
                code="EXTERNAL_CHANGE_CONFLICT",
                current={"workspace_revision": expected},
            )
        _, imported_tree_digest = canonical_tree(
            entries, case_policy=observed_case_policy
        )
        if time.monotonic() > deadline:
            raise DevelopmentLimitError(
                "project import exceeded its processing-time bound"
            )

        try:
            with session_scope(self.factory) as quarantine_session:
                begin_mutation_write(quarantine_session)
                quarantine_project = self._project(quarantine_session, identifier)
                self._author(quarantine_project, actor)
                if quarantine_project.case_policy != observed_case_policy:
                    raise DevelopmentConflictError(
                        "project case policy changed during import",
                        code="EXTERNAL_CHANGE_CONFLICT",
                    )
                operation = quarantine_session.get(
                    DevelopmentImportProvenance, operation_id
                )
                if operation is None:
                    provenance_count = quarantine_session.scalar(
                        select(func.count())
                        .select_from(DevelopmentImportProvenance)
                        .where(
                            DevelopmentImportProvenance.project_id == identifier
                        )
                    )
                    if int(provenance_count or 0) >= MAX_IMPORT_PROVENANCE_PER_PROJECT:
                        raise DevelopmentLimitError(
                            "project import provenance limit is reached"
                        )
                    correlation_id = _id()
                    audit_id = self._audit(
                        quarantine_session,
                        actor,
                        project_id=identifier,
                        action="IMPORT_QUARANTINED",
                        correlation_id=correlation_id,
                        idempotency_key=key,
                        previous_revision=expected,
                        new_revision=int(quarantine_project.workspace_revision),
                        payload={
                            "operation_id": operation_id,
                            "archive_sha256": digest,
                            "original_byte_length": len(archive_bytes),
                        },
                    )
                    operation = DevelopmentImportProvenance(
                        operation_id=operation_id,
                        project_id=identifier,
                        actor_subject=actor.subject,
                        original_filename=filename,
                        original_media_type=media_type,
                        original_byte_length=len(archive_bytes),
                        original_bytes_sha256=digest,
                        original_bytes=archive_bytes,
                        imported_tree_sha256=imported_tree_digest,
                        canonical_tree_sha256=observed_tree_digest,
                        base_workspace_revision=expected,
                        status="QUARANTINED",
                        conflict_paths=[],
                        audit_id=audit_id,
                    )
                    quarantine_session.add(operation)
                elif (
                    operation.project_id != identifier
                    or operation.actor_subject != actor.subject
                    or operation.original_filename != filename
                    or operation.original_media_type != media_type
                    or int(operation.original_byte_length) != len(archive_bytes)
                    or operation.original_bytes_sha256 != digest
                    or bytes(operation.original_bytes) != archive_bytes
                    or operation.imported_tree_sha256 != imported_tree_digest
                    or (
                        retained_identifier is None
                        and int(operation.base_workspace_revision) != expected
                    )
                ):
                    raise DevelopmentConflictError(
                        "import operation identity differs",
                        code="IDEMPOTENCY_CONFLICT",
                    )
                elif retained_identifier is not None and operation.status != "APPLYING":
                    raise DevelopmentConflictError(
                        "import operation is not claimed for application",
                        code="IMPORT_OPERATION_CLOSED",
                    )
                elif retained_identifier is None:
                    successful_replay = quarantine_session.scalar(
                        select(DevelopmentIdempotency).where(
                            DevelopmentIdempotency.actor_subject == actor.subject,
                            DevelopmentIdempotency.operation_scope == scope,
                            DevelopmentIdempotency.idempotency_key == key,
                        )
                    )
                    if successful_replay is None:
                        raise DevelopmentConflictError(
                            "retained import operation must be applied or discarded explicitly",
                            code="IMPORT_OPERATION_CLOSED",
                            current={
                                "operation_id": operation_id,
                                "status": operation.status,
                            },
                        )
                quarantine_session.flush()
        except DevelopmentError:
            raise
        except Exception as exc:
            translated = self._translate_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            if project.case_policy != observed_case_policy:
                raise DevelopmentConflictError(
                    "project case policy changed during import",
                    code="EXTERNAL_CHANGE_CONFLICT",
                )
            operation = session.get(DevelopmentImportProvenance, operation_id)
            if operation is None:
                raise DevelopmentCorruptionError(
                    "import quarantine operation is unavailable"
                )
            expected_operation_status = (
                "APPLYING" if retained_identifier is not None else "QUARANTINED"
            )
            if operation.status != expected_operation_status:
                raise DevelopmentConflictError(
                    "import operation state changed before application",
                    code="IMPORT_OPERATION_CLOSED",
                    current={
                        "operation_id": operation_id,
                        "status": operation.status,
                    },
                )
            if bounded_imported_manifest != project.manifest:
                raise DevelopmentConflictError(
                    "imported project manifest differs from the target project",
                    code="EXTERNAL_CHANGE_CONFLICT",
                    current={"workspace_revision": expected},
                )
            existing = {
                row.path_identity: row for row in self._resource_rows(session, identifier)
            }
            conflicts = [
                entry["path"]
                for entry in entries
                if entry["path_identity"] in existing
                and (
                    existing[entry["path_identity"]].path != entry["path"]
                    or existing[entry["path_identity"]].kind != entry["kind"]
                    or existing[entry["path_identity"]].media_type != entry["media_type"]
                    or existing[entry["path_identity"]].content_sha256
                    != entry["content_sha256"]
                )
            ]
            if conflicts:
                raise DevelopmentConflictError(
                    "import conflicts with existing workspace resources",
                    code="EXTERNAL_CHANGE_CONFLICT",
                    current={"paths": conflicts, "workspace_revision": expected},
                )
            added: list[DevelopmentResource] = []
            for entry in entries:
                if entry["path_identity"] in existing:
                    continue
                row = DevelopmentResource(
                    resource_id=_id(),
                    project_id=identifier,
                    path=entry["path"],
                    path_identity=entry["path_identity"],
                    kind=entry["kind"],
                    media_type=entry["media_type"],
                    content=entry["content"],
                    content_sha256=entry["content_sha256"],
                    byte_length=len(entry["content"]),
                    revision=1,
                    created_by_subject=actor.subject,
                    updated_by_subject=actor.subject,
                )
                session.add(row)
                self._replace_resource_projection(
                    session,
                    row,
                    _validate_resource_document(
                        kind=row.kind,
                        media_type=row.media_type,
                        raw=bytes(row.content),
                    ),
                )
                added.append(row)
            tree_rows = [*existing.values(), *added]
            self._require_project_tree(project, tree_rows)
            if time.monotonic() > deadline:
                raise DevelopmentLimitError(
                    "project import exceeded its processing-time bound"
                )
            _, tree_digest = canonical_tree(
                self._analysis_inputs(tree_rows), case_policy=project.case_policy
            )
            operation.canonical_tree_sha256 = tree_digest
            operation.status = "APPLIED" if added else "NO_CHANGE"
            operation.conflict_paths = []
            if added:
                project.workspace_revision += 1
                project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="IMPORT_PROJECT",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(project.workspace_revision),
                payload={
                    "operation_id": operation_id,
                    "archive_sha256": digest,
                    "added": len(added),
                },
                outbox_topic="development.workspace.changed" if added else None,
                aggregate_id=identifier,
            )
            if time.monotonic() > deadline:
                raise DevelopmentLimitError(
                    "project import exceeded its processing-time bound"
                )
            session.flush()
            return {
                "project": _project_dict(project),
                "import": {
                    "operation_id": operation_id,
                    "original_filename": filename,
                    "original_bytes_sha256": digest,
                    "imported_tree_sha256": imported_tree_digest,
                    "canonical_tree_sha256": tree_digest,
                    "added": len(added),
                },
            }

        try:
            result = self._mutate(
                actor,
                scope=scope,
                idempotency_key=key,
                request=request,
                apply=apply,
            )
        except DevelopmentConflictError as exc:
            current = dict(exc.current) if isinstance(exc.current, dict) else {}
            conflict_paths = current.get("paths")
            bounded_paths = (
                [normalize_path(item) for item in conflict_paths[:MAX_RESOURCES]]
                if type(conflict_paths) is list
                else []
            )
            with session_scope(self.factory) as conflict_session:
                begin_mutation_write(conflict_session)
                operation = conflict_session.get(
                    DevelopmentImportProvenance, operation_id
                )
                if operation is not None and operation.status not in {
                    "APPLIED",
                    "NO_CHANGE",
                }:
                    if operation.status != "CONFLICT":
                        self._audit(
                            conflict_session,
                            actor,
                            project_id=identifier,
                            action="IMPORT_PROJECT_CONFLICT",
                            correlation_id=_id(),
                            idempotency_key=key,
                            previous_revision=expected,
                            new_revision=None,
                            payload={
                                "operation_id": operation_id,
                                "conflict_code": exc.code,
                                "paths": bounded_paths,
                            },
                        )
                    operation.status = "CONFLICT"
                    operation.conflict_paths = bounded_paths
            current["operation_id"] = operation_id
            raise DevelopmentConflictError(
                str(exc), code=exc.code, current=current
            ) from exc
        return result

    def get_import_operation(
        self,
        project_id: Any,
        operation_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        bounded_operation_id = require_identifier(operation_id, "operation_id")
        with self.factory() as session:
            self._project(session, identifier)
            row = session.get(DevelopmentImportProvenance, bounded_operation_id)
            if row is None or row.project_id != identifier:
                raise DevelopmentNotFoundError("import operation was not found")
            return {
                "import_operation": {
                    "operation_id": row.operation_id,
                    "project_id": row.project_id,
                    "actor_subject": row.actor_subject,
                    "original_filename": row.original_filename,
                    "original_media_type": row.original_media_type,
                    "original_byte_length": int(row.original_byte_length),
                    "original_bytes_sha256": row.original_bytes_sha256,
                    "original_bytes_available": True,
                    "imported_tree_sha256": row.imported_tree_sha256,
                    "canonical_tree_sha256": row.canonical_tree_sha256,
                    "base_workspace_revision": int(row.base_workspace_revision),
                    "status": row.status,
                    "conflict_paths": list(row.conflict_paths),
                    "audit_id": row.audit_id,
                    "created_at": _iso(row.created_at_database_time),
                }
            }

    def apply_import_operation(
        self,
        project_id: Any,
        operation_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        bounded_operation_id = require_identifier(operation_id, "operation_id")
        expected = require_revision(expected_workspace_revision)
        key = require_idempotency_key(idempotency_key)
        scope = f"project:{identifier}:import"
        replay_response: dict[str, Any] | None = None
        try:
            with session_scope(self.factory) as claim_session:
                begin_mutation_write(claim_session)
                project = self._project(claim_session, identifier)
                self._author(project, actor)
                row = claim_session.scalar(
                    select(DevelopmentImportProvenance)
                    .where(
                        DevelopmentImportProvenance.operation_id
                        == bounded_operation_id,
                        DevelopmentImportProvenance.project_id == identifier,
                    )
                    .with_for_update()
                )
                if row is None:
                    raise DevelopmentNotFoundError("import operation was not found")
                if row.actor_subject != actor.subject:
                    raise DevelopmentAuthorizationError(
                        "only the import actor may apply retained archive bytes"
                    )
                archive_bytes = bytes(row.original_bytes)
                filename = row.original_filename
                media_type = row.original_media_type
                digest = row.original_bytes_sha256
                retained_request = {
                    "original_filename": filename,
                    "original_media_type": media_type,
                    "archive_sha256": digest,
                    "expected_workspace_revision": expected,
                    "retained_operation_id": bounded_operation_id,
                }
                existing = claim_session.scalar(
                    select(DevelopmentIdempotency).where(
                        DevelopmentIdempotency.actor_subject == actor.subject,
                        DevelopmentIdempotency.operation_scope == scope,
                        DevelopmentIdempotency.idempotency_key == key,
                    )
                )
                if existing is not None:
                    if existing.request_sha256 != canonical_request_digest(
                        retained_request
                    ):
                        raise DevelopmentConflictError(
                            "idempotency key was used for another request",
                            code="IDEMPOTENCY_CONFLICT",
                        )
                    replay_response = {**existing.response, "replayed": True}
                else:
                    self._check_revision(project, expected)
                    if row.status not in {"QUARANTINED", "CONFLICT"}:
                        raise DevelopmentConflictError(
                            "import operation is not available for application",
                            code="IMPORT_OPERATION_CLOSED",
                        )
                    row.status = "APPLYING"
                    self._audit(
                        claim_session,
                        actor,
                        project_id=identifier,
                        action="CLAIM_IMPORT_OPERATION",
                        correlation_id=_id(),
                        idempotency_key=key,
                        previous_revision=expected,
                        new_revision=expected,
                        payload={"operation_id": bounded_operation_id},
                    )
                claim_session.flush()
        except DevelopmentError:
            raise
        except Exception as exc:
            translated = self._translate_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise
        if replay_response is not None:
            return {**replay_response, "source_operation_id": bounded_operation_id}
        try:
            result = self.import_project(
                identifier,
                subject=actor.subject,
                role=actor.role,
                original_filename=filename,
                original_media_type=media_type,
                archive_bytes=archive_bytes,
                archive_sha256=digest,
                expected_workspace_revision=expected,
                idempotency_key=key,
                retained_operation_id=bounded_operation_id,
            )
        except Exception as exc:
            failure_code = (
                exc.code if isinstance(exc, DevelopmentError) else "UNEXPECTED_FAILURE"
            )
            with session_scope(self.factory) as failure_session:
                begin_mutation_write(failure_session)
                failed = failure_session.get(
                    DevelopmentImportProvenance, bounded_operation_id
                )
                if failed is not None and failed.status == "APPLYING":
                    failed.status = "CONFLICT"
                    self._audit(
                        failure_session,
                        actor,
                        project_id=identifier,
                        action="IMPORT_OPERATION_APPLY_FAILED",
                        correlation_id=_id(),
                        idempotency_key=key,
                        previous_revision=expected,
                        new_revision=None,
                        payload={
                            "operation_id": bounded_operation_id,
                            "failure_code": failure_code,
                        },
                    )
            if isinstance(exc, DevelopmentError):
                current = dict(exc.current) if isinstance(exc.current, dict) else {}
                current["source_operation_id"] = bounded_operation_id
                if isinstance(exc, DevelopmentConflictError):
                    raise DevelopmentConflictError(
                        str(exc), code=exc.code, current=current
                    ) from exc
                exc.current = current
            raise
        return {**result, "source_operation_id": bounded_operation_id}

    def recover_import_operations(self) -> int:
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            rows = session.scalars(
                select(DevelopmentImportProvenance).where(
                    DevelopmentImportProvenance.status == "APPLYING"
                )
            ).all()
            for row in rows:
                row.status = "CONFLICT"
            return len(rows)

    def discard_import_operation(
        self,
        project_id: Any,
        operation_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
        reason: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        bounded_operation_id = require_identifier(operation_id, "operation_id")
        expected = require_revision(expected_workspace_revision)
        bounded_reason = require_text(reason, "reason", 4096)
        request = {
            "expected_workspace_revision": expected,
            "reason": bounded_reason,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            self._check_revision(project, expected)
            row = session.scalar(
                select(DevelopmentImportProvenance)
                .where(
                    DevelopmentImportProvenance.operation_id
                    == bounded_operation_id,
                    DevelopmentImportProvenance.project_id == identifier,
                )
                .with_for_update()
            )
            if row is None:
                raise DevelopmentNotFoundError("import operation was not found")
            if row.actor_subject != actor.subject:
                raise DevelopmentAuthorizationError(
                    "only the import actor may discard retained archive bytes"
                )
            if row.status not in {"QUARANTINED", "CONFLICT"}:
                raise DevelopmentConflictError(
                    "import operation is already closed",
                    code="IMPORT_OPERATION_CLOSED",
                )
            row.status = "DISCARDED"
            row.conflict_paths = []
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="DISCARD_IMPORT_OPERATION",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=expected,
                payload={
                    "operation_id": bounded_operation_id,
                    "reason": bounded_reason,
                },
            )
            session.flush()
            return {
                "project": _project_dict(project),
                "import_operation": {
                    "operation_id": bounded_operation_id,
                    "status": "DISCARDED",
                },
            }

        return self._mutate(
            actor,
            scope=f"project:{identifier}:import:{bounded_operation_id}:discard",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def export_project(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        expected_workspace_revision: Any,
    ) -> tuple[bytes, str]:
        self._actor(subject, role)
        identifier = require_identifier(project_id, "project_id")
        expected = require_revision(expected_workspace_revision)
        with self.factory() as session:
            project = self._project(session, identifier)
            self._check_revision(project, expected)
            rows = self._resource_rows(session, identifier)
            self._require_project_tree(project, rows)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                for row in rows:
                    is_directory = row.kind in {"FOLDER", "SOURCE_FOLDER"}
                    archive_path = row.path + "/" if is_directory else row.path
                    info = zipfile.ZipInfo(archive_path, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (
                        (stat.S_IFDIR | 0o755) if is_directory else (stat.S_IFREG | 0o644)
                    ) << 16
                    info.create_system = 3
                    info.comment = canonical_json_bytes(
                        {
                            "kind": row.kind,
                            "media_type": row.media_type,
                            "path": row.path,
                            "schema_version": "spell.archive-resource/1",
                        }
                    )
                    archive.writestr(info, row.content)
            raw = stream.getvalue()
            if len(raw) > MAX_ARCHIVE_BYTES:
                raise DevelopmentLimitError("export archive exceeds its byte limit")
            return raw, sha256_bytes(raw)

    def apply_external_changes(
        self,
        project_id: Any,
        *,
        subject: Any,
        role: Any,
        base_workspace_revision: Any,
        base_history_revision_id: Any = None,
        changes: Any,
        resolution: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(project_id, "project_id")
        base_revision = require_revision(base_workspace_revision, "base_workspace_revision")
        base_history_identifier = (
            require_identifier(base_history_revision_id, "base_history_revision_id")
            if base_history_revision_id is not None
            else None
        )
        if resolution not in {"RELOAD", "KEEP_AS_NEW_CHANGE", "THREE_WAY_MERGE"}:
            raise DevelopmentError("external-change resolution is invalid")
        if type(changes) is not list or len(changes) > MAX_RESOURCES:
            raise DevelopmentError("external changes are invalid")
        canonical_json_bytes(changes)
        request = {
            "base_workspace_revision": base_revision,
            "base_history_revision_id": base_history_identifier,
            "changes": changes,
            "resolution": resolution,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            project = self._project(session, identifier)
            self._author(project, actor)
            if resolution != "THREE_WAY_MERGE" and int(project.workspace_revision) != base_revision:
                raise DevelopmentConflictError(
                    "external change base revision differs",
                    code="EXTERNAL_CHANGE_CONFLICT",
                    current={"workspace_revision": int(project.workspace_revision)},
                )
            if resolution == "RELOAD":
                return {"project": _project_dict(project), "applied": 0, "reloaded": True}
            if resolution == "THREE_WAY_MERGE":
                if base_history_identifier is None:
                    raise DevelopmentError(
                        "base_history_revision_id is required for a three-way merge"
                    )
                base_history = session.get(
                    DevelopmentHistoryRevision, base_history_identifier
                )
                if (
                    base_history is None
                    or base_history.project_id != identifier
                    or int(base_history.workspace_revision) != base_revision
                ):
                    raise DevelopmentConflictError(
                        "three-way base history does not match the requested revision",
                        code="EXTERNAL_CHANGE_CONFLICT",
                    )
                base_map = self._snapshot_map(base_history)
                conflict_ids = []
                seen_paths: set[str] = set()
                for item in changes:
                    if type(item) is not dict or set(item).difference(
                        {
                            "path",
                            "from_path",
                            "content",
                            "content_sha256",
                            "delete",
                            "base_content_sha256",
                            "kind",
                            "media_type",
                        }
                    ) or "path" not in item:
                        raise DevelopmentError("external change item is invalid")
                    path = normalize_path(item["path"], allow_manifest=False)
                    from_path = normalize_path(
                        item.get("from_path", path), allow_manifest=False
                    )
                    identity = path_identity(path, project.case_policy)
                    if identity in seen_paths:
                        raise DevelopmentConflictError(
                            "external change paths collide", code="CASE_CONFLICT"
                        )
                    seen_paths.add(identity)
                    base_entry = base_map.get(from_path)
                    if base_entry is None:
                        raise DevelopmentConflictError(
                            "three-way merge requires an immutable base resource",
                            code="EXTERNAL_CHANGE_CONFLICT",
                            current={"path": from_path},
                        )
                    declared_base_digest = require_digest(
                        item.get("base_content_sha256"), "base_content_sha256"
                    )
                    if declared_base_digest != base_entry["content_sha256"]:
                        raise DevelopmentConflictError(
                            "three-way base content digest differs",
                            code="EXTERNAL_CHANGE_CONFLICT",
                            current={"path": from_path},
                        )
                    deleting = item.get("delete") is True
                    theirs = None if deleting else _content(item.get("content", ""))
                    theirs_kind = None
                    theirs_media_type = None
                    if theirs is not None:
                        theirs_digest = require_digest(
                            item.get("content_sha256"), "content_sha256"
                        )
                        if sha256_bytes(theirs) != theirs_digest:
                            raise DevelopmentError("external content SHA-256 differs")
                        theirs_kind = item.get("kind", base_entry["kind"])
                        if theirs_kind not in RESOURCE_KINDS or theirs_kind == "PROJECT":
                            raise DevelopmentError("external resource kind is invalid")
                        theirs_media_type = require_text(
                            item.get("media_type", base_entry["media_type"]),
                            "media_type",
                            160,
                        )
                        if theirs_kind in {"SOURCE_FOLDER", "FOLDER"} and theirs:
                            raise DevelopmentError("folder resources cannot contain bytes")
                        _validate_resource_document(
                            kind=str(theirs_kind),
                            media_type=theirs_media_type,
                            raw=theirs,
                        )
                    ours = session.get(
                        DevelopmentResource, str(base_entry["resource_id"])
                    )
                    if ours is not None and ours.project_id != identifier:
                        ours = None
                    kind = (
                        "RENAME_DELETE"
                        if deleting and ours is not None and ours.path != from_path
                        else "DELETE_MODIFY"
                        if deleting
                        else "CASE_COLLISION"
                        if from_path != path
                        and path_identity(from_path, project.case_policy) == identity
                        else "RENAME_RENAME"
                        if from_path != path
                        else "DEPENDENCY"
                        if base_entry["media_type"] == CATALOG_MEDIA_TYPE
                        else "METADATA"
                        if item.get("kind", base_entry["kind"]) != base_entry["kind"]
                        or item.get("media_type", base_entry["media_type"])
                        != base_entry["media_type"]
                        else "TEXT"
                    )
                    payload = canonical_json_bytes(
                        {
                            "base_history_revision_id": base_history_identifier,
                            "base_revision": base_revision,
                            "base": base_entry["content_sha256"],
                            "kind": kind,
                            "ours": ours.content_sha256 if ours else None,
                            "ours_resource_id": ours.resource_id if ours else None,
                            "ours_resource_revision": int(ours.revision) if ours else None,
                            "ours_path": ours.path if ours else None,
                            "ours_kind": ours.kind if ours else None,
                            "ours_media_type": ours.media_type if ours else None,
                            "path": path,
                            "theirs_kind": theirs_kind,
                            "theirs_media_type": theirs_media_type,
                            "theirs": sha256_bytes(theirs) if theirs is not None else None,
                            "workspace_revision": int(project.workspace_revision),
                        }
                    )
                    conflict = DevelopmentConflict(
                        conflict_id=_id(),
                        project_id=identifier,
                        path=path,
                        base_path=from_path,
                        kind=kind,
                        conflict_digest=sha256_bytes(payload),
                        base_history_revision_id=base_history_identifier,
                        base_workspace_revision=base_revision,
                        detected_workspace_revision=int(project.workspace_revision),
                        ours_resource_id=ours.resource_id if ours else None,
                        ours_resource_revision=int(ours.revision) if ours else None,
                        ours_path=ours.path if ours else None,
                        base_kind=base_entry["kind"],
                        base_media_type=base_entry["media_type"],
                        ours_kind=ours.kind if ours else None,
                        ours_media_type=ours.media_type if ours else None,
                        theirs_kind=str(theirs_kind) if theirs_kind is not None else None,
                        theirs_media_type=theirs_media_type,
                        base_content=base_entry["content"],
                        ours_content=ours.content if ours else None,
                        theirs_content=theirs,
                        resolved=False,
                    )
                    session.add(conflict)
                    conflict_ids.append(conflict.conflict_id)
                self._audit(
                    session,
                    actor,
                    project_id=identifier,
                    action="RECORD_EXTERNAL_CONFLICTS",
                    correlation_id=correlation_id,
                    idempotency_key=str(idempotency_key),
                    previous_revision=base_revision,
                    new_revision=int(project.workspace_revision),
                    payload={"conflict_ids": conflict_ids},
                )
                return {
                    "project": _project_dict(project),
                    "applied": 0,
                    "conflict_ids": conflict_ids,
                }
            applied = 0
            resource_count, projected_total = self._resource_totals(session, identifier)
            seen_change_identities: set[str] = set()
            for item in changes:
                if type(item) is not dict or set(item).difference(
                    {"path", "content", "content_sha256", "delete", "base_content_sha256", "kind", "media_type"}
                ):
                    raise DevelopmentError("external change item is invalid")
                path = normalize_path(item.get("path"), allow_manifest=False)
                change_identity = path_identity(path, project.case_policy)
                if change_identity in seen_change_identities:
                    raise DevelopmentConflictError(
                        "external change paths collide", code="CASE_CONFLICT"
                    )
                seen_change_identities.add(change_identity)
                row = session.scalar(
                    select(DevelopmentResource).where(
                        DevelopmentResource.project_id == identifier,
                        DevelopmentResource.path_identity
                        == path_identity(path, project.case_policy),
                    )
                )
                base_digest = item.get("base_content_sha256")
                deleting = item.get("delete") is True
                if base_digest is None and (row is not None or deleting):
                    raise DevelopmentConflictError(
                        "external change requires the current resource digest",
                        code="EXTERNAL_CHANGE_CONFLICT",
                        current={
                            "path": path,
                            "content_sha256": row.content_sha256 if row else None,
                        },
                    )
                if base_digest is not None:
                    require_digest(base_digest, "base_content_sha256")
                    if row is None or row.content_sha256 != base_digest:
                        raise DevelopmentConflictError(
                            "external resource digest differs",
                            code="EXTERNAL_CHANGE_CONFLICT",
                            current={"path": path, "content_sha256": row.content_sha256 if row else None},
                        )
                if deleting:
                    if row is not None:
                        if row.kind in {"SOURCE_FOLDER", "FOLDER"} and session.scalar(
                            select(DevelopmentResource.resource_id).where(
                                DevelopmentResource.project_id == identifier,
                                DevelopmentResource.path.like(
                                    _descendant_pattern(row.path), escape="\\"
                                ),
                            )
                        ) is not None:
                            raise DevelopmentConflictError(
                                "non-empty folder cannot be deleted",
                                code="RESOURCE_HAS_CHILDREN",
                            )
                        session.execute(
                            delete(DevelopmentDictionaryArtifact).where(
                                DevelopmentDictionaryArtifact.resource_id == row.resource_id
                            )
                        )
                        session.execute(
                            delete(DevelopmentCatalogSnapshot).where(
                                DevelopmentCatalogSnapshot.resource_id == row.resource_id
                            )
                        )
                        projected_total -= int(row.byte_length)
                        resource_count -= 1
                        session.delete(row)
                        applied += 1
                    continue
                raw = _content(item.get("content", ""))
                digest = require_digest(item.get("content_sha256"), "content_sha256")
                if sha256_bytes(raw) != digest:
                    raise DevelopmentError("external content SHA-256 differs")
                bounded_kind = item.get(
                    "kind",
                    row.kind
                    if row is not None
                    else "PROCEDURE"
                    if path.endswith(".spell.py")
                    else "DICTIONARY"
                    if path.endswith((".db", ".imp"))
                    else "PROJECT_METADATA",
                )
                if bounded_kind not in RESOURCE_KINDS or bounded_kind == "PROJECT":
                    raise DevelopmentError("external resource kind is invalid")
                bounded_media = item.get(
                    "media_type",
                    row.media_type
                    if row is not None
                    else "text/x-python"
                    if path.endswith(".spell.py")
                    else DB_MEDIA_TYPE
                    if path.endswith(".db")
                    else IMP_MEDIA_TYPE
                    if path.endswith(".imp")
                    else "text/plain",
                )
                bounded_media = require_text(bounded_media, "media_type", 160)
                projection = _validate_resource_document(
                    kind=str(bounded_kind), media_type=bounded_media, raw=raw
                )
                resulting_total = projected_total + len(raw) - (
                    int(row.byte_length) if row is not None else 0
                )
                resulting_count = resource_count + (1 if row is None else 0)
                if resulting_count > MAX_RESOURCES or resulting_total > MAX_PROJECT_BYTES:
                    raise DevelopmentLimitError("project resource limits would be exceeded")
                if row is None:
                    row = DevelopmentResource(
                        resource_id=_id(),
                        project_id=identifier,
                        path=path,
                        path_identity=path_identity(path, project.case_policy),
                        kind=str(bounded_kind),
                        media_type=bounded_media,
                        content=raw,
                        content_sha256=digest,
                        byte_length=len(raw),
                        revision=1,
                        created_by_subject=actor.subject,
                        updated_by_subject=actor.subject,
                    )
                    session.add(row)
                else:
                    row.kind = str(bounded_kind)
                    row.media_type = bounded_media
                    row.content = raw
                    row.content_sha256 = digest
                    row.byte_length = len(raw)
                    row.revision += 1
                    row.updated_by_subject = actor.subject
                    row.updated_at_database_time = utc_now()
                self._replace_resource_projection(session, row, projection)
                projected_total = resulting_total
                resource_count = resulting_count
                applied += 1
            session.flush()
            self._require_project_tree(project, self._resource_rows(session, identifier))
            if applied:
                project.workspace_revision += 1
                project.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=identifier,
                action="APPLY_EXTERNAL_CHANGES",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=base_revision,
                new_revision=int(project.workspace_revision),
                payload={"applied": applied, "resolution": resolution},
                outbox_topic="development.workspace.changed" if applied else None,
                aggregate_id=identifier,
            )
            session.flush()
            return {"project": _project_dict(project), "applied": applied}

        return self._mutate(
            actor,
            scope=f"project:{identifier}:external-changes",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    @staticmethod
    def _verify_history_evidence(
        session: Session,
        history: DevelopmentHistoryRevision,
        review: DevelopmentHistoryReview | None = None,
    ) -> dict[str, Any]:
        resources = DevelopmentService._snapshot_resources(history.snapshot_bytes)
        manifest_entry = next(
            (entry for entry in resources if entry["path"] == "spell-project.yaml"),
            None,
        )
        if manifest_entry is None:
            raise DevelopmentCorruptionError("history snapshot lacks project manifest")
        manifest = _strict_json_document(manifest_entry["content"], "project manifest")
        try:
            case_policy = require_case_policy(manifest["case_policy"])
        except (DevelopmentError, KeyError, TypeError) as exc:
            raise DevelopmentCorruptionError("history project manifest is invalid") from exc
        try:
            tree_bytes, tree_digest = canonical_tree(resources, case_policy=case_policy)
        except DevelopmentError as exc:
            raise DevelopmentCorruptionError("history source tree is invalid") from exc
        if tree_digest != history.tree_digest or tree_bytes != bytes(history.tree_bytes):
            raise DevelopmentCorruptionError("history source tree evidence differs")
        job = session.get(DevelopmentAnalysisJob, history.validation_job_id)
        if (
            job is None
            or job.project_id != history.project_id
            or int(job.workspace_revision) != int(history.workspace_revision)
            or job.scope != "PROJECT"
            or job.state != "COMPLETED"
            or job.report is None
            or job.report_sha256 is None
        ):
            raise DevelopmentConflictError(
                "completed history analysis evidence is unavailable",
                code="VALIDATION_REQUIRED",
            )
        raw_report = bytes(job.report)
        if sha256_bytes(raw_report) != job.report_sha256:
            raise DevelopmentCorruptionError("history analysis report digest differs")
        report = strict_json_bytes(raw_report, "history analysis report")
        if canonical_json_bytes(report) != raw_report:
            raise DevelopmentCorruptionError("history analysis report is not canonical")
        expected_inputs = {
            str(entry["path"]): str(entry["content_sha256"]) for entry in resources
        }
        if (
            report.get("outcome") != "PASS"
            or report.get("input_digests") != expected_inputs
            or job.input_digest != history.tree_digest
            or DevelopmentService._validation_summary_digest(report)
            != history.validation_summary_digest
        ):
            raise DevelopmentConflictError(
                "history analysis evidence does not cover the immutable tree",
                code="VALIDATION_STALE",
            )
        if review is not None and (
            review.history_revision_id != history.history_revision_id
            or review.decision != "APPROVED"
            or review.reviewer_subject == history.author_subject
        ):
            raise DevelopmentConflictError(
                "distinct-subject approved history review is required",
                code="REVIEW_REQUIRED",
            )
        return report

    @staticmethod
    def _bundle_payload(
        history: DevelopmentHistoryRevision,
        review: DevelopmentHistoryReview,
    ) -> tuple[bytes, dict[str, Any], list[str]]:
        resources = DevelopmentService._snapshot_resources(history.snapshot_bytes)
        if len(resources) > MAX_BUNDLE_ENTRIES:
            raise DevelopmentLimitError("bundle entry count exceeds its bound")
        project_manifest_entry = next(
            (item for item in resources if item["path"] == "spell-project.yaml"), None
        )
        if project_manifest_entry is None:
            raise DevelopmentCorruptionError("history snapshot lacks project manifest")
        if len(project_manifest_entry["content"]) > MAX_MANIFEST_BYTES:
            raise DevelopmentLimitError("project manifest exceeds its byte limit")
        project_manifest = _strict_json_document(
            project_manifest_entry["content"], "project manifest"
        )
        expected_project_fields = {
            "schema_version",
            "project_id",
            "display_name",
            "language_profile",
            "source_roots",
            "case_policy",
            "catalog_dependencies",
            "owners",
            "policy_labels",
        }
        if type(project_manifest) is not dict or set(project_manifest) != expected_project_fields:
            raise DevelopmentCorruptionError("project manifest fields differ")
        if (
            project_manifest["schema_version"] != PROJECT_SCHEMA_VERSION
            or project_manifest["project_id"] != history.project_id
            or project_manifest["language_profile"] != LANGUAGE_PROFILE
            or "LOCAL_SYNTHETIC_NON_CUI_ONLY" not in project_manifest["policy_labels"]
        ):
            raise DevelopmentCorruptionError("project manifest identity differs")
        catalog_by_key: dict[tuple[str, int], dict[str, Any]] = {}
        for resource in resources:
            if resource["media_type"] != CATALOG_MEDIA_TYPE:
                continue
            projection = _validate_resource_document(
                kind=resource["kind"],
                media_type=resource["media_type"],
                raw=resource["content"],
            )["catalog"]
            key = (
                projection["catalog_id"].casefold(),
                int(projection["catalog_revision"]),
            )
            if key in catalog_by_key:
                raise DevelopmentConflictError(
                    "bundle catalog snapshots collide", code="CASE_CONFLICT"
                )
            catalog_by_key[key] = projection
            if len(catalog_by_key) > MAX_BUNDLE_CATALOG_SNAPSHOTS:
                raise DevelopmentLimitError(
                    "bundle catalog snapshot count exceeds its bound"
                )
        closure: list[dict[str, Any]] = []
        visiting: set[tuple[str, int]] = set()
        visited: set[tuple[str, int]] = set()

        def visit(dependency: Mapping[str, Any]) -> None:
            if type(dependency) is not dict or set(dependency) != {
                "catalog_id",
                "catalog_revision",
                "content_digest",
            }:
                raise DevelopmentCorruptionError("bundle dependency fields differ")
            key = (
                require_identifier(dependency["catalog_id"], "catalog_id").casefold(),
                require_revision(dependency["catalog_revision"], "catalog_revision"),
            )
            if key in visiting:
                raise DevelopmentConflictError(
                    "bundle dependency graph contains a cycle",
                    code="DEPENDENCY_CYCLE",
                )
            if key in visited:
                return
            if len(visited) >= 1024:
                raise DevelopmentLimitError("bundle dependency graph exceeds its bound")
            snapshot = catalog_by_key.get(key)
            if snapshot is None:
                raise DevelopmentConflictError(
                    "bundle dependency is missing", code="DEPENDENCY_MISSING"
                )
            if snapshot["content_digest"] != dependency["content_digest"]:
                raise DevelopmentConflictError(
                    "bundle dependency digest differs",
                    code="DEPENDENCY_DIGEST_MISMATCH",
                )
            visiting.add(key)
            for child in snapshot["dependencies"]:
                visit(child)
            visiting.remove(key)
            visited.add(key)
            closure.append(
                {
                    "catalog_id": snapshot["catalog_id"],
                    "catalog_revision": int(snapshot["catalog_revision"]),
                    "content_digest": snapshot["content_digest"],
                }
            )

        for dependency in project_manifest["catalog_dependencies"]:
            visit(dependency)
        closure.sort(
            key=lambda item: (
                item["catalog_id"].casefold(),
                item["catalog_revision"],
                item["content_digest"],
            )
        )
        entries: list[dict[str, Any]] = []
        procedure_ids: list[str] = []
        ir_versions: set[str] = set()
        for resource in resources:
            entry = {
                "content": base64.b64encode(resource["content"]).decode("ascii"),
                "content_sha256": resource["content_sha256"],
                "kind": resource["kind"],
                "media_type": resource["media_type"],
                "path": resource["path"],
            }
            if resource["kind"] == "PROCEDURE":
                try:
                    source = resource["content"].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise DevelopmentError("bundle procedure source is not UTF-8") from exc
                result = analyze_source(
                    source,
                    resource["path"],
                    workspace_revision=int(history.workspace_revision),
                )
                if result.diagnostics or resource["path"] not in result.compiled:
                    raise DevelopmentConflictError(
                        "bundle source has blocking diagnostics",
                        code="VALIDATION_FAILED",
                        current={"path": resource["path"], "diagnostics": list(result.diagnostics)},
                    )
                compiled = result.compiled[resource["path"]]
                procedure_id = compiled["procedure_id"]
                if procedure_id.casefold() in {item.casefold() for item in procedure_ids}:
                    raise DevelopmentConflictError(
                        "bundle procedure identities collide", code="CASE_CONFLICT"
                    )
                procedure_ids.append(procedure_id)
                ir_versions.add(compiled["ir_version"])
                entry["compiled"] = {
                    "description": compiled["description"],
                    "ir_version": compiled["ir_version"],
                    "procedure_id": procedure_id,
                    "source_sha256": compiled["source_sha256"],
                    "steps": compiled["steps"],
                    "source_map": [
                        {
                            "step_index": index,
                            "source_line": int(step.get("line") or 1),
                        }
                        for index, step in enumerate(compiled["steps"])
                    ],
                    "user_actions": compiled["user_actions"],
                }
            entries.append(entry)
        if not procedure_ids:
            raise DevelopmentConflictError(
                "bundle requires at least one validated procedure",
                code="VALIDATION_REQUIRED",
            )
        if len(procedure_ids) != 1:
            raise DevelopmentConflictError(
                "a development bundle must contain exactly one procedure",
                code="BUNDLE_PROCEDURE_COUNT",
            )
        dependency_digests = sorted(
            {item["content_digest"] for item in closure}
        )
        manifest_without_digest = {
            "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
            "project_id": history.project_id,
            "procedure_ids": sorted(procedure_ids, key=lambda item: item.encode("utf-8")),
            "history_revision_id": history.history_revision_id,
            "source_tree_digest": history.tree_digest,
            "language_profile": "spell-restricted-ast/0.9",
            "compatibility_profile": COMPATIBILITY_PROFILE,
            "parser_version": TOOL_VERSION,
            "validator_version": TOOL_VERSION,
            "compiler_version": TOOL_VERSION,
            "ir_schema_version": sorted(ir_versions),
            "dependency_digests": dependency_digests,
            "catalog_digests": dependency_digests,
            "validation_report_digest": history.validation_summary_digest,
            "review_subject": review.reviewer_subject,
            "builder_identity": BUILDER_IDENTITY,
            "toolchain_digest": toolchain_digest(),
            "created_at_database_time": _iso(history.created_at_database_time),
        }
        payload = {
            "dependency_closure": closure,
            "entries": sorted(entries, key=lambda item: item["path"].encode("utf-8")),
            "format": "spell.bundle/1 canonical uncompressed entry stream",
            "manifest": manifest_without_digest,
            "validation_reference": {
                "history_revision_id": history.history_revision_id,
                "validation_report_digest": history.validation_summary_digest,
            },
        }
        if len(canonical_json_bytes(manifest_without_digest)) > 1_048_576:
            raise DevelopmentLimitError("bundle manifest exceeds its byte limit")
        return canonical_json_bytes(payload), manifest_without_digest, procedure_ids

    @staticmethod
    def _verify_bundle_row(row: DevelopmentBundle) -> dict[str, Any]:
        if sha256_bytes(row.bundle_bytes) != row.bundle_digest:
            raise DevelopmentCorruptionError("stored bundle digest differs")
        if int(row.byte_length) != len(row.bundle_bytes):
            raise DevelopmentCorruptionError("stored bundle byte length differs")
        if len(row.bundle_bytes) > MAX_PROJECT_BYTES:
            raise DevelopmentCorruptionError("stored bundle exceeds its byte limit")
        payload = strict_json_bytes(row.bundle_bytes, "bundle bytes")
        if type(payload) is not dict or set(payload) != {
            "dependency_closure",
            "entries",
            "format",
            "manifest",
            "validation_reference",
        }:
            raise DevelopmentCorruptionError("bundle payload schema differs")
        if canonical_json_bytes(payload) != bytes(row.bundle_bytes):
            raise DevelopmentCorruptionError("bundle bytes are not canonical")
        if payload["format"] != "spell.bundle/1 canonical uncompressed entry stream":
            raise DevelopmentCorruptionError("bundle format differs")
        manifest = row.manifest
        if type(manifest) is not dict or manifest.get("bundle_digest") != row.bundle_digest:
            raise DevelopmentCorruptionError("bundle database envelope differs")
        without_digest = {key: value for key, value in manifest.items() if key != "bundle_digest"}
        if without_digest != payload["manifest"]:
            raise DevelopmentCorruptionError("bundle manifest bytes differ from its envelope")
        if len(canonical_json_bytes(without_digest)) > 1_048_576:
            raise DevelopmentCorruptionError("bundle manifest exceeds its byte limit")
        required = {
            "bundle_schema_version",
            "project_id",
            "procedure_ids",
            "history_revision_id",
            "source_tree_digest",
            "language_profile",
            "compatibility_profile",
            "parser_version",
            "validator_version",
            "compiler_version",
            "ir_schema_version",
            "dependency_digests",
            "catalog_digests",
            "validation_report_digest",
            "review_subject",
            "builder_identity",
            "toolchain_digest",
            "created_at_database_time",
        }
        if set(without_digest) != required:
            raise DevelopmentCorruptionError("bundle manifest fields differ")
        if without_digest["bundle_schema_version"] != BUNDLE_SCHEMA_VERSION:
            raise DevelopmentCorruptionError("bundle manifest version differs")
        if (
            without_digest["project_id"] != row.project_id
            or without_digest["history_revision_id"] != row.history_revision_id
            or without_digest["source_tree_digest"] != row.source_tree_digest
            or without_digest["validation_report_digest"]
            != row.validation_report_digest
            or without_digest["review_subject"] != row.review_subject
            or without_digest["builder_identity"] != row.builder_identity
        ):
            raise DevelopmentCorruptionError("bundle manifest envelope identity differs")
        if (
            without_digest["compatibility_profile"] != COMPATIBILITY_PROFILE
            or without_digest["language_profile"] != LANGUAGE_PROFILE
            or without_digest["parser_version"] != TOOL_VERSION
            or without_digest["validator_version"] != TOOL_VERSION
            or without_digest["compiler_version"] != TOOL_VERSION
            or without_digest["builder_identity"] != BUILDER_IDENTITY
            or without_digest["toolchain_digest"] != toolchain_digest()
        ):
            raise DevelopmentCorruptionError("bundle compatibility profile differs")
        procedure_ids = without_digest["procedure_ids"]
        if type(procedure_ids) is not list or len(procedure_ids) != 1:
            raise DevelopmentCorruptionError("bundle procedure identity set differs")
        try:
            procedure_id = ProcedureCatalog._normalize_procedure_id(procedure_ids[0])
        except KeyError as exc:
            raise DevelopmentCorruptionError("bundle procedure identity is invalid") from exc
        for field, maximum in (("dependency_digests", 1024), ("catalog_digests", 128)):
            values = without_digest[field]
            if (
                type(values) is not list
                or len(values) > maximum
                or values != sorted(set(values))
            ):
                raise DevelopmentCorruptionError(f"bundle {field} are invalid")
            try:
                for value in values:
                    require_digest(value, field)
            except DevelopmentError as exc:
                raise DevelopmentCorruptionError(f"bundle {field} are invalid") from exc
        if without_digest["dependency_digests"] != without_digest["catalog_digests"]:
            raise DevelopmentCorruptionError("bundle dependency digest sets differ")
        ir_schema_versions = without_digest["ir_schema_version"]
        if (
            type(ir_schema_versions) is not list
            or not ir_schema_versions
            or any(
                type(version) is not str
                or version not in SUPPORTED_BUNDLE_IR_SCHEMA_VERSIONS
                for version in ir_schema_versions
            )
            or ir_schema_versions != sorted(set(ir_schema_versions))
        ):
            raise DevelopmentCorruptionError("bundle IR schema versions differ")
        validation_reference = payload["validation_reference"]
        if validation_reference != {
            "history_revision_id": row.history_revision_id,
            "validation_report_digest": row.validation_report_digest,
        }:
            raise DevelopmentCorruptionError("bundle validation reference differs")
        closure = payload["dependency_closure"]
        if type(closure) is not list or len(closure) > 1024:
            raise DevelopmentCorruptionError("bundle dependency closure is invalid")
        closure_digests: list[str] = []
        closure_keys: set[tuple[str, int]] = set()
        for dependency in closure:
            if type(dependency) is not dict or set(dependency) != {
                "catalog_id",
                "catalog_revision",
                "content_digest",
            }:
                raise DevelopmentCorruptionError("bundle dependency closure fields differ")
            try:
                key = (
                    require_identifier(dependency["catalog_id"], "catalog_id").casefold(),
                    require_revision(dependency["catalog_revision"], "catalog_revision"),
                )
                digest = require_digest(dependency["content_digest"], "content_digest")
            except DevelopmentError as exc:
                raise DevelopmentCorruptionError("bundle dependency closure is invalid") from exc
            if key in closure_keys:
                raise DevelopmentCorruptionError("bundle dependency closure has duplicates")
            closure_keys.add(key)
            closure_digests.append(digest)
        if sorted(set(closure_digests)) != without_digest["dependency_digests"]:
            raise DevelopmentCorruptionError("bundle dependency closure digest set differs")
        entries = payload["entries"]
        if type(entries) is not list or not entries or len(entries) > MAX_BUNDLE_ENTRIES:
            raise DevelopmentCorruptionError("bundle entries are invalid")
        previous_path: bytes | None = None
        path_identities: set[str] = set()
        resource_inputs: list[dict[str, Any]] = []
        procedure_count = 0
        observed_ir_versions: set[str] = set()
        catalog_digests: set[str] = set()
        catalog_snapshot_count = 0
        total_bytes = 0
        for entry in entries:
            common_fields = {
                "path",
                "kind",
                "media_type",
                "content",
                "content_sha256",
            }
            if type(entry) is not dict or frozenset(entry) not in {
                frozenset(common_fields),
                frozenset({*common_fields, "compiled"}),
            }:
                raise DevelopmentCorruptionError("bundle entry schema differs")
            try:
                path = normalize_path(entry["path"])
            except DevelopmentError as exc:
                raise DevelopmentCorruptionError("bundle entry path is invalid") from exc
            encoded_path = path.encode("utf-8")
            if previous_path is not None and encoded_path <= previous_path:
                raise DevelopmentCorruptionError("bundle entry order differs")
            previous_path = encoded_path
            identity = path.casefold()
            if identity in path_identities:
                raise DevelopmentCorruptionError("bundle entry paths collide")
            path_identities.add(identity)
            try:
                content = base64.b64decode(entry["content"], validate=True)
            except (TypeError, ValueError) as exc:
                raise DevelopmentCorruptionError("bundle entry bytes are invalid") from exc
            if (
                base64.b64encode(content).decode("ascii") != entry["content"]
                or sha256_bytes(content) != entry["content_sha256"]
            ):
                raise DevelopmentCorruptionError("bundle entry digest differs")
            if len(content) > MAX_RESOURCE_BYTES:
                raise DevelopmentCorruptionError("bundle entry exceeds its byte limit")
            total_bytes += len(content)
            if total_bytes > MAX_PROJECT_BYTES:
                raise DevelopmentCorruptionError("bundle content exceeds its byte limit")
            kind = entry["kind"]
            media_type = entry["media_type"]
            if kind not in RESOURCE_KINDS or type(media_type) is not str:
                raise DevelopmentCorruptionError("bundle entry metadata differs")
            resource_inputs.append(
                {
                    "path": path,
                    "kind": kind,
                    "media_type": media_type,
                    "content": content,
                }
            )
            if kind == "PROCEDURE":
                procedure_count += 1
                if set(entry) != {*common_fields, "compiled"}:
                    raise DevelopmentCorruptionError("bundle procedure compiled IR is missing")
                try:
                    source = content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise DevelopmentCorruptionError("bundle procedure is not UTF-8") from exc
                result = analyze_source(source, path, workspace_revision=0)
                if result.diagnostics or path not in result.compiled:
                    raise DevelopmentCorruptionError("bundle procedure no longer validates")
                compiled = result.compiled[path]
                expected_compiled = {
                    "description": compiled["description"],
                    "ir_version": compiled["ir_version"],
                    "procedure_id": compiled["procedure_id"],
                    "source_sha256": compiled["source_sha256"],
                    "steps": compiled["steps"],
                    "source_map": [
                        {
                            "step_index": index,
                            "source_line": int(step.get("line") or 1),
                        }
                        for index, step in enumerate(compiled["steps"])
                    ],
                    "user_actions": compiled["user_actions"],
                }
                if entry["compiled"] != expected_compiled or compiled["procedure_id"] != procedure_id:
                    raise DevelopmentCorruptionError("bundle compiled IR differs")
                observed_ir_versions.add(compiled["ir_version"])
            elif "compiled" in entry:
                raise DevelopmentCorruptionError("non-procedure bundle entry contains compiled IR")
            try:
                projection = _validate_resource_document(
                    kind=kind, media_type=media_type, raw=content
                )
            except DevelopmentError as exc:
                raise DevelopmentCorruptionError("bundle data resource is invalid") from exc
            if "catalog" in projection:
                catalog_snapshot_count += 1
                if catalog_snapshot_count > MAX_BUNDLE_CATALOG_SNAPSHOTS:
                    raise DevelopmentCorruptionError(
                        "bundle catalog snapshot count exceeds its bound"
                    )
                catalog_digests.add(projection["catalog"]["content_digest"])
        if procedure_count != 1:
            raise DevelopmentCorruptionError("bundle procedure count differs")
        if ir_schema_versions != sorted(observed_ir_versions):
            raise DevelopmentCorruptionError("bundle IR schema versions differ")
        if not set(without_digest["catalog_digests"]).issubset(catalog_digests):
            raise DevelopmentCorruptionError("bundle catalog snapshot closure is incomplete")
        try:
            _, source_tree_digest = canonical_tree(
                resource_inputs, case_policy="CASE_INSENSITIVE"
            )
        except DevelopmentError as exc:
            raise DevelopmentCorruptionError("bundle source tree is invalid") from exc
        if source_tree_digest != row.source_tree_digest:
            # Tree digest case policy is encoded by the project manifest; recompute it.
            project_entry = next(
                item for item in resource_inputs if item["path"] == "spell-project.yaml"
            )
            try:
                project_manifest = _strict_json_document(
                    project_entry["content"], "project manifest"
                )
                _, source_tree_digest = canonical_tree(
                    resource_inputs, case_policy=project_manifest["case_policy"]
                )
            except (DevelopmentError, KeyError) as exc:
                raise DevelopmentCorruptionError("bundle source tree is invalid") from exc
            if source_tree_digest != row.source_tree_digest:
                raise DevelopmentCorruptionError("bundle source tree digest differs")
        return payload

    def build_bundle(
        self,
        history_revision_id: Any,
        *,
        subject: Any,
        role: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, mutation=True)
        identifier = require_identifier(history_revision_id, "history_revision_id")
        request = {"history_revision_id": identifier}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            history = session.get(DevelopmentHistoryRevision, identifier)
            if history is None:
                raise DevelopmentNotFoundError("history revision was not found")
            project = self._project(session, history.project_id)
            self._author(project, actor)
            review = session.scalar(
                select(DevelopmentHistoryReview).where(
                    DevelopmentHistoryReview.history_revision_id == identifier,
                    DevelopmentHistoryReview.decision == "APPROVED",
                )
            )
            if review is None or review.reviewer_subject == history.author_subject:
                raise DevelopmentConflictError(
                    "distinct-subject approved history review is required",
                    code="REVIEW_REQUIRED",
            )
            self._verify_history_evidence(session, history, review)
            if self.bundle_builder is None:
                raise DevelopmentConflictError(
                    "two independent isolated bundle builders are unavailable",
                    code="BUILDER_UNAVAILABLE",
                )
            build = self.bundle_builder.build(
                make_build_request(
                    history_revision_id=history.history_revision_id,
                    project_id=history.project_id,
                    tree_digest=history.tree_digest,
                    snapshot_bytes=bytes(history.snapshot_bytes),
                    workspace_revision=int(history.workspace_revision),
                    created_at_database_time=_iso(history.created_at_database_time) or "",
                    validation_summary_digest=history.validation_summary_digest,
                    review_subject=review.reviewer_subject,
                )
            )
            raw = build.bundle_bytes
            manifest_without_digest = build.manifest_without_digest
            procedure_ids = list(build.procedure_ids)
            if build.toolchain_digest != toolchain_digest():
                raise DevelopmentCorruptionError("bundle builder toolchain differs")
            payload = strict_json_bytes(raw, "bundle builder bytes")
            if (
                type(payload) is not dict
                or canonical_json_bytes(payload) != raw
                or payload.get("manifest") != manifest_without_digest
                or manifest_without_digest.get("procedure_ids") != procedure_ids
            ):
                raise DevelopmentCorruptionError("bundle builder result differs")
            if procedure_ids[0].casefold() in self.reserved_procedure_ids:
                raise DevelopmentConflictError(
                    "development procedure collides with an inherited runtime fixture",
                    code="CASE_CONFLICT",
                )
            if len(raw) > MAX_PROJECT_BYTES:
                raise DevelopmentLimitError("bundle exceeds its byte limit")
            digest = sha256_bytes(raw)
            existing = session.get(DevelopmentBundle, digest)
            if existing is not None:
                self._verify_bundle_row(existing)
                if existing.bundle_bytes != raw:
                    raise DevelopmentCorruptionError("bundle digest collision detected")
                return {"bundle": _bundle_dict(existing)}
            manifest = {"bundle_digest": digest, **manifest_without_digest}
            row = DevelopmentBundle(
                bundle_digest=digest,
                project_id=history.project_id,
                history_revision_id=identifier,
                bundle_bytes=raw,
                byte_length=len(raw),
                manifest=manifest,
                source_tree_digest=history.tree_digest,
                validation_report_digest=history.validation_summary_digest,
                author_subject=history.author_subject,
                review_subject=review.reviewer_subject,
                builder_identity=BUILDER_IDENTITY,
                state="CANDIDATE",
                state_revision=1,
                approved_by_subject=None,
                approval_reason=None,
            )
            session.add(row)
            self._audit(
                session,
                actor,
                project_id=history.project_id,
                action="BUILD_BUNDLE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=0,
                new_revision=1,
                payload={"bundle_digest": digest, "history_revision_id": identifier},
                outbox_topic="development.bundle.created",
                aggregate_id=digest,
            )
            session.flush()
            self._verify_bundle_row(row)
            return {"bundle": _bundle_dict(row)}

        return self._mutate(
            actor,
            scope=f"history:{identifier}:bundle",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def get_bundle(
        self,
        bundle_digest: Any,
        *,
        subject: Any,
        role: Any,
        include_bytes: bool = False,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        digest = require_digest(bundle_digest, "bundle_digest")
        with self.factory() as session:
            row = session.get(DevelopmentBundle, digest)
            if row is None:
                raise DevelopmentNotFoundError("bundle was not found")
            self._verify_bundle_row(row)
            history = session.get(DevelopmentHistoryRevision, row.history_revision_id)
            if history is None:
                raise DevelopmentCorruptionError("bundle history revision is missing")
            review = session.scalar(
                select(DevelopmentHistoryReview).where(
                    DevelopmentHistoryReview.history_revision_id
                    == history.history_revision_id
                )
            )
            self._verify_history_evidence(session, history, review)
            result = {"bundle": _bundle_dict(row)}
            if include_bytes:
                result["bundle_bytes"] = bytes(row.bundle_bytes)
            return result

    def approve_bundle(
        self,
        bundle_digest: Any,
        *,
        subject: Any,
        role: Any,
        expected_state_revision: Any,
        reason: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, admin=True)
        digest = require_digest(bundle_digest, "bundle_digest")
        expected = require_revision(expected_state_revision, "expected_state_revision")
        bounded_reason = require_text(reason, "reason", 4096)
        request = {"expected_state_revision": expected, "reason": bounded_reason}

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            row = session.get(DevelopmentBundle, digest)
            if row is None:
                raise DevelopmentNotFoundError("bundle was not found")
            self._verify_bundle_row(row)
            history = session.get(DevelopmentHistoryRevision, row.history_revision_id)
            if history is None:
                raise DevelopmentCorruptionError("bundle history revision is missing")
            review = session.scalar(
                select(DevelopmentHistoryReview).where(
                    DevelopmentHistoryReview.history_revision_id
                    == history.history_revision_id
                )
            )
            self._verify_history_evidence(session, history, review)
            if row.author_subject == actor.subject:
                raise DevelopmentAuthorizationError("bundle author cannot approve the same bundle")
            if int(row.state_revision) != expected:
                raise DevelopmentConflictError(
                    "bundle state revision differs",
                    code="REVISION_CONFLICT",
                    current={"state": row.state, "state_revision": int(row.state_revision)},
                )
            if row.state != "CANDIDATE":
                raise DevelopmentConflictError("only a candidate bundle can be approved")
            row.state = "APPROVED"
            row.state_revision += 1
            row.approved_by_subject = actor.subject
            row.approval_reason = bounded_reason
            row.updated_at_database_time = utc_now()
            self._audit(
                session,
                actor,
                project_id=row.project_id,
                action="APPROVE_BUNDLE",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(row.state_revision),
                payload={"bundle_digest": digest, "reason": bounded_reason},
                outbox_topic="development.bundle.approved",
                aggregate_id=digest,
            )
            session.flush()
            return {"bundle": _bundle_dict(row)}

        return self._mutate(
            actor,
            scope=f"bundle:{digest}:approve",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    def get_catalog_entry(
        self,
        procedure_id: Any,
        *,
        subject: Any,
        role: Any,
    ) -> dict[str, Any]:
        self._actor(subject, role)
        try:
            identifier = ProcedureCatalog._normalize_procedure_id(procedure_id)
        except KeyError as exc:
            raise DevelopmentError("procedure_id is invalid") from exc
        with self.factory() as session:
            row = session.get(DevelopmentCatalogEntry, identifier)
            if row is None:
                return {
                    "catalog_entry": {
                        "procedure_id": identifier,
                        "registry_revision": 0,
                        "current_bundle_digest": None,
                        "previous_bundle_digest": None,
                        "state": "UNPUBLISHED",
                        "updated_by_subject": None,
                        "created_at": None,
                        "updated_at": None,
                    },
                    "decisions": [],
                }
            decisions = session.scalars(
                select(DevelopmentPromotionDecision)
                .where(DevelopmentPromotionDecision.procedure_id == identifier)
                .order_by(DevelopmentPromotionDecision.registry_revision.desc())
            ).all()
            return {
                "catalog_entry": _catalog_dict(row),
                "decisions": [
                    {
                        "decision_id": item.decision_id,
                        "procedure_id": item.procedure_id,
                        "registry_revision": int(item.registry_revision),
                        "operation": item.operation,
                        "previous_bundle_digest": item.previous_bundle_digest,
                        "new_bundle_digest": item.new_bundle_digest,
                        "actor_subject": item.actor_subject,
                        "reason": item.reason,
                        "correlation_id": item.correlation_id,
                        "created_at": _iso(item.created_at_database_time),
                    }
                    for item in decisions
                ],
            }

    def catalog_decision(
        self,
        procedure_id: Any,
        *,
        subject: Any,
        role: Any,
        operation: Any,
        bundle_digest: Any,
        expected_registry_revision: Any,
        reason: Any,
        idempotency_key: Any,
    ) -> dict[str, Any]:
        actor = self._actor(subject, role, admin=True)
        try:
            identifier = ProcedureCatalog._normalize_procedure_id(procedure_id)
        except KeyError as exc:
            raise DevelopmentError("procedure_id is invalid") from exc
        if identifier.casefold() in self.reserved_procedure_ids:
            raise DevelopmentConflictError(
                "development procedure collides with an inherited runtime fixture",
                code="CASE_CONFLICT",
            )
        if operation not in PROMOTION_OPERATIONS:
            raise DevelopmentError("catalog decision operation is invalid")
        bounded_operation = str(operation)
        digest = require_digest(bundle_digest, "bundle_digest") if bundle_digest is not None else None
        expected = require_revision(expected_registry_revision, "expected_registry_revision")
        bounded_reason = require_text(reason, "reason", 4096)
        request = {
            "operation": bounded_operation,
            "bundle_digest": digest,
            "expected_registry_revision": expected,
            "reason": bounded_reason,
        }

        def apply(session: Session, correlation_id: str) -> dict[str, Any]:
            self._lock_subject_limit(session, "development:promotion-catalog")
            entry = session.get(
                DevelopmentCatalogEntry, identifier, with_for_update=True
            )
            if entry is None:
                entry_count = session.scalar(
                    select(func.count()).select_from(DevelopmentCatalogEntry)
                )
                if int(entry_count or 0) >= MAX_PROMOTION_CATALOG_ENTRIES:
                    raise DevelopmentLimitError(
                        "promotion catalog entry limit is reached"
                    )
            decision_count = session.scalar(
                select(func.count())
                .select_from(DevelopmentPromotionDecision)
                .where(DevelopmentPromotionDecision.procedure_id == identifier)
            )
            if int(decision_count or 0) >= MAX_PROMOTION_DECISIONS_PER_ENTRY:
                raise DevelopmentLimitError(
                    "promotion decision history limit is reached"
                )
            current_revision = int(entry.registry_revision) if entry is not None else 0
            if current_revision != expected:
                raise DevelopmentConflictError(
                    "catalog registry revision differs",
                    code="REVISION_CONFLICT",
                    current={
                        "registry_revision": current_revision,
                        "current_bundle_digest": entry.current_bundle_digest if entry else None,
                    },
                )
            target = (
                session.get(DevelopmentBundle, digest, with_for_update=True)
                if digest is not None
                else None
            )
            if digest is not None and target is None:
                raise DevelopmentNotFoundError("bundle was not found")
            if target is not None:
                self._verify_bundle_row(target)
                history = session.get(
                    DevelopmentHistoryRevision, target.history_revision_id
                )
                if history is None:
                    raise DevelopmentCorruptionError(
                        "bundle history revision is missing"
                    )
                review = session.scalar(
                    select(DevelopmentHistoryReview).where(
                        DevelopmentHistoryReview.history_revision_id
                        == history.history_revision_id
                    )
                )
                self._verify_history_evidence(session, history, review)
                if target.author_subject == actor.subject:
                    raise DevelopmentAuthorizationError(
                        "bundle author cannot make an administrative catalog decision"
                    )
                if identifier not in target.manifest.get("procedure_ids", []):
                    raise DevelopmentError("bundle does not contain the catalog procedure")
            current_digest = entry.current_bundle_digest if entry is not None else None
            previous_digest = current_digest
            if bounded_operation == "PROMOTE":
                if target is None or target.state != "APPROVED":
                    raise DevelopmentConflictError("approved bundle is required for promotion")
                if entry is not None and (
                    entry.state == "PROMOTED" or current_digest is not None
                ):
                    raise DevelopmentConflictError(
                        "current promotion must be explicitly superseded first",
                        code="SUPERSEDE_REQUIRED",
                    )
                previous_digest = (
                    entry.previous_bundle_digest
                    if entry is not None and entry.state == "SUPERSEDED"
                    else None
                )
                target.state = "PROMOTED"
                target.state_revision += 1
                target.updated_at_database_time = utc_now()
                new_digest = digest
                new_state = "PROMOTED"
            elif bounded_operation == "ROLLBACK_PROMOTE":
                if target is None or target.state != "SUPERSEDED":
                    raise DevelopmentConflictError("superseded bundle is required for rollback")
                if (
                    entry is None
                    or entry.state != "SUPERSEDED"
                    or current_digest is not None
                ):
                    raise DevelopmentConflictError(
                        "catalog must be explicitly superseded before rollback",
                        code="ROLLBACK_STATE_INVALID",
                    )
                previous_digest = entry.previous_bundle_digest
                target.state = "PROMOTED"
                target.state_revision += 1
                target.updated_at_database_time = utc_now()
                new_digest = digest
                new_state = "PROMOTED"
            elif bounded_operation == "WITHDRAW":
                withdrawal_digest = current_digest or digest
                if withdrawal_digest is None:
                    raise DevelopmentConflictError(
                        "approved or promoted bundle is required for withdrawal"
                    )
                if current_digest is not None and digest is not None and digest != current_digest:
                    raise DevelopmentConflictError("withdrawal bundle differs from current promotion")
                current_bundle = session.get(
                    DevelopmentBundle, withdrawal_digest, with_for_update=True
                )
                if current_bundle is None or current_bundle.state not in {"APPROVED", "PROMOTED"}:
                    raise DevelopmentConflictError(
                        "approved or promoted bundle is required for withdrawal"
                    )
                self._verify_bundle_row(current_bundle)
                if current_bundle.author_subject == actor.subject:
                    raise DevelopmentAuthorizationError(
                        "bundle author cannot withdraw the same bundle"
                    )
                if identifier not in current_bundle.manifest.get("procedure_ids", []):
                    raise DevelopmentError("bundle does not contain the catalog procedure")
                if current_bundle.state == "PROMOTED" and (
                    entry is None
                    or entry.state != "PROMOTED"
                    or current_digest != withdrawal_digest
                ):
                    raise DevelopmentConflictError(
                        "promoted withdrawal requires the current catalog entry"
                    )
                if current_bundle.state == "APPROVED" and current_digest is not None:
                    raise DevelopmentConflictError(
                        "approved bundle cannot be withdrawn while another digest is promoted"
                    )
                previous_digest = withdrawal_digest
                current_bundle.state = "WITHDRAWN"
                current_bundle.state_revision += 1
                current_bundle.updated_at_database_time = utc_now()
                new_digest = None
                new_state = "WITHDRAWN"
            else:  # SUPERSEDE
                if (
                    entry is None
                    or entry.state != "PROMOTED"
                    or current_digest is None
                ):
                    raise DevelopmentConflictError("promoted catalog entry is required")
                if digest is None or digest != current_digest:
                    raise DevelopmentConflictError(
                        "supersede bundle differs from the current promotion"
                    )
                current_bundle = target
                if current_bundle is None or current_bundle.state != "PROMOTED":
                    raise DevelopmentConflictError(
                        "promoted bundle is required for supersede"
                    )
                current_bundle.state = "SUPERSEDED"
                current_bundle.state_revision += 1
                current_bundle.updated_at_database_time = utc_now()
                previous_digest = current_digest
                new_digest = None
                new_state = "SUPERSEDED"
            if entry is None:
                entry = DevelopmentCatalogEntry(
                    procedure_id=identifier,
                    registry_revision=1,
                    current_bundle_digest=new_digest,
                    previous_bundle_digest=previous_digest,
                    state=new_state,
                    updated_by_subject=actor.subject,
                )
                session.add(entry)
            else:
                entry.registry_revision += 1
                entry.previous_bundle_digest = previous_digest
                entry.current_bundle_digest = new_digest
                entry.state = new_state
                entry.updated_by_subject = actor.subject
                entry.updated_at_database_time = utc_now()
            decision = DevelopmentPromotionDecision(
                decision_id=_id(),
                procedure_id=identifier,
                registry_revision=int(entry.registry_revision),
                operation=bounded_operation,
                previous_bundle_digest=previous_digest,
                new_bundle_digest=new_digest,
                actor_subject=actor.subject,
                reason=bounded_reason,
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
            )
            session.add(decision)
            project_id = target.project_id if target is not None else None
            self._audit(
                session,
                actor,
                project_id=project_id,
                action=f"CATALOG_{bounded_operation}",
                correlation_id=correlation_id,
                idempotency_key=str(idempotency_key),
                previous_revision=expected,
                new_revision=int(entry.registry_revision),
                payload={
                    "procedure_id": identifier,
                    "previous_bundle_digest": previous_digest,
                    "new_bundle_digest": new_digest,
                    "reason": bounded_reason,
                },
                outbox_topic="development.catalog.decision",
                aggregate_id=identifier,
            )
            session.flush()
            return {
                "catalog_entry": _catalog_dict(entry),
                "decision": {
                    "decision_id": decision.decision_id,
                    "procedure_id": identifier,
                    "registry_revision": int(entry.registry_revision),
                    "operation": bounded_operation,
                    "previous_bundle_digest": previous_digest,
                    "new_bundle_digest": new_digest,
                    "actor_subject": actor.subject,
                    "reason": bounded_reason,
                    "correlation_id": correlation_id,
                },
            }

        return self._mutate(
            actor,
            scope=f"catalog:{identifier}:decision",
            idempotency_key=idempotency_key,
            request=request,
            apply=apply,
        )

    @staticmethod
    def _procedure_from_bundle(
        row: DevelopmentBundle,
        payload: Mapping[str, Any],
        procedure_id: str,
    ) -> Procedure:
        for entry in payload["entries"]:
            compiled = entry.get("compiled")
            if type(compiled) is not dict or compiled.get("procedure_id") != procedure_id:
                continue
            content = base64.b64decode(entry["content"], validate=True)
            source = content.decode("utf-8")
            if sha256_bytes(content) != compiled.get("source_sha256"):
                raise DevelopmentCorruptionError("bundle compiled source digest differs")
            return Procedure(
                id=procedure_id,
                name=procedure_id.replace("_", " ").title(),
                description=str(compiled.get("description", "")),
                path=Path("development") / f"{procedure_id}.spell.py",
                source=source,
                sha256=str(compiled["source_sha256"]),
                steps=tuple(compiled.get("steps", [])),
                ir_version=str(compiled.get("ir_version", "")),
                user_actions=tuple(compiled.get("user_actions", [])),
                bundle_digest=row.bundle_digest,
            )
        raise DevelopmentCorruptionError("promoted procedure is absent from its bundle")

    def list_promoted_procedures(self) -> list[Procedure]:
        with self.factory() as session:
            entries = session.scalars(
                select(DevelopmentCatalogEntry)
                .where(
                    DevelopmentCatalogEntry.state == "PROMOTED",
                    DevelopmentCatalogEntry.current_bundle_digest.is_not(None),
                )
                .order_by(DevelopmentCatalogEntry.procedure_id)
            ).all()
            result = []
            for entry in entries:
                row = session.get(DevelopmentBundle, entry.current_bundle_digest)
                if row is None or row.state != "PROMOTED":
                    raise DevelopmentCorruptionError("promoted catalog bundle is unavailable")
                payload = self._verify_bundle_row(row)
                result.append(self._procedure_from_bundle(row, payload, entry.procedure_id))
            return result

    def get_promoted_procedure(self, procedure_id: str) -> Procedure:
        identifier = require_text(procedure_id, "procedure_id", 200)
        with self.factory() as session:
            entry = session.get(DevelopmentCatalogEntry, identifier)
            if entry is None or entry.state != "PROMOTED" or entry.current_bundle_digest is None:
                raise KeyError(identifier)
            row = session.get(DevelopmentBundle, entry.current_bundle_digest)
            if row is None or row.state != "PROMOTED":
                raise DevelopmentCorruptionError("promoted catalog bundle is unavailable")
            return self._procedure_from_bundle(row, self._verify_bundle_row(row), identifier)

    def is_runtime_admitted(self, procedure_id: str, bundle_digest: str) -> bool:
        try:
            identifier = ProcedureCatalog._normalize_procedure_id(procedure_id)
            digest = require_digest(bundle_digest, "bundle_digest")
        except (DevelopmentError, KeyError):
            return False
        with self.factory() as session:
            entry = session.get(DevelopmentCatalogEntry, identifier)
            if (
                entry is None
                or entry.state != "PROMOTED"
                or entry.current_bundle_digest != digest
            ):
                return False
            bundle = session.get(DevelopmentBundle, digest)
            if bundle is None or bundle.state != "PROMOTED":
                return False
            self._verify_bundle_row(bundle)
            return True

    def pin_runtime_reference(
        self,
        *,
        runtime_kind: Any,
        runtime_id: Any,
        procedure_id: Any,
    ) -> dict[str, Any]:
        with session_scope(self.factory) as session:
            begin_mutation_write(session)
            result = self.pin_runtime_reference_in_session(
                session,
                runtime_kind=runtime_kind,
                runtime_id=runtime_id,
                procedure_id=procedure_id,
            )
            if result is None:
                raise DevelopmentConflictError(
                    "v0.9 authored procedure is not promoted",
                    code="NOT_PROMOTED",
                )
            return result

    def pin_runtime_reference_in_session(
        self,
        session: Session,
        *,
        runtime_kind: Any,
        runtime_id: Any,
        procedure_id: Any,
        bundle_digest: Any | None = None,
        inherited_runtime_kind: Any | None = None,
        inherited_runtime_id: Any | None = None,
    ) -> dict[str, Any] | None:
        """Atomically validate admission and create an immutable runtime pin.

        The caller supplies the transaction that creates the schedule, StartProc
        admission, or execution. PostgreSQL row locks serialize this operation
        with promotion decisions; SQLite callers already own the database writer
        lock by the time this method inserts the pin.
        """

        if runtime_kind not in {"EXECUTION", "SCHEDULE", "STARTPROC"}:
            raise DevelopmentError("runtime pin kind is invalid")
        bounded_runtime_id = require_identifier(runtime_id, "runtime_id")
        try:
            bounded_procedure = ProcedureCatalog._normalize_procedure_id(
                require_text(procedure_id, "procedure_id", 200)
            )
        except KeyError as exc:
            raise DevelopmentError("procedure_id is invalid") from exc
        requested_digest = (
            require_digest(bundle_digest, "bundle_digest")
            if bundle_digest is not None
            else None
        )
        existing = session.scalar(
            select(DevelopmentRuntimePin)
            .where(
                DevelopmentRuntimePin.runtime_kind == runtime_kind,
                DevelopmentRuntimePin.runtime_id == bounded_runtime_id,
            )
            .with_for_update()
        )
        if existing is not None:
            if (
                existing.procedure_id != bounded_procedure
                or (
                    requested_digest is not None
                    and existing.bundle_digest != requested_digest
                )
            ):
                raise DevelopmentConflictError("runtime reference is already pinned")
            return {
                "runtime_kind": existing.runtime_kind,
                "runtime_id": existing.runtime_id,
                "procedure_id": existing.procedure_id,
                "bundle_digest": existing.bundle_digest,
            }

        entry = session.get(
            DevelopmentCatalogEntry, bounded_procedure, with_for_update=True
        )
        admitted_digest = (
            entry.current_bundle_digest
            if entry is not None and entry.state == "PROMOTED"
            else None
        )
        if requested_digest is None:
            requested_digest = admitted_digest
        admitted = admitted_digest == requested_digest and requested_digest is not None

        if not admitted and inherited_runtime_kind is not None:
            if inherited_runtime_kind not in {"EXECUTION", "SCHEDULE", "STARTPROC"}:
                raise DevelopmentError("inherited runtime pin kind is invalid")
            inherited_id = require_identifier(
                inherited_runtime_id, "inherited_runtime_id"
            )
            inherited = session.scalar(
                select(DevelopmentRuntimePin)
                .where(
                    DevelopmentRuntimePin.runtime_kind == inherited_runtime_kind,
                    DevelopmentRuntimePin.runtime_id == inherited_id,
                )
                .with_for_update()
            )
            admitted = bool(
                inherited is not None
                and inherited.procedure_id == bounded_procedure
                and inherited.bundle_digest == requested_digest
            )
        if not admitted or requested_digest is None:
            return None

        bundle = session.get(
            DevelopmentBundle, requested_digest, with_for_update=True
        )
        if bundle is None:
            raise DevelopmentCorruptionError("runtime bundle is unavailable")
        # A predecessor pin intentionally remains valid after withdrawal. The
        # immutable bytes are still verified before a derived runtime is pinned.
        self._verify_bundle_row(bundle)
        row = DevelopmentRuntimePin(
            pin_id=_id(),
            runtime_kind=str(runtime_kind),
            runtime_id=bounded_runtime_id,
            procedure_id=bounded_procedure,
            bundle_digest=requested_digest,
        )
        session.add(row)
        session.flush()
        return {
            "runtime_kind": row.runtime_kind,
            "runtime_id": row.runtime_id,
            "procedure_id": row.procedure_id,
            "bundle_digest": row.bundle_digest,
        }


__all__ = [
    "BUILDER_IDENTITY",
    "BUNDLE_SCHEMA_VERSION",
    "COMPATIBILITY_PROFILE",
    "DevelopmentService",
    "PROJECT_SCHEMA_VERSION",
]
