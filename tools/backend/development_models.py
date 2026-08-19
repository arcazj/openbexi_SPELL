"""SQLAlchemy models for the bounded v0.9 development environment."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


MIGRATION_ID = "0008_development_environment"


def _time() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DevelopmentProject(Base):
    __tablename__ = "development_projects"
    __table_args__ = (
        CheckConstraint("workspace_revision >= 0", name="ck_dev_project_revision"),
        CheckConstraint(
            "case_policy IN ('CASE_SENSITIVE','CASE_INSENSITIVE')",
            name="ck_dev_project_case_policy",
        ),
        UniqueConstraint("workspace_id", name="uq_dev_project_workspace"),
        UniqueConstraint("owner_subject", "normalized_name", name="uq_dev_project_name"),
    )

    project_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    author_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    case_policy: Mapped[str] = mapped_column(String(24), nullable=False)
    workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    base_history_revision_id: Mapped[str | None] = mapped_column(String(128))
    base_bundle_digest: Mapped[str | None] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    closed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at_database_time: Mapped[datetime] = _time()
    updated_at_database_time: Mapped[datetime] = _time()


class DevelopmentResource(Base):
    __tablename__ = "development_resources"
    __table_args__ = (
        UniqueConstraint("project_id", "path_identity", name="uq_dev_resource_path"),
        CheckConstraint("revision >= 1", name="ck_dev_resource_revision"),
        CheckConstraint("byte_length >= 0", name="ck_dev_resource_size"),
        Index("ix_dev_resource_project_path", "project_id", "path"),
    )

    resource_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("development_projects.project_id", ondelete="RESTRICT"), nullable=False
    )
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    path_identity: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_by_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_by_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()
    updated_at_database_time: Mapped[datetime] = _time()


class DevelopmentIdempotency(Base):
    __tablename__ = "development_idempotency"
    __table_args__ = (
        UniqueConstraint("actor_subject", "operation_scope", "idempotency_key", name="uq_dev_idempotency"),
    )

    record_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    operation_scope: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentAuditEvent(Base):
    __tablename__ = "development_audit_events"
    __table_args__ = (Index("ix_dev_audit_project_time", "project_id", "created_at_database_time"),)

    audit_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(String(128))
    actor_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(24), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    previous_revision: Mapped[int | None] = mapped_column(BigInteger)
    new_revision: Mapped[int | None] = mapped_column(BigInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentOutbox(Base):
    __tablename__ = "development_outbox"
    __table_args__ = (Index("ix_dev_outbox_topic_time", "topic", "created_at_database_time"),)

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    aggregate_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentAnalysisJob(Base):
    __tablename__ = "development_analysis_jobs"
    __table_args__ = (
        CheckConstraint("progress BETWEEN 0 AND 100", name="ck_dev_job_progress"),
        Index("ix_dev_job_project_revision", "project_id", "workspace_revision"),
    )

    job_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    scope: Mapped[str] = mapped_column(String(24), nullable=False)
    scope_path: Mapped[str | None] = mapped_column(String(512))
    reparse_libraries: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    progress: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    report: Mapped[bytes | None] = mapped_column(LargeBinary)
    report_sha256: Mapped[str | None] = mapped_column(String(64))
    failure_code: Mapped[str | None] = mapped_column(String(80))
    created_at_database_time: Mapped[datetime] = _time()
    started_at_database_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at_database_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DevelopmentProblem(Base):
    __tablename__ = "development_problems"
    __table_args__ = (
        UniqueConstraint("project_id", "workspace_revision", "diagnostic_id", name="uq_dev_problem"),
        Index("ix_dev_problem_sort", "project_id", "source_path", "start_line", "start_column"),
    )

    problem_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    diagnostic_id: Mapped[str] = mapped_column(String(64), nullable=False)
    job_id: Mapped[str] = mapped_column(ForeignKey("development_analysis_jobs.job_id"), nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_path: Mapped[str] = mapped_column(String(512), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_column: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_column: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    language_profile: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentLibraryCache(Base):
    __tablename__ = "development_library_cache"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "cache_kind",
            "content_digest",
            "language_profile",
            "tool_version",
            name="uq_dev_library_cache_key",
        ),
    )

    cache_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    cache_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    language_profile: Mapped[str] = mapped_column(String(80), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_result: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentHistoryRevision(Base):
    __tablename__ = "development_history_revisions"
    __table_args__ = (
        UniqueConstraint("project_id", "ordinal", name="uq_dev_history_ordinal"),
    )

    history_revision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    ordinal: Mapped[int] = mapped_column(BigInteger, nullable=False)
    parent_revision_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    tree_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    tree_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    snapshot_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    author_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    message_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_job_id: Mapped[str] = mapped_column(String(128), nullable=False)
    validation_summary_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentHistoryReview(Base):
    __tablename__ = "development_history_reviews"
    __table_args__ = (UniqueConstraint("history_revision_id", name="uq_dev_history_review"),)

    review_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    history_revision_id: Mapped[str] = mapped_column(ForeignKey("development_history_revisions.history_revision_id"), nullable=False)
    review_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reviewer_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentConflict(Base):
    __tablename__ = "development_conflicts"

    conflict_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    base_path: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    conflict_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    base_history_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    base_workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detected_workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ours_resource_id: Mapped[str | None] = mapped_column(String(128))
    ours_resource_revision: Mapped[int | None] = mapped_column(BigInteger)
    ours_path: Mapped[str | None] = mapped_column(String(512))
    base_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    base_media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    ours_kind: Mapped[str | None] = mapped_column(String(32))
    ours_media_type: Mapped[str | None] = mapped_column(String(160))
    theirs_kind: Mapped[str | None] = mapped_column(String(32))
    theirs_media_type: Mapped[str | None] = mapped_column(String(160))
    base_content: Mapped[bytes | None] = mapped_column(LargeBinary)
    ours_content: Mapped[bytes | None] = mapped_column(LargeBinary)
    theirs_content: Mapped[bytes | None] = mapped_column(LargeBinary)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolution_digest: Mapped[str | None] = mapped_column(String(64))
    created_at_database_time: Mapped[datetime] = _time()
    resolved_at_database_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DevelopmentImportProvenance(Base):
    __tablename__ = "development_import_provenance"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUARANTINED','APPLYING','APPLIED','NO_CHANGE','CONFLICT','DISCARDED')",
            name="ck_dev_import_status",
        ),
        UniqueConstraint("audit_id", name="uq_dev_import_audit"),
    )

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    original_media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    original_byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    original_bytes_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    original_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    imported_tree_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_tree_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    base_workspace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    conflict_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("development_audit_events.audit_id"), nullable=False
    )
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentDictionaryArtifact(Base):
    __tablename__ = "development_dictionary_artifacts"

    resource_id: Mapped[str] = mapped_column(
        ForeignKey("development_resources.resource_id", ondelete="RESTRICT"), primary_key=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    dictionary_id: Mapped[str] = mapped_column(String(256), nullable=False)
    source_format: Mapped[str] = mapped_column(String(8), nullable=False)
    base_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    original_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    original_bytes_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    canonical_bytes_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()
    updated_at_database_time: Mapped[datetime] = _time()


class DevelopmentCatalogSnapshot(Base):
    __tablename__ = "development_catalog_snapshots"
    __table_args__ = (
        UniqueConstraint("project_id", "catalog_id", "catalog_revision", name="uq_dev_catalog_snapshot"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    resource_id: Mapped[str] = mapped_column(
        ForeignKey("development_resources.resource_id", ondelete="RESTRICT"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    catalog_id: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    catalog_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_snapshot: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    entries: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    dependencies: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentPresence(Base):
    __tablename__ = "development_presence"
    __table_args__ = (
        UniqueConstraint("project_id", "subject", "client_instance_id", name="uq_dev_presence_subject"),
    )

    presence_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    client_instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at_database_time: Mapped[datetime] = _time()
    expires_at_database_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DevelopmentBundle(Base):
    __tablename__ = "development_bundles"
    __table_args__ = (CheckConstraint("state_revision >= 1", name="ck_dev_bundle_revision"),)

    bundle_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("development_projects.project_id"), nullable=False)
    history_revision_id: Mapped[str] = mapped_column(ForeignKey("development_history_revisions.history_revision_id"), nullable=False)
    bundle_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_tree_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    author_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    review_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    builder_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    state_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    approved_by_subject: Mapped[str | None] = mapped_column(String(200))
    approval_reason: Mapped[str | None] = mapped_column(Text)
    created_at_database_time: Mapped[datetime] = _time()
    updated_at_database_time: Mapped[datetime] = _time()


class DevelopmentCatalogEntry(Base):
    __tablename__ = "development_catalog_entries"

    procedure_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    registry_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_bundle_digest: Mapped[str | None] = mapped_column(String(64))
    previous_bundle_digest: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    updated_by_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()
    updated_at_database_time: Mapped[datetime] = _time()


class DevelopmentPromotionDecision(Base):
    __tablename__ = "development_promotion_decisions"
    __table_args__ = (UniqueConstraint("procedure_id", "registry_revision", name="uq_dev_decision_revision"),)

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    procedure_id: Mapped[str] = mapped_column(String(200), nullable=False)
    registry_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_bundle_digest: Mapped[str | None] = mapped_column(String(64))
    new_bundle_digest: Mapped[str | None] = mapped_column(String(64))
    actor_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


class DevelopmentRuntimePin(Base):
    __tablename__ = "development_runtime_pins"
    __table_args__ = (UniqueConstraint("runtime_kind", "runtime_id", name="uq_dev_runtime_pin"),)

    pin_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    runtime_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    runtime_id: Mapped[str] = mapped_column(String(128), nullable=False)
    procedure_id: Mapped[str] = mapped_column(String(200), nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at_database_time: Mapped[datetime] = _time()


DEVELOPMENT_TABLES = tuple(
    model.__table__
    for model in (
        DevelopmentProject,
        DevelopmentResource,
        DevelopmentIdempotency,
        DevelopmentAuditEvent,
        DevelopmentOutbox,
        DevelopmentAnalysisJob,
        DevelopmentProblem,
        DevelopmentLibraryCache,
        DevelopmentHistoryRevision,
        DevelopmentHistoryReview,
        DevelopmentConflict,
        DevelopmentImportProvenance,
        DevelopmentDictionaryArtifact,
        DevelopmentCatalogSnapshot,
        DevelopmentPresence,
        DevelopmentBundle,
        DevelopmentCatalogEntry,
        DevelopmentPromotionDecision,
        DevelopmentRuntimePin,
    )
)
DEVELOPMENT_TABLE_NAMES = tuple(table.name for table in DEVELOPMENT_TABLES)


__all__ = [name for name in globals() if name.startswith("Development")] + [
    "DEVELOPMENT_TABLES",
    "DEVELOPMENT_TABLE_NAMES",
    "MIGRATION_ID",
]
