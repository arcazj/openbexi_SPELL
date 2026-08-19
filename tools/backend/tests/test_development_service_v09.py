from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from backend.development_domain import (
    DevelopmentAuthorizationError,
    DevelopmentConflictError,
    DevelopmentCorruptionError,
    canonical_json_bytes,
)
from backend.development_bundle_builder import InProcessDualBundleBuilder
from backend.development_models import (
    DevelopmentBundle,
    DevelopmentCatalogEntry,
    DevelopmentProblem,
    DevelopmentProject,
)
from backend.development_service import DevelopmentService
from backend.migrations.versions import v0008_development_environment as migration
from backend.procedure_parser import ProcedureCatalog


OPERATOR = {"subject": "author name@example.com", "role": "operator"}
ADMIN = {"subject": "reviewer@example.com", "role": "admin"}


def _service(tmp_path: Path, name: str = "development.sqlite") -> DevelopmentService:
    engine = create_engine(
        f"sqlite:///{(tmp_path / name).as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 5},
    )
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE schema_migrations ("
            "version VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL)"
        )
        connection.execute(
            text(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (:version, CURRENT_TIMESTAMP)"
            ),
            {"version": migration.REQUIRED_PREDECESSOR},
        )
        migration.upgrade(connection)
    return DevelopmentService(
        sessionmaker(engine, expire_on_commit=False),
        bundle_builder=InProcessDualBundleBuilder(),
    )


def _source(procedure_id: str, message: str = "ready") -> str:
    return "\n".join(
        (
            f"# @procedure {procedure_id}",
            f"# @display-name {procedure_id}",
            "# @description Local test procedure",
            "# @language-profile spell-restricted-ast/0.9",
            '"""Local test procedure."""',
            "ARGS()",
            'DataContainer("LOCAL.TEST")',
            f"Log({message!r})",
            "",
        )
    )


def _create_project(service: DevelopmentService, name: str = "Demo") -> dict:
    return service.create_project(
        **OPERATOR,
        name=name,
        case_policy="CASE_INSENSITIVE",
        manifest=None,
        idempotency_key=f"project-{name}",
    )["project"]


def _create_procedure(
    service: DevelopmentService,
    project: dict,
    *,
    procedure_id: str = "local/demo",
    path: str = "procedures/demo.spell.py",
    revision: int = 1,
) -> dict:
    source = _source(procedure_id)
    return service.create_resource(
        project["project_id"],
        **OPERATOR,
        path=path,
        kind="PROCEDURE",
        media_type="text/x-python",
        content=source,
        content_sha256=hashlib.sha256(source.encode()).hexdigest(),
        expected_workspace_revision=revision,
        idempotency_key=f"create-{procedure_id}",
    )["resource"]


def _run_project_check(
    service: DevelopmentService,
    project_id: str,
    revision: int,
    key: str,
) -> dict:
    queued = service.create_check(
        project_id,
        **OPERATOR,
        scope="PROJECT",
        scope_path=None,
        expected_workspace_revision=revision,
        reparse_libraries=False,
        idempotency_key=key,
    )
    return service.run_check(queued["job"]["job_id"])["job"]


def _candidate_bundle(service: DevelopmentService, project: dict) -> dict:
    job = _run_project_check(
        service, project["project_id"], project["workspace_revision"], "check-project"
    )
    assert job["state"] == "COMPLETED"
    assert job["report"]["outcome"] == "PASS"
    history = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=project["workspace_revision"],
        message="Validated baseline",
        selected_resource_ids=None,
        idempotency_key="history-1",
    )["history_revision"]
    service.review_history(
        history["history_revision_id"],
        **ADMIN,
        decision="APPROVE",
        reason="Independent local review",
        expected_review_revision=0,
        idempotency_key="review-1",
    )
    return service.build_bundle(
        history["history_revision_id"],
        **OPERATOR,
        idempotency_key="bundle-1",
    )["bundle"]


def test_project_lifecycle_security_copy_and_metadata_only_snapshot(tmp_path: Path) -> None:
    service = _service(tmp_path)
    project = _create_project(service)
    assert len(service.workspace_snapshot(project["project_id"], subject="v", role="viewer")["workspace"]["resources"]) == 2

    closed = service.set_project_open(
        project["project_id"],
        **OPERATOR,
        opened=False,
        expected_workspace_revision=1,
        idempotency_key="close",
    )["project"]
    with pytest.raises(DevelopmentConflictError, match="closed"):
        _create_procedure(service, closed, revision=2)
    reopened = service.set_project_open(
        project["project_id"],
        **OPERATOR,
        opened=True,
        expected_workspace_revision=2,
        idempotency_key="open",
    )["project"]
    resource = _create_procedure(service, reopened, revision=3)
    with pytest.raises(DevelopmentAuthorizationError):
        service.update_resource(
            project["project_id"],
            resource["resource_id"],
            **ADMIN,
            changes={"path": "procedures/admin.spell.py"},
            expected_workspace_revision=4,
            idempotency_key="admin-edit",
        )
    copied = service.copy_resource(
        project["project_id"],
        resource["resource_id"],
        **OPERATOR,
        destination_path="procedures/copy.spell.py",
        expected_workspace_revision=4,
        idempotency_key="copy",
    )
    assert copied["project"]["workspace_revision"] == 5
    properties = service.project_properties(project["project_id"], subject="v", role="viewer")
    assert properties["resource_counts"]["PROCEDURE"] == 2
    snapshot = service.workspace_snapshot(project["project_id"], subject="v", role="viewer")
    assert all("content" not in item for item in snapshot["workspace"]["resources"])


def test_project_revision_open_close_and_quota_races_are_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backend import development_service as module

    quota_service = _service(tmp_path, "project-quota.sqlite")
    monkeypatch.setattr(module, "MAX_PROJECTS_PER_SUBJECT", 1)
    create_barrier = threading.Barrier(2)
    create_results: list[tuple[str, object]] = []

    def create(name: str) -> None:
        create_barrier.wait()
        try:
            result = quota_service.create_project(
                **OPERATOR,
                name=name,
                case_policy="CASE_INSENSITIVE",
                manifest=None,
                idempotency_key=f"quota-{name}",
            )
            create_results.append((name, result))
        except Exception as exc:
            create_results.append((name, exc))

    create_threads = [
        threading.Thread(target=create, args=(name,)) for name in ("Quota A", "Quota B")
    ]
    for thread in create_threads:
        thread.start()
    for thread in create_threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sum(not isinstance(result, Exception) for _, result in create_results) == 1
    rejected = next(result for _, result in create_results if isinstance(result, Exception))
    assert isinstance(rejected, DevelopmentConflictError)
    assert rejected.code == "PROJECT_LIMIT_REACHED"
    with quota_service.factory() as session:
        assert session.scalar(select(func.count()).select_from(DevelopmentProject)) == 1

    monkeypatch.setattr(module, "MAX_PROJECTS_PER_SUBJECT", 32)
    lifecycle = _service(tmp_path, "open-quota.sqlite")
    projects = [_create_project(lifecycle, name) for name in ("Open A", "Open B")]
    for index, project in enumerate(projects):
        closed = lifecycle.set_project_open(
            project["project_id"],
            **OPERATOR,
            opened=False,
            expected_workspace_revision=1,
            idempotency_key=f"close-open-quota-{index}",
        )["project"]
        assert closed["closed"] is True
        assert closed["workspace_revision"] == 2
    monkeypatch.setattr(module, "MAX_OPEN_WORKSPACES_PER_SUBJECT", 1)
    open_barrier = threading.Barrier(2)
    open_results: list[tuple[int, object]] = []

    def reopen(index: int) -> None:
        open_barrier.wait()
        try:
            result = lifecycle.set_project_open(
                projects[index]["project_id"],
                **OPERATOR,
                opened=True,
                expected_workspace_revision=2,
                idempotency_key=f"reopen-quota-{index}",
            )
            open_results.append((index, result))
        except Exception as exc:
            open_results.append((index, exc))

    open_threads = [threading.Thread(target=reopen, args=(index,)) for index in range(2)]
    for thread in open_threads:
        thread.start()
    for thread in open_threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    successful_index, successful = next(
        item for item in open_results if not isinstance(item[1], Exception)
    )
    failed = next(result for _, result in open_results if isinstance(result, Exception))
    assert successful["project"]["workspace_revision"] == 3
    assert isinstance(failed, DevelopmentConflictError)
    assert failed.code == "OPEN_WORKSPACE_LIMIT_REACHED"
    replay = lifecycle.set_project_open(
        projects[successful_index]["project_id"],
        **OPERATOR,
        opened=True,
        expected_workspace_revision=2,
        idempotency_key=f"reopen-quota-{successful_index}",
    )
    assert replay["replayed"] is True
    with lifecycle.factory() as session:
        rows = session.scalars(select(DevelopmentProject)).all()
        assert sum(not row.closed for row in rows) == 1
        assert sorted(int(row.workspace_revision) for row in rows) == [2, 3]


def test_stable_identity_survives_rename_and_scoped_problems_are_preserved(tmp_path: Path) -> None:
    service = _service(tmp_path)
    project = _create_project(service)
    first = _create_procedure(service, project, procedure_id="stable/one", revision=1)
    bad_source = "# @procedure stable/two\nARGS()\nUnknownCall()\n"
    second = service.create_resource(
        project["project_id"],
        **OPERATOR,
        path="procedures/two.spell.py",
        kind="PROCEDURE",
        media_type="text/x-python",
        content=bad_source,
        content_sha256=hashlib.sha256(bad_source.encode()).hexdigest(),
        expected_workspace_revision=2,
        idempotency_key="bad-two",
    )["resource"]
    project_job = _run_project_check(service, project["project_id"], 3, "all-bad")
    assert project_job["report"]["outcome"] == "FAILED"
    before = service.workspace_snapshot(project["project_id"], subject="v", role="viewer")
    assert any(item["source_path"].endswith("two.spell.py") for item in before["workspace"]["problems"])

    renamed = service.update_resource(
        project["project_id"],
        first["resource_id"],
        **OPERATOR,
        changes={"path": "procedures/RENAMED.spell.py"},
        expected_workspace_revision=3,
        idempotency_key="rename-one",
    )
    read = service.get_resource(
        project["project_id"], first["resource_id"], subject="v", role="viewer"
    )["resource"]
    assert read["metadata"]["procedure_id"] == "stable/one"
    queued = service.create_check(
        project["project_id"],
        **OPERATOR,
        scope="FILE",
        scope_path="procedures/RENAMED.spell.py",
        expected_workspace_revision=4,
        reparse_libraries=False,
        idempotency_key="file-one",
    )
    service.run_check(queued["job"]["job_id"])
    after = service.workspace_snapshot(project["project_id"], subject="v", role="viewer")
    assert any(item["source_path"].endswith("two.spell.py") for item in after["workspace"]["problems"])
    assert renamed["resource"]["path"] == "procedures/RENAMED.spell.py"


def test_bundle_promotion_withdrawal_pin_continuity_and_strict_tamper(tmp_path: Path) -> None:
    service = _service(tmp_path)
    project = _create_project(service)
    resource = _create_procedure(service, project)
    project = {**project, "workspace_revision": 2}
    bundle = _candidate_bundle(service, project)
    procedure_id = "local/demo"
    assert service.get_catalog_entry(procedure_id, subject="v", role="viewer")["catalog_entry"]["registry_revision"] == 0
    service.approve_bundle(
        bundle["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Approve candidate",
        idempotency_key="approve-bundle",
    )
    promoted = service.catalog_decision(
        procedure_id,
        **ADMIN,
        operation="PROMOTE",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=0,
        reason="Promote locally",
        idempotency_key="promote",
    )
    catalog = ProcedureCatalog(tmp_path / "no-fixtures", service.list_promoted_procedures)
    loaded = catalog.get(procedure_id)
    assert loaded.bundle_digest == bundle["bundle_digest"]
    assert loaded.sha256 == resource["content_sha256"]
    pin = service.pin_runtime_reference(
        runtime_kind="EXECUTION", runtime_id="execution-1", procedure_id=procedure_id
    )
    assert pin["bundle_digest"] == bundle["bundle_digest"]

    service.catalog_decision(
        procedure_id,
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=1,
        reason="Withdraw locally",
        idempotency_key="withdraw",
    )
    with pytest.raises(KeyError):
        catalog.get(procedure_id)
    assert service.pin_runtime_reference(
        runtime_kind="EXECUTION", runtime_id="execution-1", procedure_id=procedure_id
    ) == pin
    with pytest.raises(DevelopmentConflictError, match="not promoted"):
        service.pin_runtime_reference(
            runtime_kind="SCHEDULE", runtime_id="schedule-new", procedure_id=procedure_id
        )

    with service.factory() as session:
        row = session.get(DevelopmentBundle, bundle["bundle_digest"])
        assert row is not None
        payload = json.loads(bytes(row.bundle_bytes))
        payload["entries"][0]["unexpected"] = True
        tampered_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        tampered_digest = hashlib.sha256(tampered_bytes).hexdigest()
        fake = DevelopmentBundle(
            bundle_digest=tampered_digest,
            project_id=row.project_id,
            history_revision_id=row.history_revision_id,
            bundle_bytes=tampered_bytes,
            byte_length=len(tampered_bytes),
            manifest={**row.manifest, "bundle_digest": tampered_digest},
            source_tree_digest=row.source_tree_digest,
            validation_report_digest=row.validation_report_digest,
            author_subject=row.author_subject,
            review_subject=row.review_subject,
            builder_identity=row.builder_identity,
            state=row.state,
            state_revision=row.state_revision,
        )
        with pytest.raises(DevelopmentCorruptionError, match="entry schema"):
            service._verify_bundle_row(fake)


def test_v09_minimal_procedure_bundle_binds_actual_compiler_ir_schema(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, "minimal-ir-bundle.sqlite")
    project = _create_project(service, "Minimal IR bundle")
    source = "\n".join(
        (
            "# @procedure qualification-chromium",
            "# @display-name qualification-chromium",
            "# @description Local simulator procedure",
            "# @language-profile spell-restricted-ast/0.9",
            '"""qualification-chromium local simulator procedure."""',
            "Log('Procedure ready')",
            "Log('real qualification edit')",
            "",
        )
    )
    service.create_resource(
        project["project_id"],
        **OPERATOR,
        path="procedures/qualification-chromium.spell.py",
        kind="PROCEDURE",
        media_type="text/x-python",
        content=source,
        content_sha256=hashlib.sha256(source.encode()).hexdigest(),
        expected_workspace_revision=1,
        idempotency_key="minimal-ir-source",
    )
    bundle = _candidate_bundle(service, {**project, "workspace_revision": 2})
    assert bundle["manifest"]["language_profile"] == "spell-restricted-ast/0.9"
    assert bundle["manifest"]["ir_schema_version"] == ["0.3"]
    service.get_bundle(
        bundle["bundle_digest"], subject="viewer", role="viewer", include_bytes=True
    )

    with service.factory() as session:
        row = session.get(DevelopmentBundle, bundle["bundle_digest"])
        assert row is not None
        payload = json.loads(bytes(row.bundle_bytes))
        procedure_entry = next(
            entry for entry in payload["entries"] if entry["kind"] == "PROCEDURE"
        )
        assert procedure_entry["compiled"]["ir_version"] == "0.3"
        payload["manifest"]["ir_schema_version"] = ["0.8"]
        tampered_bytes = canonical_json_bytes(payload)
        tampered_digest = hashlib.sha256(tampered_bytes).hexdigest()
        fake = DevelopmentBundle(
            bundle_digest=tampered_digest,
            project_id=row.project_id,
            history_revision_id=row.history_revision_id,
            bundle_bytes=tampered_bytes,
            byte_length=len(tampered_bytes),
            manifest={**payload["manifest"], "bundle_digest": tampered_digest},
            source_tree_digest=row.source_tree_digest,
            validation_report_digest=row.validation_report_digest,
            author_subject=row.author_subject,
            review_subject=row.review_subject,
            builder_identity=row.builder_identity,
            state=row.state,
            state_revision=row.state_revision,
        )
        with pytest.raises(DevelopmentCorruptionError, match="IR schema versions"):
            service._verify_bundle_row(fake)


def test_immutable_bundle_is_insert_only_and_referenced_bytes_cannot_be_changed_or_deleted(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, "bundle-retention.sqlite")
    project = _create_project(service, "Bundle retention")
    _create_procedure(service, project, procedure_id="local/retention")
    project = {**project, "workspace_revision": 2}
    bundle = _candidate_bundle(service, project)
    digest = bundle["bundle_digest"]
    first_bytes = service.get_bundle(
        digest, subject="viewer", role="viewer", include_bytes=True
    )["bundle_bytes"]
    rebuilt = service.build_bundle(
        bundle["history_revision_id"],
        **OPERATOR,
        idempotency_key="bundle-retention-independent-idempotency",
    )["bundle"]
    assert rebuilt["bundle_digest"] == digest
    with service.factory() as session:
        assert session.scalar(select(func.count()).select_from(DevelopmentBundle)) == 1

    service.approve_bundle(
        digest,
        **ADMIN,
        expected_state_revision=1,
        reason="Approve retained bytes",
        idempotency_key="bundle-retention-approve",
    )
    service.catalog_decision(
        "local/retention",
        **ADMIN,
        operation="PROMOTE",
        bundle_digest=digest,
        expected_registry_revision=0,
        reason="Reference exact retained bytes",
        idempotency_key="bundle-retention-promote",
    )
    service.pin_runtime_reference(
        runtime_kind="EXECUTION",
        runtime_id="bundle-retention-execution",
        procedure_id="local/retention",
    )
    with pytest.raises(DBAPIError, match="payload is immutable"):
        with service.factory.begin() as session:
            session.execute(
                text(
                    "UPDATE development_bundles SET bundle_bytes = :bytes "
                    "WHERE bundle_digest = :digest"
                ),
                {"bytes": b"changed", "digest": digest},
            )
    with pytest.raises(DBAPIError, match="retention forbids deletion"):
        with service.factory.begin() as session:
            session.execute(
                text("DELETE FROM development_bundles WHERE bundle_digest = :digest"),
                {"digest": digest},
            )
    assert service.get_bundle(
        digest, subject="viewer", role="viewer", include_bytes=True
    )["bundle_bytes"] == first_bytes

    with service.factory() as session:
        legitimate = session.get(DevelopmentBundle, digest)
        assert legitimate is not None
        row_values = {
            "project_id": legitimate.project_id,
            "history_revision_id": legitimate.history_revision_id,
            "source_tree_digest": legitimate.source_tree_digest,
            "validation_report_digest": legitimate.validation_report_digest,
            "author_subject": legitimate.author_subject,
            "review_subject": legitimate.review_subject,
            "builder_identity": legitimate.builder_identity,
        }
        manifest = dict(legitimate.manifest)
    corrupt_digests = {}
    with service.factory.begin() as session:
        for label, state in (
            ("read", "CANDIDATE"),
            ("promotion", "APPROVED"),
            ("runtime", "PROMOTED"),
        ):
            raw = canonical_json_bytes({"tampered_path": label})
            corrupt_digest = hashlib.sha256(raw).hexdigest()
            corrupt_digests[label] = corrupt_digest
            session.add(
                DevelopmentBundle(
                    bundle_digest=corrupt_digest,
                    bundle_bytes=raw,
                    byte_length=len(raw),
                    manifest={**manifest, "bundle_digest": corrupt_digest},
                    state=state,
                    state_revision=1,
                    approved_by_subject=(ADMIN["subject"] if state != "CANDIDATE" else None),
                    approval_reason=("tamper fixture" if state != "CANDIDATE" else None),
                    **row_values,
                )
            )
        session.add(
            DevelopmentCatalogEntry(
                procedure_id="local/tampered-runtime",
                registry_revision=1,
                current_bundle_digest=corrupt_digests["runtime"],
                previous_bundle_digest=None,
                state="PROMOTED",
                updated_by_subject=ADMIN["subject"],
            )
        )
    with pytest.raises(DevelopmentCorruptionError):
        service.get_bundle(
            corrupt_digests["read"], subject="viewer", role="viewer"
        )
    with pytest.raises(DevelopmentCorruptionError):
        service.catalog_decision(
            "local/retention",
            **ADMIN,
            operation="PROMOTE",
            bundle_digest=corrupt_digests["promotion"],
            expected_registry_revision=1,
            reason="Tampered bundle must not promote",
            idempotency_key="bundle-tamper-promotion",
        )
    with pytest.raises(DevelopmentCorruptionError):
        service.get_promoted_procedure("local/tampered-runtime")


def test_running_check_can_be_cancelled_without_partial_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, "cancel.sqlite")
    project = _create_project(service)
    _create_procedure(service, project)
    queued = service.create_check(
        project["project_id"],
        **OPERATOR,
        scope="PROJECT",
        scope_path=None,
        expected_workspace_revision=2,
        reparse_libraries=False,
        idempotency_key="cancel-job",
    )
    entered = threading.Event()
    release = threading.Event()
    from backend import development_service as module

    original = module.analyze_resources

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(4)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "analyze_resources", blocked)
    result: dict = {}
    thread = threading.Thread(
        target=lambda: result.update(service.run_check(queued["job"]["job_id"])),
        daemon=True,
    )
    thread.start()
    assert entered.wait(2)
    cancelled = service.cancel_check(
        queued["job"]["job_id"],
        **OPERATOR,
        idempotency_key="cancel-now",
    )
    assert cancelled["job"]["state"] == "CANCEL_REQUESTED"
    assert cancelled["job"]["completed_at"] is None
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert result["job"]["state"] == "CANCELLED"
    with service.factory() as session:
        assert session.query(DevelopmentProblem).count() == 0


def test_multi_procedure_bundle_is_rejected_before_catalog_admission(tmp_path: Path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Multi")
    _create_procedure(service, project, procedure_id="local/one", path="procedures/one.spell.py")
    _create_procedure(
        service,
        project,
        procedure_id="local/two",
        path="procedures/two.spell.py",
        revision=2,
    )
    checked = _run_project_check(service, project["project_id"], 3, "multi-check")
    assert checked["report"]["outcome"] == "PASS"
    history = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=3,
        message="Two procedures",
        selected_resource_ids=None,
        idempotency_key="multi-history",
    )["history_revision"]
    service.review_history(
        history["history_revision_id"],
        **ADMIN,
        decision="APPROVE",
        reason="Reviewed",
        expected_review_revision=0,
        idempotency_key="multi-review",
    )
    with pytest.raises(DevelopmentConflictError, match="exactly one"):
        service.build_bundle(
            history["history_revision_id"],
            **OPERATOR,
            idempotency_key="multi-bundle",
        )


def test_builder_failure_rolls_back_without_partial_bundle_row(tmp_path: Path) -> None:
    service = _service(tmp_path, "builder-failure.sqlite")
    project = _create_project(service, "Builder Failure")
    _create_procedure(service, project)
    checked = _run_project_check(service, project["project_id"], 2, "failure-check")
    assert checked["report"]["outcome"] == "PASS"
    history = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=2,
        message="Reviewed but unavailable builder",
        selected_resource_ids=None,
        idempotency_key="failure-history",
    )["history_revision"]
    service.review_history(
        history["history_revision_id"],
        **ADMIN,
        decision="APPROVE",
        reason="Independent review",
        expected_review_revision=0,
        idempotency_key="failure-review",
    )

    class UnavailableBuilder:
        def build(self, request):
            raise DevelopmentConflictError(
                "worker timed out", code="BUILDER_UNAVAILABLE"
            )

    service.bundle_builder = UnavailableBuilder()
    with pytest.raises(DevelopmentConflictError) as caught:
        service.build_bundle(
            history["history_revision_id"],
            **OPERATOR,
            idempotency_key="failure-bundle",
        )
    assert caught.value.code == "BUILDER_UNAVAILABLE"
    with service.factory() as session:
        assert session.query(DevelopmentBundle).count() == 0
