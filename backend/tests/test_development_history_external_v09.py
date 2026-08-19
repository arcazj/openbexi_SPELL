from __future__ import annotations

import ast
import hashlib
import threading
from pathlib import Path

import pytest
from sqlalchemy import delete, func, select

from backend.development_domain import DevelopmentConflictError
from backend.development_models import (
    DevelopmentAnalysisJob,
    DevelopmentAuditEvent,
    DevelopmentConflict,
    DevelopmentHistoryRevision,
    DevelopmentHistoryReview,
    DevelopmentOutbox,
)
from backend.tests.test_development_authoring_v09 import _check, _create_text_resource
from backend.tests.test_development_service_v09 import (
    OPERATOR,
    _create_project,
    _service,
    _source,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _commit_base(service, project_id: str, revision: int, key: str) -> dict:
    assert _check(
        service,
        project_id,
        revision,
        scope="PROJECT",
        path=None,
        reparse=False,
        key=f"{key}-check",
    )["report"]["outcome"] == "PASS"
    return service.commit_history(
        project_id,
        **OPERATOR,
        expected_workspace_revision=revision,
        message=f"Immutable base {key}",
        selected_resource_ids=None,
        idempotency_key=f"{key}-commit",
    )["history_revision"]


def test_concurrent_selected_history_commits_are_revision_bound_and_at_most_one_wins(
    tmp_path, monkeypatch
) -> None:
    service = _service(tmp_path, "selected-history-race.sqlite")
    project = _create_project(service, "Selected history race")
    first = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/first.spell.py",
        content=_source("local/selected-first", "base"),
        key="selected-race-first",
    )
    second = _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/second.spell.py",
        content=_source("local/selected-second", "base"),
        key="selected-race-second",
    )
    base = _commit_base(service, project["project_id"], 3, "selected-race-base")
    for revision, resource, procedure_id in (
        (3, first, "local/selected-first"),
        (4, second, "local/selected-second"),
    ):
        changed = _source(procedure_id, "changed")
        service.update_resource(
            project["project_id"],
            resource["resource_id"],
            **OPERATOR,
            changes={"content": changed, "content_sha256": _digest(changed)},
            expected_workspace_revision=revision,
            idempotency_key=f"selected-race-change-{revision}",
        )

    barrier = threading.Barrier(2)
    original_mutate = service._mutate

    def synchronized_mutate(*args, **kwargs):
        barrier.wait(timeout=3)
        return original_mutate(*args, **kwargs)

    monkeypatch.setattr(service, "_mutate", synchronized_mutate)
    outcomes: list[tuple[str, object]] = []

    def commit(label: str, resource_id: str) -> None:
        try:
            outcomes.append(
                (
                    label,
                    service.commit_history(
                        project["project_id"],
                        **OPERATOR,
                        expected_workspace_revision=5,
                        message=f"Selected {label}",
                        selected_resource_ids=[resource_id],
                        idempotency_key=f"selected-race-commit-{label}",
                    ),
                )
            )
        except Exception as exc:
            outcomes.append((label, exc))

    threads = [
        threading.Thread(target=commit, args=("first", first["resource_id"])),
        threading.Thread(target=commit, args=("second", second["resource_id"])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    successes = [result for _, result in outcomes if not isinstance(result, Exception)]
    failures = [result for _, result in outcomes if isinstance(result, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], DevelopmentConflictError)
    assert failures[0].code == "HISTORY_BASE_CONFLICT"
    committed_id = successes[0]["history_revision"]["history_revision_id"]
    with service.factory() as session:
        assert session.scalar(
            select(func.count()).select_from(DevelopmentHistoryRevision).where(
                DevelopmentHistoryRevision.project_id == project["project_id"]
            )
        ) == 2
        committed = session.get(DevelopmentHistoryRevision, committed_id)
        assert committed is not None
        assert committed.parent_revision_ids == [base["history_revision_id"]]
    status = service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]
    assert status["base_history_revision_id"] == committed_id
    assert len(status["changes"]) == 1


def test_history_is_provider_neutral_and_persists_no_remote_credentials(
    tmp_path,
) -> None:
    service = _service(tmp_path, "provider-neutral-history.sqlite")
    project = _create_project(service, "Provider neutral history")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/local-only.spell.py",
        content=_source("local/provider-neutral"),
        key="provider-neutral-source",
    )
    history = _commit_base(
        service, project["project_id"], 2, "provider-neutral-base"
    )
    assert set(history) == {
        "history_revision_id",
        "project_id",
        "ordinal",
        "parent_revision_ids",
        "tree_digest",
        "author_subject",
        "message",
        "validation_job_id",
        "validation_summary_digest",
        "workspace_revision",
        "created_at",
    }
    forbidden_fragments = {
        "credential",
        "password",
        "provider",
        "remote",
        "repository",
        "secret",
        "token",
    }
    for model in (
        DevelopmentHistoryRevision,
        DevelopmentHistoryReview,
        DevelopmentConflict,
    ):
        for column in model.__table__.columns:
            lowered = column.name.casefold()
            assert not any(fragment in lowered for fragment in forbidden_fragments)

    def assert_no_forbidden_keys(value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).casefold()
                assert not any(
                    fragment in lowered for fragment in forbidden_fragments
                )
                assert_no_forbidden_keys(item)
        elif isinstance(value, list):
            for item in value:
                assert_no_forbidden_keys(item)

    with service.factory() as session:
        revision = session.get(
            DevelopmentHistoryRevision, history["history_revision_id"]
        )
        assert revision is not None
        assert revision.parent_revision_ids == []
        assert revision.snapshot_bytes
        for row in session.scalars(
            select(DevelopmentAuditEvent).where(
                DevelopmentAuditEvent.project_id == project["project_id"]
            )
        ).all():
            assert_no_forbidden_keys(row.payload)
        for row in session.scalars(
            select(DevelopmentOutbox).where(
                DevelopmentOutbox.aggregate_id.in_(
                    [project["project_id"], history["history_revision_id"]]
                )
            )
        ).all():
            assert_no_forbidden_keys(row.payload)

    tree = ast.parse(
        (Path(__file__).parents[1] / "development_service.py").read_text(
            encoding="utf-8"
        )
    )
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_roots.isdisjoint(
        {"git", "github", "gitlab", "svn", "cvs", "requests", "httpx", "socket"}
    )


def test_selected_history_diff_revert_and_three_way_conflict_resolution(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "History")
    original_a = _source("local/a", "base-a")
    original_b = _source("local/b", "base-b")
    a = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/a.spell.py",
        content=original_a,
        key="history-a",
    )
    b = _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/b.spell.py",
        content=original_b,
        key="history-b",
    )
    assert _check(
        service,
        project["project_id"],
        3,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="history-check-1",
    )["report"]["outcome"] == "PASS"
    first = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=3,
        message="Initial full tree",
        selected_resource_ids=None,
        idempotency_key="history-commit-1",
    )["history_revision"]

    service.update_resource(
        project["project_id"],
        a["resource_id"],
        **OPERATOR,
        changes={"path": "procedures/A.spell.py"},
        expected_workspace_revision=3,
        idempotency_key="history-case-rename",
    )
    changed_b = _source("local/b", "workspace-only-b")
    service.update_resource(
        project["project_id"],
        b["resource_id"],
        **OPERATOR,
        changes={"content": changed_b, "content_sha256": _digest(changed_b)},
        expected_workspace_revision=4,
        idempotency_key="history-change-b",
    )
    assert _check(
        service,
        project["project_id"],
        5,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="history-check-2",
    )["report"]["outcome"] == "PASS"
    selected = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=5,
        message="Only the rename",
        selected_resource_ids=[a["resource_id"]],
        idempotency_key="history-commit-selected",
    )["history_revision"]
    diff = service.diff_history(
        selected["history_revision_id"],
        subject="viewer",
        role="viewer",
        against_revision_id=first["history_revision_id"],
    )["diff"]
    assert [(item["status"], item["before_path"], item["after_path"]) for item in diff["changes"]] == [
        ("CASE_CHANGED", "procedures/a.spell.py", "procedures/A.spell.py")
    ]
    assert diff["changes"][0]["dependency_impact"] is True
    assert "before_digest" in diff["validation_delta"]

    reverted = service.revert_history(
        first["history_revision_id"],
        **OPERATOR,
        expected_workspace_revision=5,
        reason="Restore the immutable base as a new change",
        idempotency_key="history-revert",
    )["project"]
    assert reverted["workspace_revision"] == 6
    workspace = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]
    paths = {item["path"] for item in workspace["resources"]}
    assert "procedures/a.spell.py" in paths
    restored_b = service.get_resource(
        project["project_id"], b["resource_id"], subject="viewer", role="viewer"
    )["resource"]
    assert restored_b["content"] == original_b

    ours = _source("local/a", "ours")
    service.update_resource(
        project["project_id"],
        a["resource_id"],
        **OPERATOR,
        changes={"content": ours, "content_sha256": _digest(ours)},
        expected_workspace_revision=6,
        idempotency_key="external-ours",
    )
    theirs = _source("local/a", "theirs")
    merged = service.apply_external_changes(
        project["project_id"],
        **OPERATOR,
        base_workspace_revision=3,
        base_history_revision_id=first["history_revision_id"],
        changes=[
            {
                "from_path": "procedures/a.spell.py",
                "path": "procedures/A.spell.py",
                "content": theirs,
                "content_sha256": _digest(theirs),
                "base_content_sha256": _digest(original_a),
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="external-three-way",
    )
    conflict = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]
    assert merged["conflict_ids"] == [conflict["conflict_id"]]
    assert conflict["kind"] == "CASE_COLLISION"
    assert conflict["base_content_sha256"] == _digest(original_a)
    resolved = service.resolve_conflict(
        project["project_id"],
        **OPERATOR,
        path="procedures/A.spell.py",
        resolution="THEIRS",
        resolved_content=None,
        expected_conflict_digest=conflict["conflict_digest"],
        expected_workspace_revision=7,
        idempotency_key="external-resolve-theirs",
    )
    assert resolved["project"]["workspace_revision"] == 8
    assert resolved["resource"]["path"] == "procedures/A.spell.py"
    assert resolved["resource"]["content"] == theirs

    created = _source("local/external", "created")
    service.apply_external_changes(
        project["project_id"],
        **OPERATOR,
        base_workspace_revision=8,
        changes=[
            {
                "path": "procedures/external.spell.py",
                "content": created,
                "content_sha256": _digest(created),
            }
        ],
        resolution="KEEP_AS_NEW_CHANGE",
        idempotency_key="external-create",
    )
    service.apply_external_changes(
        project["project_id"],
        **OPERATOR,
        base_workspace_revision=9,
        changes=[
            {
                "path": "procedures/external.spell.py",
                "delete": True,
                "base_content_sha256": _digest(created),
            }
        ],
        resolution="KEEP_AS_NEW_CHANGE",
        idempotency_key="external-delete",
    )
    paths = {
        item["path"]
        for item in service.workspace_snapshot(
            project["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
    }
    assert "procedures/external.spell.py" not in paths


def test_external_change_casefold_collisions_fail_atomically(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "External collision")
    one = _source("local/one")
    two = _source("local/two")
    with pytest.raises(DevelopmentConflictError) as raised:
        service.apply_external_changes(
            project["project_id"],
            **OPERATOR,
            base_workspace_revision=1,
            changes=[
                {
                    "path": "procedures/Same.spell.py",
                    "content": one,
                    "content_sha256": _digest(one),
                },
                {
                    "path": "procedures/same.spell.py",
                    "content": two,
                    "content_sha256": _digest(two),
                },
            ],
            resolution="KEEP_AS_NEW_CHANGE",
            idempotency_key="external-case-collision",
        )
    assert raised.value.code == "CASE_CONFLICT"
    assert service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["workspace_revision"] == 1


def test_conflict_resolution_rejects_stale_workspace_and_ours_preserves_path(
    tmp_path,
) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Conflict binding")
    original = _source("local/binding", "base")
    resource = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/binding.spell.py",
        content=original,
        key="binding-resource",
    )
    base = _commit_base(service, project["project_id"], 2, "binding-base")
    theirs = _source("local/binding", "theirs")
    service.apply_external_changes(
        project["project_id"],
        **OPERATOR,
        base_workspace_revision=2,
        base_history_revision_id=base["history_revision_id"],
        changes=[
            {
                "from_path": "procedures/binding.spell.py",
                "path": "procedures/theirs.spell.py",
                "content": theirs,
                "content_sha256": _digest(theirs),
                "base_content_sha256": _digest(original),
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="binding-conflict",
    )
    conflict = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]

    unrelated = _source("local/unrelated")
    _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/unrelated.spell.py",
        content=unrelated,
        key="binding-unrelated",
    )
    with pytest.raises(DevelopmentConflictError) as stale:
        service.resolve_conflict(
            project["project_id"],
            **OPERATOR,
            path="procedures/theirs.spell.py",
            resolution="THEIRS",
            resolved_content=None,
            expected_conflict_digest=conflict["conflict_digest"],
            expected_workspace_revision=3,
            idempotency_key="binding-stale-resolution",
        )
    assert stale.value.code == "STALE_CONFLICT"
    assert service.get_resource(
        project["project_id"], resource["resource_id"], subject="viewer", role="viewer"
    )["resource"]["content"] == original
    dismissed = service.dismiss_conflict(
        project["project_id"],
        conflict["conflict_id"],
        **OPERATOR,
        expected_conflict_digest=conflict["conflict_digest"],
        expected_workspace_revision=3,
        reason="Workspace advanced; re-import from a new base",
        idempotency_key="binding-dismiss-stale",
    )
    assert dismissed["conflict"]["resolution"] == "DISMISSED_STALE"
    assert service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"] == []

    ours_project = _create_project(service, "Ours rename")
    ours = _source("local/ours", "ours")
    _create_text_resource(
        service,
        ours_project["project_id"],
        revision=1,
        path="procedures/ours.spell.py",
        content=ours,
        key="ours-resource",
    )
    ours_base = _commit_base(service, ours_project["project_id"], 2, "ours-base")
    external = _source("local/ours", "external")
    service.apply_external_changes(
        ours_project["project_id"],
        **OPERATOR,
        base_workspace_revision=2,
        base_history_revision_id=ours_base["history_revision_id"],
        changes=[
            {
                "from_path": "procedures/ours.spell.py",
                "path": "procedures/external-name.spell.py",
                "content": external,
                "content_sha256": _digest(external),
                "base_content_sha256": _digest(ours),
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="ours-conflict",
    )
    ours_conflict = service.workspace_snapshot(
        ours_project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]
    resolved = service.resolve_conflict(
        ours_project["project_id"],
        **OPERATOR,
        path="procedures/external-name.spell.py",
        resolution="OURS",
        resolved_content=None,
        expected_conflict_digest=ours_conflict["conflict_digest"],
        expected_workspace_revision=2,
        idempotency_key="ours-resolution",
    )["resource"]
    assert resolved["path"] == "procedures/ours.spell.py"
    assert resolved["content"] == ours


def test_external_existing_update_and_delete_require_exact_base_digest(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "External digest binding")
    original = _source("local/digest", "original")
    resource = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/digest.spell.py",
        content=original,
        key="digest-resource",
    )
    changed = _source("local/digest", "changed")
    for index, change in enumerate(
        (
            {
                "path": "procedures/digest.spell.py",
                "content": changed,
                "content_sha256": _digest(changed),
            },
            {"path": "procedures/digest.spell.py", "delete": True},
            {
                "path": "procedures/digest.spell.py",
                "content": changed,
                "content_sha256": _digest(changed),
                "base_content_sha256": "0" * 64,
            },
        )
    ):
        with pytest.raises(DevelopmentConflictError) as caught:
            service.apply_external_changes(
                project["project_id"],
                **OPERATOR,
                base_workspace_revision=2,
                changes=[change],
                resolution="KEEP_AS_NEW_CHANGE",
                idempotency_key=f"digest-reject-{index}",
            )
        assert caught.value.code == "EXTERNAL_CHANGE_CONFLICT"
        current = service.get_resource(
            project["project_id"], resource["resource_id"], subject="viewer", role="viewer"
        )["resource"]
        assert current["content"] == original
        assert current["revision"] == 1
    assert service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["workspace_revision"] == 2


def test_conflict_resolution_preserves_metadata_and_folder_subtrees(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Conflict metadata")
    metadata = '{"value":1}'
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="metadata.json",
        content=metadata,
        kind="PROJECT_METADATA",
        media_type="text/plain",
        key="metadata-resource",
    )
    base = _commit_base(service, project["project_id"], 2, "metadata-base")
    service.apply_external_changes(
        project["project_id"],
        **OPERATOR,
        base_workspace_revision=2,
        base_history_revision_id=base["history_revision_id"],
        changes=[
            {
                "path": "metadata.json",
                "content": metadata,
                "content_sha256": _digest(metadata),
                "base_content_sha256": _digest(metadata),
                "kind": "PROJECT_METADATA",
                "media_type": "application/json",
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="metadata-conflict",
    )
    conflict = service.workspace_snapshot(
        project["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]
    assert conflict["kind"] == "METADATA"
    resolved = service.resolve_conflict(
        project["project_id"],
        **OPERATOR,
        path="metadata.json",
        resolution="THEIRS",
        resolved_content=None,
        expected_conflict_digest=conflict["conflict_digest"],
        expected_workspace_revision=2,
        idempotency_key="metadata-resolution",
    )["resource"]
    assert resolved["kind"] == "PROJECT_METADATA"
    assert resolved["media_type"] == "application/json"

    tree = _create_project(service, "Conflict subtree")
    folder = _create_text_resource(
        service,
        tree["project_id"],
        revision=1,
        path="procedures/group",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="subtree-folder",
    )
    child = _source("local/subtree")
    _create_text_resource(
        service,
        tree["project_id"],
        revision=2,
        path="procedures/group/child.spell.py",
        content=child,
        key="subtree-child",
    )
    tree_base = _commit_base(service, tree["project_id"], 3, "subtree-base")
    empty_digest = _digest("")
    service.apply_external_changes(
        tree["project_id"],
        **OPERATOR,
        base_workspace_revision=3,
        base_history_revision_id=tree_base["history_revision_id"],
        changes=[
            {
                "from_path": "procedures/group",
                "path": "procedures/moved",
                "content": "",
                "content_sha256": empty_digest,
                "base_content_sha256": empty_digest,
                "kind": "FOLDER",
                "media_type": "application/x-directory",
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="subtree-move-conflict",
    )
    move_conflict = service.workspace_snapshot(
        tree["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]
    moved = service.resolve_conflict(
        tree["project_id"],
        **OPERATOR,
        path="procedures/moved",
        resolution="THEIRS",
        resolved_content=None,
        expected_conflict_digest=move_conflict["conflict_digest"],
        expected_workspace_revision=3,
        idempotency_key="subtree-move-resolution",
    )
    assert moved["resource"]["resource_id"] == folder["resource_id"]
    paths = {
        item["path"]
        for item in service.workspace_snapshot(
            tree["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
    }
    assert "procedures/moved" in paths
    assert "procedures/moved/child.spell.py" in paths
    assert "procedures/group/child.spell.py" not in paths

    moved_base = _commit_base(service, tree["project_id"], 4, "subtree-moved-base")
    service.apply_external_changes(
        tree["project_id"],
        **OPERATOR,
        base_workspace_revision=4,
        base_history_revision_id=moved_base["history_revision_id"],
        changes=[
            {
                "path": "procedures/moved",
                "delete": True,
                "base_content_sha256": empty_digest,
            }
        ],
        resolution="THREE_WAY_MERGE",
        idempotency_key="subtree-delete-conflict",
    )
    delete_conflict = service.workspace_snapshot(
        tree["project_id"], subject="viewer", role="viewer"
    )["workspace"]["conflicts"][0]
    deleted = service.resolve_conflict(
        tree["project_id"],
        **OPERATOR,
        path="procedures/moved",
        resolution="THEIRS",
        resolved_content=None,
        expected_conflict_digest=delete_conflict["conflict_digest"],
        expected_workspace_revision=4,
        idempotency_key="subtree-delete-resolution",
    )
    assert deleted["resource"] is None
    paths = {
        item["path"]
        for item in service.workspace_snapshot(
            tree["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
    }
    assert not any(path == "procedures/moved" or path.startswith("procedures/moved/") for path in paths)


def test_workspace_status_stable_identity_selected_validation_and_refresh_base(
    tmp_path,
) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Status selected")
    first_source = _source("local/status-a", "first")
    second_source = _source("local/status-b", "first")
    first = _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/status-a.spell.py",
        content=first_source,
        key="status-a",
    )
    second = _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="procedures/status-b.spell.py",
        content=second_source,
        key="status-b",
    )
    base = _commit_base(service, project["project_id"], 3, "status-base")
    clean = service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]
    assert clean["clean"] is True

    renamed_source = _source("local/status-a", "renamed-and-modified")
    service.update_resource(
        project["project_id"],
        first["resource_id"],
        **OPERATOR,
        changes={
            "path": "procedures/renamed-status-a.spell.py",
            "content": renamed_source,
            "content_sha256": _digest(renamed_source),
        },
        expected_workspace_revision=3,
        idempotency_key="status-rename-modify",
    )
    invalid_unselected = "# @procedure local/status-b\nUnknownCall()\n"
    service.update_resource(
        project["project_id"],
        second["resource_id"],
        **OPERATOR,
        changes={
            "content": invalid_unselected,
            "content_sha256": _digest(invalid_unselected),
        },
        expected_workspace_revision=4,
        idempotency_key="status-invalid-unselected",
    )
    status = service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]
    rename = next(item for item in status["changes"] if item["resource_id"] == first["resource_id"])
    assert rename["status"] == "RENAMED"
    assert rename["old_path"] == "procedures/status-a.spell.py"
    diff = service.diff_workspace_to_base(
        project["project_id"], subject="viewer", role="viewer"
    )["diff"]
    renamed = next(item for item in diff["changes"] if item["resource_id"] == first["resource_id"])
    assert renamed["status"] == "RENAMED"
    assert renamed["content_changed"] is True

    selected = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=5,
        message="Commit only the valid rename",
        selected_resource_ids=[first["resource_id"]],
        idempotency_key="status-selected",
    )["history_revision"]
    assert selected["validation_job_id"]
    selected_snapshot = service.get_history(
        selected["history_revision_id"], subject="viewer", role="viewer"
    )["history_revision"]
    assert selected_snapshot["validation_summary_digest"]

    assert service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]["clean"] is False
    service.update_resource(
        project["project_id"],
        second["resource_id"],
        **OPERATOR,
        changes={"content": second_source, "content_sha256": _digest(second_source)},
        expected_workspace_revision=5,
        idempotency_key="status-restore-unselected",
    )
    assert service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]["clean"] is True
    service.refresh_base(
        project["project_id"],
        **OPERATOR,
        history_revision_id=base["history_revision_id"],
        expected_workspace_revision=6,
        idempotency_key="status-refresh-base",
    )
    refreshed = service.workspace_status(
        project["project_id"], subject="viewer", role="viewer"
    )["status"]
    assert refreshed["clean"] is True
    assert refreshed["base_history_revision_id"] == base["history_revision_id"]
    restored_second = service.get_resource(
        project["project_id"], second["resource_id"], subject="viewer", role="viewer"
    )["resource"]
    assert restored_second["content"] == second_source

    changed_again = _source("local/status-a", "dirty")
    service.update_resource(
        project["project_id"],
        first["resource_id"],
        **OPERATOR,
        changes={
            "content": changed_again,
            "content_sha256": _digest(changed_again),
        },
        expected_workspace_revision=7,
        idempotency_key="status-dirty-again",
    )
    with pytest.raises(DevelopmentConflictError) as dirty:
        service.refresh_base(
            project["project_id"],
            **OPERATOR,
            history_revision_id=selected["history_revision_id"],
            expected_workspace_revision=8,
            idempotency_key="status-refresh-dirty",
        )
    assert dirty.value.code == "WORKSPACE_DIRTY"


def test_bundle_approval_fails_closed_when_history_analysis_evidence_is_deleted(
    tmp_path,
) -> None:
    from backend.tests.test_development_service_v09 import ADMIN, _candidate_bundle

    service = _service(tmp_path)
    project = _create_project(service, "Evidence deletion")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="procedures/evidence.spell.py",
        content=_source("local/evidence"),
        key="evidence-source",
    )
    bundle = _candidate_bundle(
        service, {**project, "workspace_revision": 2}
    )
    history_id = bundle["history_revision_id"]
    history = service.get_history(history_id, subject="viewer", role="viewer")[
        "history_revision"
    ]
    with service.factory.begin() as session:
        session.execute(
            delete(DevelopmentAnalysisJob).where(
                DevelopmentAnalysisJob.job_id == history["validation_job_id"]
            )
        )
    with pytest.raises(DevelopmentConflictError) as missing:
        service.approve_bundle(
            bundle["bundle_digest"],
            **ADMIN,
            expected_state_revision=1,
            reason="Evidence must still exist",
            idempotency_key="evidence-missing-approval",
        )
    assert missing.value.code == "VALIDATION_REQUIRED"
