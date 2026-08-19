from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.condition_engine import QualityFreshnessPolicy
from backend.condition_service import ConditionServiceConflictError
from backend.development_domain import (
    DevelopmentAuthorizationError,
    DevelopmentConflictError,
    DevelopmentLimitError,
)
from backend.development_models import (
    DevelopmentAnalysisJob,
    DevelopmentAuditEvent,
    DevelopmentBundle,
    DevelopmentCatalogEntry,
    DevelopmentIdempotency,
    DevelopmentOutbox,
    DevelopmentPromotionDecision,
    DevelopmentRuntimePin,
)
from backend.development_service import DevelopmentService
from backend.models import Execution
from backend.operator_models import ProcedureCatalogRevision, ProcedureSchedule
from backend.operator_service import OperatorConflictError
from backend.supervisor import ConflictError
from backend.tests.test_development_service_v09 import (
    ADMIN,
    OPERATOR,
    _candidate_bundle,
    _create_procedure,
    _create_project,
    _run_project_check,
    _service,
)
from backend.tests.test_condition_service_v07 import SnapshotQueue, plan, snapshot


def _promote(service: DevelopmentService) -> tuple[dict, dict]:
    return _promote_named(service, "Runtime", "local/runtime")


def _promote_named(
    service: DevelopmentService, project_name: str, procedure_id: str
) -> tuple[dict, dict]:
    project = _create_project(service, project_name)
    _create_procedure(service, project, procedure_id=procedure_id)
    project = {**project, "workspace_revision": 2}
    bundle = _candidate_bundle(service, project)
    approved = service.approve_bundle(
        bundle["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Independent runtime approval",
        idempotency_key=f"runtime-approve-{procedure_id}",
    )["bundle"]
    assert approved["state"] == "APPROVED"
    promoted = service.catalog_decision(
        procedure_id,
        **ADMIN,
        operation="PROMOTE",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=0,
        reason="Admit to the local simulator",
        idempotency_key=f"runtime-promote-{procedure_id}",
    )["catalog_entry"]
    assert promoted["state"] == "PROMOTED"
    return project, bundle


def _control_proof(operator_service, execution: Execution, key: str) -> dict:
    actor = "pytest-operator"
    lease = operator_service.acquire_control(
        execution.id,
        expected_execution_revision=execution.revision,
        actor=actor,
        holder_session_id=f"session-{key}",
        client_instance_key_id=f"client-{key}",
        lease_seconds=60,
        idempotency_key=f"lease-{key}",
        reason="v0.9 runtime continuity proof",
    )["control_lease"]
    return {
        "actor": actor,
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "holder_session_id": f"session-{key}",
        "client_instance_key_id": f"client-{key}",
    }


def test_promoted_runtime_exact_digest_withdrawal_and_existing_pin_continuity(
    client: TestClient,
    operator_headers: dict[str, str],
) -> None:
    service: DevelopmentService = client.app.state.development_service
    _, bundle = _promote(service)
    procedure = client.app.state.catalog.get("local/runtime")
    assert procedure.bundle_digest == bundle["bundle_digest"]
    client.app.state.operator_service.sync_catalog(actor="runtime-test")
    with client.app.state.session_factory() as session:
        revision = session.scalar(
            select(ProcedureCatalogRevision)
            .where(
                ProcedureCatalogRevision.bundle_digest == bundle["bundle_digest"]
            )
            .order_by(ProcedureCatalogRevision.revision.desc())
        )
        assert revision is not None
        assert revision.source_digest == procedure.sha256
        assert revision.properties["development_bundle_digest"] == bundle["bundle_digest"]

    response = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "local/runtime",
            "context_id": "simulator",
            "reason": "v0.9 direct admission",
            "idempotency_key": "runtime-direct-execution",
        },
    )
    assert response.status_code == 202, response.text
    direct_execution_id = response.json()["execution"]["id"]
    schedule_pin = service.pin_runtime_reference(
        runtime_kind="SCHEDULE",
        runtime_id="schedule-existing-v09",
        procedure_id="local/runtime",
    )
    assert schedule_pin["bundle_digest"] == bundle["bundle_digest"]

    withdrawn = service.catalog_decision(
        "local/runtime",
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=1,
        reason="Withdraw new admissions",
        idempotency_key="runtime-withdraw",
    )["catalog_entry"]
    assert withdrawn["state"] == "WITHDRAWN"
    assert client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "local/runtime",
            "context_id": "simulator",
            "reason": "must be rejected",
            "idempotency_key": "runtime-after-withdraw",
        },
    ).status_code == 404
    assert client.get(
        f"/api/v1/executions/{direct_execution_id}/snapshot",
        headers=operator_headers,
    ).status_code == 200

    derived = client.app.state.supervisor.create_execution(
        procedure,
        actor="schedule-service",
        role="operator",
        reason="Fire already admitted schedule",
        idempotency_key="schedule-derived-v09",
        automatic=False,
        runtime_pin_parent_kind="SCHEDULE",
        runtime_pin_parent_id="schedule-existing-v09",
    )
    with pytest.raises(ConflictError, match="not currently promoted"):
        client.app.state.supervisor.create_execution(
            procedure,
            actor="operator",
            role="operator",
            reason="Unpinned admission after withdrawal",
            idempotency_key="runtime-unpinned-after-withdraw",
            automatic=False,
        )
    with client.app.state.session_factory() as session:
        pins = session.scalars(
            select(DevelopmentRuntimePin).order_by(
                DevelopmentRuntimePin.runtime_kind,
                DevelopmentRuntimePin.runtime_id,
            )
        ).all()
        by_runtime = {(item.runtime_kind, item.runtime_id): item for item in pins}
        assert by_runtime[("EXECUTION", direct_execution_id)].bundle_digest == bundle["bundle_digest"]
        assert by_runtime[("EXECUTION", derived.id)].bundle_digest == bundle["bundle_digest"]
        assert by_runtime[("SCHEDULE", "schedule-existing-v09")].bundle_digest == bundle["bundle_digest"]


def test_withdraw_and_new_pin_are_serialized_without_unadmitted_pin(tmp_path) -> None:
    service = _service(tmp_path, "withdraw-race.sqlite")
    _, bundle = _promote(service)
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def pin() -> None:
        barrier.wait()
        try:
            outcomes["pin"] = service.pin_runtime_reference(
                runtime_kind="EXECUTION",
                runtime_id="race-execution",
                procedure_id="local/runtime",
            )
        except Exception as exc:  # captured for deterministic postcondition checks
            outcomes["pin"] = exc

    def withdraw() -> None:
        barrier.wait()
        try:
            outcomes["withdraw"] = service.catalog_decision(
                "local/runtime",
                **ADMIN,
                operation="WITHDRAW",
                bundle_digest=bundle["bundle_digest"],
                expected_registry_revision=1,
                reason="Concurrent withdrawal",
                idempotency_key="race-withdraw",
            )
        except Exception as exc:
            outcomes["withdraw"] = exc

    threads = [threading.Thread(target=pin), threading.Thread(target=withdraw)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert not isinstance(outcomes["withdraw"], Exception)
    pin_outcome = outcomes["pin"]
    if isinstance(pin_outcome, Exception):
        assert isinstance(pin_outcome, DevelopmentConflictError)
        with service.factory() as session:
            assert session.scalar(
                select(DevelopmentRuntimePin).where(
                    DevelopmentRuntimePin.runtime_id == "race-execution"
                )
            ) is None
    else:
        assert pin_outcome["bundle_digest"] == bundle["bundle_digest"]
        with service.factory() as session:
            assert session.scalar(
                select(DevelopmentRuntimePin).where(
                    DevelopmentRuntimePin.runtime_id == "race-execution"
                )
            ).bundle_digest == bundle["bundle_digest"]
    assert service.get_catalog_entry(
        "local/runtime", subject="viewer", role="viewer"
    )["catalog_entry"]["state"] == "WITHDRAWN"


def test_true_schedule_fire_after_withdrawal_preserves_execution_pin(
    client: TestClient,
    operator_headers: dict[str, str],
) -> None:
    development: DevelopmentService = client.app.state.development_service
    _, bundle = _promote(development)
    operator = client.app.state.operator_service
    operator.sync_catalog(actor="schedule-v09-test")
    response = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "local/runtime",
            "context_id": "simulator",
            "reason": "v0.9 schedule controller",
            "idempotency_key": "v09-schedule-controller",
        },
    )
    assert response.status_code == 202, response.text
    controller_id = response.json()["execution"]["id"]
    with client.app.state.session_factory() as session:
        controller = session.get(Execution, controller_id)
        session.expunge(controller)
    proof = _control_proof(operator, controller, "v09-schedule")
    catalog_item = next(
        item
        for item in operator.list_catalog()
        if item["procedure_ref"] == "local/runtime"
    )
    schedule = operator.create_schedule(
        controller_execution_id=controller.id,
        schedule_type="RELATIVE",
        target="60.0",
        procedure_catalog_id=catalog_item["id"],
        procedure_revision=None,
        context_id="simulator",
        arguments={},
        automatic=False,
        background_allowed=False,
        visible=True,
        misfire_policy="FIRE_ONCE",
        maximum_lateness_seconds=3600,
        expected_execution_revision=controller.revision,
        idempotency_key="v09-schedule-existing",
        reason="pin before withdrawal",
        **proof,
    )
    development.catalog_decision(
        "local/runtime",
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=1,
        reason="withdraw after schedule admission",
        idempotency_key="v09-schedule-withdraw",
    )
    with pytest.raises(OperatorConflictError, match="not currently promoted"):
        operator.create_schedule(
            controller_execution_id=controller.id,
            schedule_type="RELATIVE",
            target="60.0",
            procedure_catalog_id=catalog_item["id"],
            procedure_revision=None,
            context_id="simulator",
            arguments={},
            automatic=False,
            background_allowed=False,
            visible=True,
            misfire_policy="FIRE_ONCE",
            maximum_lateness_seconds=3600,
            expected_execution_revision=controller.revision,
            idempotency_key="v09-schedule-new-after-withdraw",
            reason="must reject new schedule",
            **proof,
        )
    with client.app.state.session_factory() as session:
        stored = session.get(ProcedureSchedule, schedule["id"])
        stored.target_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    assert operator.reconcile_schedules() == 1
    fired = next(
        item for item in operator.list_schedules() if item["id"] == schedule["id"]
    )
    assert fired["state"] == "FIRED"
    with client.app.state.session_factory() as session:
        pin = session.scalar(
            select(DevelopmentRuntimePin).where(
                DevelopmentRuntimePin.runtime_kind == "EXECUTION",
                DevelopmentRuntimePin.runtime_id == fired["execution_id"],
            )
        )
        assert pin is not None
        assert pin.bundle_digest == bundle["bundle_digest"]


def test_true_startproc_resume_after_withdrawal_preserves_execution_pin(
    client: TestClient,
    operator_headers: dict[str, str],
) -> None:
    development: DevelopmentService = client.app.state.development_service
    _promote_named(development, "Runtime parent", "local/parent")
    _, child_bundle = _promote_named(development, "Runtime child", "local/child")
    operator = client.app.state.operator_service
    operator.sync_catalog(actor="startproc-v09-test")
    response = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "local/parent",
            "context_id": "simulator",
            "reason": "v0.9 StartProc parent",
            "idempotency_key": "v09-startproc-parent",
        },
    )
    assert response.status_code == 202, response.text
    parent_id = response.json()["execution"]["id"]
    original_starter = operator.execution_starter
    operator.execution_starter = None
    try:
        operation = operator.admit_startproc(
            parent_id,
            "v09-startproc-existing",
            0,
            {
                "child_reference": "local/child",
                "arguments": {},
                "blocking": False,
                "visible": True,
                "automatic": False,
                "idempotency_key": "v09-startproc-existing",
            },
        )
    finally:
        operator.execution_starter = original_starter
    assert operation["state"] == "ADMITTING"
    development.catalog_decision(
        "local/child",
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=child_bundle["bundle_digest"],
        expected_registry_revision=1,
        reason="withdraw after StartProc admission",
        idempotency_key="v09-startproc-withdraw",
    )
    resumed = operator._resume_startproc_admission(operation["id"])
    assert resumed["state"] == "SETTLED"
    assert resumed["child_execution_id"] is not None
    rejected = operator.admit_startproc(
        parent_id,
        "v09-startproc-new-after-withdraw",
        0,
        {
            "child_reference": "local/child",
            "arguments": {},
            "blocking": False,
            "visible": True,
            "automatic": False,
            "idempotency_key": "v09-startproc-new-after-withdraw",
        },
    )
    assert rejected["state"] == "REJECTED"
    assert rejected["rejection_code"] in {
        "PROCEDURE_NOT_FOUND",
        "PROCEDURE_NOT_PROMOTED",
    }
    with client.app.state.session_factory() as session:
        pin = session.scalar(
            select(DevelopmentRuntimePin).where(
                DevelopmentRuntimePin.runtime_kind == "EXECUTION",
                DevelopmentRuntimePin.runtime_id == resumed["child_execution_id"],
            )
        )
        assert pin is not None
        assert pin.bundle_digest == child_bundle["bundle_digest"]


def test_explicit_supersede_and_rollback_state_machine_is_atomic(tmp_path) -> None:
    service = _service(tmp_path, "promotion-state.sqlite")
    _, first = _promote_named(service, "Promotion first", "local/state")
    second_project = _create_project(service, "Promotion second")
    _create_procedure(service, second_project, procedure_id="local/state")
    second = _candidate_bundle(
        service, {**second_project, "workspace_revision": 2}
    )
    service.approve_bundle(
        second["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Approve replacement",
        idempotency_key="state-approve-second",
    )
    with pytest.raises(DevelopmentConflictError) as implicit:
        service.catalog_decision(
            "local/state",
            **ADMIN,
            operation="PROMOTE",
            bundle_digest=second["bundle_digest"],
            expected_registry_revision=1,
            reason="Implicit replacement is forbidden",
            idempotency_key="state-implicit-replacement",
        )
    assert implicit.value.code == "SUPERSEDE_REQUIRED"

    superseded_first = service.catalog_decision(
        "local/state",
        **ADMIN,
        operation="SUPERSEDE",
        bundle_digest=first["bundle_digest"],
        expected_registry_revision=1,
        reason="Explicitly supersede the first digest",
        idempotency_key="state-supersede-first",
    )["catalog_entry"]
    assert superseded_first["state"] == "SUPERSEDED"
    promoted_second = service.catalog_decision(
        "local/state",
        **ADMIN,
        operation="PROMOTE",
        bundle_digest=second["bundle_digest"],
        expected_registry_revision=2,
        reason="Promote only after explicit supersede",
        idempotency_key="state-promote-second",
    )["catalog_entry"]
    assert promoted_second["current_bundle_digest"] == second["bundle_digest"]
    with pytest.raises(DevelopmentConflictError) as rollback_while_promoted:
        service.catalog_decision(
            "local/state",
            **ADMIN,
            operation="ROLLBACK_PROMOTE",
            bundle_digest=first["bundle_digest"],
            expected_registry_revision=3,
            reason="Current digest must be superseded first",
            idempotency_key="state-rollback-while-promoted",
        )
    assert rollback_while_promoted.value.code == "ROLLBACK_STATE_INVALID"

    service.catalog_decision(
        "local/state",
        **ADMIN,
        operation="SUPERSEDE",
        bundle_digest=second["bundle_digest"],
        expected_registry_revision=3,
        reason="Supersede replacement before rollback",
        idempotency_key="state-supersede-second",
    )
    rolled_back = service.catalog_decision(
        "local/state",
        **ADMIN,
        operation="ROLLBACK_PROMOTE",
        bundle_digest=first["bundle_digest"],
        expected_registry_revision=4,
        reason="Audited rollback promotion",
        idempotency_key="state-rollback-first",
    )["catalog_entry"]
    assert rolled_back["state"] == "PROMOTED"
    assert rolled_back["current_bundle_digest"] == first["bundle_digest"]
    service.catalog_decision(
        "local/state",
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=first["bundle_digest"],
        expected_registry_revision=5,
        reason="Withdraw the rolled-back digest",
        idempotency_key="state-withdraw-first",
    )
    with pytest.raises(DevelopmentConflictError) as rollback_withdrawn:
        service.catalog_decision(
            "local/state",
            **ADMIN,
            operation="ROLLBACK_PROMOTE",
            bundle_digest=second["bundle_digest"],
            expected_registry_revision=6,
            reason="Withdrawn catalog cannot roll back",
            idempotency_key="state-rollback-withdrawn",
        )
    assert rollback_withdrawn.value.code == "ROLLBACK_STATE_INVALID"

    with service.factory() as session:
        bundles = {
            row.bundle_digest: row.state
            for row in session.scalars(
                select(DevelopmentBundle).where(
                    DevelopmentBundle.bundle_digest.in_(
                        [first["bundle_digest"], second["bundle_digest"]]
                    )
                )
            ).all()
        }
        assert bundles == {
            first["bundle_digest"]: "WITHDRAWN",
            second["bundle_digest"]: "SUPERSEDED",
        }
        decisions = session.scalars(
            select(DevelopmentPromotionDecision).where(
                DevelopmentPromotionDecision.procedure_id == "local/state"
            )
        ).all()
        assert [row.operation for row in decisions] == [
            "PROMOTE",
            "SUPERSEDE",
            "PROMOTE",
            "SUPERSEDE",
            "ROLLBACK_PROMOTE",
            "WITHDRAW",
        ]
        outbox = session.scalars(
            select(DevelopmentOutbox).where(
                DevelopmentOutbox.topic == "development.catalog.decision",
                DevelopmentOutbox.aggregate_id == "local/state",
            )
        ).all()
        assert len(outbox) == len(decisions)


def test_promotion_catalog_and_decision_history_bounds_fail_closed(
    tmp_path, monkeypatch
) -> None:
    catalog_service = _service(tmp_path, "promotion-catalog-bound.sqlite")
    catalog_project = _create_project(catalog_service, "Catalog bound")
    _create_procedure(
        catalog_service, catalog_project, procedure_id="local/catalog-bound"
    )
    catalog_bundle = _candidate_bundle(
        catalog_service, {**catalog_project, "workspace_revision": 2}
    )
    catalog_service.approve_bundle(
        catalog_bundle["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Approve before catalog bound proof",
        idempotency_key="catalog-bound-approve",
    )
    monkeypatch.setattr(
        "backend.development_service.MAX_PROMOTION_CATALOG_ENTRIES", 0
    )
    with pytest.raises(DevelopmentLimitError, match="catalog entry limit"):
        catalog_service.catalog_decision(
            "local/catalog-bound",
            **ADMIN,
            operation="PROMOTE",
            bundle_digest=catalog_bundle["bundle_digest"],
            expected_registry_revision=0,
            reason="Must fail without partial catalog state",
            idempotency_key="catalog-bound-promote",
        )
    with catalog_service.factory() as session:
        assert session.get(
            DevelopmentBundle, catalog_bundle["bundle_digest"]
        ).state == "APPROVED"
        assert session.scalar(select(DevelopmentPromotionDecision)) is None

    monkeypatch.setattr(
        "backend.development_service.MAX_PROMOTION_CATALOG_ENTRIES", 10_000
    )
    decision_service = _service(tmp_path, "promotion-decision-bound.sqlite")
    _, decision_bundle = _promote_named(
        decision_service, "Decision bound", "local/decision-bound"
    )
    monkeypatch.setattr(
        "backend.development_service.MAX_PROMOTION_DECISIONS_PER_ENTRY", 1
    )
    with pytest.raises(DevelopmentLimitError, match="decision history limit"):
        decision_service.catalog_decision(
            "local/decision-bound",
            **ADMIN,
            operation="SUPERSEDE",
            bundle_digest=decision_bundle["bundle_digest"],
            expected_registry_revision=1,
            reason="Must fail before state mutation",
            idempotency_key="decision-bound-supersede",
        )
    with decision_service.factory() as session:
        assert session.get(
            DevelopmentBundle, decision_bundle["bundle_digest"]
        ).state == "PROMOTED"
        decisions = session.scalars(
            select(DevelopmentPromotionDecision).where(
                DevelopmentPromotionDecision.procedure_id
                == "local/decision-bound"
            )
        ).all()
        assert len(decisions) == 1


def test_promotion_separation_of_duties_is_exact_and_role_bound(tmp_path) -> None:
    service = _service(tmp_path, "promotion-sod.sqlite")
    project = _create_project(service, "Promotion separation")
    _create_procedure(service, project, procedure_id="local/promotion-sod")
    job = _run_project_check(
        service, project["project_id"], 2, "promotion-sod-check"
    )
    assert job["report"]["outcome"] == "PASS"
    history = service.commit_history(
        project["project_id"],
        **OPERATOR,
        expected_workspace_revision=2,
        message="Promotion separation history",
        selected_resource_ids=None,
        idempotency_key="promotion-sod-history",
    )["history_revision"]
    author_admin = {"subject": OPERATOR["subject"], "role": "admin"}
    reviewer_operator = {"subject": ADMIN["subject"], "role": "operator"}
    with pytest.raises(DevelopmentAuthorizationError):
        service.review_history(
            history["history_revision_id"],
            **reviewer_operator,
            decision="APPROVE",
            reason="Operator cannot review",
            expected_review_revision=0,
            idempotency_key="promotion-sod-review-role",
        )
    with pytest.raises(DevelopmentAuthorizationError, match="author cannot review"):
        service.review_history(
            history["history_revision_id"],
            **author_admin,
            decision="APPROVE",
            reason="Author cannot self-review",
            expected_review_revision=0,
            idempotency_key="promotion-sod-self-review",
        )
    review = service.review_history(
        history["history_revision_id"],
        **ADMIN,
        decision="APPROVE",
        reason="Distinct admin review",
        expected_review_revision=0,
        idempotency_key="promotion-sod-review",
    )["review"]
    assert review["reviewer_subject"] == ADMIN["subject"]
    bundle = service.build_bundle(
        history["history_revision_id"],
        **OPERATOR,
        idempotency_key="promotion-sod-build",
    )["bundle"]
    with pytest.raises(DevelopmentAuthorizationError):
        service.approve_bundle(
            bundle["bundle_digest"],
            **reviewer_operator,
            expected_state_revision=1,
            reason="Operator cannot approve",
            idempotency_key="promotion-sod-approve-role",
        )
    with pytest.raises(DevelopmentAuthorizationError, match="author cannot approve"):
        service.approve_bundle(
            bundle["bundle_digest"],
            **author_admin,
            expected_state_revision=1,
            reason="Author cannot self-approve",
            idempotency_key="promotion-sod-self-approve",
        )
    service.approve_bundle(
        bundle["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Distinct admin approval",
        idempotency_key="promotion-sod-approve",
    )
    with pytest.raises(DevelopmentAuthorizationError):
        service.catalog_decision(
            "local/promotion-sod",
            **reviewer_operator,
            operation="PROMOTE",
            bundle_digest=bundle["bundle_digest"],
            expected_registry_revision=0,
            reason="Operator cannot promote",
            idempotency_key="promotion-sod-promote-role",
        )
    with pytest.raises(
        DevelopmentAuthorizationError, match="bundle author cannot make"
    ):
        service.catalog_decision(
            "local/promotion-sod",
            **author_admin,
            operation="PROMOTE",
            bundle_digest=bundle["bundle_digest"],
            expected_registry_revision=0,
            reason="Author cannot self-promote",
            idempotency_key="promotion-sod-self-promote",
        )
    promoted = service.catalog_decision(
        "local/promotion-sod",
        **ADMIN,
        operation="PROMOTE",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=0,
        reason="Distinct admin promotion",
        idempotency_key="promotion-sod-promote",
    )
    assert promoted["catalog_entry"]["state"] == "PROMOTED"
    assert promoted["decision"]["actor_subject"] == ADMIN["subject"]


@pytest.mark.parametrize(
    "failed_model",
    (DevelopmentAuditEvent, DevelopmentOutbox),
    ids=("audit-insert", "outbox-insert"),
)
def test_promotion_audit_outbox_failure_rolls_back_atomically(
    tmp_path, monkeypatch, failed_model
) -> None:
    service = _service(tmp_path, "promotion-fault.sqlite")
    project = _create_project(service, "Promotion fault")
    _create_procedure(service, project, procedure_id="local/promotion-fault")
    bundle = _candidate_bundle(service, {**project, "workspace_revision": 2})
    service.approve_bundle(
        bundle["bundle_digest"],
        **ADMIN,
        expected_state_revision=1,
        reason="Prepare promotion rollback proof",
        idempotency_key="promotion-fault-approve",
    )
    with service.factory() as session:
        before = {
            model: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                DevelopmentAuditEvent,
                DevelopmentIdempotency,
                DevelopmentOutbox,
                DevelopmentPromotionDecision,
            )
        }
    original_add = Session.add

    def fail_durable_insert(session, instance, *args, **kwargs):
        if isinstance(instance, failed_model):
            raise RuntimeError(
                f"injected {failed_model.__tablename__} insertion failure"
            )
        return original_add(session, instance, *args, **kwargs)

    monkeypatch.setattr(Session, "add", fail_durable_insert)
    with pytest.raises(RuntimeError, match="insertion failure"):
        service.catalog_decision(
            "local/promotion-fault",
            **ADMIN,
            operation="PROMOTE",
            bundle_digest=bundle["bundle_digest"],
            expected_registry_revision=0,
            reason="Must roll back every durable effect",
            idempotency_key="promotion-fault-promote",
        )
    with service.factory() as session:
        assert session.get(
            DevelopmentBundle, bundle["bundle_digest"]
        ).state == "APPROVED"
        assert session.get(DevelopmentCatalogEntry, "local/promotion-fault") is None
        after = {
            model: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in before
        }
        assert after == before


def test_telemetry_condition_schedule_pins_and_fires_after_withdrawal(
    client: TestClient,
    operator_headers: dict[str, str],
) -> None:
    development: DevelopmentService = client.app.state.development_service
    _, bundle = _promote(development)
    operator = client.app.state.operator_service
    operator.sync_catalog(actor="condition-v09-test")
    response = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "local/runtime",
            "context_id": "simulator",
            "reason": "v0.9 condition controller",
            "idempotency_key": "v09-condition-controller",
        },
    )
    assert response.status_code == 202, response.text
    controller_id = response.json()["execution"]["id"]
    history = operator.catalog_history("local/runtime")
    entry = history["procedure"]
    revision = history["items"][0]
    condition = client.app.state.condition_service
    condition.snapshot_provider = SnapshotQueue(snapshot(1, 10))

    def create(key: str) -> dict:
        return condition.create_telemetry_schedule(
            plan=plan(plan_id=f"plan.{key}"),
            policy=QualityFreshnessPolicy("simulator-default", "v07-r1"),
            start_snapshot_cursor=0,
            timeout_seconds=60,
            retry_count=0,
            retry_interval_seconds=0,
            controller_execution_id=controller_id,
            procedure_catalog_id=entry["id"],
            procedure_id="local/runtime",
            procedure_revision=revision["revision"],
            bundle_digest=revision["bundle_digest"],
            development_bundle_digest=revision["properties"][
                "development_bundle_digest"
            ],
            context_id="simulator",
            arguments={},
            automatic=False,
            background_allowed=False,
            visible=True,
            created_by="pytest-operator",
            idempotency_key=key,
        )

    existing = create("condition-existing-v09")
    development.catalog_decision(
        "local/runtime",
        **ADMIN,
        operation="WITHDRAW",
        bundle_digest=bundle["bundle_digest"],
        expected_registry_revision=1,
        reason="withdraw after condition admission",
        idempotency_key="condition-withdraw-v09",
    )
    with pytest.raises(
        ConditionServiceConflictError, match="not currently promoted"
    ):
        create("condition-new-after-withdraw-v09")
    fired = condition.reconcile_telemetry_schedule(existing["schedule_id"])
    assert fired["state"] == "FIRED"
    with client.app.state.session_factory() as session:
        pin = session.scalar(
            select(DevelopmentRuntimePin).where(
                DevelopmentRuntimePin.runtime_kind == "EXECUTION",
                DevelopmentRuntimePin.runtime_id == fired["fired_execution_id"],
            )
        )
        assert pin is not None
        assert pin.bundle_digest == bundle["bundle_digest"]


def test_sqlite_idempotency_races_and_restart_job_recovery(tmp_path) -> None:
    service = _service(tmp_path, "mutation-race.sqlite")
    project = _create_project(service, "Race")
    source = "# @procedure local/race\nLog('race')\n"
    digest = hashlib.sha256(source.encode()).hexdigest()
    barrier = threading.Barrier(2)
    results: list[object] = []

    def same_request() -> None:
        barrier.wait()
        try:
            results.append(
                service.create_resource(
                    project["project_id"],
                    **OPERATOR,
                    path="procedures/race.spell.py",
                    kind="PROCEDURE",
                    media_type="text/x-python",
                    content=source,
                    content_sha256=digest,
                    expected_workspace_revision=1,
                    idempotency_key="same-race-key",
                )
            )
        except Exception as exc:
            results.append(exc)

    threads = [threading.Thread(target=same_request) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(isinstance(item, Exception) for item in results)
    assert sorted(item["replayed"] for item in results) == [False, True]
    assert len(
        service.workspace_snapshot(
            project["project_id"], subject="viewer", role="viewer"
        )["workspace"]["resources"]
    ) == 3

    other = _create_project(service, "Different race")
    barrier = threading.Barrier(2)
    results = []

    def competing(key: str, path: str) -> None:
        barrier.wait()
        try:
            results.append(
                service.create_resource(
                    other["project_id"],
                    **OPERATOR,
                    path=path,
                    kind="PROCEDURE",
                    media_type="text/x-python",
                    content=source,
                    content_sha256=digest,
                    expected_workspace_revision=1,
                    idempotency_key=key,
                )
            )
        except Exception as exc:
            results.append(exc)

    threads = [
        threading.Thread(target=competing, args=("different-a", "procedures/a.spell.py")),
        threading.Thread(target=competing, args=("different-b", "procedures/b.spell.py")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sum(not isinstance(item, Exception) for item in results) == 1
    assert sum(isinstance(item, DevelopmentConflictError) for item in results) == 1

    queued = service.create_check(
        other["project_id"],
        **OPERATOR,
        scope="PROJECT",
        scope_path=None,
        expected_workspace_revision=2,
        reparse_libraries=False,
        idempotency_key="restart-queued",
    )["job"]
    with service.factory.begin() as session:
        row = session.get(DevelopmentAnalysisJob, queued["job_id"])
        row.state = "RUNNING"
        row.progress = 37
    restarted = DevelopmentService(service.factory)
    assert restarted.recover_analysis_jobs() == 1
    recovered = restarted.get_check(
        queued["job_id"], subject="viewer", role="viewer"
    )["job"]
    assert recovered["state"] == "FAILED"
    assert recovered["failure_code"] == "FAILED_RETRYABLE"
    assert recovered["progress"] == 100
