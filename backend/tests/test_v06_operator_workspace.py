from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import threading
import time
import uuid

import pytest
from sqlalchemy import func, select

from backend.auth import issue_local_dev_token
from backend.models import Command, Event, Execution, Prompt
from backend.operator_models import (
    ControllerHandover,
    ControllerLease,
    ExecutionOperatorState,
    InspectionEditOperation,
    MonitorSubscription,
    OperatorAuditEvent,
    OperatorBreakpoint,
    OperatorCommand,
    OperatorContext,
    OperatorPrompt,
    OperatorUserActionInvocation,
    ParentChildLink,
    ProcedureSchedule,
    PromptAttempt,
    ScheduleOccurrence,
    StartProcOperation,
)
from backend.operator_service import (
    OperatorAuthorizationError,
    OperatorConflictError,
    OperatorNotFoundError,
    OperatorService,
    OperatorValidationError,
    PromptSecretMaterialError,
)
from backend.ir_v06 import COMMAND_ALLOWED_STATES
from backend.operator_service import _COMMAND_MATRIX


def _paused_execution(client, *, procedure_id: str = "pause", suffix: str = "base"):
    supervisor = client.app.state.supervisor
    procedure = client.app.state.catalog.get(procedure_id)
    execution = supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason=f"v0.6 focused {suffix}",
        idempotency_key=f"v06-focused-{suffix}",
        automatic=False,
    )
    client.app.state.operator_service.ensure_execution_projection(
        execution, actor="operator-bootstrap", automatic=False
    )
    return execution, client.app.state.operator_service


def _acquire(service, execution: Execution, *, actor: str = "pytest-operator"):
    result = service.acquire_control(
        execution.id,
        expected_execution_revision=execution.revision,
        actor=actor,
        holder_session_id=f"session-{actor}",
        client_instance_key_id=f"client-{actor}",
        lease_seconds=60,
        idempotency_key=f"lease-{execution.id}-{actor}",
        reason="focused controller acquisition",
    )
    return result["control_lease"]


def _proof(lease: dict, *, actor: str = "pytest-operator") -> dict:
    return {
        "actor": actor,
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "holder_session_id": f"session-{actor}",
        "client_instance_key_id": f"client-{actor}",
    }


def _command_proof(lease: dict, *, actor: str = "pytest-operator") -> dict:
    proof = _proof(lease, actor=actor)
    proof["controller_lease_id"] = proof.pop("lease_id")
    return proof


def _wait_for_operator_prompt(client, execution_id: str, headers: dict) -> tuple[dict, dict]:
    deadline = time.monotonic() + 8
    last: dict = {}
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v1/executions/{execution_id}/snapshot", headers=headers
        )
        assert response.status_code == 200, response.text
        last = response.json()
        prompt = last.get("active_prompt")
        if isinstance(prompt, dict) and prompt.get("type") == "LIST":
            return last, prompt
        time.sleep(0.05)
    raise AssertionError(f"operator prompt was not projected; last snapshot: {last}")


def test_monitor_reconnect_count_and_wrong_parent_are_atomic(client) -> None:
    first, service = _paused_execution(client, suffix="monitor-a")
    second, _ = _paused_execution(client, suffix="monitor-b")
    monitor = service.start_monitor(
        first.id,
        actor="pytest-viewer",
        session_id="viewer-session",
        client_instance_key_id="viewer-client",
    )
    assert service.active_monitor_count(first.id) == 1
    with pytest.raises(OperatorAuthorizationError):
        service.stop_monitor(
            first.id,
            monitor["id"],
            actor="pytest-viewer",
            session_id="another-session",
            client_instance_key_id="viewer-client",
        )
    assert service.active_monitor_count(first.id) == 1
    with pytest.raises(OperatorNotFoundError):
        service.stop_monitor(
            second.id,
            monitor["id"],
            actor="pytest-viewer",
            session_id="viewer-session",
            client_instance_key_id="viewer-client",
        )
    assert service.active_monitor_count(first.id) == 1
    service.stop_monitor(
        first.id,
        monitor["id"],
        actor="pytest-viewer",
        session_id="viewer-session",
        client_instance_key_id="viewer-client",
    )
    replacement = service.start_monitor(
        first.id,
        actor="pytest-viewer",
        session_id="viewer-session",
        client_instance_key_id="viewer-client",
    )
    service.stop_monitor(
        first.id,
        replacement["id"],
        actor="pytest-viewer",
        session_id="viewer-session",
        client_instance_key_id="viewer-client",
    )
    assert service.active_monitor_count(first.id) == 0
    master = next(item for item in service.master() if item["id"] == first.id)
    assert master["monitor_count"] == 0


def test_run_to_line_owns_one_shot_and_failure_cleans_only_owned_row(client) -> None:
    execution, service = _paused_execution(client, suffix="run-line")
    lease = _acquire(service, execution)
    line = execution.steps[-1]["line"]
    persistent = service.put_breakpoint(
        execution.id,
        line,
        one_shot=False,
        expected_execution_revision=execution.revision,
        idempotency_key="persistent-line",
        reason="persistent breakpoint",
        **_proof(lease),
    )
    command = service.accept_operator_command(
        execution.id,
        "RUN",
        execution.revision,
        "run-to-line",
        role="operator",
        reason="run to executable line",
        payload={},
        target={"line": line, "source_digest": execution.procedure_hash},
        **_command_proof(lease),
    )
    assert command["result"]["run_to_line"]["owned_by_command"] is True
    replay = service.accept_operator_command(
        execution.id,
        "RUN",
        execution.revision,
        "run-to-line",
        role="operator",
        reason="run to executable line",
        payload={},
        target={"line": line, "source_digest": execution.procedure_hash},
        **_command_proof(lease),
    )
    assert replay["id"] == command["id"]
    with client.app.state.session_factory() as session:
        rows = session.scalars(
            select(OperatorBreakpoint).where(
                OperatorBreakpoint.execution_id == execution.id,
                OperatorBreakpoint.line_id == f"line:{line}",
            )
        ).all()
        assert len(rows) == 2
    service.transition_operator_command(command["id"], "FAILED")
    with client.app.state.session_factory() as session:
        rows = session.scalars(
            select(OperatorBreakpoint).where(
                OperatorBreakpoint.execution_id == execution.id
            )
        ).all()
        assert [row.id for row in rows] == [persistent["id"]]


def test_command_application_refences_renewed_lease_and_cleans_target(client) -> None:
    execution, service = _paused_execution(client, suffix="command-refence")
    lease = _acquire(service, execution)
    line = execution.steps[-1]["line"]
    command = service.accept_operator_command(
        execution.id,
        "RUN",
        execution.revision,
        "run-refence",
        role="operator",
        reason="prove safe-point re-fence",
        payload={},
        target={"line": line},
        **_command_proof(lease),
    )
    service.renew_control(
        execution.id,
        lease_id=lease["id"],
        expected_lease_revision=lease["revision"],
        control_fencing_token=lease["control_fencing_token"],
        actor="pytest-operator",
        holder_session_id="session-pytest-operator",
        client_instance_key_id="client-pytest-operator",
        lease_seconds=60,
        idempotency_key="renew-before-application",
        reason="renew fence revision",
    )
    fenced = service.begin_operator_command_application(
        command["id"], "safe-point:before-statement"
    )
    assert fenced["state"] == "SUPERSEDED"
    assert fenced["rejection_code"] == "CONTROL_FENCE_STALE"
    assert fenced["result"] == {"target_mutation": "NONE"}
    assert service.list_breakpoints(execution.id) == []


def test_background_command_settles_and_releases_lease_atomically(client) -> None:
    execution, service = _paused_execution(client, suffix="background")
    with client.app.state.session_factory() as session:
        projection = session.get(ExecutionOperatorState, execution.id)
        projection.background_allowed = True
        session.commit()
    lease = _acquire(service, execution)
    command = service.accept_operator_command(
        execution.id,
        "BACKGROUND",
        execution.revision,
        "background-command",
        role="operator",
        reason="release to background",
        payload={},
        **_command_proof(lease),
    )
    settled = service.apply_background_command(command["id"], "safe-point:background")
    assert settled["state"] == "SETTLED"
    with client.app.state.session_factory() as session:
        projection = session.get(ExecutionOperatorState, execution.id)
        stored_lease = session.get(ControllerLease, lease["id"])
        assert projection.ownership_mode == "B"
        assert projection.current_lease_id is None
        assert stored_lease.state == "RELEASED"


def test_inspection_edit_is_pending_until_atomic_worker_ack(client) -> None:
    execution, service = _paused_execution(client, suffix="inspection")
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        stored.variables = {"value": 1}
        session.commit()
    lease = _acquire(service, execution)
    edit = service.edit_inspection(
        execution.id,
        path="variables.value",
        scope="LOCAL_VARIABLE",
        declared_type="INTEGER",
        value=2,
        expected_value_revision=execution.revision,
        expected_execution_revision=execution.revision,
        idempotency_key="inspection-edit",
        reason="focused typed edit",
        **_proof(lease),
    )
    assert edit["state"] == "PENDING_SAFE_POINT"
    with client.app.state.session_factory() as session:
        assert session.get(Execution, execution.id).variables == {"value": 1}
    assert [item["id"] for item in service.list_unacked_inspection_edits()] == [
        edit["id"]
    ]
    reserved = service.begin_inspection_edit_application(
        edit["id"], edit["revision"], "safe-point:edit"
    )
    assert reserved["state"] == "APPLYING"
    recovered = OperatorService(
        client.app.state.session_factory,
        client.app.state.catalog,
    )
    assert [
        item["id"] for item in recovered.list_unacked_inspection_edits()
    ] == [edit["id"]]
    assert recovered.begin_inspection_edit_application(
        edit["id"], edit["revision"], "safe-point:edit"
    )["state"] == "APPLYING"
    recovered.mark_inspection_edit_delivery_attempt(edit["id"], edit["revision"])
    applied = recovered.ack_inspection_edit_application(
        edit["id"],
        "inspection-application",
        outcome="APPLIED",
        application_safe_point_id="safe-point:edit",
        variables=edit["variables"],
    )
    assert applied["state"] == "APPLIED"
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        assert stored.variables == {"value": 2}
        assert stored.revision == execution.revision + 1
        assert session.scalar(
            select(func.count()).select_from(InspectionEditOperation)
        ) == 1


def test_action_bundle_registration_and_atomic_effect_settlement(client) -> None:
    source = (
        "accepted: bool = False\n"
        'UserAction("ack", "Acknowledge", handler=['
        '{"op":"LOG","message":"acknowledged","severity":"info"},'
        '{"op":"SET_LITERAL","name":"accepted","declared_type":"bool","value":True}])\n'
        'Prompt("Hold", type="OK")\n'
    )
    catalog = client.app.state.catalog
    procedure = catalog.validate_source(source, "focused-actions.spell.py")
    execution = client.app.state.supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason="static action admission",
        idempotency_key="v06-static-action",
        automatic=False,
    )
    service = client.app.state.operator_service
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        stored.variables = {"accepted": False}
        session.commit()
    actions = service.list_user_actions(execution.id)
    assert [item["name"] for item in actions] == ["ack"]
    lease = _acquire(service, execution)
    invocation = service.invoke_user_action(
        execution.id,
        actions[0]["id"],
        expected_action_revision=actions[0]["revision"],
        expected_execution_revision=execution.revision,
        arguments={},
        idempotency_key="invoke-static-action",
        reason="invoke pinned action",
        **_proof(lease),
    )
    reserved = service.begin_user_action_application(
        invocation["id"], "safe-point:action"
    )
    assert reserved["state"] == "APPLYING"
    recovered = OperatorService(
        client.app.state.session_factory,
        client.app.state.catalog,
    )
    assert [
        item["id"] for item in recovered.list_replayable_user_action_invocations()
    ] == [invocation["id"]]
    delivery = recovered.begin_user_action_application(
        invocation["id"], "safe-point:action"
    )
    assert delivery["pinned_handler"] == actions[0]["definition"]["handler"]
    recovered.mark_user_action_delivery_attempt(invocation["id"])
    settled = recovered.settle_user_action_invocation(
        invocation["id"],
        "EXECUTED",
        result={
            "application_id": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"openbexi-spell:user-action:{execution.id}:{invocation['id']}",
                )
            ),
            "safe_point_step": execution.current_step,
            "replayed": False,
        },
        application_safe_point_id="safe-point:action",
        variables={"accepted": True},
        effects=[
            {
                "event_type": "procedure.user_action_log",
                "source": "procedure",
                "severity": "info",
                "payload": {
                    "message": "acknowledged",
                    "step_index": execution.current_step,
                    "invocation_id": invocation["id"],
                },
            }
        ],
    )
    assert settled["state"] == "EXECUTED"
    recovered.settle_user_action_invocation(
        invocation["id"],
        "EXECUTED",
        variables={"accepted": True},
        effects=[{"event_type": "would.duplicate", "payload": {}}],
    )
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        assert stored.variables == {"accepted": True}
        assert session.scalar(
            select(func.count()).select_from(Event).where(
                Event.causation_id == invocation["id"]
            )
        ) == 1
        assert session.get(OperatorUserActionInvocation, invocation["id"]).delivered_at


def test_action_and_inspection_application_reject_stale_controller_fence(client) -> None:
    source = (
        "value: int = 1\n"
        'UserAction("set", "Set value", handler=['
        '{"op":"SET_LITERAL","name":"value","declared_type":"int","value":2}])\n'
        'Prompt("Hold", type="OK")\n'
    )
    catalog = client.app.state.catalog
    procedure = catalog.validate_source(source, "focused-refence.spell.py")
    execution = client.app.state.supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason="stale application authority",
        idempotency_key="v06-stale-application-authority",
        automatic=False,
    )
    service = client.app.state.operator_service
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        stored.variables = {"value": 1}
        session.commit()
    action = service.list_user_actions(execution.id)[0]
    lease = _acquire(service, execution)
    invocation = service.invoke_user_action(
        execution.id,
        action["id"],
        expected_action_revision=action["revision"],
        expected_execution_revision=execution.revision,
        arguments={},
        idempotency_key="stale-action-invocation",
        reason="admit before lease renewal",
        **_proof(lease),
    )
    edit = service.edit_inspection(
        execution.id,
        path="variables.value",
        scope="LOCAL_VARIABLE",
        declared_type="INTEGER",
        value=2,
        expected_value_revision=execution.revision,
        expected_execution_revision=execution.revision,
        idempotency_key="stale-inspection-edit",
        reason="admit before lease renewal",
        **_proof(lease),
    )
    service.renew_control(
        execution.id,
        lease_id=lease["id"],
        expected_lease_revision=lease["revision"],
        control_fencing_token=lease["control_fencing_token"],
        actor="pytest-operator",
        holder_session_id="session-pytest-operator",
        client_instance_key_id="client-pytest-operator",
        lease_seconds=60,
        idempotency_key="renew-before-action-edit-application",
        reason="invalidate accepted application authority",
    )
    rejected_invocation = service.begin_user_action_application(
        invocation["id"], "safe-point:stale-action"
    )
    assert rejected_invocation["state"] == "SUPERSEDED"
    assert rejected_invocation["rejection_code"] == "CONTROL_FENCE_STALE"
    assert rejected_invocation["result"] == {"target_mutation": "NONE"}
    rejected_edit = service.begin_inspection_edit_application(
        edit["id"], edit["revision"], "safe-point:stale-edit"
    )
    assert rejected_edit["state"] == "REJECTED"
    assert rejected_edit["rejection_code"] == "CONTROL_FENCE_STALE"
    assert rejected_edit["result"] == {"target_mutation": "NONE"}
    assert service.list_replayable_user_action_invocations(execution.id) == []
    assert service.list_unacked_inspection_edits(execution.id) == []
    with client.app.state.session_factory() as session:
        assert session.get(Execution, execution.id).variables == {"value": 1}


def test_cross_feature_application_reservation_prevents_lost_update(client) -> None:
    source = (
        "value: int = 1\n"
        'UserAction("set", "Set value", handler=['
        '{"op":"SET_LITERAL","name":"value","declared_type":"int","value":2}])\n'
        'Prompt("Hold", type="OK")\n'
    )
    catalog = client.app.state.catalog
    procedure = catalog.validate_source(source, "focused-reservation.spell.py")
    execution = client.app.state.supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason="cross-feature mutation reservation",
        idempotency_key="v06-cross-feature-reservation",
        automatic=False,
    )
    service = client.app.state.operator_service
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        stored.variables = {"value": 1}
        session.commit()
    action = service.list_user_actions(execution.id)[0]
    lease = _acquire(service, execution)
    invocation = service.invoke_user_action(
        execution.id,
        action["id"],
        expected_action_revision=action["revision"],
        expected_execution_revision=execution.revision,
        arguments={},
        idempotency_key="reserved-action",
        reason="reserve action first",
        **_proof(lease),
    )
    edit = service.edit_inspection(
        execution.id,
        path="variables.value",
        scope="LOCAL_VARIABLE",
        declared_type="INTEGER",
        value=3,
        expected_value_revision=execution.revision,
        expected_execution_revision=execution.revision,
        idempotency_key="reserved-edit",
        reason="must wait behind action",
        **_proof(lease),
    )
    command = service.accept_operator_command(
        execution.id,
        "RUN",
        execution.revision,
        "reserved-command",
        role="operator",
        reason="must wait behind action",
        payload={},
        **_command_proof(lease),
    )
    assert service.begin_user_action_application(
        invocation["id"], "safe-point:reserved-action"
    )["state"] == "APPLYING"
    assert service.begin_inspection_edit_application(
        edit["id"], edit["revision"], "safe-point:reserved-edit"
    )["state"] == "PENDING_SAFE_POINT"
    assert service.begin_operator_command_application(
        command["id"], "safe-point:reserved-command"
    )["state"] in {"ACCEPTED", "WAITING_SAFE_POINT"}
    service.settle_user_action_invocation(
        invocation["id"],
        "EXECUTED",
        result={
            "application_id": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"openbexi-spell:user-action:{execution.id}:{invocation['id']}",
                )
            ),
            "safe_point_step": execution.current_step,
            "replayed": False,
        },
        application_safe_point_id="safe-point:reserved-action",
        variables={"value": 2},
    )
    stale_command = service.begin_operator_command_application(
        command["id"], "safe-point:next"
    )
    assert stale_command["state"] == "SUPERSEDED"
    assert stale_command["rejection_code"] == "STALE_EXECUTION_REVISION"
    stale_edit = service.begin_inspection_edit_application(
        edit["id"], edit["revision"], "safe-point:next"
    )
    assert stale_edit["state"] == "REJECTED"
    assert stale_edit["rejection_code"] == "CONTROL_FENCE_STALE"
    with client.app.state.session_factory() as session:
        assert session.get(Execution, execution.id).variables == {"value": 2}


def test_prompt_secret_rejection_and_settings_snapshot_are_fail_closed(client) -> None:
    execution, service = _paused_execution(client, suffix="prompt-policy")
    with pytest.raises(PromptSecretMaterialError) as secret_error:
        service.open_typed_prompt(
            execution.id,
            "prompt-secret",
            0,
            {"type": "ALPHA", "question": "password=do-not-store"},
            {},
        )
    assert "do-not-store" not in str(secret_error.value)
    with client.app.state.session_factory() as session:
        assert session.get(OperatorPrompt, "prompt-secret") is None
        context = session.get(OperatorContext, "simulator")
        context.settings = {
            "PROMPT_WARNING_DELAY": 10,
            "PROMPT_RESPONSE_TIMEOUT": 20,
            "NO_CONTROLLER_GRACE": 30,
        }
        projection = session.get(ExecutionOperatorState, execution.id)
        projection.settings = {"PROMPT_WARNING_DELAY": 5}
        session.commit()
    prompt = service.open_typed_prompt(
        execution.id,
        "prompt-settings",
        0,
        {"type": "OK", "question": "Continue?"},
        {"PROMPT_RESPONSE_TIMEOUT": 2, "NO_CONTROLLER_GRACE": 0},
    )
    assert prompt["settings"] == {
        "PROMPT_WARNING_DELAY": 5.0,
        "PROMPT_RESPONSE_TIMEOUT": 2.0,
        "NO_CONTROLLER_GRACE": None,
    }
    with client.app.state.session_factory() as session:
        session.get(ExecutionOperatorState, execution.id).settings = {
            "PROMPT_WARNING_DELAY": 1
        }
        session.commit()
    replay = service.open_typed_prompt(
        execution.id,
        "prompt-settings",
        0,
        {"type": "OK", "question": "Continue?"},
        {"PROMPT_RESPONSE_TIMEOUT": 2, "NO_CONTROLLER_GRACE": 0},
    )
    assert replay["settings"] == prompt["settings"]


def test_handover_expiry_commits_and_is_audited(client) -> None:
    execution, service = _paused_execution(client, suffix="handover-expiry")
    _acquire(service, execution, actor="pytest-operator")
    monitor = service.start_monitor(
        execution.id,
        actor="requester",
        session_id="session-requester",
        client_instance_key_id="client-requester",
    )
    handover = service.request_control_handover(
        execution.id,
        requester_monitor_id=monitor["id"],
        expected_execution_revision=execution.revision,
        actor="requester",
        requester_session_id="session-requester",
        requester_client_instance_key_id="client-requester",
        responsibility_acknowledgement="I accept controller responsibility",
        expires_seconds=60,
        idempotency_key="handover-expiry",
        reason="focused expiry",
    )
    with client.app.state.session_factory() as session:
        stored = session.get(ControllerHandover, handover["id"])
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    assert service.expire_due_handovers() == 1
    with client.app.state.session_factory() as session:
        assert session.get(ControllerHandover, handover["id"]).state == "EXPIRED"
        assert session.scalar(
            select(func.count()).select_from(OperatorAuditEvent).where(
                OperatorAuditEvent.aggregate_id == handover["id"],
                OperatorAuditEvent.event_type == "control.handover_expired",
            )
        ) == 1


def test_startproc_admitting_restart_repairs_one_child_and_link(
    client, monkeypatch
) -> None:
    parent, service = _paused_execution(client, suffix="startproc-parent")
    starter_lock_states: list[bool] = []
    original_starter = service.execution_starter

    def checked_starter(*args, **kwargs):
        starter_lock_states.append(not service._lock._is_owned())
        assert original_starter is not None
        return original_starter(*args, **kwargs)

    monkeypatch.setattr(service, "execution_starter", checked_starter)
    with client.app.state.session_factory() as session:
        projection = session.get(ExecutionOperatorState, parent.id)
        projection.settings = {"PROMPT_RESPONSE_TIMEOUT": 12}
        session.commit()
    operation = service.admit_startproc(
        parent.id,
        "focused-startproc",
        0,
        {
            "child_reference": "integration",
            "arguments": {"sample": 7},
            "blocking": False,
            "visible": False,
            "automatic": False,
            "idempotency_key": "focused-startproc",
        },
    )
    assert operation["visible"] is False
    assert operation["dependency_closure"]
    assert operation["dependency_closure"][0]["catalog_revision_id"] == (
        operation["resolved_child_catalog_revision_id"]
    )
    assert operation["dependency_closure"][0]["bundle_digest"] == operation[
        "bundle_digest"
    ]
    child_id = operation["child_execution_id"]
    with client.app.state.session_factory() as session:
        stored = session.get(StartProcOperation, operation["id"])
        stored.state = "ADMITTING"
        stored.child_execution_id = None
        stored.result_payload = {}
        stored.settled_at = None
        link = session.scalar(
            select(ParentChildLink).where(ParentChildLink.startproc_id == operation["id"])
        )
        session.delete(link)
        session.commit()
    restarted = OperatorService(
        client.app.state.session_factory,
        client.app.state.catalog,
        execution_starter=service.execution_starter,
    )
    first = restarted.reconcile_startproc_admissions(parent.id)
    second = restarted.reconcile_startproc_admissions(parent.id)
    assert first[0]["child_execution_id"] == child_id
    assert second == []
    with client.app.state.session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(Execution).where(
                Execution.created_by == "startproc-service"
            )
        ) == 1
        child_projection = session.get(ExecutionOperatorState, child_id)
        assert child_projection.depth == 1
        assert child_projection.predecessor_execution_id == parent.id
        assert child_projection.settings == {"PROMPT_RESPONSE_TIMEOUT": 12}
        assert session.scalar(
            select(func.count()).select_from(ParentChildLink).where(
                ParentChildLink.startproc_id == operation["id"]
            )
        ) == 1
    master_child = next(item for item in service.master() if item["id"] == child_id)
    assert master_child["visible"] is False
    relationships = service.relationships(parent.id)
    linked_child = next(
        item for item in relationships["children"] if item["child_execution_id"] == child_id
    )
    assert linked_child["visible"] is False
    assert starter_lock_states and all(starter_lock_states)


def test_viewer_mutation_and_strict_json_fail_without_durable_rows(
    client, viewer_headers, operator_headers
) -> None:
    execution, _service = _paused_execution(client, suffix="api-security")
    control_body = {
        "action": "ACQUIRE",
        "session_id": "viewer-session",
        "client_instance_key_id": "viewer-client",
        "expected_execution_revision": execution.revision,
        "lease_seconds": 60,
        "idempotency_key": "viewer-acquire",
        "reason": "viewer must not mutate",
    }
    response = client.post(
        f"/api/v1/executions/{execution.id}/control",
        headers=viewer_headers,
        json=control_body,
    )
    assert response.status_code == 403
    duplicate = client.put(
        "/api/v1/contexts/simulator/settings",
        headers={**operator_headers, "Content-Type": "application/json"},
        content=(
            '{"settings":{"PROMPT_WARNING_DELAY":1},"expected_revision":0,'
            '"idempotency_key":"one","idempotency_key":"two","reason":"strict"}'
        ),
    )
    assert duplicate.status_code == 422
    nonfinite = client.put(
        "/api/v1/contexts/simulator/settings",
        headers={**operator_headers, "Content-Type": "application/json"},
        content=(
            '{"settings":{"PROMPT_WARNING_DELAY":NaN},"expected_revision":0,'
            '"idempotency_key":"nan","reason":"strict"}'
        ),
    )
    assert nonfinite.status_code == 422
    with client.app.state.session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(ControllerLease).where(
                ControllerLease.execution_id == execution.id
            )
        ) == 0
        assert session.scalar(select(func.count()).select_from(OperatorCommand)) == 0


def test_legacy_command_adapter_cannot_bypass_a_controller(
    client, auth_config
) -> None:
    execution, service = _paused_execution(client, suffix="legacy-fence")
    _acquire(service, execution)
    other_token = issue_local_dev_token(
        auth_config,
        subject="other-operator",
        role="operator",
        peer_host="127.0.0.1",
        lifetime_seconds=600,
    )
    response = client.post(
        f"/api/v1/executions/{execution.id}/commands",
        headers={"Authorization": f"Bearer {other_token}"},
        json={
            "type": "abort",
            "expected_revision": execution.revision,
            "reason": "must use fenced command contract",
            "idempotency_key": "legacy-bypass",
        },
    )
    assert response.status_code == 403
    with client.app.state.session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(OperatorCommand).where(
                OperatorCommand.execution_id == execution.id
            )
        ) == 0


def test_snapshot_projects_the_durable_typed_prompt(
    client, viewer_headers
) -> None:
    execution, service = _paused_execution(client, suffix="typed-snapshot")
    opened = service.open_typed_prompt(
        execution.id,
        "typed-snapshot-prompt",
        0,
        {
            "type": "LIST",
            "question": "Choose mode",
            "list_mode": "VALUE",
            "options": [
                {"value": "safe", "label": "Safe"},
                {"value": "fast", "label": "Fast"},
            ],
            "default": "safe",
        },
        {},
    )
    response = client.get(
        f"/api/v1/executions/{execution.id}/snapshot", headers=viewer_headers
    )
    assert response.status_code == 200
    snapshot = response.json()
    assert snapshot["active_prompt"]["id"] == opened["id"]
    assert snapshot["active_prompt"]["type"] == "LIST"
    assert snapshot["active_prompt"]["settings"] == opened["settings"]
    assert snapshot["typed_prompt"] == snapshot["active_prompt"]


@pytest.mark.parametrize(
    ("action", "value", "settlement_outcome", "legacy_status"),
    [
        ("COMMIT", "yes", "ANSWERED", "answered"),
        ("ABORT", None, "CANCELLED", "cancelled"),
    ],
)
def test_legacy_ir_prompt_uses_fenced_operator_settlement_and_worker_ack(
    client,
    operator_headers,
    action: str,
    value,
    settlement_outcome: str,
    legacy_status: str,
) -> None:
    suffix = action.lower()
    session_id = f"legacy-prompt-session-{suffix}"
    client_id = f"legacy-prompt-client-{suffix}"
    bound_headers = {
        **operator_headers,
        "X-Spell-Session-Id": session_id,
        "X-Spell-Client-Instance-Key-Id": client_id,
    }
    created = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "integration",
            "reason": "exercise fenced legacy prompt bridge",
            "idempotency_key": f"legacy-prompt-execution-{suffix}",
        },
    )
    assert created.status_code == 202, created.text
    execution_id = created.json()["execution"]["id"]
    snapshot, prompt = _wait_for_operator_prompt(
        client, execution_id, bound_headers
    )
    assert prompt["legacy_prompt_id"] == prompt["id"]
    assert prompt["options"] == [{"value": "yes", "label": "yes"}]

    unfenced = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": "must not bypass the operator fence",
            "idempotency_key": f"legacy-unfenced-{suffix}",
        },
    )
    assert unfenced.status_code == 403

    acquired = client.post(
        f"/api/v1/executions/{execution_id}/control",
        headers=bound_headers,
        json={
            "action": "ACQUIRE",
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "expected_execution_revision": snapshot["execution"]["revision"],
            "lease_seconds": 60,
            "acknowledgement": "I accept responsibility for the open prompt",
            "idempotency_key": f"legacy-prompt-acquire-{suffix}",
            "reason": "answer projected legacy prompt",
        },
    )
    assert acquired.status_code == 200, acquired.text
    lease = acquired.json()["control_lease"]
    body = {
        "action": action,
        "value": value,
        "expected_prompt_revision": prompt["revision"],
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "session_id": session_id,
        "client_instance_key_id": client_id,
        "idempotency_key": f"legacy-prompt-settle-{suffix}",
        "reason": "commit the fenced prompt decision",
    }

    wrong_session = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers={
            **operator_headers,
            "X-Spell-Session-Id": "wrong-session",
            "X-Spell-Client-Instance-Key-Id": client_id,
        },
        json=body,
    )
    assert wrong_session.status_code == 403
    wrong_fence = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=bound_headers,
        json={
            **body,
            "control_fencing_token": lease["control_fencing_token"] + 1,
            "idempotency_key": f"legacy-prompt-wrong-fence-{suffix}",
        },
    )
    assert wrong_fence.status_code == 403
    with client.app.state.session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(PromptAttempt).where(
                PromptAttempt.prompt_id == prompt["id"]
            )
        ) == 0

    settled = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=bound_headers,
        json=body,
    )
    assert settled.status_code == 202, settled.text
    assert settled.json()["prompt"]["settlement"]["outcome"] == settlement_outcome
    replay = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=bound_headers,
        json=body,
    )
    assert replay.status_code == 202
    assert replay.json()["attempt"]["id"] == settled.json()["attempt"]["id"]

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with client.app.state.session_factory() as session:
            execution = session.get(Execution, execution_id)
            operator_prompt = session.get(OperatorPrompt, prompt["id"])
            legacy_prompt = session.get(Prompt, prompt["id"])
            if execution.state == "completed":
                assert operator_prompt.settlement_delivered_at is not None
                assert legacy_prompt.status == legacy_status
                assert legacy_prompt.response == value
                break
        time.sleep(0.05)
    else:
        raise AssertionError("legacy prompt settlement was not checkpointed")


def test_legacy_prompt_stream_event_carries_canonical_revision_before_response(
    client, operator_headers
) -> None:
    created = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "integration",
            "reason": "exercise event-driven fenced legacy prompt",
            "idempotency_key": "legacy-prompt-event-driven",
        },
    )
    assert created.status_code == 202, created.text
    execution_id = created.json()["execution"]["id"]

    websocket_token = operator_headers["Authorization"].removeprefix("Bearer ")
    prompt_event = None
    deadline = time.monotonic() + 8
    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence=0",
        subprotocols=["spell-auth", websocket_token],
    ) as websocket:
        while time.monotonic() < deadline:
            item = websocket.receive_json()
            if item.get("event_type") in {"prompt.opened", "prompt.reopened"}:
                prompt_event = item
                break
    assert prompt_event is not None
    payload = prompt_event["payload"]
    assert "revision" not in payload
    assert payload["prompt_revision"] == 1
    assert type(payload["execution_revision"]) is int

    prompt_id = payload["prompt_id"]
    with client.app.state.session_factory() as session:
        projected = session.get(OperatorPrompt, prompt_id)
        assert projected is not None
        assert projected.revision == payload["prompt_revision"]
        assert projected.state == "OPEN"

    session_id = "legacy-prompt-event-session"
    client_id = "legacy-prompt-event-client"
    headers = {
        **operator_headers,
        "X-Spell-Session-Id": session_id,
        "X-Spell-Client-Instance-Key-Id": client_id,
    }
    acquired = client.post(
        f"/api/v1/executions/{execution_id}/control",
        headers=headers,
        json={
            "action": "ACQUIRE",
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "expected_execution_revision": payload["execution_revision"],
            "lease_seconds": 60,
            "acknowledgement": "I accept responsibility for the streamed prompt",
            "idempotency_key": "legacy-prompt-event-acquire",
            "reason": "answer from the canonical stream event",
        },
    )
    assert acquired.status_code == 200, acquired.text
    lease = acquired.json()["control_lease"]
    body = {
        "action": "COMMIT",
        "value": payload["options"][0]["value"],
        "expected_prompt_revision": payload["prompt_revision"],
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "session_id": session_id,
        "client_instance_key_id": client_id,
        "idempotency_key": "legacy-prompt-event-answer",
        "reason": "commit the streamed prompt decision",
    }
    settled = client.post(
        f"/api/v1/prompts/{prompt_id}/responses", headers=headers, json=body
    )
    assert settled.status_code == 202, settled.text
    assert settled.json()["attempt"]["outcome"] == "ACCEPTED_SETTLEMENT"
    settlement_id = settled.json()["prompt"]["settlement"]["id"]
    replay = client.post(
        f"/api/v1/prompts/{prompt_id}/responses", headers=headers, json=body
    )
    assert replay.status_code == 202, replay.text
    assert replay.json()["attempt"]["id"] == settled.json()["attempt"]["id"]

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with client.app.state.session_factory() as session:
            execution = session.get(Execution, execution_id)
            projected = session.get(OperatorPrompt, prompt_id)
            if execution.state == "completed":
                assert projected.settlement_delivered_at is not None
                answered = session.scalar(
                    select(Event).where(
                        Event.execution_id == execution_id,
                        Event.event_type == "prompt.answered",
                    )
                )
                assert answered is not None
                assert answered.causation_id == settlement_id
                assert len(answered.causation_id) == 36
                break
        time.sleep(0.05)
    else:
        raise AssertionError("streamed legacy prompt settlement was not acknowledged")


def test_synthetic_worker_event_references_fit_the_legacy_schema(client) -> None:
    execution, _service = _paused_execution(
        client, suffix="synthetic-event-references"
    )
    identity = str(uuid.uuid4())
    long_references = {
        "settlement": f"settlement:{identity}",
        "operator-recovery-pause": f"operator-recovery-pause:{identity}",
        "breakpoint": f"breakpoint:{identity}:{'f' * 64}",
        "control-loss": f"control-loss:control-loss:{identity}:7",
    }
    assert Event.__table__.c.causation_id.type.length == 36
    assert Event.__table__.c.correlation_id.type.length == 36

    normalized: dict[str, str] = {}
    for name, reference in long_references.items():
        event = client.app.state.supervisor.append_event(
            execution.id,
            f"pytest.synthetic_{name}",
            {"kind": name},
            source="pytest",
            correlation_id=reference,
            causation_id=reference,
        )
        assert event["correlation_id"] == event["causation_id"]
        assert event["causation_id"] != reference
        assert len(event["causation_id"]) == 36
        uuid.UUID(event["causation_id"])
        normalized[name] = event["causation_id"]
    assert len(set(normalized.values())) == len(normalized)

    replay = client.app.state.supervisor.append_event(
        execution.id,
        "pytest.synthetic_settlement_replay",
        {},
        source="pytest",
        causation_id=long_references["settlement"],
    )
    assert replay["causation_id"] == normalized["settlement"]
    direct = client.app.state.supervisor.append_event(
        execution.id,
        "pytest.direct_reference",
        {},
        source="pytest",
        correlation_id=identity,
        causation_id=identity,
    )
    assert direct["correlation_id"] == identity
    assert direct["causation_id"] == identity


def test_parallel_prompt_abort_and_master_do_not_invert_runtime_locks(
    client, operator_headers, viewer_headers, monkeypatch
) -> None:
    service = client.app.state.operator_service
    supervisor = client.app.state.supervisor
    sink_lock_states: list[bool] = []
    ack_lock_states: list[bool] = []
    bundle_lock_states: list[bool] = []
    original_sink = service.prompt_settlement_sink
    original_ack = service.ack_prompt_settlement_application
    original_ensure_projection = service.ensure_execution_projection

    def checked_sink(delivery):
        sink_lock_states.append(not service._lock._is_owned())
        assert original_sink is not None
        return original_sink(delivery)

    def checked_ack(*args, **kwargs):
        ack_lock_states.append(not supervisor._lock._is_owned())
        return original_ack(*args, **kwargs)

    def checked_ensure_projection(*args, **kwargs):
        bundle_lock_states.append(not supervisor._lock._is_owned())
        return original_ensure_projection(*args, **kwargs)

    monkeypatch.setattr(service, "prompt_settlement_sink", checked_sink)
    monkeypatch.setattr(service, "ack_prompt_settlement_application", checked_ack)
    monkeypatch.setattr(
        service, "ensure_execution_projection", checked_ensure_projection
    )

    def create_prompt_execution(index: int) -> tuple[str, str, dict, dict]:
        created = client.post(
            "/api/v1/executions",
            headers=operator_headers,
            json={
                "procedure_id": "integration",
                "reason": "parallel prompt lock-order regression",
                "idempotency_key": f"parallel-prompt-execution-{index}",
            },
        )
        assert created.status_code == 202, created.text
        execution_id = created.json()["execution"]["id"]
        deadline = time.monotonic() + 8
        prompt_event = None
        while time.monotonic() < deadline:
            events = client.get(
                f"/api/v1/executions/{execution_id}/events",
                headers=viewer_headers,
            )
            assert events.status_code == 200, events.text
            prompt_event = next(
                (
                    item
                    for item in events.json()["items"]
                    if item["event_type"] in {"prompt.opened", "prompt.reopened"}
                ),
                None,
            )
            if prompt_event is not None:
                break
            time.sleep(0.02)
        assert prompt_event is not None
        payload = prompt_event["payload"]
        session_id = f"parallel-prompt-session-{index}"
        client_id = f"parallel-prompt-client-{index}"
        headers = {
            **operator_headers,
            "X-Spell-Session-Id": session_id,
            "X-Spell-Client-Instance-Key-Id": client_id,
        }
        acquired = client.post(
            f"/api/v1/executions/{execution_id}/control",
            headers=headers,
            json={
                "action": "ACQUIRE",
                "session_id": session_id,
                "client_instance_key_id": client_id,
                "expected_execution_revision": payload["execution_revision"],
                "lease_seconds": 60,
                "acknowledgement": "I accept the parallel prompt",
                "idempotency_key": f"parallel-prompt-acquire-{index}",
                "reason": "parallel prompt lock-order regression",
            },
        )
        assert acquired.status_code == 200, acquired.text
        lease = acquired.json()["control_lease"]
        body = {
            "action": "COMMIT",
            "value": payload["options"][0]["value"],
            "expected_prompt_revision": payload["prompt_revision"],
            "lease_id": lease["id"],
            "expected_lease_revision": lease["revision"],
            "control_fencing_token": lease["control_fencing_token"],
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "idempotency_key": f"parallel-prompt-answer-{index}",
            "reason": "parallel prompt lock-order regression",
        }
        return execution_id, payload["prompt_id"], headers, body

    prompt_requests = [create_prompt_execution(index) for index in range(4)]
    abort_requests: list[tuple[str, dict]] = []
    for index in range(4):
        created = client.post(
            "/api/v1/executions",
            headers=operator_headers,
            json={
                "procedure_id": "recovery",
                "reason": "parallel abort lock-order regression",
                "idempotency_key": f"parallel-abort-execution-{index}",
            },
        )
        assert created.status_code == 202, created.text
        execution_id = created.json()["execution"]["id"]
        deadline = time.monotonic() + 8
        execution_revision = None
        while time.monotonic() < deadline:
            events = client.get(
                f"/api/v1/executions/{execution_id}/events",
                headers=viewer_headers,
            )
            assert events.status_code == 200, events.text
            prompt_event = next(
                (
                    item
                    for item in events.json()["items"]
                    if item["event_type"] in {"prompt.opened", "prompt.reopened"}
                ),
                None,
            )
            if prompt_event is not None:
                execution_revision = prompt_event["payload"]["execution_revision"]
                break
            time.sleep(0.02)
        assert type(execution_revision) is int
        abort_requests.append(
            (
                execution_id,
                {
                    "type": "abort",
                    "expected_revision": execution_revision,
                    "reason": "parallel abort lock-order regression",
                    "idempotency_key": f"parallel-abort-{index}",
                },
            )
        )

    operations = []
    for _execution_id, prompt_id, headers, body in prompt_requests:
        operations.append(
            lambda prompt_id=prompt_id, headers=headers, body=body: client.post(
                f"/api/v1/prompts/{prompt_id}/responses",
                headers=headers,
                json=body,
            )
        )
    for execution_id, body in abort_requests:
        operations.append(
            lambda execution_id=execution_id, body=body: client.post(
                f"/api/v1/executions/{execution_id}/commands",
                headers=operator_headers,
                json=body,
            )
        )
    operations.append(lambda: client.get("/api/v1/master", headers=viewer_headers))

    barrier = threading.Barrier(len(operations) + 1)
    results: list = [None] * len(operations)
    failures: list[BaseException] = []

    def invoke(index: int, operation) -> None:
        try:
            barrier.wait(timeout=5)
            results[index] = operation()
        except BaseException as exc:
            failures.append(exc)

    threads = [
        threading.Thread(target=invoke, args=(index, operation), daemon=True)
        for index, operation in enumerate(operations)
    ]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=5)
    deadline = time.monotonic() + 15
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    assert not [thread for thread in threads if thread.is_alive()]
    assert not failures
    assert all(response.status_code in {200, 202} for response in results)

    prompt_execution_ids = {item[0] for item in prompt_requests}
    abort_execution_ids = {item[0] for item in abort_requests}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with client.app.state.session_factory() as session:
            prompt_rows = session.scalars(
                select(OperatorPrompt).where(
                    OperatorPrompt.execution_id.in_(prompt_execution_ids)
                )
            ).all()
            prompt_states = {
                row.execution_id: (
                    session.get(Execution, row.execution_id).state,
                    row.settlement_delivered_at,
                )
                for row in prompt_rows
            }
            abort_states = {
                execution_id: session.get(Execution, execution_id).state
                for execution_id in abort_execution_ids
            }
        if (
            len(prompt_states) == 4
            and all(
                state == "completed" and delivered_at is not None
                for state, delivered_at in prompt_states.values()
            )
            and all(state == "aborted" for state in abort_states.values())
        ):
            break
        time.sleep(0.05)
    else:
        raise AssertionError(
            f"parallel runtime did not drain: prompts={prompt_states}, aborts={abort_states}"
        )
    master = client.get("/api/v1/master", headers=viewer_headers)
    assert master.status_code == 200, master.text
    assert len(master.json()["items"]) >= 8
    assert len(sink_lock_states) >= 4 and all(sink_lock_states)
    assert len(ack_lock_states) >= 4 and all(ack_lock_states)
    assert len(bundle_lock_states) >= 8 and all(bundle_lock_states)


def test_unprojected_legacy_prompt_retains_bounded_compatibility(
    client, operator_headers
) -> None:
    execution, _service = _paused_execution(client, suffix="legacy-prompt-compat")
    prompt_id = str(uuid.uuid4())
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        projection = session.get(ExecutionOperatorState, execution.id)
        session.delete(projection)
        stored.state = "prompting"
        session.add(
            Prompt(
                id=prompt_id,
                execution_id=execution.id,
                step_index=0,
                status="open",
                question="Compatibility prompt",
                choices=["yes"],
                default_choice="yes",
            )
        )
        expected_revision = stored.revision
        session.commit()
    response = client.post(
        f"/api/v1/prompts/{prompt_id}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": expected_revision,
            "reason": "bounded pre-projection compatibility",
            "idempotency_key": "legacy-prompt-compatibility",
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["command"]["type"] == "prompt_response"
    with client.app.state.session_factory() as session:
        assert session.get(ExecutionOperatorState, execution.id) is None
        assert session.scalar(
            select(func.count()).select_from(Command).where(
                Command.execution_id == execution.id,
                Command.command_type == "prompt_response",
            )
        ) == 1


def test_legacy_prompt_terminal_transition_between_projection_phases_stays_closed(
    client, operator_headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, service = _paused_execution(client, suffix="prompt-terminal-race")
    generation = 17
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        assert stored is not None
        stored.state = "running"
        stored.worker_generation = generation
        session.commit()

    supervisor = client.app.state.supervisor
    original_projection = service.ensure_legacy_prompt_projection
    transition_won = threading.Event()

    def abort_before_projection(
        prompt_id: str, *, worker_generation: int | None = None
    ) -> dict:
        supervisor._set_state(execution.id, "aborted", source="pytest")
        transition_won.set()
        return original_projection(
            prompt_id, worker_generation=worker_generation
        )

    monkeypatch.setattr(
        service, "ensure_legacy_prompt_projection", abort_before_projection
    )
    prompt_id = str(uuid.uuid4())
    supervisor._open_prompt(
        execution.id,
        generation,
        {
            "prompt_id": prompt_id,
            "step_index": 0,
            "question": "Continue?",
            "choices": ["yes", "no"],
            "default": None,
        },
    )

    assert transition_won.is_set()
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        legacy = session.get(Prompt, prompt_id)
        projected = session.get(OperatorPrompt, prompt_id)
        prompt_events = session.scalars(
            select(Event).where(
                Event.execution_id == execution.id,
                Event.event_type.in_(["prompt.opened", "prompt.reopened"]),
            )
        ).all()
        assert stored is not None and stored.state == "aborted"
        assert legacy is not None and legacy.status == "cancelled"
        assert projected is not None and projected.state == "SETTLED"
        assert projected.settlement_outcome == "EXECUTION_TERMINATED"
        assert prompt_events == []

    snapshot = client.get(
        f"/api/v1/executions/{execution.id}/snapshot", headers=operator_headers
    )
    assert snapshot.status_code == 200, snapshot.text
    assert snapshot.json()["active_prompt"] is None


def test_legacy_prompt_snapshot_is_coherent_across_projection_phases(
    client, operator_headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, service = _paused_execution(client, suffix="prompt-publication")
    generation = 18
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        assert stored is not None
        stored.state = "running"
        stored.worker_generation = generation
        session.commit()

    supervisor = client.app.state.supervisor
    original_projection = service.ensure_legacy_prompt_projection
    snapshots: list[dict] = []

    def inspect_projection_boundary(
        prompt_id: str, *, worker_generation: int | None = None
    ) -> dict:
        before = client.get(
            f"/api/v1/executions/{execution.id}/snapshot", headers=operator_headers
        )
        assert before.status_code == 200, before.text
        snapshots.append(before.json())
        projected = original_projection(
            prompt_id, worker_generation=worker_generation
        )
        after = client.get(
            f"/api/v1/executions/{execution.id}/snapshot", headers=operator_headers
        )
        assert after.status_code == 200, after.text
        snapshots.append(after.json())
        return projected

    monkeypatch.setattr(
        service, "ensure_legacy_prompt_projection", inspect_projection_boundary
    )
    prompt_id = str(uuid.uuid4())
    supervisor._open_prompt(
        execution.id,
        generation,
        {
            "prompt_id": prompt_id,
            "step_index": 0,
            "question": "Continue?",
            "choices": ["yes", "no"],
            "default": None,
        },
    )

    assert [item["execution"]["state"] for item in snapshots] == [
        "running",
        "running",
    ]
    assert [item["active_prompt"] for item in snapshots] == [None, None]
    published = client.get(
        f"/api/v1/executions/{execution.id}/snapshot", headers=operator_headers
    )
    assert published.status_code == 200, published.text
    assert published.json()["execution"]["state"] == "prompting"
    assert published.json()["active_prompt"]["id"] == prompt_id


def test_fenced_response_upgrades_an_already_open_legacy_only_prompt(
    client, operator_headers
) -> None:
    execution, _service = _paused_execution(client, suffix="legacy-prompt-live-upgrade")
    prompt_id = str(uuid.uuid4())
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        projection = session.get(ExecutionOperatorState, execution.id)
        stored.state = "prompting"
        projection.state = "PROMPT"
        projection.resume_state = "PAUSED"
        session.add(
            Prompt(
                id=prompt_id,
                execution_id=execution.id,
                step_index=0,
                status="open",
                question="Upgrade the live legacy prompt?",
                choices=["yes"],
                default_choice=None,
            )
        )
        expected_revision = stored.revision
        session.commit()

    session_id = "legacy-live-upgrade-session"
    client_id = "legacy-live-upgrade-client"
    headers = {
        **operator_headers,
        "X-Spell-Session-Id": session_id,
        "X-Spell-Client-Instance-Key-Id": client_id,
    }
    acquired = client.post(
        f"/api/v1/executions/{execution.id}/control",
        headers=headers,
        json={
            "action": "ACQUIRE",
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "expected_execution_revision": expected_revision,
            "lease_seconds": 60,
            "idempotency_key": "legacy-live-upgrade-acquire",
            "reason": "upgrade already-open prompt",
        },
    )
    assert acquired.status_code == 200, acquired.text
    lease = acquired.json()["control_lease"]
    settled = client.post(
        f"/api/v1/prompts/{prompt_id}/responses",
        headers=headers,
        json={
            "action": "COMMIT",
            "value": "yes",
            "expected_prompt_revision": 1,
            "lease_id": lease["id"],
            "expected_lease_revision": lease["revision"],
            "control_fencing_token": lease["control_fencing_token"],
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "idempotency_key": "legacy-live-upgrade-settle",
            "reason": "settle upgraded legacy prompt",
        },
    )
    assert settled.status_code == 202, settled.text
    assert settled.json()["prompt"]["legacy_prompt_id"] == prompt_id
    assert settled.json()["prompt"]["settlement"]["outcome"] == "ANSWERED"
    with client.app.state.session_factory() as session:
        projected = session.get(OperatorPrompt, prompt_id)
        assert projected is not None
        assert projected.legacy_prompt_id == prompt_id


def test_vendor_json_is_strict_and_structured_bodies_are_bounded(
    client, operator_headers
) -> None:
    headers = {**operator_headers, "Content-Type": "application/vnd.spell+json"}
    duplicate = client.post(
        "/api/v1/executions",
        headers=headers,
        content=(
            b'{"procedure_id":"pause","procedure_id":"integration",'
            b'"reason":"duplicate","idempotency_key":"duplicate"}'
        ),
    )
    assert duplicate.status_code == 422
    assert duplicate.json()["detail"][0]["type"] == "json_invalid"
    nonfinite = client.post(
        "/api/v1/executions",
        headers=headers,
        content=(
            b'{"procedure_id":"pause","reason":"finite",'
            b'"idempotency_key":"finite","value":NaN}'
        ),
    )
    assert nonfinite.status_code == 422
    oversized = client.post(
        "/api/v1/executions",
        headers=headers,
        content=b'{"padding":"' + (b"x" * 1_000_001) + b'"}',
    )
    assert oversized.status_code == 413


def test_prompt_canonical_defaults_exact_list_types_and_replay(client) -> None:
    numeric, service = _paused_execution(client, suffix="prompt-num-default")
    opened = service.open_typed_prompt(
        numeric.id,
        "prompt-num-default",
        0,
        {"type": "NUM", "question": "Number", "default": "1.0"},
        {"PROMPT_RESPONSE_TIMEOUT": 0},
    )
    assert opened["default"] == "1.0"
    assert opened["response_deadline"] is None
    assert service.open_typed_prompt(
        numeric.id,
        "prompt-num-default",
        0,
        {"type": "NUM", "question": "Number", "default": "1.0"},
        {"PROMPT_RESPONSE_TIMEOUT": 0},
    )["id"] == opened["id"]

    exponent, _ = _paused_execution(client, suffix="prompt-num-exponent")
    exponent_prompt = service.open_typed_prompt(
        exponent.id,
        "prompt-num-exponent",
        0,
        {"type": "NUM", "question": "Exponent", "default": "1e2"},
        {},
    )
    assert exponent_prompt["default"] == "100"
    assert service.open_typed_prompt(
        exponent.id,
        "prompt-num-exponent",
        0,
        {"type": "NUM", "question": "Exponent", "default": "1e2"},
        {},
    )["default"] == "100"

    listed, _ = _paused_execution(client, suffix="prompt-list-types")
    lease = _acquire(service, listed)
    list_prompt = service.open_typed_prompt(
        listed.id,
        "prompt-list-types",
        0,
        {
            "type": "LIST",
            "question": "Typed value",
            "list_mode": "VALUE",
            "options": [{"value": 1, "label": "Integer one"}],
        },
        {},
    )
    invalid = service.settle_prompt(
        list_prompt["id"],
        1,
        "COMMIT",
        True,
        idempotency_key="prompt-bool-not-int",
        **_command_proof(lease),
    )
    assert invalid["attempt"]["outcome"] == "INVALID_VALUE"
    accepted = service.settle_prompt(
        list_prompt["id"],
        1,
        "COMMIT",
        1,
        idempotency_key="prompt-int-exact",
        **_command_proof(lease),
    )
    assert accepted["prompt"]["settlement"]["outcome"] == "ANSWERED"

    fixed, _ = _paused_execution(client, suffix="prompt-type-default")
    fixed_prompt = service.open_typed_prompt(
        fixed.id,
        "prompt-type-default",
        0,
        {"type": "YES_NO", "question": "Continue?"},
        {},
    )
    assert fixed_prompt["default"] is None
    with pytest.raises(OperatorValidationError):
        service.open_typed_prompt(
            fixed.id,
            "prompt-tampered",
            0,
            {"type": 1, "question": "Tampered"},
            {},
        )


def test_prompt_timeout_never_invents_a_fixed_choice_default(client) -> None:
    no_default_execution, service = _paused_execution(
        client, suffix="prompt-timeout-no-default"
    )
    no_default = service.open_typed_prompt(
        no_default_execution.id,
        "prompt-timeout-no-default",
        0,
        {
            "type": "YES_NO",
            "question": "Continue without a declared default?",
            "response_timeout_seconds": 60,
        },
        {},
    )
    explicit_execution, _ = _paused_execution(
        client, suffix="prompt-timeout-explicit-default"
    )
    explicit = service.open_typed_prompt(
        explicit_execution.id,
        "prompt-timeout-explicit-default",
        0,
        {
            "type": "YES_NO",
            "question": "Continue with a declared default?",
            "default": "YES",
            "response_timeout_seconds": 60,
        },
        {},
    )
    assert no_default["default"] is None
    assert explicit["default"] == "YES"
    with client.app.state.session_factory() as session:
        due = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.get(OperatorPrompt, no_default["id"]).response_deadline = due
        session.get(OperatorPrompt, explicit["id"]).response_deadline = due
        session.commit()
    service.reconcile_prompt_timers()
    with client.app.state.session_factory() as session:
        timed_out = session.get(OperatorPrompt, no_default["id"])
        answered = session.get(OperatorPrompt, explicit["id"])
        assert timed_out.settlement_outcome == "TIMED_OUT"
        assert timed_out.settled_value is None
        assert answered.settlement_outcome == "ANSWERED"
        assert answered.settled_value == "YES"


def test_prompt_controller_loss_grace_starts_at_loss_and_reacquire_clears_it(
    client,
) -> None:
    execution, service = _paused_execution(client, suffix="prompt-loss-grace")
    lease = _acquire(service, execution)
    prompt = service.open_typed_prompt(
        execution.id,
        "prompt-loss-grace",
        0,
        {"type": "ALPHA", "question": "Wait for controller"},
        {"NO_CONTROLLER_GRACE": 30},
    )
    assert prompt["no_controller_deadline"] is None
    with client.app.state.session_factory() as session:
        stored_lease = session.get(ControllerLease, lease["id"])
        stored_prompt = session.get(OperatorPrompt, prompt["id"])
        stored_lease.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        stored_prompt.opened_at = datetime.now(timezone.utc) - timedelta(hours=1)
        session.commit()
    assert service.expire_due_leases() == 1
    with client.app.state.session_factory() as session:
        deadline = session.get(OperatorPrompt, prompt["id"]).no_controller_deadline
        seconds = (
            deadline.replace(tzinfo=timezone.utc)
            if deadline.tzinfo is None
            else deadline
        ) - datetime.now(timezone.utc)
        assert 20 < seconds.total_seconds() <= 30
    expected_revision = execution.revision
    for attempt in range(2):
        try:
            service.acquire_control(
                execution.id,
                expected_execution_revision=expected_revision,
                actor="pytest-operator",
                holder_session_id="session-pytest-operator",
                client_instance_key_id="client-pytest-operator",
                lease_seconds=60,
                idempotency_key="prompt-loss-reacquire",
                reason="reacquire after prompt controller loss",
                acknowledgement="I accept the suspended prompt responsibility",
            )
            break
        except OperatorConflictError as exc:
            assert attempt == 0
            assert exc.current is not None
            expected_revision = exc.current["execution_revision"]
    else:
        raise AssertionError("controller reacquisition did not settle")
    with client.app.state.session_factory() as session:
        assert session.get(OperatorPrompt, prompt["id"]).no_controller_deadline is None


def test_control_loss_event_and_audit_are_idempotent_and_proof_free(client) -> None:
    execution, service = _paused_execution(client, suffix="control-loss-event")
    lease = _acquire(service, execution)
    with client.app.state.session_factory() as session:
        stored = session.get(ControllerLease, lease["id"])
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()

    service.get_execution_projection(execution.id)
    service.expire_due_leases()
    with client.app.state.session_factory() as session:
        events = session.scalars(
            select(Event).where(
                Event.execution_id == execution.id,
                Event.event_type == "operator.control_loss_requested",
            )
        ).all()
        audits = session.scalars(
            select(OperatorAuditEvent).where(
                OperatorAuditEvent.execution_id == execution.id,
                OperatorAuditEvent.event_type == "control.lease_expired",
            )
        ).all()
        projection = session.get(ExecutionOperatorState, execution.id)
        assert len(events) == 1
        assert len(audits) == 1
        assert events[0].id == projection.control_loss_event_id
        assert events[0].causation_id is None
        public_event = {
            "id": events[0].id,
            "execution_id": events[0].execution_id,
            "sequence": events[0].sequence,
            "payload": events[0].payload,
        }
        serialized = json.dumps(public_event)
        assert lease["id"] not in serialized
        assert "control_fencing_token" not in serialized


def test_command_admission_is_schema_exact_and_matches_ir_certainty(client) -> None:
    assert {
        command: frozenset(states)
        for command, (states, _safe_point) in _COMMAND_MATRIX.items()
    } == COMMAND_ALLOWED_STATES
    execution, service = _paused_execution(client, suffix="command-certainty")
    lease = _acquire(service, execution)
    with pytest.raises(OperatorValidationError):
        service.accept_operator_command(
            execution.id,
            "RUN",
            execution.revision,
            "command-payload-override",
            role="operator",
            reason="reject envelope override",
            payload={"type": "ABORT", "command_id": "forged"},
            **_command_proof(lease),
        )
    with pytest.raises(OperatorValidationError):
        service.accept_operator_command(
            execution.id,
            "STEP",
            execution.revision,
            "command-target-override",
            role="operator",
            reason="reject target override",
            target={"target_step": 1, "safe_point_id": "forged"},
            **_command_proof(lease),
        )
    with client.app.state.session_factory() as session:
        projection = session.get(ExecutionOperatorState, execution.id)
        projection.effect_certainty = "EFFECT_UNKNOWN"
        session.commit()
    rejected = service.accept_operator_command(
        execution.id,
        "RUN",
        execution.revision,
        "command-effect-unknown",
        role="operator",
        reason="do not cross unresolved effect",
        **_command_proof(lease),
    )
    assert rejected["state"] == "REJECTED"
    assert rejected["rejection_code"] == "UNRESOLVED_EXTERNAL_EFFECT"


def test_control_proof_privacy_and_running_direct_background_release_fail_closed(
    client,
) -> None:
    execution, service = _paused_execution(client, suffix="control-privacy")
    lease = _acquire(service, execution)
    with pytest.raises(OperatorAuthorizationError) as wrong_session:
        service.require_control(
            execution.id,
            actor="pytest-operator",
            holder_session_id="wrong-session",
            client_instance_key_id="client-pytest-operator",
            lease_id=lease["id"],
            expected_lease_revision=lease["revision"] + 99,
            control_fencing_token=lease["control_fencing_token"],
        )
    assert wrong_session.value.current is None
    assert "session-pytest-operator" not in str(wrong_session.value)
    with pytest.raises(OperatorAuthorizationError) as wrong_fence:
        service.require_control(
            execution.id,
            actor="pytest-operator",
            holder_session_id="session-pytest-operator",
            client_instance_key_id="client-pytest-operator",
            lease_id=lease["id"],
            expected_lease_revision=lease["revision"] + 99,
            control_fencing_token=lease["control_fencing_token"] + 1,
        )
    assert wrong_fence.value.current is None
    assert "session-pytest-operator" not in str(wrong_fence.value)
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        projection = session.get(ExecutionOperatorState, execution.id)
        stored.state = "running"
        projection.state = "RUNNING"
        projection.background_allowed = True
        projection.current_safe_point_id = "safe-point:stale"
        session.commit()
    with pytest.raises(OperatorConflictError):
        service.release_control_to_background(
            execution.id,
            expected_execution_revision=execution.revision,
            lease_id=lease["id"],
            expected_lease_revision=lease["revision"],
            control_fencing_token=lease["control_fencing_token"],
            actor="pytest-operator",
            holder_session_id="session-pytest-operator",
            client_instance_key_id="client-pytest-operator",
            idempotency_key="running-direct-background",
            reason="must use safe-point command",
        )


def test_schedule_identity_misfire_restart_and_authoritative_child_projection(
    client, procedures_dir,
) -> None:
    controller, service = _paused_execution(client, suffix="schedule-controller")
    lease = _acquire(service, controller)
    catalog_item = next(
        item for item in service.list_catalog() if item["procedure_ref"] == "pause"
    )

    def create(key: str, policy: str, maximum: int) -> dict:
        return service.create_schedule(
            controller_execution_id=controller.id,
            schedule_type="RELATIVE",
            target="60.0",
            procedure_catalog_id=catalog_item["id"],
            procedure_revision=None,
            context_id="simulator",
            arguments={"mode": key},
            automatic=False,
            background_allowed=False,
            visible=True,
            misfire_policy=policy,
            maximum_lateness_seconds=maximum,
            expected_execution_revision=controller.revision,
            idempotency_key=key,
            reason="focused durable schedule",
            **_proof(lease),
        )

    fire = create("schedule-fire-once", "FIRE_ONCE", 0)
    skip = create("schedule-skip", "SKIP", 1)
    stable_target = fire["target_at_database_time"]
    assert fire["procedure_catalog_id"] == catalog_item["id"]
    assert fire["procedure_revision"] == catalog_item["current_revision"]
    assert len(fire["bundle_digest"]) == 64
    restarted = OperatorService(client.app.state.session_factory, client.app.state.catalog)
    assert next(
        item for item in restarted.list_schedules() if item["id"] == fire["id"]
    )["target_at_database_time"] == stable_target
    pinned_identity = (
        fire["catalog_revision_id"],
        fire["procedure_catalog_id"],
        fire["procedure_revision"],
        fire["bundle_digest"],
    )
    (procedures_dir / "pause.spell.py").write_text(
        '"""Changed catalog source after schedule admission."""\n\n'
        'Log("new catalog revision")\n'
        'Wait(3.0)\n'
        'Log("done")\n',
        encoding="utf-8",
    )
    service.sync_catalog(actor="focused-catalog-refresh")
    persisted_fire = next(
        item for item in service.list_schedules() if item["id"] == fire["id"]
    )
    assert (
        persisted_fire["catalog_revision_id"],
        persisted_fire["procedure_catalog_id"],
        persisted_fire["procedure_revision"],
        persisted_fire["bundle_digest"],
    ) == pinned_identity
    with client.app.state.session_factory() as session:
        due = datetime.now(timezone.utc) - timedelta(seconds=10)
        session.get(ProcedureSchedule, fire["id"]).target_at = due
        session.get(ProcedureSchedule, skip["id"]).target_at = due
        session.commit()
    service.reconcile_schedules()
    schedules = {item["id"]: item for item in service.list_schedules()}
    assert schedules[skip["id"]]["state"] == "MISSED"
    assert schedules[fire["id"]]["state"] == "FIRED"
    child_id = schedules[fire["id"]]["execution_id"]
    with client.app.state.session_factory() as session:
        child = session.get(Execution, child_id)
        projection = session.get(ExecutionOperatorState, child_id)
        assert child.variables == {"ARGS": {"mode": "schedule-fire-once"}}
        assert child.state == "ready"
        assert projection.state == "PAUSED"
        assert projection.ownership_mode == "CONTROL_LOST"
        assert projection.catalog_revision_id == fire["catalog_revision_id"]
        assert session.scalar(
            select(func.count()).select_from(ScheduleOccurrence).where(
                ScheduleOccurrence.schedule_id == fire["id"]
            )
        ) == 1
    service.reconcile_schedules()
    assert next(
        item for item in service.list_schedules() if item["id"] == fire["id"]
    )["execution_id"] == child_id
    with pytest.raises(OperatorValidationError):
        service.create_schedule(
            controller_execution_id=controller.id,
            schedule_type="TELEMETRY_CONDITION",
            target=1,
            procedure_catalog_id=catalog_item["id"],
            procedure_revision=None,
            context_id="simulator",
            arguments={},
            automatic=False,
            background_allowed=False,
            visible=True,
            misfire_policy="FIRE_ONCE",
            maximum_lateness_seconds=1,
            expected_execution_revision=controller.revision,
            idempotency_key="schedule-deferred",
            reason="must fail closed",
            **_proof(lease),
        )


def test_nested_redaction_workspace_views_and_report_hide_secrets(
    client, viewer_headers
) -> None:
    execution, service = _paused_execution(client, suffix="nested-redaction")
    lease = _acquire(service, execution)
    secret = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        stored.variables = {
            "profile": {"name": "ordinary", "password": "canary-password"},
            "note": "clean",
        }
        session.add(
            Event(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                sequence=stored.next_sequence,
                event_type="procedure.log",
                source="procedure",
                severity="warning",
                payload={"message": secret, "correlation": "visible"},
                created_at=datetime.now(timezone.utc),
            )
        )
        stored.next_sequence += 1
        session.commit()
    inspection = service.inspection(execution.id)
    profile = next(item for item in inspection["items"] if item["name"] == "profile")
    assert profile["value"] == {"name": "ordinary", "password": None}
    assert profile["redacted"] is True
    with pytest.raises(OperatorAuthorizationError):
        service.edit_inspection(
            execution.id,
            path="variables.note",
            scope="LOCAL_VARIABLE",
            declared_type="STRING",
            value=secret,
            expected_value_revision=execution.revision,
            expected_execution_revision=execution.revision,
            idempotency_key="secret-edit",
            reason="must reject secret material",
            **_proof(lease),
        )
    snapshot = client.get(
        f"/api/v1/executions/{execution.id}/snapshot", headers=viewer_headers
    )
    assert snapshot.status_code == 200
    serialized = json.dumps(snapshot.json())
    assert "canary-password" not in serialized
    assert secret not in serialized
    assert snapshot.json()["execution"]["text_entries"]
    assert snapshot.json()["execution"]["as_run_entries"]
    report = client.get(
        f"/api/v1/executions/{execution.id}/report", headers=viewer_headers
    )
    assert report.status_code == 200
    report_text = report.text
    assert "canary-password" not in report_text
    assert secret not in report_text
    assert "session-pytest-operator" not in report_text
    assert "client-pytest-operator" not in report_text
    for lease_projection in report.json()["controller_leases"]:
        assert "holder_session_id" not in lease_projection
        assert "client_instance_key_id" not in lease_projection
        assert "control_fencing_token" not in lease_projection


def test_workspace_view_pages_full_committed_history_beyond_snapshot_window(
    client, viewer_headers
) -> None:
    execution, _ = _paused_execution(client, suffix="workspace-history-page")
    secret = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution.id)
        first_sequence = stored.next_sequence
        session.add_all(
            [
                Event(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    sequence=first_sequence + index,
                    event_type="procedure.log",
                    source="procedure",
                    severity="warning" if index == 210 else "info",
                    correlation_id=str(uuid.uuid4()),
                    payload={
                        "message": secret if index == 210 else f"history-{index:03d}",
                        "step_index": 0,
                    },
                    created_at=datetime.now(timezone.utc),
                )
                for index in range(245)
            ]
        )
        stored.next_sequence += 245
        session.commit()

    snapshot = client.get(
        f"/api/v1/executions/{execution.id}/snapshot", headers=viewer_headers
    )
    assert snapshot.status_code == 200
    assert len(snapshot.json()["execution"]["text_entries"]) == 200

    items: list[dict] = []
    cursor = 0
    while True:
        response = client.get(
            f"/api/v1/executions/{execution.id}/workspace-view",
            params={
                "view": "TEXT",
                "source_digest": execution.procedure_hash,
                "after_sequence": cursor,
                "limit": 100,
            },
            headers=viewer_headers,
        )
        assert response.status_code == 200
        page = response.json()
        assert page["source_digest"] == execution.procedure_hash
        items.extend(page["items"])
        if page["next_cursor"] is None:
            assert page["has_more"] is False
            break
        assert page["has_more"] is True
        cursor = page["next_cursor"]

    assert len(items) == 245
    assert [item["sequence"] for item in items] == sorted(
        item["sequence"] for item in items
    )
    assert items[-1]["message"] == "history-244"
    assert secret not in json.dumps(items)
    stale = client.get(
        f"/api/v1/executions/{execution.id}/workspace-view",
        params={"view": "AS_RUN", "source_digest": "0" * 64},
        headers=viewer_headers,
    )
    assert stale.status_code == 409
