from __future__ import annotations

import copy

from sqlalchemy import select

from backend.bundled_observation_catalog import (
    CATALOG_DIGEST,
    POLICY_ID,
    POLICY_REVISION,
)
from backend.condition_engine import (
    ComparisonOperator,
    ConditionPlan,
    LiteralOperand,
    PredicateNode,
    QualityFreshnessPolicy,
    ScalarType,
    TelemetryOperand,
    TypedScalar,
)
from backend.condition_models import VerifyOperation, WaitForOperation
from backend.development_models import DevelopmentRuntimePin
from backend.models import Execution


SESSION_ID = "session-pytest-operator"
CLIENT_ID = "client-pytest-operator"


def _controller(client, suffix: str):
    supervisor = client.app.state.supervisor
    procedure = client.app.state.catalog.get("pause")
    execution = supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason=f"v0.7 telemetry schedule {suffix}",
        idempotency_key=f"v07-telemetry-controller-{suffix}",
        automatic=False,
    )
    client.app.state.operator_service.ensure_execution_projection(
        execution,
        actor="operator-bootstrap",
        automatic=False,
    )
    return execution


def _lease(client, execution):
    return client.app.state.operator_service.acquire_control(
        execution.id,
        expected_execution_revision=execution.revision,
        actor="pytest-operator",
        holder_session_id=SESSION_ID,
        client_instance_key_id=CLIENT_ID,
        lease_seconds=60,
        idempotency_key=f"v07-telemetry-lease-{execution.id}",
        reason="control telemetry schedule",
    )["control_lease"]


def _bound_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        **headers,
        "X-Spell-Session-Id": SESSION_ID,
        "X-Spell-Client-Instance-Key-Id": CLIENT_ID,
    }


def _condition_plan(plan_id: str = "schedule.route.plan") -> ConditionPlan:
    return ConditionPlan(
        plan_id,
        PredicateNode(
            "voltage-high",
            ComparisonOperator.GT,
            TelemetryOperand(
                "TM.POWER.BUS_VOLTAGE",
                CATALOG_DIGEST,
                ScalarType.FINITE_DOUBLE,
            ),
            LiteralOperand(TypedScalar(ScalarType.FINITE_DOUBLE, 99.0)),
        ),
    )


def _schedule_payload(client, execution, lease, *, key: str) -> dict:
    catalog_item = next(
        item
        for item in client.app.state.operator_service.list_catalog()
        if item["procedure_ref"] == "pause"
    )
    return {
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "session_id": SESSION_ID,
        "client_instance_key_id": CLIENT_ID,
        "controller_execution_id": execution.id,
        "condition_plan": _condition_plan().as_dict(),
        "timeout_seconds": 3600,
        "retry_count": 3,
        "retry_interval_seconds": 60,
        "procedure_catalog_id": catalog_item["id"],
        "procedure_revision": catalog_item["current_revision"],
        "context_id": "simulator",
        "arguments": {"mode": "telemetry-route"},
        "automatic": True,
        "background_allowed": True,
        "visible": True,
        "expected_execution_revision": execution.revision,
        "idempotency_key": key,
        "reason": "focused telemetry schedule route",
    }


def test_telemetry_schedule_routes_require_bound_controller_authority(
    client,
    viewer_headers,
    operator_headers,
    monkeypatch,
) -> None:
    client.app.state.condition_recovery.stop()
    monkeypatch.setattr(
        client.app.state.observation_repository,
        "snapshot",
        lambda context_id: {
            "context_id": context_id,
            "through_sequence": "17",
        },
    )
    controller = _controller(client, "route-authority")
    lease = _lease(client, controller)
    payload = _schedule_payload(
        client,
        controller,
        lease,
        key="telemetry-route-authority",
    )
    operator = _bound_headers(operator_headers)
    viewer = _bound_headers(viewer_headers)

    assert client.get("/api/v1/telemetry-schedules").status_code == 401
    assert (
        client.post(
            "/api/v1/telemetry-schedules",
            headers=viewer,
            json=payload,
        ).status_code
        == 403
    )

    mismatched_headers = {
        **operator,
        "X-Spell-Session-Id": "another-session",
    }
    mismatch = client.post(
        "/api/v1/telemetry-schedules",
        headers=mismatched_headers,
        json=payload,
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"]["code"] == "SESSION_BINDING_MISMATCH"

    wrong_fence = copy.deepcopy(payload)
    wrong_fence["control_fencing_token"] += 1
    rejected = client.post(
        "/api/v1/telemetry-schedules",
        headers=operator,
        json=wrong_fence,
    )
    assert rejected.status_code == 403
    assert rejected.json()["detail"]["code"] == "FORBIDDEN"

    stale_execution = copy.deepcopy(payload)
    stale_execution["expected_execution_revision"] += 1
    conflict = client.post(
        "/api/v1/telemetry-schedules",
        headers=operator,
        json=stale_execution,
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "CONFLICT"


def test_telemetry_schedule_create_list_get_cancel_is_controller_bound(
    client,
    viewer_headers,
    operator_headers,
    monkeypatch,
) -> None:
    client.app.state.condition_recovery.stop()
    monkeypatch.setattr(
        client.app.state.observation_repository,
        "snapshot",
        lambda context_id: {
            "context_id": context_id,
            "through_sequence": "23",
        },
    )
    controller = _controller(client, "route-crud")
    lease = _lease(client, controller)
    payload = _schedule_payload(client, controller, lease, key="telemetry-route-crud")
    operator = _bound_headers(operator_headers)

    created_response = client.post(
        "/api/v1/telemetry-schedules",
        headers=operator,
        json=payload,
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()["schedule"]
    assert created["state"] == "PENDING"
    assert created["idempotency_key"] == payload["idempotency_key"]
    assert created["controller_execution_id"] == controller.id
    assert created["start_snapshot_cursor"] == "23"
    assert created["procedure_revision"] == payload["procedure_revision"]
    assert created["context_id"] == "simulator"
    assert created["arguments"] == {"mode": "telemetry-route"}
    assert created["automatic"] is True
    assert created["background_allowed"] is True
    assert created["bundle_digest"]
    with client.app.state.session_factory() as session:
        assert session.scalar(
            select(DevelopmentRuntimePin).where(
                DevelopmentRuntimePin.runtime_kind == "SCHEDULE",
                DevelopmentRuntimePin.runtime_id == created["schedule_id"],
            )
        ) is None

    replay = client.post(
        "/api/v1/telemetry-schedules",
        headers=operator,
        json=payload,
    )
    assert replay.status_code == 201
    assert replay.json()["schedule"] == created

    conflicting_payload = copy.deepcopy(payload)
    conflicting_payload["arguments"] = {"mode": "different"}
    conflict = client.post(
        "/api/v1/telemetry-schedules",
        headers=operator,
        json=conflicting_payload,
    )
    assert conflict.status_code == 409

    listed = client.get(
        "/api/v1/telemetry-schedules",
        params={"controller_execution_id": controller.id},
        headers=viewer_headers,
    )
    assert listed.status_code == 200
    assert [item["schedule_id"] for item in listed.json()["items"]] == [
        created["schedule_id"]
    ]

    fetched = client.get(
        f"/api/v1/telemetry-schedules/{created['schedule_id']}",
        headers=viewer_headers,
    )
    assert fetched.status_code == 200
    assert fetched.json()["schedule"] == created

    other_controller = _controller(client, "route-crud-other")
    wrong_controller = {
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "session_id": SESSION_ID,
        "client_instance_key_id": CLIENT_ID,
        "controller_execution_id": other_controller.id,
        "expected_schedule_revision": created["revision"],
        "idempotency_key": "cancel-wrong-controller",
        "reason": "must not cross controller binding",
    }
    rejected = client.post(
        f"/api/v1/telemetry-schedules/{created['schedule_id']}/cancel",
        headers=operator,
        json=wrong_controller,
    )
    assert rejected.status_code == 409
    assert "controller mismatch" in rejected.json()["detail"]["message"]

    cancel_payload = {
        **wrong_controller,
        "controller_execution_id": controller.id,
        "idempotency_key": "cancel-correct-controller",
    }
    cancelled_response = client.post(
        f"/api/v1/telemetry-schedules/{created['schedule_id']}/cancel",
        headers=operator,
        json=cancel_payload,
    )
    assert cancelled_response.status_code == 200
    cancelled = cancelled_response.json()["schedule"]
    assert cancelled["state"] == "CANCELLED"
    assert cancelled["revision"] == created["revision"] + 1
    assert cancelled["idempotency_key"] == payload["idempotency_key"]
    assert cancelled["fired_execution_id"] is None

    replayed_cancel = client.post(
        f"/api/v1/telemetry-schedules/{created['schedule_id']}/cancel",
        headers=operator,
        json=cancel_payload,
    )
    assert replayed_cancel.status_code == 200
    assert replayed_cancel.json()["schedule"] == cancelled


def _delayed_operations(client, execution_id: str, suffix: str) -> tuple[dict, dict]:
    service = client.app.state.condition_service
    verify = service.verify(
        plan=_condition_plan(f"lifecycle.verify.{suffix}"),
        policy=QualityFreshnessPolicy(POLICY_ID, POLICY_REVISION),
        delay_seconds=3600,
        timeout_seconds=7200,
        retry_count=0,
        retry_interval_seconds=0,
        request_scope=execution_id,
        idempotency_key=f"lifecycle-verify-{suffix}",
    )
    wait = service.create_wait(
        execution_id=execution_id,
        statement_id=f"lifecycle-wait-{suffix}",
        wait_type="RELATIVE",
        target=3600,
        idempotency_key=f"lifecycle-wait-{suffix}",
    )
    return verify, wait


def _force_execution_state(client, execution_id: str, state: str) -> None:
    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        execution.state = state
        execution.revision += 1
        session.commit()


def _operation_states(client, verify_id: str, wait_id: str) -> tuple[str, str]:
    with client.app.state.session_factory() as session:
        verify_state = session.scalar(
            select(VerifyOperation.state).where(VerifyOperation.id == verify_id)
        )
        wait_state = session.scalar(
            select(WaitForOperation.state).where(WaitForOperation.id == wait_id)
        )
    assert verify_state is not None
    assert wait_state is not None
    return verify_state, wait_state


def test_supervisor_and_recovery_apply_pause_resume_and_terminal_lifecycle(
    client,
) -> None:
    recovery = client.app.state.condition_recovery
    recovery.stop()
    supervisor = client.app.state.supervisor

    immediate = _controller(client, "supervisor-hooks")
    _force_execution_state(client, immediate.id, "running")
    immediate_verify, immediate_wait = _delayed_operations(
        client,
        immediate.id,
        "supervisor",
    )

    supervisor._set_state(immediate.id, "paused", source="focused-test")
    assert _operation_states(
        client,
        immediate_verify["verify_id"],
        immediate_wait["wait_id"],
    ) == ("DELAYED", "INTERRUPTED")

    supervisor._set_state(immediate.id, "running", source="focused-test")
    assert _operation_states(
        client,
        immediate_verify["verify_id"],
        immediate_wait["wait_id"],
    ) == ("DELAYED", "WAITING")

    supervisor._set_state(immediate.id, "completed", source="focused-test")
    assert _operation_states(
        client,
        immediate_verify["verify_id"],
        immediate_wait["wait_id"],
    ) == ("CANCELLED", "CANCELLED")

    recovered = _controller(client, "recovery-hooks")
    recovered_verify, recovered_wait = _delayed_operations(
        client,
        recovered.id,
        "recovery",
    )

    _force_execution_state(client, recovered.id, "paused")
    counts = recovery.reconcile_once()
    assert set(counts) == {"verifies", "waits", "schedules"}
    assert _operation_states(
        client,
        recovered_verify["verify_id"],
        recovered_wait["wait_id"],
    ) == ("DELAYED", "INTERRUPTED")

    _force_execution_state(client, recovered.id, "running")
    recovery.reconcile_once()
    assert _operation_states(
        client,
        recovered_verify["verify_id"],
        recovered_wait["wait_id"],
    ) == ("DELAYED", "WAITING")

    _force_execution_state(client, recovered.id, "failed")
    recovery.reconcile_once()
    assert _operation_states(
        client,
        recovered_verify["verify_id"],
        recovered_wait["wait_id"],
    ) == ("CANCELLED", "CANCELLED")
