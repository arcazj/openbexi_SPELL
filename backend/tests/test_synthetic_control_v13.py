from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import time
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from backend.models import Execution
from backend.operator_models import ControllerLease, OperatorAuditEvent, OperatorCommand
from backend.operator_service import OperatorService
from backend.synthetic_control import CompatibilityCommand, OPERATIONS, SyntheticControl, profile

PREFIX = "/api/v1/legacy-control"


@pytest.fixture
def procedures_dir(procedures_dir):
    (procedures_dir / "v13.spell.py").write_text(
        'Log("before wait")\nWait(3.0)\nPrompt("Done?", type="YES_NO")\n', encoding="utf-8")
    return procedures_dir


@pytest.fixture
def controlled(client, operator_headers):
    service, supervisor = client.app.state.operator_service, client.app.state.supervisor
    execution = supervisor.create_execution(client.app.state.catalog.get("v13"), actor="pytest-operator",
        role="operator", reason="v13 control qualification", idempotency_key="v13-create", automatic=False)
    # Acquire control before the worker starts its three-second wait. The
    # preparation PAUSE still uses the real fenced compatibility operation.
    lease = service.acquire_control(execution.id, expected_execution_revision=execution.revision,
        actor="pytest-operator", holder_session_id="v13-session", client_instance_key_id="v13-client",
        lease_seconds=120, idempotency_key="v13-lease", reason="qualification controller")["control_lease"]
    supervisor.issue_command(execution.id, command_type="start",
        expected_revision=supervisor.get_execution(execution.id).revision, idempotency_key="v13-start",
        actor="pytest-operator", role="operator", reason="start owned control qualification", correlation_id=None, payload={})
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        current = supervisor.get_execution(execution.id)
        if current.state == "waiting":
            break
        time.sleep(0.02)
    assert current.state == "waiting"
    assert service.get_execution_projection(execution.id)["state"] == "WAITING"
    current = supervisor.get_execution(execution.id)
    body = dict(operation="STEP", operation_id=str(uuid.uuid4()), source_digest=current.procedure_hash,
        expected_execution_revision=current.revision, reason="exercise bounded control", lease_id=lease["id"],
        expected_lease_revision=lease["revision"], control_fencing_token=lease["control_fencing_token"],
        session_id="v13-session", client_instance_key_id="v13-client")
    headers = {**operator_headers, "X-Spell-Session-Id": "v13-session", "X-Spell-Client-Instance-Key-Id": "v13-client"}
    if current.state != "paused":
        body["operation"] = "PAUSE"
        preparation = (execution.id, body, headers)
        response = submit(client, preparation)
        assert response.status_code == 202, response.text
        assert settled(client, preparation)["command"]["state"] == "SETTLED"
        body.update(operation="STEP", operation_id=str(uuid.uuid4()),
                    expected_execution_revision=supervisor.get_execution(execution.id).revision)
    return execution.id, body, headers


def submit(client, controlled, **changes):
    execution_id, body, headers = controlled
    return client.post(f"{PREFIX}/executions/{execution_id}/operations", json={**body, **changes}, headers=headers)


def receipt(client, controlled):
    execution_id, body, headers = controlled
    return client.get(f"{PREFIX}/executions/{execution_id}/operations/{body['operation_id']}", headers=headers)


def settled(client, controlled):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = receipt(client, controlled)
        assert response.status_code == 200, response.text
        result = response.json()
        if result["command"]["state"] in {"SETTLED", "REJECTED", "FAILED", "CANCELLED", "SUPERSEDED"}:
            return result
        time.sleep(0.02)
    raise AssertionError("operation did not settle")


def test_profile_has_no_remote_endpoint_or_unbounded_command(client, viewer_headers):
    assert client.get(PREFIX + "/profile").status_code == 401
    value = client.get(PREFIX + "/profile", headers=viewer_headers).json()
    assert value == profile()
    assert value["commands"] == OPERATIONS
    assert value["legacy_protocol_implemented"] is False
    assert value["automatic_replacement_commands"] is False
    assert "endpoint" not in value and "credentials" not in value


@pytest.mark.parametrize("operation", ["STEP", "RUN", "ABORT", "RETURN_TO_READ_ONLY"])
def test_real_supervisor_settles_control_and_rollback(client, controlled, operation):
    controlled[1]["operation"] = operation
    response = submit(client, controlled)
    assert response.status_code == 202, response.text
    result = settled(client, controlled)
    assert result["command"]["state"] == "SETTLED", (result["command"]["result"], result["command"]["rejection_code"])
    assert result["command"]["actor"] == "pytest-operator"
    assert f"[v13 {operation}]" in result["command"]["reason"]
    assert result["read_only_confirmed"] is (operation == "RETURN_TO_READ_ONLY")
    assert result["legacy_system_qualified"] is False
    assert result["source_digest"] == controlled[1]["source_digest"]


def test_run_then_pause_retains_audited_safe_point(client, controlled):
    controlled[1]["operation"] = "RUN"
    assert submit(client, controlled).status_code == 202
    assert settled(client, controlled)["command"]["state"] == "SETTLED"
    time.sleep(0.1)
    current = client.app.state.supervisor.get_execution(controlled[0])
    controlled[1].update(operation="PAUSE", operation_id=str(uuid.uuid4()), expected_execution_revision=current.revision)
    assert submit(client, controlled).status_code == 202
    assert settled(client, controlled)["command"]["state"] == "SETTLED"
    assert client.app.state.supervisor.get_execution(controlled[0]).state == "paused"


def test_retry_conflict_reconnect_and_service_restart_use_one_durable_outcome(client, controlled):
    assert submit(client, controlled).status_code == 202
    first = settled(client, controlled)
    duplicate = submit(client, controlled)
    assert duplicate.status_code == 202 and duplicate.json() == first
    assert submit(client, controlled, reason="different intent").status_code == 409
    new_service = OperatorService(client.app.state.operator_service.session_factory, client.app.state.catalog)
    restarted = SyntheticControl(new_service, client.app.state.supervisor)
    assert restarted.receipt(controlled[0], uuid.UUID(controlled[1]["operation_id"])) == first
    with new_service.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(OperatorCommand).where(
            OperatorCommand.execution_id == controlled[0],
            OperatorCommand.idempotency_key == "compat-v13:" + controlled[1]["operation_id"])) == 1
        assert session.scalar(select(func.count()).select_from(OperatorAuditEvent).where(
            OperatorAuditEvent.execution_id == controlled[0])) > 0


def test_competing_duplicate_submissions_do_not_duplicate_effects(client, controlled):
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: submit(client, controlled), range(4)))
    assert all(response.status_code == 202 for response in responses), [r.text for r in responses]
    assert len({response.json()["command"]["id"] for response in responses}) == 1
    assert settled(client, controlled)["command"]["state"] == "SETTLED"


@pytest.mark.parametrize("field,value,status", [
    ("source_digest", "0" * 64, 409), ("expected_execution_revision", 999999, 409),
    ("expected_lease_revision", 999999, 409), ("control_fencing_token", 999999, 403),
    ("session_id", "different-session", 403), ("client_instance_key_id", "different-client", 403),
    ("operation", "KILL", 422), ("operation", "Send", 422), ("endpoint", "http://example.invalid", 422),
    ("source_digest", "invalid", 422), ("reason", "  ", 422), ("reason", "x" * 901, 422),
    ("expected_execution_revision", True, 422), ("control_fencing_token", "1", 422),
])
def test_fail_closed_before_acceptance(client, controlled, field, value, status):
    response = submit(client, controlled, **{field: value})
    assert response.status_code == status, response.text
    assert receipt(client, controlled).status_code == 404


def test_authentication_role_spoofing_and_actor_binding(client, controlled, viewer_headers, admin_headers):
    path = f"{PREFIX}/executions/{controlled[0]}/operations"
    assert client.post(path, json=controlled[1]).status_code == 401
    assert client.post(path, json=controlled[1], headers={**viewer_headers, "X-Role": "admin"}).status_code == 403
    assert client.post(path, json=controlled[1], headers={**controlled[2], **admin_headers}).status_code == 403
    assert receipt(client, controlled).status_code == 404


def test_expired_lease_cannot_control(client, controlled):
    service = client.app.state.operator_service
    with service._lock, service.session_factory() as session:
        lease = session.get(ControllerLease, controlled[1]["lease_id"])
        lease.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    assert submit(client, controlled).status_code == 403
    assert receipt(client, controlled).status_code == 404


def test_non_simulator_context_cannot_control(client, controlled):
    with client.app.state.operator_service.session_factory() as session:
        session.get(Execution, controlled[0]).context_id = "not-approved"
        session.commit()
    assert submit(client, controlled).status_code == 403


def test_unfenced_ir_is_rejected_before_acceptance(client, controlled):
    with client.app.state.operator_service.session_factory() as session:
        session.get(Execution, controlled[0]).ir_version = "0.3"
        session.commit()
    assert submit(client, controlled).status_code == 422


def test_invalid_state_is_a_retained_rejected_operation(client, controlled):
    response = submit(client, controlled, operation="PAUSE")
    assert response.status_code == 202
    assert response.json()["command"]["state"] == "REJECTED"
    assert response.json()["read_only_confirmed"] is False


def test_rollback_does_not_claim_completion_before_supervisor_settlement(client, controlled, monkeypatch):
    original = client.app.state.supervisor.dispatch_operator_command
    monkeypatch.setattr(client.app.state.supervisor, "dispatch_operator_command", lambda command: command)
    controlled[1]["operation"] = "RETURN_TO_READ_ONLY"
    result = submit(client, controlled).json()
    assert result["rollback_pending"] is True and result["read_only_confirmed"] is False
    original(result["command"])
    assert settled(client, controlled)["read_only_confirmed"] is True


def test_database_failure_never_fabricates_a_receipt(client, controlled, monkeypatch):
    def fail(**_):
        raise RuntimeError("database unavailable")
    monkeypatch.setattr(client.app.state.operator_service, "accept_operator_command", fail)
    with pytest.raises(RuntimeError, match="database unavailable"):
        submit(client, controlled)
    assert receipt(client, controlled).status_code == 404


def test_readback_is_scoped_to_execution_and_operation(client, controlled, viewer_headers):
    assert submit(client, controlled).status_code == 202
    assert client.get(f"{PREFIX}/executions/{controlled[0]}/operations/{controlled[1]['operation_id']}",
                      headers=viewer_headers).status_code == 200
    assert client.get(f"{PREFIX}/executions/{controlled[0]}/operations/{uuid.uuid4()}", headers=viewer_headers).status_code == 404


def test_bounded_parallel_readback_has_one_stable_outcome(client, controlled):
    assert submit(client, controlled).status_code == 202
    expected = settled(client, controlled)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: receipt(client, controlled), range(128)))
    assert time.monotonic() - started < 30
    assert all(result.status_code == 200 and result.json() == expected for result in results)
