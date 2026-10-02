from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.operator_models import OperatorPrompt
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution, fenced_prompt_request


@pytest.fixture
def procedures_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "procedures"
    directory.mkdir()
    sources = {
        "native_number": "result = Prompt('Enter number', NUM)\nDisplay('Done')\n",
        "native_default": "result = Prompt('Enter number', NUM, Default=2.5, Timeout=60)\nDisplay('Done')\n",
        "native_warning": "result = Prompt('Choose', YES_NO, Timeout=60)\nDisplay(result)\n",
        "native_cancel": "result = Prompt('Finish', OK_CANCEL)\nDisplay('After answer')\n",
    }
    for name, source in sources.items():
        (directory / f"{name}.spell.py").write_text(source, encoding="utf-8")
    return directory


def _respond(client, headers, body, prompt_id):
    response = client.post(f"/api/v1/prompts/{prompt_id}/responses", headers=headers, json=body)
    assert response.status_code == 202, response.text
    return response.json()


def test_native_number_api_retries_invalid_value_and_preserves_fencing_and_typed_result(client, operator_headers, viewer_headers):
    execution_id = create_execution(client, operator_headers, "native_number")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    prompt = snapshot["active_prompt"]
    assert prompt["prompt_profile"] == "spell-lrm244/0.17"
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, snapshot,
                                         value="1e3", idempotency_key="invalid-number", reason="native number")
    assert _respond(client, headers, body, prompt["id"])["attempt"]["outcome"] == "INVALID_VALUE"
    for patch in ({"control_fencing_token": body["control_fencing_token"] + 1},
                  {"session_id": "another-session"}):
        response = client.post(f"/api/v1/prompts/{prompt['id']}/responses", headers=headers,
                               json={**body, **patch, "value": "2.50", "idempotency_key": "forged-" + next(iter(patch))})
        assert response.status_code in {403, 409}, response.text
    viewer = client.post(f"/api/v1/prompts/{prompt['id']}/responses", headers=viewer_headers,
                         json={**body, "value": "2.50", "idempotency_key": "viewer-number"})
    assert viewer.status_code == 403
    current = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    assert current["active_prompt"]["id"] == prompt["id"]
    body = {**body, "value": "2.50", "idempotency_key": "valid-number"}
    first = _respond(client, headers, body, prompt["id"])
    repeated = _respond(client, headers, body, prompt["id"])
    assert first["prompt"]["settlement"]["id"] == repeated["prompt"]["settlement"]["id"]
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert completed["execution"]["variables"]["result"] == 2.5
    assert type(completed["execution"]["variables"]["result"]) is float


def test_native_default_deadline_reaches_worker_as_answered_typed_result(client, operator_headers, viewer_headers):
    execution_id = create_execution(client, operator_headers, "native_default")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    prompt_id = snapshot["active_prompt"]["id"]
    with client.app.state.session_factory() as session:
        session.get(OperatorPrompt, prompt_id).response_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    client.app.state.operator_service.reconcile_prompt_timers()
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert type(completed["execution"]["variables"]["result"]) is float
    assert completed["execution"]["variables"]["result"] == 2.5
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, prompt_id)
        assert prompt.settlement_outcome == "ANSWERED" and prompt.settled_value == "2.5"


@pytest.mark.parametrize("action,state", [("COMMIT", "completed"), ("ABORT", "aborted")])
def test_native_cancel_answer_and_abort_have_different_execution_outcomes(client, operator_headers, viewer_headers, action, state):
    execution_id = create_execution(client, operator_headers, "native_cancel")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, snapshot,
                                         value="CANCEL" if action == "COMMIT" else None,
                                         idempotency_key="native-cancel", reason="cancel distinction", action=action)
    _respond(client, headers, body, snapshot["active_prompt"]["id"])
    finished = wait_for_state(client, execution_id, viewer_headers, {state})
    if action == "COMMIT":
        assert finished["execution"]["variables"]["result"] == "CANCEL"
        assert finished["execution"]["current_step"] == 2
    else:
        assert "result" not in finished["execution"]["variables"]
        assert finished["execution"]["current_step"] == 0


def test_native_warning_survives_worker_recovery_and_remains_answerable(client, operator_headers, viewer_headers, admin_headers):
    execution_id = create_execution(client, operator_headers, "native_warning")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    prompt_id = snapshot["active_prompt"]["id"]
    with client.app.state.session_factory() as session:
        session.get(OperatorPrompt, prompt_id).warning_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    client.app.state.operator_service.reconcile_prompt_timers()
    warned = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    assert warned["active_prompt"]["warning_emitted_at"] is not None
    supervisor = client.app.state.supervisor
    supervisor.issue_command(execution_id, command_type="simulate_crash", expected_revision=warned["execution"]["revision"],
                             actor="pytest-admin", role="admin", reason="native recovery proof",
                             idempotency_key="native-crash", payload={}, correlation_id=None)
    failed = wait_for_state(client, execution_id, viewer_headers, {"recovery_required"})
    supervisor.command_ack_timeout_seconds = 30
    supervisor.issue_command(execution_id, command_type="recover", expected_revision=failed["execution"]["revision"],
                             actor="pytest-operator", role="operator", reason="recover native prompt",
                             idempotency_key="native-recover", payload={}, correlation_id=None)
    recovered = wait_for_state(client, execution_id, viewer_headers, {"prompting"}, timeout=35)
    for field in ("id", "warning_at", "warning_emitted_at", "response_deadline", "prompt_profile"):
        assert recovered["active_prompt"][field] == warned["active_prompt"][field]
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, recovered,
                                         value="YES", idempotency_key="after-recover", reason="answer after warning")
    _respond(client, headers, body, prompt_id)
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert completed["execution"]["variables"]["result"] == "YES"
