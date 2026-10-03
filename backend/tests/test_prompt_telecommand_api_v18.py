from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend.models import Event
from backend.operator_models import OperatorPrompt
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution, fenced_prompt_request
from backend.tests.test_v11_operator_integration import _install_dispatch_spy, _wait_for_open_prompt, _answer_prompt, _acquire_control


@pytest.fixture
def procedures_dir(procedures_dir):
    sources = {
        "branch": "item = BuildTC('CMDNAME')\nanswer = Prompt('Proceed?', YES_NO)\nif answer == 'YES' and 2 ** 3 == 8:\n    Send(command=item)\nDisplay(answer)\n",
        "default_yes": "answer = Prompt('Proceed?', YES_NO, Default=YES, Timeout=60)\nif answer == 'YES':\n    Send(command='CMDNAME')\n",
        "default_no": "answer = Prompt('Proceed?', YES_NO, Default=NO, Timeout=60)\nif answer == 'YES':\n    Send(command='CMDNAME')\n",
        "cancel": "answer = Prompt('Proceed?', OK_CANCEL)\nSend(command='CMDNAME')\n",
        "confirmation": "answer = Prompt('Proceed?', YES_NO, Timeout=60)\nif answer == 'YES':\n    Send(command='CMDNAME', Confirm=True)\n",
        "default_confirmation": "answer = Prompt('Proceed?', YES_NO, Default=YES, Timeout=60)\nSend(command='CMDNAME', Confirm=True)\n",
        "failure": "answer = Prompt('Proceed?', YES_NO)\nSend(command='CMDNAME', OnFailure=CANCEL)\nDisplay(answer)\n",
    }
    for name, source in sources.items():
        (procedures_dir / f"v18_{name}.spell.py").write_text(source, encoding="utf-8")
    return procedures_dir


def _finish_answer(client, execution_id, snapshot, operator_headers, answer="YES", action="COMMIT"):
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, snapshot,
        value=answer, action=action, idempotency_key="v18-native", reason="bounded native command test")
    response = client.post(f"/api/v1/prompts/{snapshot['active_prompt']['id']}/responses", headers=headers, json=body)
    assert response.status_code == 202, response.text
    return headers, body


def _expire(client, prompt_id, field="response_deadline"):
    with client.app.state.session_factory() as session:
        setattr(session.get(OperatorPrompt, prompt_id), field, datetime.now(timezone.utc) - timedelta(seconds=1))
        session.commit()
    client.app.state.operator_service.reconcile_prompt_timers()


def _counts(client, execution_id):
    with client.app.state.session_factory() as session:
        events = session.scalars(select(Event).where(Event.execution_id == execution_id)).all()
        return {kind: sum(event.event_type == kind for event in events) for kind in (
            "procedure.telecommand_requested", "procedure.telecommand_result", "procedure.telecommand_settled")}


@pytest.mark.parametrize("answer,count", [("YES", 1), ("NO", 0)])
def test_native_answer_reaches_real_built_send_only_in_selected_branch(client, operator_headers, viewer_headers, monkeypatch, answer, count):
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v18_branch")
    snapshot, _ = _wait_for_open_prompt(client, execution_id, viewer_headers)
    assert snapshot["execution"]["procedure_subset_version"] == "spell-lrm244-conformance/0.18"
    _finish_answer(client, execution_id, snapshot, operator_headers, answer)
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert completed["execution"]["variables"]["answer"] == answer
    assert len(calls) == count and set(_counts(client, execution_id).values()) == {count}


@pytest.mark.parametrize("answer,count", [("YES", 1), ("NO", 0)])
def test_native_timeout_default_is_typed_branch_input_and_not_implicit_confirmation(client, operator_headers, viewer_headers, monkeypatch, answer, count):
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v18_default_" + answer.lower())
    _, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)
    _expire(client, prompt["id"])
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert completed["execution"]["variables"]["answer"] == answer
    assert len(calls) == count and set(_counts(client, execution_id).values()) == {count}


@pytest.mark.parametrize("action,state,count", [("COMMIT", "completed", 1), ("ABORT", "aborted", 0)])
def test_native_cancel_is_an_answer_but_abort_prevents_later_send(client, operator_headers, viewer_headers, monkeypatch, action, state, count):
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v18_cancel")
    snapshot, _ = _wait_for_open_prompt(client, execution_id, viewer_headers)
    _finish_answer(client, execution_id, snapshot, operator_headers, "CANCEL" if action == "COMMIT" else None, action)
    finished = wait_for_state(client, execution_id, viewer_headers, {state}, timeout=15)
    assert len(calls) == count and set(_counts(client, execution_id).values()) == {count}
    assert (finished["execution"]["variables"].get("answer") == "CANCEL") is (action == "COMMIT")


def test_recovered_warning_then_native_yes_still_requires_separate_fenced_confirmation(client, operator_headers, viewer_headers, monkeypatch):
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v18_confirmation")
    snapshot, native = _wait_for_open_prompt(client, execution_id, viewer_headers)
    _expire(client, native["id"], "warning_at")
    snapshot, native = _wait_for_open_prompt(client, execution_id, viewer_headers)
    supervisor = client.app.state.supervisor
    supervisor.issue_command(execution_id, command_type="simulate_crash", expected_revision=snapshot["execution"]["revision"],
        actor="pytest-admin", role="admin", reason="crash before intent", idempotency_key="v18-crash", payload={}, correlation_id=None)
    stopped = wait_for_state(client, execution_id, viewer_headers, {"recovery_required"})
    assert calls == [] and set(_counts(client, execution_id).values()) == {0}
    supervisor.command_ack_timeout_seconds = 30
    supervisor.issue_command(execution_id, command_type="recover", expected_revision=stopped["execution"]["revision"],
        actor="pytest-operator", role="operator", reason="recover native gate", idempotency_key="v18-recover", payload={}, correlation_id=None)
    recovered, same = _wait_for_open_prompt(client, execution_id, viewer_headers, timeout=35)
    assert same["id"] == native["id"] and same["warning_emitted_at"] == native["warning_emitted_at"]
    headers, native_body = _finish_answer(client, execution_id, recovered, operator_headers)
    current, confirmation = _wait_for_open_prompt(client, execution_id, viewer_headers, excluding={native["id"]})
    assert confirmation["default"] == "NO" and confirmation["prompt_profile"] is None and calls == []
    # The checkpoint now contains a native return and the derived Send guard.
    # Recovery must map original IR indexes and select the exact TC prompt.
    supervisor.issue_command(execution_id, command_type="simulate_crash", expected_revision=current["execution"]["revision"],
        actor="pytest-admin", role="admin", reason="crash at command confirmation", idempotency_key="v18-confirm-crash", payload={}, correlation_id=None)
    stopped = wait_for_state(client, execution_id, viewer_headers, {"recovery_required"})
    supervisor.issue_command(execution_id, command_type="recover", expected_revision=stopped["execution"]["revision"],
        actor="pytest-operator", role="operator", reason="recover exact command confirmation", idempotency_key="v18-confirm-recover", payload={}, correlation_id=None)
    current, same_confirmation = _wait_for_open_prompt(client, execution_id, viewer_headers, excluding={native["id"]}, timeout=35)
    assert same_confirmation["id"] == confirmation["id"] and calls == []
    assert current["execution"]["variables"]["answer"] == "YES"
    repeated = client.post(f"/api/v1/prompts/{native['id']}/responses", headers=headers, json=native_body)
    assert repeated.status_code == 202 and calls == []
    for patch in ({"control_fencing_token": native_body["control_fencing_token"] + 1}, {"expected_prompt_revision": confirmation["revision"] + 1}):
        forged = {**native_body, "expected_prompt_revision": confirmation["revision"], **patch, "idempotency_key": "forged-" + next(iter(patch))}
        response = client.post(f"/api/v1/prompts/{confirmation['id']}/responses", headers=headers, json=forged)
        if "expected_prompt_revision" in patch:
            assert response.status_code == 202, response.text
            assert response.json()["attempt"]["outcome"] == "STALE_PROMPT_REVISION"
            assert response.json()["prompt"]["state"] == "OPEN"
        else:
            assert response.status_code in {403, 409}, response.text
    assert calls == []
    correct = {**native_body, "expected_prompt_revision": confirmation["revision"], "idempotency_key": "v18-confirmation"}
    response = client.post(f"/api/v1/prompts/{confirmation['id']}/responses", headers=headers, json=correct)
    assert response.status_code == 202, response.text
    wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert len(calls) == 1 and calls[0]["confirmation_actor"].startswith("operator-")
    assert set(_counts(client, execution_id).values()) == {1}


def test_native_default_yes_cannot_replace_command_confirmation_default_no(client, viewer_headers, monkeypatch):
    calls = _install_dispatch_spy(monkeypatch)
    supervisor = client.app.state.supervisor
    execution = supervisor.create_execution(client.app.state.catalog.get("v18_default_confirmation"), actor="pytest-operator", role="operator",
        reason="separate defaults", idempotency_key="default-confirmation", automatic=True, operator_settings={"PROMPT_RESPONSE_TIMEOUT": 60})
    _, native = _wait_for_open_prompt(client, execution.id, viewer_headers)
    _expire(client, native["id"])
    _, confirmation = _wait_for_open_prompt(client, execution.id, viewer_headers, excluding={native["id"]})
    assert confirmation["default"] == "NO" and calls == []
    _expire(client, confirmation["id"])
    wait_for_state(client, execution.id, viewer_headers, {"failed"}, timeout=15)
    assert calls == [] and set(_counts(client, execution.id).values()) == {0}


def test_native_workflow_failure_continuation_does_not_redispatch(client, operator_headers, viewer_headers, monkeypatch):
    calls = _install_dispatch_spy(monkeypatch, reject=True)
    execution_id = create_execution(client, operator_headers, "v18_failure")
    snapshot, native = _wait_for_open_prompt(client, execution_id, viewer_headers)
    headers, body = _finish_answer(client, execution_id, snapshot, operator_headers)
    _, failure = _wait_for_open_prompt(client, execution_id, viewer_headers, excluding={native["id"]})
    assert "unsuccessful" in failure["question"] and len(calls) == 1
    response = client.post(f"/api/v1/prompts/{failure['id']}/responses", headers=headers,
        json={**body, "expected_prompt_revision": failure["revision"], "idempotency_key": "v18-failure-continue"})
    assert response.status_code == 202, response.text
    wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert len(calls) == 1 and set(_counts(client, execution_id).values()) == {1}


def test_native_deadline_and_response_race_produces_one_branch_and_at_most_one_send(client, operator_headers, viewer_headers, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v18_default_yes")
    snapshot, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, snapshot,
        value="NO", idempotency_key="racing-answer", reason="native deadline winner")
    with client.app.state.session_factory() as session:
        session.get(OperatorPrompt, prompt["id"]).response_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    barrier = threading.Barrier(2)
    def answer():
        barrier.wait(timeout=5)
        return client.post(f"/api/v1/prompts/{prompt['id']}/responses", headers=headers, json=body)
    def timeout():
        barrier.wait(timeout=5)
        return client.app.state.operator_service.reconcile_prompt_timers()
    with ThreadPoolExecutor(max_workers=2) as pool:
        response_future, timer_future = pool.submit(answer), pool.submit(timeout)
        response = response_future.result(timeout=10)
        timer_future.result(timeout=10)
    assert response.status_code == 202, response.text
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    with client.app.state.session_factory() as session:
        stored = session.get(OperatorPrompt, prompt["id"])
        assert stored.settlement_outcome == "ANSWERED" and stored.settled_value in {"YES", "NO"}
        winner = stored.settled_value
    assert completed["execution"]["variables"]["answer"] == winner
    count = int(winner == "YES")
    assert len(calls) == count and set(_counts(client, execution_id).values()) == {count}
