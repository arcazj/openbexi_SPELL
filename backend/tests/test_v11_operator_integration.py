from __future__ import annotations

from datetime import datetime, timezone
import threading
import time
import uuid

import pytest
from sqlalchemy import select

import backend.supervisor as supervisor_module
from backend.ir_v11 import ordinary_prompt_id
from backend.models import Event, Execution
from backend.operator_models import OperatorPrompt
from backend.operator_service import OperatorAuthorizationError
from backend.telecommand_runtime_v11 import execute_preflight
from backend.telecommand_v11 import (
    DeterministicScriptedProvider,
    ElementStage,
    ProviderStep,
)

from .conftest import wait_for_state


_PROMPT_SETTINGS = {
    "PROMPT_WARNING_DELAY": 300,
    "PROMPT_RESPONSE_TIMEOUT": 600,
    "NO_CONTROLLER_GRACE": 600,
}


def _start_v11_execution(
    client,
    source: str,
    suffix: str,
    *,
    settings: dict | None = None,
) -> str:
    procedure = client.app.state.catalog.validate_source(
        source, f"v11-operator-{suffix}.spell.py"
    )
    assert procedure.ir_version == "0.11"
    execution = client.app.state.supervisor.create_execution(
        procedure,
        actor="pytest-operator",
        role="operator",
        reason=f"v0.11 operator integration {suffix}",
        idempotency_key=f"v11-operator-{suffix}",
        automatic=True,
        operator_settings=settings or {},
    )
    return execution.id


def _wait_for_open_prompt(
    client,
    execution_id: str,
    headers: dict[str, str],
    *,
    excluding: set[str] | None = None,
    timeout: float = 12,
) -> tuple[dict, dict]:
    excluded = excluding or set()
    deadline = time.monotonic() + timeout
    last: dict = {}
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v1/executions/{execution_id}/snapshot", headers=headers
        )
        assert response.status_code == 200, response.text
        last = response.json()
        prompt = last.get("active_prompt")
        if (
            last["execution"]["state"] == "prompting"
            and prompt is not None
            and prompt["state"] == "OPEN"
            and prompt["id"] not in excluded
        ):
            return last, prompt
        time.sleep(0.05)
    raise AssertionError(f"execution did not open the expected prompt: {last}")


def _acquire_control(
    client,
    operator_headers: dict[str, str],
    execution_id: str,
    snapshot: dict,
    suffix: str,
) -> tuple[dict[str, str], dict]:
    session_id = f"v11-prompt-session-{suffix}"
    client_id = f"v11-prompt-client-{suffix}"
    headers = {
        **operator_headers,
        "X-Spell-Session-Id": session_id,
        "X-Spell-Client-Instance-Key-Id": client_id,
    }
    response = client.post(
        f"/api/v1/executions/{execution_id}/control",
        headers=headers,
        json={
            "action": "ACQUIRE",
            "session_id": session_id,
            "client_instance_key_id": client_id,
            "expected_execution_revision": snapshot["execution"]["revision"],
            "lease_seconds": 60,
            "acknowledgement": "I accept responsibility for this telecommand prompt",
            "idempotency_key": f"v11-prompt-lease-{suffix}",
            "reason": "settle the v0.11 telecommand prompt",
        },
    )
    assert response.status_code == 200, response.text
    return headers, response.json()["control_lease"]


def _answer_prompt(
    client,
    execution_id: str,
    prompt: dict,
    headers: dict[str, str],
    lease: dict,
    suffix: str,
    *,
    value: str = "YES",
) -> dict:
    response = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=headers,
        json={
            "action": "COMMIT",
            "value": value,
            "expected_prompt_revision": prompt["revision"],
            "lease_id": lease["id"],
            "expected_lease_revision": lease["revision"],
            "control_fencing_token": lease["control_fencing_token"],
            "session_id": headers["X-Spell-Session-Id"],
            "client_instance_key_id": headers[
                "X-Spell-Client-Instance-Key-Id"
            ],
            "idempotency_key": f"v11-prompt-answer-{suffix}",
            "reason": "record the human telecommand decision",
        },
    )
    assert response.status_code == 202, response.text
    return response.json()


def _install_dispatch_spy(
    monkeypatch: pytest.MonkeyPatch, *, reject: bool = False
) -> list[dict]:
    real_execute = execute_preflight
    calls: list[dict] = []
    calls_lock = threading.Lock()

    def observed_execute(request, service, preflight, **kwargs):
        with calls_lock:
            calls.append(
                {
                    "request_id": request["request_id"],
                    "confirmation_actor": kwargs.get("confirmation_actor"),
                }
            )
        if not reject:
            return real_execute(request, service, preflight, **kwargs)
        provider = DeterministicScriptedProvider(
            [
                ProviderStep(
                    ElementStage.TRANSPORT,
                    "REJECTED",
                    preflight.plan.elements[0].element_id,
                )
            ]
        )
        return real_execute(
            request,
            service,
            preflight,
            confirmation_actor=kwargs.get("confirmation_actor"),
            provider=provider,
        )

    monkeypatch.setattr(supervisor_module, "execute_preflight", observed_execute)
    return calls


def _forge_prompt_settlement(
    client,
    execution_id: str,
    prompt_id: str,
    *,
    actor: str | None,
    value: str,
    default: str | None = None,
) -> str:
    settlement_id = str(uuid.uuid4())
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, prompt_id)
        assert prompt is not None
        prompt.state = "SETTLED"
        prompt.revision += 1
        if default is not None:
            prompt.default_value = default
        prompt.settlement_id = settlement_id
        prompt.settlement_outcome = "ANSWERED"
        prompt.settled_value = value
        prompt.settled_by = actor
        prompt.settled_at = datetime.now(timezone.utc)
        session.commit()
    client.app.state.supervisor.dispatch_prompt_settlement(
        {
            "prompt": {
                "id": prompt_id,
                "execution_id": execution_id,
                "settlement": {
                    "id": settlement_id,
                    "outcome": "ANSWERED",
                    "value": value,
                },
            },
            "attempt": None,
        }
    )
    return settlement_id


def _force_prompt_timeout(client, prompt_id: str) -> None:
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, prompt_id)
        assert prompt is not None
        prompt.response_deadline = datetime(2000, 1, 1, tzinfo=timezone.utc)
        session.commit()
    assert client.app.state.operator_service.reconcile_prompt_timers() == 1


def test_critical_confirmation_with_inherited_settings_dispatches_after_human_yes(
    client, viewer_headers, operator_headers, monkeypatch
) -> None:
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', Confirm=True)\nLog('after')\n",
        "critical-human-yes",
        settings=_PROMPT_SETTINGS,
    )
    snapshot, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    assert calls == []
    assert prompt["type"] == "YES_NO"
    assert prompt["input_kind"] == "FIXED_CHOICE"
    assert prompt["options"] == ["YES", "NO"]
    assert prompt["default"] == "NO"
    assert prompt["settings"] == _PROMPT_SETTINGS
    assert prompt["warning_at"] is not None
    assert prompt["response_deadline"] is not None
    assert prompt["no_controller_deadline"] is not None

    headers, lease = _acquire_control(
        client, operator_headers, execution_id, snapshot, "critical-human-yes"
    )
    _answer_prompt(
        client,
        execution_id,
        prompt,
        headers,
        lease,
        "critical-human-yes",
    )
    wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=12)

    assert len(calls) == 1
    assert calls[0]["confirmation_actor"].startswith("operator-")
    with client.app.state.session_factory() as session:
        stored = session.get(OperatorPrompt, prompt["id"])
        assert stored is not None
        assert stored.settled_by == "pytest-operator"
        assert stored.settlement_delivered_at is not None


@pytest.mark.parametrize(
    ("default", "actor", "suffix"),
    [
        ("YES", "pytest-operator", "forged-default-yes"),
        ("NO", "operator-reconciler", "forged-reconciler-yes"),
    ],
)
def test_forged_critical_confirmation_cannot_dispatch(
    client,
    viewer_headers,
    monkeypatch,
    default: str,
    actor: str,
    suffix: str,
) -> None:
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', Confirm=True)\n",
        suffix,
    )
    _, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    _forge_prompt_settlement(
        client,
        execution_id,
        prompt["id"],
        actor=actor,
        value="YES",
        default=default,
    )
    failed = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}, timeout=12
    )

    assert calls == []
    assert failed["execution"]["current_step"] == 0
    with client.app.state.session_factory() as session:
        requested = session.scalar(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "procedure.telecommand_requested",
            )
        )
        assert requested is None


def test_confirmation_timer_default_no_fails_without_dispatch(
    client, viewer_headers, monkeypatch
) -> None:
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', Confirm=True)\n",
        "confirmation-timer-no",
        settings={"PROMPT_RESPONSE_TIMEOUT": 600},
    )
    _, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    assert prompt["default"] == "NO"
    _force_prompt_timeout(client, prompt["id"])
    failed = wait_for_state(client, execution_id, viewer_headers, {"failed"}, timeout=12)

    assert calls == []
    assert failed["execution"]["current_step"] == 0
    with client.app.state.session_factory() as session:
        stored = session.get(OperatorPrompt, prompt["id"])
        assert stored is not None
        assert stored.settlement_outcome == "ANSWERED"
        assert stored.settled_value == "NO"
        assert stored.settled_by == "operator-reconciler"
        assert stored.settlement_delivered_at is not None


def test_default_failure_prompt_with_inherited_settings_continues_after_human_yes(
    client, viewer_headers, operator_headers, monkeypatch
) -> None:
    calls = _install_dispatch_spy(monkeypatch, reject=True)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', OnFailure=CANCEL)\nLog('after')\n",
        "failure-human-yes",
        settings=_PROMPT_SETTINGS,
    )
    snapshot, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    assert len(calls) == 1
    assert prompt["question"].startswith(
        "Continue procedure after unsuccessful deterministic simulator "
        "telecommand result "
    )
    assert prompt["options"] == ["YES", "NO"]
    assert prompt["default"] == "NO"
    assert prompt["settings"] == _PROMPT_SETTINGS

    headers, lease = _acquire_control(
        client, operator_headers, execution_id, snapshot, "failure-human-yes"
    )
    _answer_prompt(
        client,
        execution_id,
        prompt,
        headers,
        lease,
        "failure-human-yes",
    )
    completed = wait_for_state(
        client, execution_id, viewer_headers, {"completed"}, timeout=12
    )

    assert completed["execution"]["current_step"] == 2
    with client.app.state.session_factory() as session:
        stored = session.get(OperatorPrompt, prompt["id"])
        assert stored is not None
        assert stored.settled_by == "pytest-operator"
        assert stored.settlement_delivered_at is not None
        settled = session.scalar(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "procedure.telecommand_settled",
            )
        )
        assert settled is not None
        assert settled.payload["successful"] is False


def test_failure_prompt_timer_default_no_cannot_continue(
    client, viewer_headers, monkeypatch
) -> None:
    calls = _install_dispatch_spy(monkeypatch, reject=True)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', OnFailure=CANCEL)\nLog('must not run')\n",
        "failure-timer-no",
        settings={"PROMPT_RESPONSE_TIMEOUT": 600},
    )
    _, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    _force_prompt_timeout(client, prompt["id"])
    failed = wait_for_state(client, execution_id, viewer_headers, {"failed"}, timeout=12)

    assert len(calls) == 1
    assert failed["execution"]["current_step"] == 0
    with client.app.state.session_factory() as session:
        stored = session.get(OperatorPrompt, prompt["id"])
        assert stored is not None
        assert stored.settled_value == "NO"
        assert stored.settled_by == "operator-reconciler"
        completed = session.scalar(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "step.completed",
            )
        )
        assert completed is None


@pytest.mark.parametrize(
    ("actor", "suffix"),
    [
        ("operator-reconciler", "reconciler"),
        (None, "null-actor"),
        ("", "empty-actor"),
        (" ", "whitespace-actor"),
    ],
)
def test_forged_nonhuman_yes_cannot_commit_failure_continuation(
    client, viewer_headers, monkeypatch, actor: str | None, suffix: str
) -> None:
    calls = _install_dispatch_spy(monkeypatch, reject=True)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', OnFailure=CANCEL)\nLog('must not run')\n",
        f"failure-forged-{suffix}",
    )
    _, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)

    _forge_prompt_settlement(
        client,
        execution_id,
        prompt["id"],
        actor=actor,
        value="YES",
    )
    failed = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}, timeout=12
    )

    assert len(calls) == 1
    assert failed["execution"]["current_step"] == 0
    with client.app.state.session_factory() as session:
        completed = session.scalar(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "step.completed",
            )
        )
        assert completed is None


def test_same_second_confirmed_failure_recovery_selects_failure_prompt(
    client, viewer_headers, operator_headers, monkeypatch
) -> None:
    _install_dispatch_spy(monkeypatch, reject=True)
    execution_id = _start_v11_execution(
        client,
        "Send(command='CMDNAME', Confirm=True, OnFailure=CANCEL)\n",
        "same-second-recovery",
    )
    snapshot, confirmation = _wait_for_open_prompt(
        client, execution_id, viewer_headers
    )
    headers, lease = _acquire_control(
        client, operator_headers, execution_id, snapshot, "same-second-recovery"
    )
    _answer_prompt(
        client,
        execution_id,
        confirmation,
        headers,
        lease,
        "same-second-confirmation",
    )
    _, failure = _wait_for_open_prompt(
        client,
        execution_id,
        viewer_headers,
        excluding={confirmation["id"]},
    )

    with client.app.state.session_factory() as session:
        stored_execution = session.get(Execution, execution_id)
        stored_confirmation = session.get(OperatorPrompt, confirmation["id"])
        stored_failure = session.get(OperatorPrompt, failure["id"])
        assert stored_execution is not None
        assert stored_confirmation is not None
        assert stored_failure is not None
        same_second = stored_confirmation.settled_at.replace(microsecond=0)
        stored_confirmation.settled_at = same_second
        stored_failure.state = "SETTLED"
        stored_failure.revision += 1
        stored_failure.settlement_id = str(uuid.uuid4())
        stored_failure.settlement_outcome = "ANSWERED"
        stored_failure.settled_value = "YES"
        stored_failure.settled_by = "pytest-operator"
        stored_failure.settled_at = same_second
        session.flush()

        selected = client.app.state.supervisor._v11_resume_prompt(
            session, stored_execution
        )
        assert selected is not None
        assert selected.id == failure["id"]
        session.rollback()


def test_inspection_edit_cannot_redirect_a_future_command_selector(
    client, viewer_headers, operator_headers
) -> None:
    execution_id = _start_v11_execution(
        client,
        "tc_name: str = 'CMDNAME'\n"
        "Prompt('Proceed?', type='YES_NO')\n"
        "Send(command=tc_name)\n",
        "inspection-selector-immutable",
    )
    snapshot, prompt = _wait_for_open_prompt(
        client, execution_id, viewer_headers
    )
    headers, lease = _acquire_control(
        client,
        operator_headers,
        execution_id,
        snapshot,
        "inspection-selector-immutable",
    )

    with pytest.raises(OperatorAuthorizationError, match="telecommand dependencies"):
        client.app.state.operator_service.edit_inspection(
            execution_id,
            path="variables.tc_name",
            scope="LOCAL_VARIABLE",
            declared_type="STRING",
            value="CMD2",
            expected_value_revision=snapshot["execution"]["revision"],
            expected_execution_revision=snapshot["execution"]["revision"],
            actor="pytest-operator",
            lease_id=lease["id"],
            expected_lease_revision=lease["revision"],
            control_fencing_token=lease["control_fencing_token"],
            holder_session_id=headers["X-Spell-Session-Id"],
            client_instance_key_id=headers[
                "X-Spell-Client-Instance-Key-Id"
            ],
            idempotency_key="inspection-selector-immutable",
            reason="attempt to redirect a future command selector",
        )

    with client.app.state.session_factory() as session:
        stored = session.get(Execution, execution_id)
        assert stored is not None
        assert stored.variables["tc_name"] == "CMDNAME"

    _answer_prompt(
        client,
        execution_id,
        prompt,
        headers,
        lease,
        "inspection-selector-immutable",
    )
    completed = wait_for_state(
        client, execution_id, viewer_headers, {"completed"}, timeout=12
    )
    assert completed["execution"]["current_step"] == 3


def test_ordinary_prompt_recovery_is_retained_before_v11_send(
    client, viewer_headers, operator_headers
) -> None:
    execution_id = _start_v11_execution(
        client,
        "Prompt('Proceed?', type='YES_NO')\nSend(command='CMDNAME')\n",
        "ordinary-prompt-recovery",
    )
    first, prompt = _wait_for_open_prompt(client, execution_id, viewer_headers)
    assert prompt["id"] == ordinary_prompt_id(execution_id, 0)

    client.app.state.supervisor.issue_command(
        execution_id=execution_id,
        command_type="simulate_crash",
        expected_revision=first["execution"]["revision"],
        idempotency_key="v11-ordinary-prompt-crash",
        actor="pytest-admin",
        role="admin",
        reason="exercise ordinary v0.11 prompt recovery",
        correlation_id=None,
        payload={},
    )
    recovery_required = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}, timeout=12
    )
    assert recovery_required["active_prompt"]["id"] == prompt["id"]

    client.app.state.supervisor.command_ack_timeout_seconds = 30.0
    client.app.state.supervisor.issue_command(
        execution_id=execution_id,
        command_type="recover",
        expected_revision=recovery_required["execution"]["revision"],
        idempotency_key="v11-ordinary-prompt-recover",
        actor="pytest-operator",
        role="operator",
        reason="restart at the ordinary prompt checkpoint",
        correlation_id=None,
        payload={},
    )
    replayed, replayed_prompt = _wait_for_open_prompt(
        client, execution_id, viewer_headers, timeout=35
    )
    assert replayed_prompt["id"] == prompt["id"]
    assert replayed["execution"]["current_step"] == 0

    headers, lease = _acquire_control(
        client, operator_headers, execution_id, replayed, "ordinary-recovery"
    )
    _answer_prompt(
        client,
        execution_id,
        replayed_prompt,
        headers,
        lease,
        "ordinary-recovery",
    )
    completed = wait_for_state(
        client, execution_id, viewer_headers, {"completed"}, timeout=12
    )
    assert completed["execution"]["current_step"] == 2
