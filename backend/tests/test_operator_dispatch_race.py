from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from backend.models import Execution
from backend.operator_models import OperatorAuditEvent
from backend.operator_service import OperatorConflictError, OperatorStaleWorkerError
from backend.tests.test_v06_operator_workspace import (
    _acquire,
    _command_proof,
    _paused_execution,
)


def _accepted(client):
    execution, service = _paused_execution(client, suffix="dispatch-race")
    lease = _acquire(service, execution)
    command = service.accept_operator_command(
        execution.id, "RUN", execution.revision, "dispatch-race-command",
        role="operator", reason="race the background dispatcher", payload={},
        **_command_proof(lease),
    )
    return execution, service, command


def _advance(transition, command, state):
    if state in {"APPLYING", "RECONCILING", "SETTLED"}:
        transition(command["id"], "APPLYING")
    if state in {"RECONCILING", "SETTLED"}:
        transition(command["id"], "RECONCILING")
    return transition(command["id"], state)


def _audits(client, command_id):
    with client.app.state.session_factory() as session:
        return session.scalar(select(func.count()).select_from(OperatorAuditEvent).where(
            OperatorAuditEvent.aggregate_id == command_id
        ))


@pytest.mark.parametrize("state", [
    "WAITING_SAFE_POINT", "APPLYING", "RECONCILING", "SETTLED",
    "CANCELLED", "SUPERSEDED", "FAILED",
])
def test_conditional_dispatch_preserves_advanced_durable_command(client, state):
    _, service, accepted = _accepted(client)
    advanced = _advance(service.transition_operator_command, accepted, state)
    audits = _audits(client, accepted["id"])
    result = service.transition_operator_command(
        accepted["id"], "WAITING_SAFE_POINT", expected_state="ACCEPTED",
        result={"must_not_replace": True},
    )
    assert result == advanced
    assert _audits(client, accepted["id"]) == audits


@pytest.mark.parametrize("state", [
    "APPLYING", "RECONCILING", "SETTLED", "CANCELLED", "SUPERSEDED", "FAILED",
])
def test_background_application_wins_before_immediate_dispatch(client, monkeypatch, state):
    _, service, accepted = _accepted(client)
    supervisor = client.app.state.supervisor
    transition = service.transition_operator_command
    entered = threading.Event()
    advanced_committed = threading.Event()
    results, errors = [], []

    def delayed_transition(command_id, target, **kwargs):
        assert kwargs["expected_state"] == "ACCEPTED"
        entered.set()
        assert advanced_committed.wait(timeout=3)
        return transition(command_id, target, **kwargs)

    def forbid_application(*_args, **_kwargs):
        raise AssertionError("stale dispatch must not apply or resend")

    def dispatch():
        try:
            results.append(supervisor.dispatch_operator_command(accepted))
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(service, "transition_operator_command", delayed_transition)
    monkeypatch.setattr(supervisor, "_begin_operator_command_application", forbid_application)
    monkeypatch.setattr(supervisor, "_queue_operator_command_at_safe_point", forbid_application)
    thread = threading.Thread(target=dispatch, daemon=True)
    thread.start()
    assert entered.wait(timeout=3)
    advanced = _advance(transition, accepted, state)
    audits = _audits(client, accepted["id"])
    advanced_committed.set()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert results == [advanced]
    assert _audits(client, accepted["id"]) == audits


def test_conditional_transition_checks_epoch_before_returning_advanced_state(client):
    execution, service, accepted = _accepted(client)
    advanced = _advance(service.transition_operator_command, accepted, "SETTLED")
    with client.app.state.session_factory() as session:
        session.get(Execution, execution.id).worker_generation = 2
        session.commit()
    with pytest.raises(OperatorStaleWorkerError):
        service.transition_operator_command(
            accepted["id"], "WAITING_SAFE_POINT", expected_state="ACCEPTED",
            worker_generation=1,
        )
    assert service.transition_operator_command(
        accepted["id"], "WAITING_SAFE_POINT", expected_state="ACCEPTED",
        worker_generation=2,
    ) == advanced


def test_unconditional_transition_still_rejects_durable_state_rollback(client):
    _, service, accepted = _accepted(client)
    _advance(service.transition_operator_command, accepted, "SETTLED")
    with pytest.raises(OperatorConflictError, match="invalid operator command state transition"):
        service.transition_operator_command(accepted["id"], "WAITING_SAFE_POINT")


def test_conditional_transition_advances_only_accepted_command(client):
    _, service, accepted = _accepted(client)
    result = service.transition_operator_command(
        accepted["id"], "WAITING_SAFE_POINT", expected_state="ACCEPTED",
    )
    assert result["state"] == "WAITING_SAFE_POINT"
    assert result["revision"] == accepted["revision"] + 1
    audits = _audits(client, accepted["id"])
    assert service.transition_operator_command(
        accepted["id"], "WAITING_SAFE_POINT", expected_state="ACCEPTED",
    ) == result
    assert _audits(client, accepted["id"]) == audits
