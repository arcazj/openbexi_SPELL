from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import func, select

from backend.models import Execution
from backend.operator_models import ExecutionOperatorState, OperatorAuditEvent, OperatorPrompt
from backend.operator_service import OperatorConflictError
from backend.prompt_v17 import PROMPT_PROFILE, normalize_native_prompt_declaration
from backend.tests.test_v06_operator_workspace import _paused_execution


def _declaration(fields):
    return {"type": fields["prompt_type"], "question": fields["question"],
            "options": fields["choices"], "default": fields["default"], "list_mode": fields["list_mode"],
            "prompt_profile": PROMPT_PROFILE, "warning_delay_seconds": fields["warning_delay_seconds"],
            "response_timeout_seconds": fields["response_timeout_seconds"]}


def _open(client, *, timeout=None, default=None):
    execution, service = _paused_execution(client, suffix=str(uuid.uuid4()))
    fields = normalize_native_prompt_declaration("Choose", prompt_type="YES_NO", default=default, timeout_seconds=timeout)
    declaration = _declaration(fields)
    opened = service.open_typed_prompt(execution.id, str(uuid.uuid4()), 0, declaration, {})
    return execution, service, opened, declaration


def test_native_warning_is_durable_once_and_prompt_remains_open_after_reopen(client):
    execution, service, opened, declaration = _open(client, timeout=604800)
    assert opened["response_deadline"] is None and opened["default"] is None
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, opened["id"])
        prompt.warning_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    assert service.reconcile_prompt_timers() == 0
    first = service.open_typed_prompt(execution.id, opened["id"], 0, declaration, {})
    assert first["state"] == "OPEN" and first["warning_emitted_at"] is not None
    assert first["settlement"] is None and first["response_deadline"] is None
    assert service.reconcile_prompt_timers() == 0
    repeated = service.open_typed_prompt(execution.id, opened["id"], 0, declaration, {})
    assert repeated["warning_at"] == first["warning_at"]
    assert repeated["warning_emitted_at"] == first["warning_emitted_at"]
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(OperatorAuditEvent).where(
            OperatorAuditEvent.aggregate_id == opened["id"], OperatorAuditEvent.event_type == "prompt.warning_due")) == 1


def test_native_default_deadline_has_one_answered_winner(client):
    _, service, opened, _ = _open(client, timeout=60, default="YES")
    assert opened["default"] == "YES" and opened["warning_at"] is None
    with client.app.state.session_factory() as session:
        session.get(OperatorPrompt, opened["id"]).response_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    # Either the explicit call or the live background reconciler may win.
    service.reconcile_prompt_timers()
    with client.app.state.session_factory() as session:
        first = session.get(OperatorPrompt, opened["id"])
        settlement_id = first.settlement_id
        assert first.state == "SETTLED" and settlement_id is not None
        assert first.settlement_outcome == "ANSWERED" and first.settled_value == "YES"
        assert first.settled_by == "operator-reconciler"
    assert service.reconcile_prompt_timers() == 0
    loser = service.settle_prompt_terminal(opened["id"], "CANCELLED")
    assert loser["settlement"]["id"] == settlement_id
    assert loser["settlement"]["value"] == "YES"
    with client.app.state.session_factory() as session:
        settlements = session.scalars(select(OperatorAuditEvent).where(
            OperatorAuditEvent.aggregate_id == opened["id"],
            OperatorAuditEvent.event_type == "prompt.settled")).all()
        assert len(settlements) == 1
        assert settlements[0].payload == {
            "prompt_id": opened["id"], "settlement_id": settlement_id, "outcome": "ANSWERED"}


@pytest.mark.parametrize("timeout", [None, 0])
def test_native_indefinite_wait_cannot_inherit_an_automatic_default(client, timeout):
    execution, service = _paused_execution(client, suffix=str(uuid.uuid4()))
    with client.app.state.session_factory() as session:
        projection = session.get(ExecutionOperatorState, execution.id)
        projection.settings = {"PROMPT_RESPONSE_TIMEOUT": 1, "PROMPT_WARNING_DELAY": 2}
        session.commit()
    fields = normalize_native_prompt_declaration("Choose", prompt_type="YES_NO", default="YES", timeout_seconds=timeout)
    opened = service.open_typed_prompt(execution.id, str(uuid.uuid4()), 0, _declaration(fields), {})
    assert opened["default"] is None and opened["response_deadline"] is None
    assert opened["warning_at"] is None


def test_native_no_controller_deadline_outranks_simultaneous_default(client):
    execution, service, opened, _ = _open(client, timeout=60, default="YES")
    with client.app.state.session_factory() as session:
        due = datetime.now(timezone.utc) - timedelta(seconds=1)
        prompt = session.get(OperatorPrompt, opened["id"])
        prompt.response_deadline = due
        prompt.no_controller_deadline = due
        projection = session.get(ExecutionOperatorState, execution.id)
        projection.ownership_mode = "CONTROL_LOST"
        session.commit()
    service.reconcile_prompt_timers()
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, opened["id"])
        assert prompt.settlement_outcome == "NO_CONTROLLER" and prompt.settled_value is None


def test_native_reopen_rejects_timeout_policy_change(client):
    execution, service, opened, declaration = _open(client, timeout=30)
    with pytest.raises(OperatorConflictError):
        service.open_typed_prompt(execution.id, opened["id"], 0,
                                 {**declaration, "warning_delay_seconds": 60.0}, {})
    with pytest.raises(OperatorConflictError):
        service.open_typed_prompt(execution.id, opened["id"], 0,
                                 {**declaration, "warning_delay_seconds": None,
                                  "response_timeout_seconds": 30.0, "default": "YES"}, {})
    with pytest.raises(OperatorConflictError):
        service.open_typed_prompt(execution.id, opened["id"], 0,
                                 {key: value for key, value in declaration.items() if key != "prompt_profile"}, {})


@pytest.mark.parametrize("patch", [{"settlement_id": "00000000-0000-0000-0000-000000000000"},
                                  {"outcome": "CANCELLED"}, {"response": "NO"}])
def test_native_checkpoint_rejects_forged_settlement_even_with_correct_target(patch):
    from backend.tests.test_supervisor_v11_runtime import _ordinary_fixture, _ordinary_step_commit, _settled_yes_no_prompt
    from backend.supervisor import ConflictError
    supervisor, sessions, procedure, execution_id = _ordinary_fixture("result = Prompt('Choose', YES_NO)\n", current_step=0)
    prompt, resolution = _settled_yes_no_prompt(execution_id, 0, "Choose")
    prompt.settings_snapshot = {"PROMPT_PROFILE": PROMPT_PROFILE, "PROMPT_WARNING_DELAY": None, "PROMPT_RESPONSE_TIMEOUT": None}
    with sessions() as session:
        session.get(Execution, execution_id).ir_version = "0.17"
        session.add(prompt)
        session.commit()
    message = _ordinary_step_commit(procedure, 0, {"ARGS": {}, "result": "YES"}, prompt_resolution={**resolution, **patch})
    with pytest.raises(ConflictError):
        supervisor._commit_step(execution_id, 7, message)
    assert supervisor._commit_step(execution_id, 6, message) is False
    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 0
        assert session.get(Execution, execution_id).variables == {}


def test_native_skipped_prompt_cannot_mutate_variables_and_invalid_guard_is_bounded():
    from backend.tests.test_supervisor_v11_runtime import _ordinary_fixture, _ordinary_step_commit
    from backend.supervisor import ConflictError
    source = "result = 'before'\nif False:\n    result = Prompt('Choose', YES_NO)\n"
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(source, current_step=2, variables={"result": "before", "__spell_branch_0": False})
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        execution.ir_version = "0.17"
        session.commit()
    with pytest.raises(ConflictError, match="unrelated or skipped"):
        supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 2, {"result": "forged", "__spell_branch_0": False}))
    with sessions() as session:
        session.get(Execution, execution_id).variables = {"result": "before"}
        session.commit()
    with pytest.raises(ConflictError, match="guard cannot"):
        supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 2, {"result": "before"}))


@pytest.mark.parametrize("ir_version", ["0.6", "0.11", "0.17"])
def test_supervisor_rejects_native_profile_in_legacy_worker_message(ir_version):
    from backend.tests.test_supervisor_v11_runtime import _ordinary_fixture
    from backend.supervisor import ConflictError
    from backend.ir_v11 import ordinary_prompt_id
    supervisor, sessions, _, execution_id = _ordinary_fixture("Prompt('Choose', type='YES_NO')\n", current_step=0)
    supervisor.operator_service = object()
    with sessions() as session:
        session.get(Execution, execution_id).ir_version = ir_version
        session.commit()
    with pytest.raises(ConflictError, match="IR boundary"):
        supervisor._open_typed_prompt(execution_id, 7, {"prompt_id": ordinary_prompt_id(execution_id, 0),
            "step_index": 0, **normalize_native_prompt_declaration("Choose", prompt_type="YES_NO")})


def test_supervisor_rejects_native_worker_policy_question_and_guard_tampering(client):
    supervisor = client.app.state.supervisor
    procedure = client.app.state.catalog.validate_source(
        "enabled = 2 ** 2 == 4\nif enabled:\n    Prompt('Choose', YES_NO, Timeout=30)\n", "native-proof.spell.py")
    execution_id = supervisor.create_execution(procedure, actor="pytest-operator", role="operator",
                                              reason="native authority", idempotency_key="native-proof", automatic=False)
    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id.id)
        index = next(i for i, step in enumerate(execution.steps) if step.get("type") == "prompt")
        execution.current_step = index
        execution.variables = {"enabled": True, "__spell_branch_0": True}
        from backend.ir_v11 import ordinary_prompt_id
        fields = supervisor._native_prompt_declaration(execution.steps[index], execution.variables)
        message = {**fields, "prompt_id": ordinary_prompt_id(execution.id, index), "step_index": index}
        assert supervisor._native_prompt_message_matches(execution, message)
        for patch in ({"question": "Changed"}, {"prompt_profile": "legacy"},
                      {"warning_delay_seconds": None, "response_timeout_seconds": 30.0, "default": "YES"}):
            assert not supervisor._native_prompt_message_matches(execution, {**message, **patch})
        execution.variables = {"enabled": False, "__spell_branch_0": False}
        assert not supervisor._native_prompt_message_matches(execution, message)
