from __future__ import annotations

import threading

import pytest
from sqlalchemy import select

import backend.supervisor as module
from backend.models import Event, Execution
from backend.supervisor import ConflictError, WorkerHandle
from backend.telecommand_runtime_v11 import prepare_send_request
from backend.tests.test_supervisor_v11_runtime import _ordinary_fixture, _ordinary_step_commit, _result


def _fixture(source="Send(command='CMDNAME')\nPrompt('After')\n", *, current_step=0, variables=None):
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(source, current_step=current_step, variables=variables or {"ARGS": {}})
    assert procedure.ir_version == "0.18"
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        execution.ir_version = "0.18"
        execution.state = "running"
        session.commit()
    return supervisor, sessions, procedure, execution_id


def _request(supervisor, sessions, execution_id):
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        return prepare_send_request(execution_id, execution.current_step, execution.steps[execution.current_step], execution.variables)[0]


@pytest.mark.parametrize("guard_value", [False, 0, "YES", None])
def test_composed_request_requires_true_authoritative_guard_before_any_intent(guard_value):
    source = "answer = Prompt('Proceed?', YES_NO)\nif answer == 'YES':\n    Send(command='CMDNAME')\n"
    supervisor, sessions, _, execution_id = _fixture(source, current_step=2, variables={"ARGS": {}, "answer": "NO", "__spell_branch_0": guard_value})
    request = _request(supervisor, sessions, execution_id)
    with pytest.raises(ConflictError, match="telecommand"):
        supervisor._handle_telecommand_request(execution_id, supervisor._workers[execution_id], request)
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []


def test_composed_false_branch_cannot_open_a_valid_plan_confirmation():
    source = "answer = Prompt('Proceed?', YES_NO)\nif answer == 'YES':\n    Send(command='CMDNAME', Confirm=True)\n"
    supervisor, sessions, _, execution_id = _fixture(source, current_step=2, variables={"ARGS": {}, "answer": "NO", "__spell_branch_0": False})
    supervisor.operator_service = object()
    request = _request(supervisor, sessions, execution_id)
    from backend.telecommand_runtime_v11 import confirmation_prompt_id
    prompt_id = confirmation_prompt_id(execution_id, 2, request["plan"]["plan_digest"])
    with pytest.raises(ConflictError, match="active branch"):
        supervisor._open_typed_prompt(execution_id, 7, {"prompt_id": prompt_id, "step_index": 2})
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []


@pytest.mark.parametrize("forgery", ["settlement", "value", "item", "guard"])
def test_composed_native_checkpoint_cannot_forge_answer_or_mutate_command_dependencies(forgery):
    from backend.prompt_v17 import PROMPT_PROFILE
    from backend.tests.test_supervisor_v11_runtime import _settled_yes_no_prompt
    source = "item = BuildTC('CMDNAME')\nanswer = Prompt('Proceed?', YES_NO)\nif answer == 'YES':\n    Send(command=item)\n"
    supervisor, sessions, procedure, execution_id = _fixture(source, current_step=2, variables={"ARGS": {}, "item": "opaque-prior-item"})
    prompt, resolution = _settled_yes_no_prompt(execution_id, 2, "Proceed?")
    prompt.settings_snapshot = {"PROMPT_PROFILE": PROMPT_PROFILE, "PROMPT_WARNING_DELAY": None, "PROMPT_RESPONSE_TIMEOUT": None}
    with sessions() as session:
        session.add(prompt)
        session.commit()
    variables = {"ARGS": {}, "item": "opaque-prior-item", "answer": "YES"}
    if forgery == "settlement":
        resolution["settlement_id"] = "00000000-0000-0000-0000-000000000000"
    elif forgery == "value":
        variables["answer"] = "NO"
    elif forgery == "item":
        variables["item"] = "replacement"
    else:
        variables["__spell_branch_0"] = True
    commit = _ordinary_step_commit(procedure, 2, variables, prompt_resolution=resolution)
    assert supervisor._commit_step(execution_id, 6, commit) is False
    with pytest.raises(ConflictError):
        supervisor._commit_step(execution_id, 7, commit)
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution.current_step == 2 and "answer" not in execution.variables


@pytest.mark.parametrize("field,value", [("default", "YES"), ("question", "different plan"), ("response_timeout_seconds", 1), ("prompt_profile", "spell-lrm244/0.17")])
def test_composed_confirmation_rejects_worker_policy_or_plan_substitution(field, value):
    supervisor, sessions, _, execution_id = _fixture("Send(command='CMDNAME', Confirm=True)\nPrompt('After')\n")
    supervisor.operator_service = object()
    request = _request(supervisor, sessions, execution_id)
    from backend.telecommand_runtime_v11 import confirmation_prompt_id
    prompt_id = confirmation_prompt_id(execution_id, 0, request["plan"]["plan_digest"])
    with sessions() as session:
        fields = supervisor._v18_telecommand_prompt_fields(session, session.get(Execution, execution_id), prompt_id)
    with pytest.raises(ConflictError):
        supervisor._open_typed_prompt(execution_id, 7, {**fields, field: value})
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []


def test_composed_restart_after_intent_reports_uncertain_without_second_dispatch(monkeypatch):
    supervisor, sessions, _, execution_id = _fixture()
    request = _request(supervisor, sessions, execution_id)
    started, release = threading.Event(), threading.Event()
    calls = []
    original = module.execute_preflight
    def delayed(*args, **kwargs):
        calls.append(args[0]["request_id"])
        started.set()
        assert release.wait(timeout=5)
        return original(*args, **kwargs)
    monkeypatch.setattr(module, "execute_preflight", delayed)
    first = supervisor._workers[execution_id]
    supervisor._handle_telecommand_request(execution_id, first, request)
    assert started.wait(timeout=2)
    try:
        with sessions() as session:
            session.get(Execution, execution_id).worker_generation = 8
            assert [event.event_type for event in session.scalars(select(Event)).all()] == ["procedure.telecommand_requested"]
            session.commit()
        with pytest.raises(ConflictError):
            supervisor._handle_telecommand_request(execution_id, first, request)
        import queue
        recovered = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
        supervisor._workers[execution_id] = recovered
        supervisor._handle_telecommand_request(execution_id, recovered, request)
        result = _result(recovered.control)
        assert result["outcome"] == "UNCERTAIN"
        assert result["checkpoint"]["provider_call_count"] == 0
        assert calls == [request["request_id"]]
    finally:
        release.set()


def test_composed_result_replay_keeps_identity_and_rejects_forged_checkpoint(monkeypatch):
    supervisor, sessions, procedure, execution_id = _fixture()
    request = _request(supervisor, sessions, execution_id)
    calls = []
    original = module.execute_preflight
    def tracked(*args, **kwargs):
        calls.append(args[0]["request_id"])
        return original(*args, **kwargs)
    monkeypatch.setattr(module, "execute_preflight", tracked)
    handle = supervisor._workers[execution_id]
    supervisor._handle_telecommand_request(execution_id, handle, request)
    first = _result(handle.control)
    supervisor._handle_telecommand_request(execution_id, handle, request)
    assert _result(handle.control) == first and calls == [request["request_id"]]
    with pytest.raises(ConflictError, match="evidence differs"):
        supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 0, {"ARGS": {}}))
    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 0
