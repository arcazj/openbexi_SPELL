from __future__ import annotations

import pytest

from backend.procedure_parser import ProcedureCatalog
from backend.telecommand_runtime_v11 import execute_preflight, uncertain_replay_result, validate_send_request
from backend.tests.test_worker_v06 import _next, _start_worker


def _procedure(source):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source, "composition-v18.spell.py")
    assert procedure.ir_version == "0.18"
    return procedure


def _answer(control, opened, value="YES", **changes):
    control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                 "settlement_id": "composition-answer", "outcome": "ANSWERED", "response": value, **changes})


@pytest.mark.parametrize("answer,expected_requests", [("YES", 1), ("NO", 0)])
def test_native_answer_and_integer_guard_control_built_command_request(monkeypatch, answer, expected_requests):
    procedure = _procedure("item = BuildTC('CMDNAME')\nanswer = Prompt('Proceed?', YES_NO)\nif answer == 'YES' and 2 ** 3 == 8:\n    Send(command=item)\nDisplay(answer)\n")
    thread, control, output = _start_worker(monkeypatch, procedure, execution_id="native-branch")
    opened, seen = _next(output, lambda message: message.get("kind") == "prompt_opened")
    _answer(control, opened, answer)
    result, after = _next(output, lambda message: message.get("kind") in {"telecommand_requested", "terminal"})
    seen.extend(after)
    requests = int(result["kind"] == "telecommand_requested")
    assert requests == expected_requests
    if requests:
        variables = [message["variables"] for message in seen if message.get("kind") == "step_commit"][-1]
        request, service, preflight = validate_send_request("native-branch", result["step_index"], procedure.steps[result["step_index"]], variables,
            {key: value for key, value in result.items() if key not in {"kind", "generation"}})
        assert request["selector"]["kind"] == "item"
        control.put({"type": "telecommand_result", **execute_preflight(request, service, preflight)})
        result, _ = _next(output, lambda message: message.get("kind") == "terminal")
    assert result["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("outcome,response,terminal", [("ANSWERED", "CANCEL", "completed"), ("CANCELLED", None, "aborted")])
def test_native_cancel_and_abort_do_not_request_later_guarded_send(monkeypatch, outcome, response, terminal):
    procedure = _procedure("answer = Prompt('Proceed?', OK_CANCEL)\nif answer == 'OK':\n    Send(command='CMDNAME')\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda message: message.get("kind") == "prompt_opened")
    _answer(control, opened, response, outcome=outcome)
    done, seen = _next(output, lambda message: message.get("kind") == "terminal")
    assert done["state"] == terminal
    assert not any(message.get("kind") == "telecommand_requested" for message in seen)
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_native_settlement_cannot_answer_the_later_command_confirmation(monkeypatch):
    procedure = _procedure("answer = Prompt('Proceed?', YES_NO)\nSend(command='CMDNAME', Confirm=True)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    native, _ = _next(output, lambda message: message.get("kind") == "prompt_opened")
    _answer(control, native)
    confirmation, before = _next(output, lambda message: message.get("kind") == "prompt_opened")
    assert confirmation["prompt_id"] != native["prompt_id"]
    assert not any(message.get("kind") == "telecommand_requested" for message in before)
    _answer(control, native)
    rejected, before = _next(output, lambda message: message.get("kind") == "command_rejected")
    assert rejected["code"] == "PROMPT_NOT_OPEN"
    assert not any(message.get("kind") == "telecommand_requested" for message in before)
    _answer(control, confirmation, "NO", settlement_id="confirmation-denied")
    done, before = _next(output, lambda message: message.get("kind") == "terminal")
    assert done["state"] == "failed"
    assert not any(message.get("kind") == "telecommand_requested" for message in before)
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_worker_protects_native_branch_dependency_from_inspection_and_backward_goto(monkeypatch):
    procedure = _procedure("answer = 'NO'\nPrompt('Hold')\nif answer == 'YES':\n    Send(command='CMDNAME')\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    _, seen = _next(output, lambda message: message.get("kind") == "prompt_opened")
    variables = [message["variables"] for message in seen if message.get("kind") == "step_commit"][-1]
    control.put({"type": "inspection_edit", "edit_id": "redirect-guard", "execution_revision": 7,
                 "scope": "LOCAL_VARIABLE", "path": "variables.answer", "declared_type": "STRING",
                 "variables": {**variables, "answer": "YES"}})
    rejected, _ = _next(output, lambda message: message.get("kind") == "inspection_edit_applied")
    assert rejected["outcome"] == "REJECTED" and rejected["variables"]["answer"] == "NO"
    control.put({"type": "pause", "command_id": "pause"})
    _next(output, lambda message: message.get("kind") == "state" and message.get("state") == "paused")
    control.put({"type": "goto", "command_id": "back", "target_step": 0})
    rejected, _ = _next(output, lambda message: message.get("kind") == "command_rejected" and message.get("command_id") == "back")
    assert rejected["code"] == "TC_REENTRY_FORBIDDEN"
    control.put({"type": "abort", "command_id": "stop"})
    _next(output, lambda message: message.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_composed_worker_fails_closed_on_uncertain_intent_without_second_request(monkeypatch):
    procedure = _procedure("answer = Prompt('Proceed?', YES_NO)\nSend(command='CMDNAME')\nDisplay('must not run')\n")
    thread, control, output = _start_worker(monkeypatch, procedure, execution_id="uncertain-composition")
    opened, _ = _next(output, lambda message: message.get("kind") == "prompt_opened")
    _answer(control, opened)
    requested, seen = _next(output, lambda message: message.get("kind") == "telecommand_requested")
    variables = [message["variables"] for message in seen if message.get("kind") == "step_commit"][-1]
    request, service, preflight = validate_send_request("uncertain-composition", requested["step_index"], procedure.steps[requested["step_index"]], variables,
        {key: value for key, value in requested.items() if key not in {"kind", "generation"}})
    control.put({"type": "telecommand_result", **uncertain_replay_result(request, service, preflight)})
    done, after = _next(output, lambda message: message.get("kind") == "terminal")
    assert done["state"] == "failed"
    assert not any(message.get("kind") in {"step_commit", "telecommand_requested"} for message in after)
    thread.join(timeout=1)
    assert not thread.is_alive()
