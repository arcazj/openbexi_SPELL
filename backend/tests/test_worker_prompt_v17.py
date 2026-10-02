from __future__ import annotations

import pytest

from backend.tests.test_worker_v06 import _procedure, _start_worker, _next


@pytest.mark.parametrize("call,response,expected", [
    ("Prompt('Input')", "OK", "OK"),
    ("Prompt('Input', CANCEL)", "CANCEL", "CANCEL"),
    ("Prompt('Input', Type=OK_CANCEL)", "CANCEL", "CANCEL"),
    ("Prompt('Input', YES)", "YES", "YES"),
    ("Prompt('Input', NO)", "NO", "NO"),
    ("Prompt('Input', Type=YES_NO)", "NO", "NO"),
    ("Prompt('Input', ALPHA)", "nominal", "nominal"),
    ("Prompt('Input', NUM)", "2.50", 2.5),
    ("Prompt('Input', DATE)", "2024-02-29", "2024-02-29"),
    ("Prompt('Input', ['A :Primary', 'B:Backup'], Type=LIST)", "B", "B"),
    ("Prompt('Input', ['Primary', 'Backup'], Type=LIST|NUM)", 1, 1),
    ("Prompt('Input', ['Primary', 'Backup'], Type=LIST|ALPHA)", "Backup", "Backup"),
])
def test_native_return_is_one_atomic_typed_worker_checkpoint(monkeypatch, call, response, expected):
    procedure = _procedure("result = " + call + "\nDisplay('Done')\n")
    assert procedure.ir_version == "0.17"
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, seen = _next(output, lambda item: item.get("kind") == "prompt_opened")
    assert opened["step_index"] == 0
    assert not any(item.get("kind") == "step_commit" for item in seen)
    control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                 "settlement_id": "native-answer", "outcome": "ANSWERED", "response": response})
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    assert type(committed["variables"]["result"]) is type(expected)
    assert committed["variables"]["result"] == expected
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_native_abort_stops_without_result_or_later_display(monkeypatch):
    procedure = _procedure("result = Prompt('Input', OK_CANCEL)\nDisplay('must not appear')\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                 "settlement_id": "native-cancel", "outcome": "CANCELLED", "response": None})
    terminal, seen = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "aborted"
    assert not any(item.get("kind") == "step_commit" for item in seen)
    assert any(item.get("kind") == "prompt_settlement_consumed" for item in seen)
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_native_worker_preserves_seven_day_warning_without_an_answer_deadline(monkeypatch):
    procedure = _procedure("result = Prompt('Long warning', YES_NO, Timeout=604800)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    assert opened["warning_delay_seconds"] == 604800.0
    assert opened["response_timeout_seconds"] is None and opened["default"] is None
    control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                 "settlement_id": "long-warning-answer", "outcome": "ANSWERED", "response": "YES"})
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    assert committed["variables"]["result"] == "YES"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_native_invalid_number_does_not_advance_prompt(monkeypatch):
    procedure = _procedure("result = Prompt('Input', NUM)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    for response in (True, "1e2", "Infinity"):
        control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                     "settlement_id": "invalid", "outcome": "ANSWERED", "response": response})
        rejected, seen = _next(output, lambda item: item.get("kind") == "command_rejected")
        assert rejected["code"] == "PROMPT_VALUE_INVALID"
        assert not any(item.get("kind") == "step_commit" for item in seen)
    control.put({"type": "prompt_settlement", "prompt_id": opened["prompt_id"],
                 "settlement_id": "valid", "outcome": "ANSWERED", "response": "0"})
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    assert committed["variables"]["result"] == 0.0
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_native_settlement_replay_keeps_identity_and_return_after_crash_window(monkeypatch):
    procedure = _procedure("result = Prompt('Input', NUM)\n")
    first, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    settlement = {"prompt_id": opened["prompt_id"], "settlement_id": "native-replay",
                  "outcome": "ANSWERED", "response": "7.25", "command_id": None}
    control.put({"type": "prompt_settlement", **settlement})
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    first.join(timeout=1)
    second, _, replay = _start_worker(monkeypatch, procedure, resume_prompt_id=opened["prompt_id"], resume_settlement=settlement)
    repeated, seen = _next(replay, lambda item: item.get("kind") == "step_commit")
    assert repeated["variables"] == committed["variables"]
    assert repeated["prompt_resolution"] == committed["prompt_resolution"]
    assert not any(item.get("kind") == "prompt_opened" for item in seen)
    second.join(timeout=1)
    assert not first.is_alive() and not second.is_alive()


def test_display_empty_dynamic_whitespace_and_severity_are_real_worker_logs(monkeypatch):
    procedure = _procedure("text = ''\nDisplay(text)\nDisplay('', WARNING)\nDisplay('   ', Severity=ERROR)\n")
    thread, _, output = _start_worker(monkeypatch, procedure)
    terminal, seen = _next(output, lambda item: item.get("kind") == "terminal")
    logs = [(effect["payload"]["message"], effect["severity"])
            for item in seen for effect in item.get("effects", []) if effect["event_type"] == "procedure.log"]
    assert terminal["state"] == "completed"
    assert logs == [("", "info"), ("", "warning"), ("   ", "error")]
    thread.join(timeout=1)
