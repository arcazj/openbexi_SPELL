from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable

import pytest

import backend.worker as worker_module
from backend.procedure_parser import ProcedureCatalog


def _procedure(source: str):
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    return catalog.validate_source(source, "worker-v06.spell.py")


def _start_worker(
    monkeypatch: pytest.MonkeyPatch,
    procedure,
    *,
    initial_control: list[dict[str, Any]] | None = None,
    resume_settlement: dict[str, Any] | None = None,
    resume_prompt_id: str | None = None,
    durable_arguments: dict[str, Any] | None = None,
    safe_point_ack_required: bool = False,
    start_step: int = 0,
    checkpoint_variables: dict[str, Any] | None = None,
    execution_id: str = "execution-v06",
):
    control: queue.Queue[dict[str, Any]] = queue.Queue()
    output: queue.Queue[dict[str, Any]] = queue.Queue()
    for message in initial_control or []:
        control.put(message)
    monkeypatch.setattr(worker_module, "_replace_worker_environment", lambda: None)
    thread = threading.Thread(
        target=worker_module.worker_main,
        args=(
            execution_id,
            1,
            procedure.ir_version,
            list(procedure.steps),
            start_step,
            "start-command",
            resume_prompt_id,
            checkpoint_variables or {},
            control,
            output,
            resume_settlement,
            durable_arguments,
            safe_point_ack_required,
        ),
        daemon=True,
    )
    thread.start()
    return thread, control, output


def _next(
    output: queue.Queue[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
    *,
    timeout: float = 3,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        try:
            message = output.get(timeout=0.05)
        except queue.Empty:
            continue
        seen.append(message)
        if predicate(message):
            return message, seen
    raise AssertionError(f"worker message not received; seen={seen!r}")


def test_pause_and_resume_preserve_an_active_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    procedure = _procedure(
        'Wait(0.5)\nPrompt("done", type="OK", response_timeout=30)\n'
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    _next(
        output,
        lambda item: item.get("kind") == "event"
        and item.get("event_type") == "step.started"
        and item["payload"]["step_type"] == "wait",
    )
    control.put({"type": "pause", "command_id": "pause-wait"})
    paused, _ = _next(
        output,
        lambda item: item.get("kind") == "state" and item.get("state") == "paused",
    )
    assert paused["command_id"] == "pause-wait"
    control.put({"type": "resume", "command_id": "resume-wait"})
    prompt, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put(
        {
            "type": "prompt_response",
            "command_id": "answer",
            "prompt_id": prompt["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_worker_preflight_rejects_secret_durable_arguments_without_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "github_pat_abcdefghijklmnopqrstuvwxyz123456"
    procedure = _procedure('Log("never runs")\n')
    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        durable_arguments={"api_key": secret},
    )
    rejected, _ = _next(
        output,
        lambda item: item.get("event_type") == "worker.ir_rejected",
    )
    assert rejected["payload"]["code"] == "PROMPT_SECRET_MATERIAL_REJECTED"
    assert secret not in str(rejected)
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "failed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_pause_and_resume_preserve_the_same_typed_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    procedure = _procedure('Prompt("Confirm", type="YES_NO", default="YES")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    assert opened["prompt_type"] == "YES_NO"
    control.put({"type": "pause", "command_id": "pause-prompt"})
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    control.put({"type": "resume", "command_id": "resume-prompt"})
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "prompting")
    control.put(
        {
            "type": "prompt_response",
            "command_id": "answer-prompt",
            "prompt_id": opened["prompt_id"],
            "response": "NO",
        }
    )
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    assert committed["prompt_resolution"]["response"] == "NO"
    assert committed["prompt_resolution"]["outcome"] == "ANSWERED"
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_prompt_settlement_arriving_while_paused_is_delivered_after_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Prompt("Confirm", type="YES_NO")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put({"type": "pause", "command_id": "pause-prompt"})
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    control.put(
        {
            "type": "prompt_settlement",
            "prompt_id": opened["prompt_id"],
            "settlement_id": "settled-during-pause",
            "outcome": "ANSWERED",
            "value": "YES",
        }
    )
    control.put({"type": "resume", "command_id": "resume-prompt"})
    committed, seen = _next(output, lambda item: item.get("kind") == "step_commit")
    assert not any(item.get("kind") == "command_rejected" for item in seen)
    assert committed["prompt_resolution"]["settlement_id"] == "settled-during-pause"
    assert committed["prompt_resolution"]["response"] == "YES"
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_step_over_preserves_command_identity_and_pauses_after_one_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Log("one")\nLog("two")\n')
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[{"type": "pause", "command_id": "pause"}],
    )
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    control.put({"type": "step_over", "command_id": "step-over"})
    applied, _ = _next(
        output,
        lambda item: item.get("kind") == "command_applied"
        and item.get("command_id") == "step-over",
    )
    assert applied["command_type"] == "STEP_OVER"
    control.put({"type": "run", "command_id": "finish"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    ("command_type", "expected_target"),
    [("step", 1), ("step_over", 3)],
)
def test_step_and_step_over_use_distinct_nested_call_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    command_type: str,
    expected_target: int,
) -> None:
    procedure = _procedure(
        'def inner():\n'
        '    Log("inner one")\n'
        '    Log("inner two")\n'
        'def outer():\n'
        '    Call(inner)\n'
        '    Log("outer")\n'
        'Call(outer)\n'
        'Prompt("done", type="OK")\n'
    )
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[{"type": "pause", "command_id": "pause"}],
    )
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    control.put({"type": command_type, "command_id": command_type})
    applied, _ = _next(
        output,
        lambda item: item.get("kind") == "command_applied"
        and item.get("command_id") == command_type,
    )
    assert applied["command_type"] == command_type.upper()
    assert applied["result"]["target_step"] == expected_target
    control.put({"type": "abort", "command_id": "finish"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_duplicate_step_delivery_executes_one_statement_and_replays_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Log("one")\nLog("two")\n')
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[{"type": "pause", "command_id": "pause"}],
    )
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    command = {"type": "step", "command_id": "step-once"}
    control.put(command)
    control.put(command)

    first, first_seen = _next(
        output,
        lambda item: item.get("kind") == "command_applied"
        and item.get("command_id") == "step-once",
    )
    second, second_seen = _next(
        output,
        lambda item: item.get("kind") == "command_applied"
        and item.get("command_id") == "step-once",
    )

    commits = [
        item
        for item in [*first_seen, *second_seen]
        if item.get("kind") == "step_commit"
    ]
    assert [item["step_index"] for item in commits] == [0]
    assert first["result"]["target_step"] == 1
    assert second["result"] == first["result"]
    assert second["replayed"] is True

    control.put({"type": "run", "command_id": "finish"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    ("command", "expected_target"),
    [
        ({"type": "skip", "command_id": "move"}, 1),
        ({"type": "goto", "command_id": "move", "target_step": 2}, 2),
    ],
)
def test_skip_and_goto_replay_once_after_fresh_worker_crash_window(
    monkeypatch: pytest.MonkeyPatch,
    command: dict[str, Any],
    expected_target: int,
) -> None:
    procedure = _procedure('Log("one")\nLog("two")\nPrompt("done", type="OK")\n')
    application_ids: list[tuple[int, str]] = []
    for attempt in range(2):
        thread, control, output = _start_worker(
            monkeypatch,
            procedure,
            initial_control=[{"type": "pause", "command_id": f"pause-{attempt}"}],
        )
        _next(
            output,
            lambda item: item.get("kind") == "state" and item.get("state") == "paused",
        )
        control.put(dict(command))
        control.put(dict(command))
        first, _ = _next(
            output,
            lambda item: item.get("kind") == "command_applied"
            and item.get("command_id") == "move",
        )
        replay, _ = _next(
            output,
            lambda item: item.get("kind") == "command_applied"
            and item.get("command_id") == "move"
            and item.get("replayed") is True,
        )
        assert first["result"]["target_step"] == expected_target
        assert replay["result"] == first["result"]
        application_ids.append((first["checkpoint_step"], first["command_id"]))
        control.put({"type": "abort", "command_id": f"abort-{attempt}"})
        _next(output, lambda item: item.get("kind") == "terminal")
        thread.join(timeout=1)
        assert not thread.is_alive()
    assert application_ids == [(expected_target, "move"), (expected_target, "move")]


def test_nonblocking_startproc_waits_for_admission_not_child_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'StartProc("ops/child", args={"value": 1}, blocking=False, automatic=True)\n'
        'Log("parent continued")\n'
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(output, lambda item: item.get("kind") == "startproc_requested")
    assert requested["blocking"] is False
    assert thread.is_alive()
    control.put(
        {
            "type": "startproc_result",
            "startproc_id": requested["startproc_id"],
            "outcome": "SETTLED",
            "child_execution_id": "child-execution",
            "settlement": "ADMITTED",
        }
    )
    parent_log, _ = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and any(
            effect.get("event_type") == "procedure.log"
            and effect["payload"].get("message") == "parent continued"
            for effect in item["effects"]
        ),
    )
    assert parent_log["next_step"] == 2
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_startproc_settlement_arriving_while_paused_is_not_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'StartProc("ops/child", blocking=False)\n'
        'Log("parent continued")\n'
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(output, lambda item: item.get("kind") == "startproc_requested")
    control.put({"type": "pause", "command_id": "pause-startproc"})
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    control.put(
        {
            "type": "startproc_result",
            "startproc_id": requested["startproc_id"],
            "outcome": "SETTLED",
            "child_execution_id": "child-execution",
            "result": {"outcome": "CHILD_ADMITTED"},
        }
    )
    control.put({"type": "resume", "command_id": "resume-startproc"})
    committed, seen = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and item.get("step_index") == 0,
    )
    assert not any(item.get("kind") == "command_rejected" for item in seen)
    assert committed["next_step"] == 1
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_background_settles_at_a_wait_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'Wait(0.25)\n'
        'Prompt("done", type="OK")\n'
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    _waiting, seen = _next(
        output,
        lambda item: item.get("kind") == "state" and item.get("state") == "waiting",
    )
    assert any(
        item.get("kind") == "safe_point"
        and item.get("safe_point_kind") == "WAIT_BOUNDARY"
        for item in seen
    )
    control.put({"type": "background", "command_id": "background-wait"})
    applied, _ = _next(
        output,
        lambda item: item.get("kind") == "command_applied"
        and item.get("command_id") == "background-wait",
    )
    assert applied["command_type"] == "BACKGROUND"
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put(
        {
            "type": "prompt_response",
            "command_id": "answer",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_worker_rejects_kill_without_terminating_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Prompt("continue", type="OK")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put({"type": "kill", "command_id": "kill"})
    rejected, _ = _next(output, lambda item: item.get("kind") == "command_rejected")
    assert rejected["code"] == "KILL_UNSUPPORTED"
    assert thread.is_alive()
    control.put(
        {
            "type": "prompt_response",
            "command_id": "answer",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_before_statement_waits_for_durable_safe_point_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Log("after ack")\nPrompt("done", type="OK")\n')
    thread, control, output = _start_worker(
        monkeypatch, procedure, safe_point_ack_required=True
    )
    safe_point, _ = _next(output, lambda item: item.get("kind") == "safe_point")
    with pytest.raises(queue.Empty):
        output.get(timeout=0.05)
    control.put(
        {
            "type": "safe_point_ack",
            "safe_point_token": safe_point["safe_point_token"],
        }
    )
    second_before, _ = _next(
        output,
        lambda item: item.get("kind") == "safe_point"
        and item.get("safe_point_kind") == "BEFORE_STATEMENT"
        and item.get("step_index") == 1,
    )
    control.put(
        {
            "type": "safe_point_ack",
            "safe_point_token": second_before["safe_point_token"],
        }
    )
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    second_safe_point, _ = _next(
        output,
        lambda item: item.get("kind") == "safe_point"
        and item.get("safe_point_kind") == "PROMPT_BOUNDARY",
    )
    # PROMPT_BOUNDARY itself is informational; BEFORE_STATEMENT was already
    # acknowledged and the worker is now waiting on the prompt.
    assert second_safe_point["step_index"] == 1
    control.put(
        {
            "type": "prompt_response",
            "command_id": "answer",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_settled_prompt_replays_after_restart_without_reopening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Prompt("Confirm", type="YES_NO")\n')
    settlement = {
        "prompt_id": "prompt-stable",
        "settlement_id": "settlement-stable",
        "outcome": "ANSWERED",
        "response": "YES",
        "command_id": None,
    }
    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        resume_settlement=settlement,
        resume_prompt_id="prompt-stable",
    )
    committed, seen = _next(output, lambda item: item.get("kind") == "step_commit")
    assert not any(item.get("kind") == "prompt_opened" for item in seen)
    assert committed["prompt_resolution"] == settlement
    assert any(
        effect.get("event_type") == "prompt.settlement_replayed"
        for effect in committed["effects"]
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_prompt_settlement_delivered_before_prompt_open_is_deferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Prompt("Confirm", type="YES_NO")\n')
    settlement = {
        "type": "prompt_settlement",
        "prompt_id": "prompt-stable",
        "settlement_id": "settlement-early",
        "outcome": "ANSWERED",
        "value": "YES",
    }
    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[settlement],
        resume_prompt_id="prompt-stable",
    )
    committed, seen = _next(output, lambda item: item.get("kind") == "step_commit")
    assert not any(item.get("kind") == "command_rejected" for item in seen)
    assert committed["prompt_resolution"]["settlement_id"] == "settlement-early"
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_startproc_result_delivered_before_request_is_deferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('StartProc("ops/child", blocking=False)\n')
    startproc_id = str(
        worker_module.uuid.uuid5(
            worker_module.uuid.NAMESPACE_URL,
            "openbexi-spell:startproc:execution-v06:0",
        )
    )
    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[
            {
                "type": "startproc_result",
                "startproc_id": startproc_id,
                "delivery_revision": 3,
                "outcome": "SETTLED",
                "child_execution_id": "child",
                "result": {"outcome": "CHILD_ADMITTED"},
            }
        ],
    )
    committed, seen = _next(output, lambda item: item.get("kind") == "step_commit")
    assert not any(item.get("kind") == "command_rejected" for item in seen)
    effect = next(
        item
        for item in committed["effects"]
        if item.get("event_type") == "procedure.startproc_settled"
    )
    assert effect["payload"]["delivery_revision"] == 3
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_duplicate_user_action_invocation_executes_effects_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'accepted: bool = False\n'
        'Prompt("Confirm", type="OK")\n'
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    action = {
        "type": "user_action",
        "invocation_id": "invocation-stable",
        "handler": [
            {"op": "LOG", "message": "applied", "severity": "info"},
            {
                "op": "SET_LITERAL",
                "name": "accepted",
                "declared_type": "bool",
                "value": True,
            },
        ],
    }
    control.put(action)
    first, _ = _next(output, lambda item: item.get("kind") == "user_action_settled")
    control.put(action)
    second, _ = _next(output, lambda item: item.get("kind") == "user_action_settled")
    assert len(first["effects"]) == 1
    assert second["effects"] == []
    assert second["replayed"] is True
    assert first["application_id"] == second["application_id"]
    control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    committed, _ = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and item.get("step_index") == 1,
    )
    assert committed["variables"]["accepted"] is True
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_user_action_replays_in_a_fresh_worker_from_the_last_durable_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'accepted: bool = False\n'
        'UserAction("ack", "Acknowledge", handler=['
        '{"op": "LOG", "message": "applied", "severity": "info"},'
        '{"op": "SET_LITERAL", "name": "accepted", '
        '"declared_type": "bool", "value": True}])\n'
        'Prompt("Hold", type="OK")\n'
    )
    action = {
        "type": "user_action",
        "invocation_id": "invocation-restart",
        "handler": procedure.user_actions[0]["handler"],
    }
    first_thread, first_control, first_output = _start_worker(monkeypatch, procedure)
    checkpoint, _ = _next(
        first_output,
        lambda item: item.get("kind") == "step_commit" and item.get("next_step") == 1,
    )
    _next(first_output, lambda item: item.get("kind") == "prompt_opened")
    first_control.put(action)
    first_result, _ = _next(
        first_output, lambda item: item.get("kind") == "user_action_settled"
    )
    first_control.put({"type": "abort", "command_id": "crash-before-settle"})
    first_thread.join(timeout=1)
    assert not first_thread.is_alive()

    second_thread, second_control, second_output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[action],
        start_step=1,
        checkpoint_variables=checkpoint["variables"],
    )
    second_result, _ = _next(
        second_output, lambda item: item.get("kind") == "user_action_settled"
    )
    assert first_result["application_id"] == second_result["application_id"]
    assert first_result["effects"] == second_result["effects"]
    assert second_result["variables"]["accepted"] is True
    opened, _ = _next(second_output, lambda item: item.get("kind") == "prompt_opened")
    second_control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(second_output, lambda item: item.get("kind") == "terminal")
    second_thread.join(timeout=1)
    assert not second_thread.is_alive()


def test_inspection_edit_replays_in_a_fresh_worker_before_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        'accepted: bool = False\nPrompt("Hold", type="OK")\n'
    )
    edit = {
        "type": "inspection_edit",
        "edit_id": "edit-restart",
        "delivery_revision": 1,
        "scope": "LOCAL_VARIABLE",
        "path": "variables.accepted",
        "declared_type": "BOOLEAN",
        "variables": {"accepted": True},
    }
    first_thread, first_control, first_output = _start_worker(monkeypatch, procedure)
    checkpoint, _ = _next(
        first_output,
        lambda item: item.get("kind") == "step_commit" and item.get("next_step") == 1,
    )
    _next(first_output, lambda item: item.get("kind") == "prompt_opened")
    first_control.put(edit)
    first_result, _ = _next(
        first_output, lambda item: item.get("kind") == "inspection_edit_applied"
    )
    first_control.put({"type": "abort", "command_id": "crash-before-edit-ack"})
    first_thread.join(timeout=1)
    assert not first_thread.is_alive()

    second_thread, second_control, second_output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[edit],
        start_step=1,
        checkpoint_variables=checkpoint["variables"],
    )
    second_result, _ = _next(
        second_output, lambda item: item.get("kind") == "inspection_edit_applied"
    )
    assert first_result["application_id"] == second_result["application_id"]
    assert second_result["variables"] == {"accepted": True}
    opened, _ = _next(second_output, lambda item: item.get("kind") == "prompt_opened")
    second_control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(second_output, lambda item: item.get("kind") == "terminal")
    second_thread.join(timeout=1)
    assert not second_thread.is_alive()


def test_control_loss_replays_to_a_fresh_worker_until_safe_point_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Wait(0.5)\nLog("done")\n')
    loss = {
        "type": "control_loss",
        "delivery_id": "control-loss:execution-v06:7",
        "fencing_token": 7,
    }
    first_thread, first_control, first_output = _start_worker(monkeypatch, procedure)
    _next(
        first_output,
        lambda item: item.get("kind") == "event"
        and item.get("event_type") == "step.started",
    )
    first_control.put(loss)
    first_ack, _ = _next(
        first_output, lambda item: item.get("kind") == "control_loss_applied"
    )
    first_control.put({"type": "abort", "command_id": "crash-before-loss-ack"})
    first_thread.join(timeout=1)
    assert not first_thread.is_alive()

    second_thread, second_control, second_output = _start_worker(
        monkeypatch, procedure, initial_control=[loss]
    )
    second_ack, _ = _next(
        second_output, lambda item: item.get("kind") == "control_loss_applied"
    )
    assert first_ack["delivery_id"] == second_ack["delivery_id"]
    assert first_ack["fencing_token"] == second_ack["fencing_token"] == 7
    second_control.put({"type": "abort", "command_id": "stop-restarted-worker"})
    second_thread.join(timeout=1)
    assert not second_thread.is_alive()


@pytest.mark.parametrize("blocking", [False, True])
def test_startproc_terminal_delivery_replays_to_a_fresh_worker_before_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    blocking: bool,
) -> None:
    procedure = _procedure(
        f'StartProc("ops/child", blocking={blocking})\nPrompt("Hold", type="OK")\n'
    )
    first_thread, first_control, first_output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(
        first_output, lambda item: item.get("kind") == "startproc_requested"
    )
    result = {
        "type": "startproc_result",
        "startproc_id": requested["startproc_id"],
        "delivery_revision": 3,
        "outcome": "SETTLED",
        "child_execution_id": "child",
        "result": {
            "outcome": "CHILD_FINISHED" if blocking else "CHILD_ADMITTED"
        },
    }
    first_control.put(result)
    first_commit, _ = _next(
        first_output,
        lambda item: item.get("kind") == "step_commit" and item.get("next_step") == 1,
    )
    _next(first_output, lambda item: item.get("kind") == "prompt_opened")
    first_control.put({"type": "abort", "command_id": "crash-before-startproc-ack"})
    first_thread.join(timeout=1)
    assert not first_thread.is_alive()

    second_thread, second_control, second_output = _start_worker(
        monkeypatch,
        procedure,
        initial_control=[result],
    )
    second_commit, _ = _next(
        second_output,
        lambda item: item.get("kind") == "step_commit" and item.get("next_step") == 1,
    )
    first_effect = next(
        effect
        for effect in first_commit["effects"]
        if effect.get("payload", {}).get("startproc_id") == requested["startproc_id"]
    )
    second_effect = next(
        effect
        for effect in second_commit["effects"]
        if effect.get("payload", {}).get("startproc_id") == requested["startproc_id"]
    )
    assert first_effect["payload"] == second_effect["payload"]
    opened, _ = _next(second_output, lambda item: item.get("kind") == "prompt_opened")
    second_control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(second_output, lambda item: item.get("kind") == "terminal")
    second_thread.join(timeout=1)
    assert not second_thread.is_alive()


def test_prompt_settlement_replays_to_a_fresh_worker_before_checkpoint_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Prompt("Hold", type="YES_NO")\n')
    first_thread, first_control, first_output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(first_output, lambda item: item.get("kind") == "prompt_opened")
    settlement = {
        "type": "prompt_settlement",
        "prompt_id": opened["prompt_id"],
        "settlement_id": "settlement-restart",
        "outcome": "ANSWERED",
        "value": "YES",
    }
    first_control.put(settlement)
    first_commit, _ = _next(
        first_output, lambda item: item.get("kind") == "step_commit"
    )
    first_thread.join(timeout=1)
    assert not first_thread.is_alive()

    second_thread, _second_control, second_output = _start_worker(
        monkeypatch,
        procedure,
        resume_prompt_id=opened["prompt_id"],
        resume_settlement={
            "prompt_id": opened["prompt_id"],
            "settlement_id": settlement["settlement_id"],
            "outcome": settlement["outcome"],
            "response": settlement["value"],
            "command_id": None,
        },
    )
    second_commit, _ = _next(
        second_output, lambda item: item.get("kind") == "step_commit"
    )
    assert first_commit["prompt_resolution"] == second_commit["prompt_resolution"]
    _next(second_output, lambda item: item.get("kind") == "terminal")
    second_thread.join(timeout=1)
    assert not second_thread.is_alive()


def test_inspection_edit_reloads_prompting_worker_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('value: int = 1\nPrompt("Confirm", type="OK")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put(
        {
            "type": "inspection_edit",
            "edit_id": "edit-stable",
            "execution_revision": 7,
            "scope": "LOCAL_VARIABLE",
            "path": "variables.value",
            "declared_type": "INTEGER",
            "variables": {"value": 2},
        }
    )
    applied, _ = _next(
        output, lambda item: item.get("kind") == "inspection_edit_applied"
    )
    assert applied["outcome"] == "APPLIED"
    assert applied["variables"] == {"value": 2}
    control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    committed, _ = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and item.get("step_index") == 1,
    )
    assert committed["variables"]["value"] == 2
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_inspection_edit_validates_reserved_runtime_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('value: int = 1\nPrompt("Confirm", type="OK")\n')
    initial = {
        "value": 1,
        "GLOBALS": {"count": 1},
        "IVARS": {"mode": "old"},
        "SHARED_DATA": {"locked": True},
    }
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        start_step=1,
        checkpoint_variables=initial,
        durable_arguments={"input": 1},
    )
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")

    snapshots = [
        (
            "args",
            "ARGS",
            "ARGS.input",
            {
                **initial,
                "ARGS": {"input": 2},
            },
        ),
        (
            "globals",
            "GLOBAL_VARIABLE",
            "GLOBALS.count",
            {
                **initial,
                "ARGS": {"input": 2},
                "GLOBALS": {"count": 2},
            },
        ),
        (
            "ivars",
            "IVARS",
            "IVARS.mode",
            {
                **initial,
                "ARGS": {"input": 2},
                "GLOBALS": {"count": 2},
                "IVARS": {"mode": "new"},
            },
        ),
    ]
    latest = None
    for edit_id, scope, path, snapshot in snapshots:
        control.put(
            {
                "type": "inspection_edit",
                "edit_id": edit_id,
                "scope": scope,
                "path": path,
                "declared_type": "STRING" if scope == "IVARS" else "INTEGER",
                "variables": snapshot,
            }
        )
        latest, _ = _next(
            output,
            lambda item, expected=edit_id: item.get("kind")
            == "inspection_edit_applied"
            and item.get("edit_id") == expected,
        )
        assert latest["outcome"] == "APPLIED"

    assert latest is not None
    rejected_snapshot = {
        **latest["variables"],
        "SHARED_DATA": {"locked": False},
    }
    control.put(
        {
            "type": "inspection_edit",
            "edit_id": "shared",
            "scope": "SHARED_DATA",
            "path": "SHARED_DATA.locked",
            "declared_type": "BOOLEAN",
            "variables": rejected_snapshot,
        }
    )
    rejected, _ = _next(
        output,
        lambda item: item.get("kind") == "inspection_edit_applied"
        and item.get("edit_id") == "shared",
    )
    assert rejected["outcome"] == "REJECTED"
    assert rejected["variables"] == latest["variables"]

    control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_control_loss_pauses_wait_and_preserves_resume_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure('Wait(0.2)\nPrompt("done", type="OK")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "waiting")
    control.put(
        {
            "type": "control_loss",
            "delivery_id": "lease-expiry-stable",
            "lease_id": "lease-stable",
            "fencing_token": 4,
        }
    )
    _next(output, lambda item: item.get("kind") == "state" and item.get("state") == "paused")
    applied, _ = _next(output, lambda item: item.get("kind") == "control_loss_applied")
    assert applied["delivery_id"] == "lease-expiry-stable"
    control.put({"type": "run", "command_id": "new-controller-run"})
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": "OK",
        }
    )
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive()
