"""Execute closed observation/Prompt/command workflows through the worker."""
from copy import deepcopy
import time

import pytest

from backend.ir_v07 import canonicalize_observation_result, observation_request_for_step
from backend.procedure_parser import ProcedureCatalog
from backend.telecommand_runtime_v11 import execute_preflight, validate_send_request
from backend.tests.test_ir_v07 import _condition
from backend.tests.test_worker_v06 import _next, _start_worker


def _procedure(source):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source, "worker-composition-v19.spell.py")
    assert procedure.ir_version == "0.19"
    return procedure


def _request(message):
    return {key:value for key,value in message.items() if key not in {"kind", "generation"}}


def _drive(monkeypatch, source, *, outcomes=None, answer="YES"):
    """Real worker execution; only the external service boundary is supplied."""
    procedure = _procedure(source)
    thread, control, output = _start_worker(monkeypatch, procedure, execution_id="composition19")
    seen = []
    variables = {}
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            message, _ = _next(output, lambda item: True)
            seen.append(message)
            kind = message["kind"]
            if kind == "step_commit": variables = message["variables"]
            elif kind == "prompt_opened":
                control.put({"type":"prompt_settlement", "prompt_id":message["prompt_id"],
                    "settlement_id":f'answer-{message["step_index"]}', "outcome":"ANSWERED", "response":answer})
            elif kind == "observation_requested":
                operation = message["operation"]
                payload = (outcomes or {}).get(operation, {"GET_TM":{"outcome":"OK", "value":28.0},
                    "VERIFY":{"outcome":"TRUE"}, "WAIT_FOR":{"outcome":"SATISFIED"}}[operation])
                control.put({"type":"observation_result", **canonicalize_observation_result(_request(message), payload)})
            elif kind == "telecommand_requested":
                request, service, preflight = validate_send_request("composition19", message["step_index"],
                    procedure.steps[message["step_index"]], variables, _request(message))
                control.put({"type":"telecommand_result", **execute_preflight(request, service, preflight,
                    confirmation_actor="worker-test-boundary" if preflight.confirmation_required else None)})
            elif kind == "terminal":
                return message, seen
        pytest.fail("composition worker did not terminate")
    finally:
        if thread.is_alive(): control.put({"type":"abort", "command_id":"test-cleanup"})
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_full_read_verify_wait_prompt_guard_and_confirmed_command_execute_in_order(monkeypatch):
    source = ('reading: float = 0.0\nstatus: str = ""\nitem = BuildTC("CMDNAME")\n'
              'GetTM("TM.POWER.BUS", target=reading, scalar_type="float")\n'
              f'Verify(condition={_condition()!r}, target=status, timeout=1)\nWaitFor(seconds=0)\n'
              'answer = Prompt("Proceed?", YES_NO)\n'
              'if reading >= 27.5 and status == "TRUE" and answer == "YES" and 2 ** 3 == 8:\n'
              '    Send(command=item, Confirm=True)\nDisplay("")\n')
    terminal, seen = _drive(monkeypatch, source)
    assert terminal["state"] == "completed"
    assert [message["operation"] for message in seen if message["kind"] == "observation_requested"] == ["GET_TM", "VERIFY", "WAIT_FOR"]
    prompts = [message for message in seen if message["kind"] == "prompt_opened"]
    assert len(prompts) == 2 and prompts[0]["prompt_id"] != prompts[1]["prompt_id"]
    assert len([message for message in seen if message["kind"] == "telecommand_requested"]) == 1
    commits = [message for message in seen if message["kind"] == "step_commit"]
    assert commits[-1]["variables"]["reading"] == 28.0
    assert commits[-1]["variables"]["status"] == "TRUE"
    effects = [effect for commit in commits for effect in commit["effects"] if effect["event_type"] == "procedure.observation_settled"]
    assert len(effects) == 3
    assert all(set(effect["payload"]) == {"request_id", "operation", "outcome", "step_index"} for effect in effects)


@pytest.mark.parametrize("outcome", ["TRUE", "FALSE", "INDETERMINATE", "TIMED_OUT", "CANCELLED", "REJECTED"])
def test_verify_replaces_previous_success_and_only_explicit_true_dispatches(monkeypatch, outcome):
    source = ('status = "TRUE"\n'
              f'Verify(condition={_condition()!r}, target=status, timeout=1)\n'
              'if status == "TRUE":\n    Send(command="CMDNAME")\n')
    terminal, seen = _drive(monkeypatch, source, outcomes={"VERIFY":{"outcome":outcome}})
    assert terminal["state"] == "completed"
    assert [message for message in seen if message["kind"] == "step_commit"][-1]["variables"]["status"] == outcome
    assert len([message for message in seen if message["kind"] == "telecommand_requested"]) == int(outcome == "TRUE")


@pytest.mark.parametrize("outcome", ["NOT_FOUND", "NOT_AVAILABLE", "DEADLINE_EXCEEDED", "CANCELLED", "GAP",
                                    "STALE_GENERATION", "CLOCK_UNCERTAIN", "CONTRACT_MISMATCH", "INTERNAL"])
def test_failed_get_tm_cannot_commit_a_reading_or_request_later_command(monkeypatch, outcome):
    source = 'reading: float = 99.0\nGetTM("TM.A", target=reading, scalar_type="float")\nSend(command="CMDNAME")\n'
    terminal, seen = _drive(monkeypatch, source, outcomes={"GET_TM":{"outcome":outcome}})
    assert terminal["state"] == "failed"
    assert not any(message["kind"] == "telecommand_requested" for message in seen)
    assert [message["step_index"] for message in seen if message["kind"] == "step_commit"] == [0]


@pytest.mark.parametrize("outcome", ["TIMED_OUT", "CANCELLED", "FAILED"])
def test_failed_wait_for_cannot_advance_to_prompt_or_command(monkeypatch, outcome):
    terminal, seen = _drive(monkeypatch, 'WaitFor(seconds=0)\nPrompt("Proceed")\nSend(command="CMDNAME")\n',
                            outcomes={"WAIT_FOR":{"outcome":outcome}})
    assert terminal["state"] == "failed"
    assert not any(message["kind"] in {"step_commit", "prompt_opened", "telecommand_requested"} for message in seen)


@pytest.mark.parametrize("scalar_type,initial,value", [("float", "0.0", 28.0), ("int", "0", 3), ("bool", "False", True), ("str", '""', "ready")])
def test_exact_scalar_result_flows_to_native_display(monkeypatch, scalar_type, initial, value):
    terminal, seen = _drive(monkeypatch,
        f'reading: {scalar_type} = {initial}\nGetTM("TM.A", target=reading, scalar_type="{scalar_type}")\nPrompt("Done")\n',
        outcomes={"GET_TM":{"outcome":"OK", "value":value}}, answer="OK")
    assert terminal["state"] == "completed"
    actual = [message for message in seen if message["kind"] == "step_commit"][-1]["variables"]["reading"]
    assert actual == value and type(actual) is type(value)


@pytest.mark.parametrize("command,target", [("skip", None), ("goto", 0), ("goto", 2)])
def test_paused_observation_denies_all_skip_and_goto_without_advancing(monkeypatch, command, target):
    procedure = _procedure('reading: float = 0.0\nGetTM("TM.A", target=reading, scalar_type="float")\nSend(command="CMDNAME")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    try:
        requested, _ = _next(output, lambda message: message.get("kind") == "observation_requested")
        control.put({"type":"pause", "command_id":"pause"})
        _next(output, lambda message: message.get("kind") == "state" and message.get("state") == "paused")
        control.put({"type":command, "command_id":"bypass", "target_step":target})
        rejected, seen = _next(output, lambda message: message.get("kind") == "command_rejected" and message.get("command_id") == "bypass")
        assert rejected["code"] == "OBSERVATION_NAVIGATION_FORBIDDEN"
        assert not any(message.get("kind") in {"step_commit", "telecommand_requested"} for message in seen)
        control.put({"type":"abort", "command_id":"stop"})
        terminal, seen = _next(output, lambda message: message.get("kind") == "terminal")
        assert terminal["state"] == "aborted"
        assert not any(message.get("kind") == "telecommand_requested" for message in seen)
        assert requested["step_index"] == 1
    finally:
        control.put({"type":"abort", "command_id":"cleanup"})
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("mutation", ["identity", "execution", "step", "operation", "value-type", "extra-field"])
def test_malformed_observation_result_is_rejected_and_later_valid_result_advances_once(monkeypatch, mutation):
    procedure = _procedure('reading: float = 0.0\nGetTM("TM.A", target=reading, scalar_type="float")\nPrompt("Done")\n')
    thread, control, output = _start_worker(monkeypatch, procedure)
    try:
        requested, _ = _next(output, lambda message: message.get("kind") == "observation_requested")
        result = canonicalize_observation_result(_request(requested), {"outcome":"OK", "value":28.0})
        forged = deepcopy(result)
        if mutation == "identity": forged["request_id"] = "wrong"
        elif mutation == "execution": forged["execution_id"] = "other"
        elif mutation == "step": forged["step_index"] += 1
        elif mutation == "operation": forged["operation"] = "VERIFY"
        elif mutation == "value-type": forged["value"] = "28.0"
        elif mutation == "extra-field": forged["expression"] = "eval"
        control.put({"type":"observation_result", **forged})
        _, seen = _next(output, lambda message: message.get("kind") == "command_rejected")
        assert not any(message.get("kind") == "step_commit" for message in seen)
        control.put({"type":"observation_result", **result})
        opened, seen = _next(output, lambda message: message.get("kind") == "prompt_opened")
        assert len([message for message in seen if message.get("kind") == "step_commit"]) == 1
        control.put({"type":"observation_result", **result})
        control.put({"type":"prompt_settlement", "prompt_id":opened["prompt_id"], "settlement_id":"final", "outcome":"ANSWERED", "response":"OK"})
        terminal, seen = _next(output, lambda message: message.get("kind") == "terminal")
        assert terminal["state"] == "completed"
        assert not any(message.get("kind") == "observation_requested" for message in seen)
    finally:
        control.put({"type":"abort", "command_id":"cleanup"})
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_restart_at_observation_retains_original_request_identity_and_checkpoint(monkeypatch):
    procedure = _procedure('reading: float = 0.0\nanswer = Prompt("Read?", YES_NO)\nGetTM("TM.A", target=reading, scalar_type="float", mode="NEXT")\nDisplay("")\n')
    step = next(step for step in procedure.steps if step["type"] == "get_tm")
    expected_request = observation_request_for_step("restart19", step)
    thread, control, output = _start_worker(monkeypatch, procedure, execution_id="restart19", start_step=step["index"],
        checkpoint_variables={"answer":"YES", "reading":0.0})
    try:
        requested, _ = _next(output, lambda message: message.get("kind") == "observation_requested")
        assert _request(requested) == expected_request
        control.put({"type":"observation_result", **canonicalize_observation_result(expected_request, {"outcome":"OK", "value":29.0})})
        terminal, seen = _next(output, lambda message: message.get("kind") == "terminal")
        assert terminal["state"] == "completed"
        commits = [message for message in seen if message.get("kind") == "step_commit"]
        assert commits[0]["variables"] == {"answer":"YES", "reading":29.0}
    finally:
        control.put({"type":"abort", "command_id":"cleanup"})
        thread.join(timeout=2)
        assert not thread.is_alive()
