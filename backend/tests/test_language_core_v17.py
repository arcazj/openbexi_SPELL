"""Core boundaries, legacy service compatibility, and real worker recovery."""
from __future__ import annotations

import multiprocessing
import queue
import time
from copy import deepcopy

import pytest

from backend.core_v17 import CoreV17Error, evaluate_integer_binary
from backend.ir_v03 import IRValidationError, validate_ir_v03
from backend.ir_v17 import validate_ir_v17
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError
from backend.worker import worker_main


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source)


@pytest.mark.parametrize("operator,left,right,expected", [
    ("**", -2, 3, -8), ("**", -2, 2, 4), ("**", 0, 0, 1),
    ("**", -1, 4096, 1), ("**", 2, 4095, 1 << 4095),
    ("&", -6, 3, 2), ("|", -6, 3, -5),
    ("&", (1 << 4096) - 1, -1, (1 << 4096) - 1),
])
def test_integer_evaluation_signed_values_and_exact_bounds(operator, left, right, expected) -> None:
    assert evaluate_integer_binary(operator, left, right) == expected


@pytest.mark.parametrize("operator,left,right", [
    ("**", 2, -1), ("**", 1, 4097), ("**", 2, 4096),
    ("**", True, 1), ("&", 1, 1.0), ("|", 1 << 4096, 0),
    ("^", 1, 2),
])
def test_integer_evaluation_rejects_invalid_values_before_execution(operator, left, right) -> None:
    with pytest.raises(CoreV17Error):
        evaluate_integer_binary(operator, left, right)


@pytest.mark.parametrize("mutation", [
    "operator-list", "extra-field", "call-operand", "bool-operand", "float-operand",
    "negative-exponent", "large-exponent", "unary-operator-list",
])
def test_integer_ir_rejects_malformed_or_untyped_nodes(mutation: str) -> None:
    steps = deepcopy(list(_parse('value = 2 ** 3\nDisplay("result")\n').steps))
    expression = steps[0]["expression"]
    if mutation == "operator-list":
        expression["operator"] = []
    elif mutation == "extra-field":
        expression["source"] = "untrusted"
    elif mutation == "call-operand":
        expression["left"] = {"expr": "call", "name": "eval"}
    elif mutation in {"bool-operand", "float-operand"}:
        expression["left"]["value"] = True if mutation == "bool-operand" else 2.0
    elif mutation == "unary-operator-list":
        expression["right"] = {"expr": "unary", "operator": [], "operand": {"expr": "literal", "value": 1}}
    else:
        expression["right"]["value"] = -1 if mutation == "negative-exponent" else 4097
    with pytest.raises(ValueError):
        validate_ir_v17("0.17", steps)


def test_old_ir_still_rejects_new_integer_nodes() -> None:
    procedure = _parse('value = 2 ** 3\nDisplay("result")\n')
    assert procedure.ir_version == "0.17"
    with pytest.raises(IRValidationError):
        validate_ir_v03("0.3", list(procedure.steps))


_SERVICES = [
    ("data", "0.8", "DataContainer('CONTAINER.A', schema_revision=1)\n"),
    ("arguments", "0.8", "ARGS(mode='str')\nDataContainer('CONTAINER.A', schema_revision=1)\n"),
    ("file", "0.8", "name: str = ''\nFile('PROJECT_DATA', 'folder/item.txt', property='basename', target=name)\n"),
    ("shared", "0.8", "value: str = ''\nGetSharedData('scope', 'key', target=value, scalar_type='str')\n"),
    ("telecommand", "0.11", "tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n"),
]


@pytest.mark.parametrize("_name,version,service", _SERVICES, ids=[row[0] for row in _SERVICES])
@pytest.mark.parametrize("message", ['"ready"', 'message', 'message + " now"'])
def test_existing_display_service_mixes_retain_prior_ir(_name, version, service, message) -> None:
    procedure = _parse(service + f'message = "ready"\nDisplay({message})\n')
    assert procedure.ir_version == version
    assert procedure.steps[-1]["type"] == "log"
    assert not any(step["type"] == "display" for step in procedure.steps)


@pytest.mark.parametrize("_name,_version,service", _SERVICES, ids=[row[0] for row in _SERVICES])
@pytest.mark.parametrize("new_source", [
    'Display("")\n', 'Display("  ")\n', 'Prompt("Confirm")\n',
    'value17 = 2 ** 3\n',
    'result17 = "pending"\nLanguageCheck(0, profile="0.17", target=result17)\n',
])
def test_new_native_capabilities_do_not_expand_service_authority(_name, _version, service, new_source) -> None:
    if _name == "telecommand" and "LanguageCheck" not in new_source:
        procedure = _parse(service + new_source)
        assert procedure.ir_version == "0.18"
        # The new compiler selects the new contract; the stored v0.17
        # validator still rejects this historically unsupported combination.
        with pytest.raises(ValueError):
            validate_ir_v17("0.17", list(procedure.steps))
    else:
        with pytest.raises(ProcedureValidationError) as exc:
            _parse(service + new_source)
        assert exc.value.diagnostics[0].code == "SPELL937"


def _worker(procedure, position: int, checkpoint: dict, *, acknowledge: bool):
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = context.Process(target=worker_main, args=("core-recovery", 1,
        procedure.ir_version, list(procedure.steps), position, "recover", None,
        checkpoint, control, output, None, None, acknowledge))
    process.start()
    return process, control, output


def _stop(process, control, output) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=2)
    if process.is_alive():
        process.kill()
        process.join(timeout=2)
    control.close()
    output.close()
    assert not process.is_alive()


def _messages(output, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            yield output.get(timeout=0.2)
        except queue.Empty:
            continue
    raise AssertionError("worker did not reach its bounded terminal or safe point")


def test_integer_checkpoint_recovers_after_real_worker_loss_without_dead_loop_effects() -> None:
    procedure = _parse('value = 3\nexponent = 5\nresult = value ** exponent\n'
        'for item in range(0):\n    result = 0\n    Display("unreachable")\n'
        'Display("core restored")\n')
    position = next(step["index"] for step in procedure.steps if step.get("name") == "result")
    process, control, output = _worker(procedure, 0, {}, acknowledge=True)
    checkpoint = {}
    try:
        for message in _messages(output):
            if message.get("kind") == "step_commit":
                checkpoint = message["variables"]
            if message.get("kind") == "safe_point":
                if message["step_index"] == position:
                    break
                control.put({"type": "safe_point_ack", "safe_point_token": message["safe_point_token"]})
        assert checkpoint == {"value": 3, "exponent": 5}
        process.terminate()
        process.join(timeout=2)
        assert not process.is_alive() and process.exitcode != 0
    finally:
        _stop(process, control, output)

    results = []
    for _ in range(2):
        process, control, output = _worker(procedure, position, checkpoint, acknowledge=False)
        variables, logs = {}, []
        try:
            for message in _messages(output):
                if message.get("kind") == "step_commit":
                    variables = message["variables"]
                    logs.extend(effect["payload"]["message"] for effect in message["effects"]
                        if effect["event_type"] == "procedure.log")
                if message.get("kind") == "terminal":
                    assert message["state"] == "completed"
                    break
            process.join(timeout=2)
            assert process.exitcode == 0
            assert {key: value for key, value in variables.items() if not key.startswith("__")} == {
                "value": 3, "exponent": 5, "result": 243}
            assert "item" not in variables
            assert logs == ["core restored"]
            results.append((variables, logs))
        finally:
            _stop(process, control, output)
    assert results[0] == results[1]
