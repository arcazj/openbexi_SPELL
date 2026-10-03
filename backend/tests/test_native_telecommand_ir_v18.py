"""Closed native/TC composition, projection boundaries, and prior IR stability."""
from __future__ import annotations

from copy import deepcopy

import pytest

from backend import development_analysis
from backend.ir_v11 import validate_ir_v11
from backend.ir_v17 import validate_ir_v17
from backend.ir_v18 import V18ValidationError, validate_ir_v18
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


WORKFLOW = '''item = BuildTC("CMDNAME", args=[["ARG1", 1.0]])
answer = Prompt("Send command?", YES_NO)
mask = 2 ** 3 | 1
if answer == "YES" and mask & 1 == 1:
    Send(command=item, Confirm=True)
Display("")
'''


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source)


def test_native_prompt_core_and_built_command_have_closed_composite_ir() -> None:
    procedure = _parse(WORKFLOW)
    assert procedure.ir_version == "0.18"
    steps = list(procedure.steps)
    validated = validate_ir_v18("0.18", steps)
    assert validated.steps == steps
    assert validated.variable_types["answer"] == "str"
    assert validated.variable_types["mask"] == "int"
    assert [step["index"] for step in steps] == list(range(len(steps)))
    assert len([step for step in steps if step.get("name") == "answer"]) == 0
    assert next(step for step in steps if step["type"] == "prompt")["response_target_declaration"] is True
    assert next(step for step in steps if step["type"] == "send_tc")["guard"]["expr"] == "variable"
    for version, validator in [("0.11", validate_ir_v11), ("0.17", validate_ir_v17)]:
        with pytest.raises(ValueError):
            validator(version, steps)


@pytest.mark.parametrize("source,version", [
    ('command = "CMDNAME"\nSend(command=command)\n', "0.11"),
    ('item = BuildTC("CMDNAME")\nSend(command=item)\n', "0.11"),
    ('text = "ready"\nSend(command="CMDNAME")\nDisplay(text)\n', "0.11"),
    ('answer = Prompt("Question", YES_NO)\nDisplay(answer)\n', "0.17"),
    ('value = 2 ** 3\nDisplay("ready")\n', "0.17"),
    ('Prompt("Question", type="YES_NO")\nSend(command="CMDNAME")\n', "0.11"),
])
def test_prior_source_profiles_keep_their_contract(source: str, version: str) -> None:
    assert _parse(source).ir_version == version


@pytest.mark.parametrize("source,diagnostic", [
    ('answer = Prompt("Name", ALPHA)\nSend(command=answer)\n', "SPELL938"),
    ('answer = Prompt("Name", ALPHA)\nSend(sequence=answer)\n', "SPELL938"),
    ('answer = Prompt("Name", ALPHA)\nSend(group=[answer])\n', "SPELL938"),
    ('answer = Prompt("Argument", NUM)\nSend(command="CMDNAME", args={"ARG1": answer})\n', "SPELL914"),
    ('item = BuildTC("CMDNAME")\nitem = Prompt("Name", ALPHA)\n', "SPELL913"),
    ('Prompt("Question")\nDataContainer("LOCAL.DATA")\nSend(command="CMDNAME")\n', "SPELL937"),
    ('ARGS(name="str")\nPrompt("Question")\nSend(command="CMDNAME")\n', "SPELL937"),
    ('value: float = 0.0\nGetTM("TM.A", target=value, scalar_type="float")\nPrompt("Question")\nSend(command="CMDNAME")\n', "SPELL937"),
    ('WaitFor(seconds=1)\nPrompt("Question")\nSend(command="CMDNAME")\n', "SPELL937"),
    ('name: str = ""\nFile("PROJECT_DATA", "sample.txt", property="basename", target=name)\nPrompt("Question")\nSend(command="CMDNAME")\n', "SPELL937"),
    ('result = ""\nLanguageCheck(0, profile="0.18", target=result)\nSend(command="CMDNAME")\n', "SPELL937"),
])
def test_out_of_scope_source_combinations_are_explicit(source: str, diagnostic: str) -> None:
    with pytest.raises(ProcedureValidationError) as exc:
        _parse(source)
    assert exc.value.diagnostics[0].code == diagnostic


@pytest.mark.parametrize("mutation", [
    "version", "boolean-index", "target-index", "duplicate-reachability", "duplicate-label",
    "frame-path", "prompt-type", "prompt-declaration", "prompt-item-target", "scalar-item-write",
    "scalar-selector", "missing-item", "boolean-command", "argument-expression", "unknown-modifier",
    "modifier-unhashable", "data", "file", "environment", "observation", "argument-declarations",
    "reference", "core-untyped", "prompt-unknown-field",
])
def test_forged_composite_ir_fails_before_execution(mutation: str) -> None:
    steps = deepcopy(list(_parse(WORKFLOW).steps))
    version = "0.18"
    prompt = next(step for step in steps if step["type"] == "prompt")
    build = next(step for step in steps if step["type"] == "build_tc")
    send = next(step for step in steps if step["type"] == "send_tc")
    if mutation == "version": version = "0.17"
    elif mutation == "boolean-index": steps[0]["index"] = False
    elif mutation == "target-index": prompt["step_over_target"] = len(steps) + 1
    elif mutation == "duplicate-reachability": prompt["reachability_id"] = steps[0]["reachability_id"]
    elif mutation == "duplicate-label":
        steps[0]["labels"] = prompt["labels"] = [{"name": "again", "frame_id": "root"}]
    elif mutation == "frame-path": prompt["lexical_frame_path"] = ["wrong"]
    elif mutation == "prompt-type": prompt["response_target_type"] = "int"
    elif mutation == "prompt-declaration": prompt["response_target_declaration"] = False
    elif mutation == "prompt-item-target":
        prompt["response_target"] = "item"
        prompt["response_target_declaration"] = False
    elif mutation == "scalar-item-write": steps[0]["expression"]["value"] = "forged"
    elif mutation == "scalar-selector": send["selector"]["value"] = {"expr": "variable", "name": "answer"}
    elif mutation == "missing-item": send["selector"]["value"]["name"] = "missing"
    elif mutation == "boolean-command": build["command"] = True
    elif mutation == "argument-expression": build["arguments"] = {"expr": "variable", "name": "answer"}
    elif mutation == "unknown-modifier": send["modifiers"]["callable"] = "eval"
    elif mutation == "modifier-unhashable": send["modifiers"]["on_failure"] = []
    elif mutation in {"data", "file", "environment", "observation", "reference"}:
        send["type"] = {"data": "data_operation", "file": "file_operation", "environment": "environment_operation",
                        "observation": "get_tm", "reference": "reference_example"}[mutation]
    elif mutation == "argument-declarations": steps[0]["argument_declarations"] = {"name": "str"}
    elif mutation == "core-untyped":
        step = next(step for step in steps if step.get("name") == "mask")
        step["expression"]["left"]["left"]["value"] = True
    elif mutation == "prompt-unknown-field": prompt["execute"] = "untrusted"
    with pytest.raises(ValueError):
        validate_ir_v18(version, steps)


def test_prompt_atomic_checkpoint_and_send_resume_use_original_indices() -> None:
    procedure = _parse('item = BuildTC("CMDNAME")\nanswer = Prompt("First", YES_NO)\n'
                       'count = Prompt("Second", ["one", "two"], Type=LIST|NUM)\n'
                       'Send(command=item, Confirm=True)\nDisplay("")\n')
    steps = list(procedure.steps)
    prompts = [step for step in steps if step["type"] == "prompt"]
    first, second = [step["index"] for step in prompts]
    send = next(step["index"] for step in steps if step["type"] == "send_tc")
    states = [(first, {"item": "opaque-item"}, "first"),
              (second, {"item": "opaque-item", "answer": "YES"}, "second"),
              (send, {"item": "opaque-item", "answer": "YES", "count": 1}, "confirm")]
    for position, checkpoint, prompt_id in states:
        validated = validate_ir_v18("0.18", steps, start_step=position,
            resume_prompt_id=prompt_id, resume_prompt_step=position,
            checkpoint_variables=checkpoint, expected_total_steps=len(steps))
        assert validated.steps == steps
        assert validated.checkpoint_variables == checkpoint
    with pytest.raises(ValueError):
        validate_ir_v18("0.18", steps, start_step=first, checkpoint_variables={"item": "opaque-item", "answer": "YES"})
    with pytest.raises(ValueError):
        validate_ir_v18("0.18", steps, start_step=second, checkpoint_variables={"item": "opaque-item"})
    with pytest.raises(ValueError):
        validate_ir_v18("0.18", steps, start_step=send, checkpoint_variables={"item": "opaque-item", "answer": "YES", "count": 1.0})


def test_nested_call_targets_survive_private_prompt_declarations() -> None:
    source = '''answer: str = ""
def ask():
    answer = Prompt("Proceed?", YES_NO)
    if answer == "YES":
        Send(command="CMDNAME")
    Display("")
ask()
Display("done")
'''
    procedure = _parse(source)
    steps = list(procedure.steps)
    before = deepcopy(steps)
    validated = validate_ir_v18("0.18", steps)
    assert validated.steps == before == steps
    assert any(step["call_boundary_id"] is not None for step in steps)
    assert any(step["step_over_target"] > step["index"] + 1 for step in steps)


def test_native_seven_day_warning_survives_tc_projection() -> None:
    procedure = _parse('Prompt("Wait", Timeout=7*24*HOUR)\nSend(command="CMDNAME")\n')
    validated = validate_ir_v18("0.18", list(procedure.steps))
    assert validated.steps[0]["warning_delay_seconds"] == 604800
    assert validated.steps[0]["response_timeout_seconds"] is None


def test_existing_closed_temporal_forms_remain_available_in_native_tc_profile() -> None:
    procedure = _parse('Prompt("Send?")\nSend(command="CMDNAME", Time=NOW+30*MINUTE, Timeout=60)\n')
    send = next(step for step in procedure.steps if step["type"] == "send_tc")
    assert procedure.ir_version == "0.18"
    assert send["modifiers"] == {"time": "NOW+1800s", "timeout_seconds": 60}


@pytest.mark.parametrize("field,value", [
    ("start_step", True), ("start_step", -1), ("start_step", 1000),
    ("expected_total_steps", True), ("expected_total_steps", 0),
    ("resume_prompt_step", True), ("resume_prompt_step", 2),
    ("resume_prompt_id", []), ("checkpoint_variables", []),
])
def test_recovery_metadata_rejects_wrong_types_and_positions(field, value) -> None:
    with pytest.raises(ValueError):
        validate_ir_v18("0.18", list(_parse(WORKFLOW).steps), **{field: value})


@pytest.mark.parametrize("source", [
    'Send(command="CMDNAME")\n', 'Prompt("Question")\n', 'value = 2 ** 3\nDisplay("ready")\n',
])
def test_relabeling_prior_ir_cannot_create_composite_authority(source: str) -> None:
    with pytest.raises(V18ValidationError):
        validate_ir_v18("0.18", list(_parse(source).steps))


def test_development_cache_uses_new_profile_and_tool_identity() -> None:
    source = '# @procedure local/native-tc\n# @language-profile spell-lrm244-conformance/0.18\n' + WORKFLOW
    analysis = development_analysis.analyze_source(source, "procedures/native-tc.spell.py", workspace_revision=1)
    assert analysis.diagnostics == ()
    assert analysis.compiled["procedures/native-tc.spell.py"]["ir_version"] == "0.18"
    assert development_analysis.TOOL_VERSION == "spell-development-analysis/0.18"


@pytest.mark.parametrize("target", ["question", "answer"])
def test_user_action_cannot_mutate_native_command_decision_dependencies(target: str) -> None:
    source = (f'UserAction("change", "Change", handler=[{{"op":"SET_LITERAL","name":"{target}",'
              '"declared_type":"str","value":"changed"}])\n'
              'question = "Send command?"\nanswer = Prompt(question, YES_NO)\n'
              'if answer == "YES":\n    Send(command="CMDNAME")\n')
    with pytest.raises(ProcedureValidationError) as exc:
        _parse(source)
    assert exc.value.diagnostics[0].code == "SPELL803"
    assert "telecommand dependency" in exc.value.diagnostics[0].message
