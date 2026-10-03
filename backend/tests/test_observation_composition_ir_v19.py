"""Closed observation composition and private projection recovery boundaries."""
from copy import deepcopy

import pytest

from backend.ir_v07 import validate_ir_v07
from backend.ir_v11 import validate_ir_v11
from backend.ir_v18 import validate_ir_v18
from backend.ir_v19 import validate_ir_v19
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError
from backend.tests.test_ir_v07 import _condition


WORKFLOW = '''reading: float = 0.0
status: str = ""
item = BuildTC("CMDNAME", args=[["ARG1", 1.0]])
answer = Prompt("Read and command?", YES_NO)
GetTM("TM.POWER.BUS", target=reading, scalar_type="float", mode="NEXT")
Verify(condition=CONDITION, target=status, timeout=2)
WaitFor(seconds=0)
if answer == "YES" and reading >= 27.5 and status == "TRUE" and 2 ** 3 == 8:
    Send(command=item, Confirm=True)
Display("")
'''.replace("CONDITION", repr(_condition()))


def _parse(source):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source, "composition-v19.spell.py")


def test_full_composition_retains_original_indexes_types_and_native_atomic_binding():
    procedure = _parse(WORKFLOW)
    assert procedure.ir_version == "0.19"
    original = list(procedure.steps)
    validated = validate_ir_v19("0.19", original)
    assert validated.steps == original
    assert validated.variable_types["reading"] == "float"
    assert validated.variable_types["status"] == validated.variable_types["answer"] == "str"
    assert not any(step.get("name") == "answer" for step in original)
    assert [step["index"] for step in original] == list(range(len(original)))
    for version, validator in [("0.7", validate_ir_v07), ("0.11", validate_ir_v11), ("0.18", validate_ir_v18)]:
        with pytest.raises(ValueError):
            validator(version, original)


@pytest.mark.parametrize("source,version", [
    ('WaitFor(seconds=0)\nPrompt("Continue")\n', "0.19"),
    ('WaitFor(seconds=0)\nSend(command="CMDNAME")\n', "0.19"),
    ('WaitFor(seconds=0)\nDisplay("")\n', "0.19"),
    ('value = 2 ** 3\nWaitFor(seconds=0)\n', "0.19"),
    ('WaitFor(seconds=0)\n', "0.7"),
    ('WaitFor(seconds=0)\nPrompt("Continue", type="OK")\n', "0.7"),
    ('item = BuildTC("CMDNAME")\nSend(command=item)\n', "0.11"),
    ('Prompt("Continue")\nSend(command="CMDNAME")\n', "0.18"),
    ('Prompt("Continue")\n', "0.17"),
])
def test_version_selection_preserves_prior_standalone_profiles(source, version):
    assert _parse(source).ir_version == version


@pytest.mark.parametrize("source", [
    'Prompt("Continue")\n', 'WaitFor(seconds=0)\n', 'Send(command="CMDNAME")\n',
    'Prompt("Continue")\nSend(command="CMDNAME")\n',
])
def test_relabeling_older_ir_does_not_create_observation_authority(source):
    with pytest.raises(ValueError):
        validate_ir_v19("0.19", list(_parse(source).steps))


@pytest.mark.parametrize("suffix", [
    'DataContainer("LOCAL.DATA")\n', 'ARGS(name="str")\n',
    'name: str = ""\nFile("PROJECT_DATA", "sample.txt", property="basename", target=name)\n',
    'result = ""\nLanguageCheck(0, profile="0.19", target=result)\n',
    'result = ""\nReferenceExample(1, target=result)\n',
    'Goto("next")\n',
])
def test_excluded_service_and_navigation_sources_fail_closed(suffix):
    with pytest.raises(ProcedureValidationError):
        _parse('WaitFor(seconds=0)\nPrompt("Continue")\n' + suffix)


@pytest.mark.parametrize("source", [
    'name = "TM.A"\nvalue: float = 0.0\nGetTM(name, target=value, scalar_type="float")\nPrompt("Go")\n',
    'name = "CMDNAME"\nWaitFor(seconds=0)\nSend(command=name)\n',
    'item = BuildTC("CMDNAME")\nGetTM("TM.A", target=item, scalar_type="str")\nPrompt("Go")\n',
    'item = BuildTC("CMDNAME")\nVerify(condition=CONDITION, target=item)\nPrompt("Go")\n',
    'answer = Prompt("Argument", NUM)\nWaitFor(seconds=0)\nSend(command="CMDNAME", args={"ARG1":answer})\n',
])
def test_literal_operands_and_opaque_items_are_preserved(source):
    with pytest.raises(ProcedureValidationError):
        _parse(source.replace("CONDITION", repr(_condition())))


@pytest.mark.parametrize("mutation", [
    "version", "boolean-index", "duplicate-reachability", "target-index", "unknown-field",
    "get-target-type", "get-id-expression", "get-mode", "get-timeout", "get-unknown",
    "verify-target-type", "verify-condition", "verify-retry", "wait-multiple", "wait-timeout",
    "native-type", "native-declaration", "native-unknown", "opaque-get", "opaque-verify",
    "selector", "argument-expression", "unknown-modifier", "data", "source-goto",
    "core-boolean", "argument-declarations",
])
def test_malformed_composite_ir_is_rejected_before_execution(mutation):
    steps = deepcopy(list(_parse(WORKFLOW).steps))
    version = "0.19"
    get = next(step for step in steps if step["type"] == "get_tm")
    verify = next(step for step in steps if step["type"] == "verify")
    wait = next(step for step in steps if step["type"] == "wait_for")
    prompt = next(step for step in steps if step["type"] == "prompt")
    send = next(step for step in steps if step["type"] == "send_tc")
    if mutation == "version": version = "0.18"
    elif mutation == "boolean-index": steps[0]["index"] = False
    elif mutation == "duplicate-reachability": get["reachability_id"] = steps[0]["reachability_id"]
    elif mutation == "target-index": get["step_over_target"] = len(steps) + 1
    elif mutation == "unknown-field": get["callable"] = "eval"
    elif mutation == "get-target-type": get["target"] = "answer"
    elif mutation == "get-id-expression": get["item_id"] = {"expr":"variable", "name":"answer"}
    elif mutation == "get-mode": get["mode"] = []
    elif mutation == "get-timeout": get["timeout_seconds"] = 3601
    elif mutation == "get-unknown": get["Extended"] = True
    elif mutation == "verify-target-type": verify["target"] = "reading"
    elif mutation == "verify-condition": verify["condition"] = {"expr":"variable", "name":"status"}
    elif mutation == "verify-retry": verify["retry_count"] = True
    elif mutation == "wait-multiple": wait["at"] = "2026-10-03T00:00:00Z"
    elif mutation == "wait-timeout": wait["seconds"] = 604801
    elif mutation == "native-type": prompt["response_target_type"] = "float"
    elif mutation == "native-declaration": prompt["response_target_declaration"] = False
    elif mutation == "native-unknown": prompt["execute"] = "untrusted"
    elif mutation == "opaque-get": get.update(target="item", scalar_type="str")
    elif mutation == "opaque-verify": verify["target"] = "item"
    elif mutation == "selector": send["selector"]["value"] = {"expr":"variable", "name":"answer"}
    elif mutation == "argument-expression": send["arguments"] = {"expr":"variable", "name":"reading"}
    elif mutation == "unknown-modifier": send["modifiers"]["exec"] = "untrusted"
    elif mutation == "data": wait["type"] = "data_operation"
    elif mutation == "source-goto": wait["type"] = "goto"
    elif mutation == "core-boolean":
        branch = next(step for step in steps if step.get("name", "").startswith("__spell_branch_"))
        def corrupt(node):
            if isinstance(node, dict):
                if node.get("expr") == "integer_binary": node["left"] = {"expr":"literal", "value":True}
                else:
                    for value in node.values(): corrupt(value)
            elif isinstance(node, list):
                for value in node: corrupt(value)
        corrupt(branch)
    elif mutation == "argument-declarations": steps[0]["argument_declarations"] = {"name":"str"}
    with pytest.raises(ValueError):
        validate_ir_v19(version, steps)


def test_native_shadow_projection_preserves_observation_and_send_resume_positions():
    source = ('reading: float = 0.0\nitem = BuildTC("CMDNAME")\n'
              'answer = Prompt("First", YES_NO)\ncount = Prompt("Second", ["one", "two"], Type=LIST|NUM)\n'
              'GetTM("TM.A", target=reading, scalar_type="float")\nSend(command=item, Confirm=True)\n')
    steps = list(_parse(source).steps)
    prompt_positions = [step["index"] for step in steps if step["type"] == "prompt"]
    get = next(step["index"] for step in steps if step["type"] == "get_tm")
    send = next(step["index"] for step in steps if step["type"] == "send_tc")
    states = [(prompt_positions[0], {"reading":0.0,"item":"opaque"}, "first"),
              (prompt_positions[1], {"reading":0.0,"item":"opaque","answer":"YES"}, "second"),
              (get, {"reading":0.0,"item":"opaque","answer":"YES","count":1}, None),
              (send, {"reading":28.0,"item":"opaque","answer":"YES","count":1}, "confirm")]
    for index, checkpoint, prompt_id in states:
        validated = validate_ir_v19("0.19", steps, start_step=index, checkpoint_variables=checkpoint,
            resume_prompt_id=prompt_id, resume_prompt_step=index if prompt_id else None, expected_total_steps=len(steps))
        assert validated.steps == steps
        assert validated.checkpoint_variables == checkpoint
    with pytest.raises(ValueError):
        validate_ir_v19("0.19", steps, start_step=get, checkpoint_variables={**states[2][1], "count":1.0})


def test_literal_absolute_wait_is_canonicalized_without_rebasing_its_source_index():
    procedure = _parse('Prompt("Go")\nWaitFor(at="2026-10-03T00:00:00.123456789-04:00")\n')
    assert procedure.steps[1]["at"] == "2026-10-03T04:00:00.123457Z"
    assert procedure.steps[1]["index"] == 1


def test_loop_expansion_gives_each_read_a_distinct_source_step():
    procedure = _parse('reading: float = 0.0\nPrompt("Go")\nfor i in range(3):\n    GetTM("TM.A", target=reading, scalar_type="float")\n')
    positions = [step["index"] for step in procedure.steps if step["type"] == "get_tm"]
    assert len(positions) == len(set(positions)) == 3


def test_user_action_cannot_replace_observation_command_dependency():
    source = ('UserAction("change", "Change", handler=[{"op":"SET_LITERAL","name":"reading",'
              '"declared_type":"float","value":99.0}])\nreading: float = 0.0\n'
              'GetTM("TM.A", target=reading, scalar_type="float")\n'
              'if reading > 27.5:\n    Send(command="CMDNAME")\n')
    with pytest.raises(ProcedureValidationError) as exc:
        _parse(source)
    assert exc.value.diagnostics[0].code == "SPELL803"


def test_forged_get_tm_cannot_overwrite_an_immutable_branch_snapshot():
    procedure = _parse('flag: bool = False\nPrompt("Go")\nif True:\n'
                       '    GetTM("TM.A", target=flag, scalar_type="bool")\n'
                       '    Send(command="CMDNAME")\n')
    steps = deepcopy(list(procedure.steps))
    branch = next(step["name"] for step in steps if step.get("name", "").startswith("__spell_"))
    next(step for step in steps if step["type"] == "get_tm")["target"] = branch
    with pytest.raises(ValueError, match="internal branch snapshot"):
        validate_ir_v19("0.19", steps)
