from __future__ import annotations

import copy

import pytest

from backend.ir_v11 import (
    V11ValidationError,
    telecommand_dependency_variables,
    validate_ir_v11,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


_OVERSIZED_INTEGER_LITERAL = "0x" + ("f" * 1_025)


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source,
        "telecommand-v11.spell.py",
    )


def test_example_60_command_name_and_command_item_forms_compile_independently() -> None:
    literal = _parse("Send(command = 'CMDNAME')\n")
    item = _parse(
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command = tc_item)\n"
    )

    assert literal.ir_version == "0.11"
    assert literal.steps[0]["selector"] == {"kind": "command", "value": "CMDNAME"}
    assert item.ir_version == "0.11"
    build = next(step for step in item.steps if step["type"] == "build_tc")
    send = next(step for step in item.steps if step["type"] == "send_tc")
    assert build["target"] == "tc_item"
    assert build["target_declaration"] is True
    assert send["selector"] == {
        "kind": "command",
        "value": {"expr": "telecommand_item", "name": "tc_item"},
    }


def test_documented_command_argument_and_time_forms_are_bounded() -> None:
    procedure = _parse(
        "tc_item = BuildTC('CMDNAME', args=[[\"ARG1\", 1.0], "
        "[\"ARG2\", 0xFF, {Radix: HEX}]])\n"
        "Send(command=tc_item, Time=NOW + 30*MINUTE, Timeout=60, "
        "verify=[[\"TMparam\", eq, 10]])\n"
        "Send(command='CMDNAME', ReleaseTime='2008/04/10 10:30:00', "
        "args={\"ARG1\": 1.0})\n"
    )

    build = next(step for step in procedure.steps if step["type"] == "build_tc")
    sends = [step for step in procedure.steps if step["type"] == "send_tc"]
    first_send, second_send = sends
    assert build["arguments"][1] == ["ARG2", 255, {"Radix": "HEX"}]
    assert first_send["modifiers"] == {
        "time": "NOW+1800s",
        "timeout_seconds": 60,
        "verification": [["TMparam", "eq", 10]],
    }
    assert second_send["modifiers"]["release_time"] == "2008/04/10 10:30:00"
    assert second_send["arguments"] == {"ARG1": 1.0}


def test_sequence_group_block_and_per_command_modifier_forms_compile() -> None:
    procedure = _parse(
        "one = BuildTC('CMDNAME')\n"
        "two = BuildTC('CMDNAME')\n"
        "Send(sequence='SIM_SEQUENCE')\n"
        "Send(group=['CMD1', 'CMD2', 'CMD3'])\n"
        "Send(group=[one, two], Group=True, Block=True, SendDelay=1*MINUTE, "
        "PerCommand={\"1\": {\"timeout_seconds\": 30}})\n"
    )

    assert [step["type"] for step in procedure.steps] == [
        "variable_set",
        "build_tc",
        "variable_set",
        "build_tc",
        "send_tc",
        "send_tc",
        "send_tc",
    ]
    sends = [step for step in procedure.steps if step["type"] == "send_tc"]
    assert sends[0]["selector"] == {
        "kind": "sequence",
        "value": "SIM_SEQUENCE",
    }
    assert sends[1]["selector"]["value"] == ["CMD1", "CMD2", "CMD3"]
    assert sends[2]["modifiers"] == {
        "group": True,
        "block": True,
        "send_delay_seconds": 60,
        "per_command": {"1": {"timeout_seconds": 30}},
    }


def test_per_command_documented_aliases_are_normalized_recursively() -> None:
    procedure = _parse(
        "Send(group=['CMD1'], PerCommand={'0': {"
        "'Timeout': 30*SECOND, 'OnFailure': CONTINUE, 'PromptUser': False, "
        "'verify': [['TM1', eq, 1]], 'AdjLimits': True}})\n"
    )

    assert procedure.steps[0]["modifiers"]["per_command"] == {
        "0": {
            "timeout_seconds": 30,
            "on_failure": "CONTINUE",
            "prompt_user": False,
            "verification": [["TM1", "eq", 1]],
            "adjust_limits": True,
        }
    }


def test_latest_unconditional_build_binding_controls_static_conflict_analysis() -> None:
    procedure = _parse(
        "tc_item = BuildTC('CMD1', LoadOnly=True)\n"
        "tc_item = BuildTC('CMD1')\n"
        "Send(command=tc_item, verify=[['TM1', eq, 1]])\n"
    )

    assert procedure.steps[-1]["type"] == "send_tc"


def test_telecommand_dependency_analysis_closes_transitive_assignments_and_guards() -> None:
    procedure = _parse(
        "base: str = 'CMDNAME'\n"
        "alias: str = base\n"
        "enabled: bool = True\n"
        "if enabled:\n"
        "    Send(command=alias)\n"
    )

    dependencies = telecommand_dependency_variables(list(procedure.steps))

    assert {"base", "alias", "enabled"} <= dependencies


def test_user_action_cannot_mutate_a_telecommand_dependency() -> None:
    with pytest.raises(
        ProcedureValidationError, match="cannot mutate a telecommand dependency"
    ):
        _parse(
            'UserAction("redirect", "Redirect", handler=['
            '{"op":"SET_LITERAL","name":"tc_name",'
            '"declared_type":"str","value":"CMD2"}])\n'
            "tc_name: str = 'CMDNAME'\n"
            "Send(command=tc_name)\n"
        )


def test_block_false_remains_a_noop_for_a_command_selector() -> None:
    procedure = _parse("Send(command='CMDNAME', Block=False)\n")

    assert procedure.steps[0]["selector"]["kind"] == "command"
    assert procedure.steps[0]["modifiers"] == {"block": False}


@pytest.mark.parametrize(
    "source, message",
    [
        ("Send()\n", "exactly one"),
        ("Send(command='CMD', sequence='SEQ')\n", "exactly one"),
        ("Send(group=[])\n", "1 through 16"),
        ("Send(sequence='SEQ', args={\"A\": 1})\n", "accepted only with command"),
        (
            "Send(command='CMDNAME', Group=True)\n",
            "Group modifier must be True and is only valid with a group selector",
        ),
        (
            "Send(group=['CMD1'], Group=False)\n",
            "Group modifier must be True and is only valid with a group selector",
        ),
        (
            "Send(command='CMDNAME', Block=True)\n",
            "Block=True is only valid with a group selector",
        ),
        (
            "tc_item = BuildTC('CMDNAME')\n"
            "Send(command=tc_item, args=[[\"ARG1\", 1.0]])\n",
            "args cannot accompany a prebuilt telecommand item",
        ),
        (
            "tc_item = BuildTC('CMDNAME')\n"
            "Send(command=tc_item, args={})\n",
            "args cannot accompany a prebuilt telecommand item",
        ),
        (
            "Send(command='CMDNAME', LoadOnly=True, "
            "verify=[[\"TM1\", eq, 1]])\n",
            "LoadOnly conflicts with verification",
        ),
        (
            "Send(command='CMDNAME', LoadOnly=True, ReleaseTime=NOW)\n",
            "LoadOnly conflicts with ReleaseTime",
        ),
        (
            "Send(command='CMDNAME', AdjLimits=True)\n",
            "AdjLimits requires verification",
        ),
        (
            "tc_item = BuildTC('CMD1', LoadOnly=True)\n"
            "Send(command=tc_item, verify=[['TM1', eq, 1]])\n",
            "compiled IR failed independent validation",
        ),
        (
            "tc_item = BuildTC('CMD1', ReleaseTime=NOW)\n"
            "Send(command=tc_item, LoadOnly=True)\n",
            "compiled IR failed independent validation",
        ),
        (
            f"Send(command='CMDNAME', Timeout={_OVERSIZED_INTEGER_LITERAL})\n",
            "4096-bit safety limit",
        ),
        (
            f"Send(command='CMDNAME', Time={_OVERSIZED_INTEGER_LITERAL})\n",
            "4096-bit safety limit",
        ),
        (
            f"Send(command='CMDNAME', args={{'ARG1': {_OVERSIZED_INTEGER_LITERAL}}})\n",
            "4096-bit safety limit",
        ),
        ("Send(command='CMD', Resend=True)\n", "unsupported keyword"),
        ("tc = BuildTC(dynamic())\n", "string or telecommand"),
    ],
)
def test_unsafe_or_ambiguous_command_forms_fail_closed(source: str, message: str) -> None:
    with pytest.raises(ProcedureValidationError, match=message):
        _parse(source)


def test_telecommand_item_cannot_escape_as_a_scalar() -> None:
    with pytest.raises(ProcedureValidationError, match="telecommand item"):
        _parse(
            "value: str = ''\n"
            "tc_item = BuildTC('CMDNAME')\n"
            "value = tc_item\n"
        )


def test_v011_ir_rejects_selector_modifier_and_target_tampering() -> None:
    procedure = _parse(
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command=tc_item)\n"
    )
    steps = [copy.deepcopy(step) for step in procedure.steps]

    selector_tamper = copy.deepcopy(steps)
    send_index = next(index for index, step in enumerate(selector_tamper) if step["type"] == "send_tc")
    selector_tamper[send_index]["selector"]["extra"] = True
    with pytest.raises(V11ValidationError, match="unknown field extra"):
        validate_ir_v11("0.11", selector_tamper)

    modifier_tamper = copy.deepcopy(steps)
    send_index = next(index for index, step in enumerate(modifier_tamper) if step["type"] == "send_tc")
    modifier_tamper[send_index]["modifiers"]["resend"] = True
    with pytest.raises(V11ValidationError, match="unknown modifier resend"):
        validate_ir_v11("0.11", modifier_tamper)

    target_tamper = copy.deepcopy(steps)
    build_index = next(index for index, step in enumerate(target_tamper) if step["type"] == "build_tc")
    target_tamper[build_index]["target_type"] = "int"
    with pytest.raises(V11ValidationError, match="target metadata"):
        validate_ir_v11("0.11", target_tamper)


def test_v011_ir_rejects_static_send_control_conflicts() -> None:
    literal = _parse("Send(command='CMDNAME')\n")

    grouped_command = [copy.deepcopy(step) for step in literal.steps]
    grouped_command[0]["modifiers"] = {"group": True}
    with pytest.raises(V11ValidationError, match="only valid with a group selector"):
        validate_ir_v11("0.11", grouped_command)

    blocked_command = [copy.deepcopy(step) for step in literal.steps]
    blocked_command[0]["modifiers"] = {"block": True}
    with pytest.raises(V11ValidationError, match="Block=True"):
        validate_ir_v11("0.11", blocked_command)

    group = _parse("Send(group=['CMD1'])\n")
    disabled_group = [copy.deepcopy(step) for step in group.steps]
    disabled_group[0]["modifiers"] = {"group": False}
    with pytest.raises(V11ValidationError, match="Group modifier must be True"):
        validate_ir_v11("0.11", disabled_group)

    item = _parse("tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n")
    item_with_args = [copy.deepcopy(step) for step in item.steps]
    item_with_args[-1]["arguments"] = [["ARG1", 1.0]]
    with pytest.raises(V11ValidationError, match="prebuilt telecommand item"):
        validate_ir_v11("0.11", item_with_args)


def test_v011_ir_rejects_modifier_conflicts_and_oversized_numbers() -> None:
    literal = _parse("Send(command='CMDNAME')\n")

    for modifiers, message in (
        (
            {"load_only": True, "verification": [["TM1", "eq", 1]]},
            "LoadOnly conflicts with verification",
        ),
        (
            {"load_only": True, "release_time": "NOW"},
            "LoadOnly conflicts with ReleaseTime",
        ),
        ({"adjust_limits": True}, "AdjLimits requires verification"),
    ):
        tampered = [copy.deepcopy(step) for step in literal.steps]
        tampered[0]["modifiers"] = modifiers
        with pytest.raises(V11ValidationError, match=message):
            validate_ir_v11("0.11", tampered)

    item = _parse("tc_item = BuildTC('CMD1')\nSend(command=tc_item)\n")
    build_index = next(
        index for index, step in enumerate(item.steps) if step["type"] == "build_tc"
    )
    send_index = next(
        index for index, step in enumerate(item.steps) if step["type"] == "send_tc"
    )
    cross_step = [copy.deepcopy(step) for step in item.steps]
    cross_step[build_index]["modifiers"] = {"load_only": True}
    cross_step[send_index]["modifiers"] = {
        "verification": [["TM1", "eq", 1]]
    }
    with pytest.raises(V11ValidationError, match="effective command modifiers conflict"):
        validate_ir_v11("0.11", cross_step)

    oversized = int("f" * 1_025, 16)
    for field, value in (
        ("modifiers", {"timeout_seconds": oversized}),
        ("modifiers", {"time": oversized}),
        ("arguments", {"ARG1": oversized}),
    ):
        tampered = [copy.deepcopy(step) for step in literal.steps]
        tampered[0][field] = value
        with pytest.raises(V11ValidationError, match="4096-bit safety limit"):
            validate_ir_v11("0.11", tampered)


def test_v011_rejects_unbrokered_capability_mixing() -> None:
    with pytest.raises(ProcedureValidationError, match="independent validation"):
        _parse(
            "value: float = 0.0\n"
            "Send(command='CMDNAME')\n"
            "GetTM('TM.POWER.BUS_VOLTAGE', target=value, scalar_type='float')\n"
        )


def test_legacy_ir_selection_is_unchanged() -> None:
    assert _parse("Log('legacy')\n").ir_version == "0.3"
    assert _parse("Prompt('typed', type='OK')\n").ir_version == "0.6"
    assert (
        _parse("result: str = ''\nReferenceExample(60, target=result)\n").ir_version
        == "0.10"
    )


def test_tampered_telecommand_variable_references_are_rejected() -> None:
    procedure = _parse("tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n")
    tampered = [copy.deepcopy(step) for step in procedure.steps]
    tampered[-1]["selector"] = {
        "kind": "command",
        "value": {"expr": "variable", "name": "missing"},
    }

    with pytest.raises(V11ValidationError, match="declared string variable"):
        validate_ir_v11("0.11", tampered)

    tampered = [copy.deepcopy(step) for step in procedure.steps]
    tampered[1]["command"] = {"expr": "variable", "name": "missing"}
    with pytest.raises(V11ValidationError, match="literal catalog name"):
        validate_ir_v11("0.11", tampered)


def test_build_tc_rejects_send_only_control_modifiers() -> None:
    procedure = _parse("tc_item = BuildTC('CMDNAME')\n")
    tampered = [copy.deepcopy(step) for step in procedure.steps]
    tampered[-1]["modifiers"] = {"block": True}

    with pytest.raises(V11ValidationError, match="BuildTC does not accept block"):
        validate_ir_v11("0.11", tampered)


def test_send_confirmation_prompt_can_resume_at_the_same_step() -> None:
    procedure = _parse("Send(command='CMDNAME', Confirm=True)\n")

    resumed = validate_ir_v11(
        "0.11",
        list(procedure.steps),
        start_step=0,
        resume_prompt_id="confirmation-prompt",
        resume_prompt_step=0,
        checkpoint_variables={},
    )

    assert resumed.steps[0]["type"] == "send_tc"
