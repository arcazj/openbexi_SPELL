from __future__ import annotations

import pytest

from backend.procedure_parser import ProcedureCatalog


COMMAND_CORPUS = (
    ("example-057-v01", "tc_item = BuildTC('CMDNAME')\n"),
    (
        "example-058-v01",
        "tc_item = BuildTC('CMDNAME', args=[[\"ARG1\", 1.0], "
        "[\"ARG2\", 0xFF, {Radix: HEX}]])\n",
    ),
    (
        "example-059-v01",
        "tc_item = BuildTC('CMDNAME', args=[[\"ARG1\", 1.0]])\n",
    ),
    ("example-060-v01", "Send(command='CMDNAME')\n"),
    (
        "example-060-v02",
        "tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n",
    ),
    (
        "example-061-v01",
        "Send(command='CMDNAME', Time=NOW + 30*MINUTE)\n",
    ),
    (
        "example-061-v02",
        "Send(command='CMDNAME', Time='2008/04/10 10:30:00')\n",
    ),
    (
        "example-062-v01",
        "Send(command='CMDNAME', ReleaseTime=NOW + 30*MINUTE)\n",
    ),
    (
        "example-062-v02",
        "Send(command='CMDNAME', ReleaseTime='2008/04/10 10:30:00')\n",
    ),
    ("example-063-v01", "Send(command='CMDNAME', LoadOnly=True)\n"),
    ("example-064-v01", "Send(command='CMDNAME', Confirm=True)\n"),
    (
        "example-065-v01",
        "Send(command='CMDNAME', ConfirmCritical=True)\n",
    ),
    (
        "example-066-v01",
        "tc_item = BuildTC('CMDNAME', args=[[\"ARG1\", 1.0]])\n"
        "Send(command=tc_item)\n",
    ),
    (
        "example-066-v02",
        "Send(command='CMDNAME', args=[[\"ARG1\", 1.0]])\n",
    ),
    ("example-067-v01", "Send(sequence='SEQNAME')\n"),
    (
        "example-068-v01",
        "Send(group=['CMD1', 'CMD2', 'CMD3'])\n",
    ),
    (
        "example-069-v01",
        "one = BuildTC('CMD1')\n"
        "two = BuildTC('CMD2')\n"
        "three = BuildTC('CMD3')\n"
        "Send(group=[one, two, three])\n",
    ),
    (
        "example-070-v01",
        "one = BuildTC('CMD1')\n"
        "two = BuildTC('CMD2')\n"
        "three = BuildTC('CMD3')\n"
        "Send(group=[one, two, three], Group=True)\n",
    ),
    (
        "example-071-v01",
        "one = BuildTC('CMD1')\n"
        "two = BuildTC('CMD2')\n"
        "three = BuildTC('CMD3')\n"
        "Send(group=[one, two, three], Block=True)\n",
    ),
    (
        "example-072-v01",
        "tc_item = BuildTC('CMDNAME')\nSend(command=tc_item, Timeout=1*MINUTE)\n",
    ),
    (
        "example-073-v01",
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command=tc_item, addInfo={\"any key\": \"any data\"})\n",
    ),
    (
        "example-074-v01",
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command=tc_item, SendDelay=1*MINUTE)\n",
    ),
    (
        "example-074-v02",
        "one = BuildTC('CMD1')\n"
        "two = BuildTC('CMD2')\n"
        "three = BuildTC('CMD3')\n"
        "Send(group=[one, two, three], SendDelay=1*MINUTE)\n",
    ),
    (
        "example-075-v01",
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command=tc_item, verify=[[\"TMparam\", eq, 10]])\n",
    ),
    (
        "example-076-v01",
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command=tc_item, verify=[[\"TMparam\", eq, 10]], AdjLimits=True)\n",
    ),
    (
        "example-077-v01",
        "Send(command='TCNAME', "
        "args=[[\"ARG1\", 1.0], [\"ARG2\", 0xFF, {Radix: HEX}]], "
        "verify=[[\"TM1\", eq, 10.0, {Tolerance: 0.1}], "
        "[\"TM2\", gt, 0, {Timeout: 20}]], "
        "Delay=10*SECOND, Tolerance=0.5, OnFailure=CANCEL, PromptUser=False)\n",
    ),
)


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source,
        "v11-command-corpus.spell.py",
    )


def test_command_corpus_contains_all_26_documented_statements() -> None:
    assert len(COMMAND_CORPUS) == 26
    assert len({case_id for case_id, _ in COMMAND_CORPUS}) == 26
    assert {int(case_id[8:11]) for case_id, _ in COMMAND_CORPUS} == set(range(57, 78))


@pytest.mark.parametrize("case_id, source", COMMAND_CORPUS, ids=lambda value: value)
def test_every_documented_command_statement_has_a_bounded_v011_form(
    case_id: str,
    source: str,
) -> None:
    procedure = _parse(source)

    assert procedure.ir_version == "0.11", case_id
    assert any(step["type"] in {"build_tc", "send_tc"} for step in procedure.steps)
    assert all(
        step["type"] in {"variable_set", "build_tc", "send_tc"}
        for step in procedure.steps
    )


def test_example_60_variants_retain_distinct_selector_shapes() -> None:
    literal = _parse(dict(COMMAND_CORPUS)["example-060-v01"])
    item = _parse(dict(COMMAND_CORPUS)["example-060-v02"])

    assert literal.steps[-1]["selector"]["value"] == "CMDNAME"
    assert item.steps[-1]["selector"]["value"] == {
        "expr": "telecommand_item",
        "name": "tc_item",
    }
