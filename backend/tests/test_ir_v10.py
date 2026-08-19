from __future__ import annotations

import copy

import pytest

from backend.ir_v10 import V10ValidationError, validate_ir_v10
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source,
        "reference_runner.spell.py",
    )


def test_reference_runner_compiles_to_closed_v010_ir() -> None:
    procedure = _parse(
        "selected: int = -1\n"
        "example_number: int = 0\n"
        "result: str = ''\n"
        "Prompt('Choose', type='LIST', choices=['Example 001', 'Example 002'], "
        "list_mode='INDEX', default=0, target=selected)\n"
        "example_number = selected + 1\n"
        "ReferenceExample(example_number, target=result)\n"
    )

    assert procedure.ir_version == "0.10"
    prompt = next(step for step in procedure.steps if step["type"] == "prompt")
    reference = next(
        step for step in procedure.steps if step["type"] == "reference_example"
    )
    assert prompt["response_target"] == "selected"
    assert prompt["response_target_type"] == "int"
    assert reference["target"] == "result"
    assert reference["target_type"] == "str"
    assert reference["example"]["expr"] == "variable"


def test_reference_example_requires_bounded_number_and_exact_target() -> None:
    with pytest.raises(ProcedureValidationError, match="1 through 195"):
        _parse("result: str = ''\nReferenceExample(196, target=result)\n")
    with pytest.raises(ProcedureValidationError, match="declared type str"):
        _parse("result: int = 0\nReferenceExample(1, target=result)\n")


def test_v010_ir_rejects_prompt_target_and_example_tampering() -> None:
    procedure = _parse(
        "selected: int = -1\n"
        "result: str = ''\n"
        "Prompt('Choose', type='LIST', choices=['Example 001'], "
        "list_mode='INDEX', target=selected)\n"
        "ReferenceExample(selected + 1, target=result)\n"
    )
    steps = [dict(step) for step in procedure.steps]

    prompt_tamper = copy.deepcopy(steps)
    prompt = next(step for step in prompt_tamper if step["type"] == "prompt")
    prompt["response_target_type"] = "str"
    with pytest.raises(V10ValidationError, match="integer LIST index"):
        validate_ir_v10("0.10", prompt_tamper)

    reference_tamper = copy.deepcopy(steps)
    reference = next(
        step for step in reference_tamper if step["type"] == "reference_example"
    )
    reference["target"] = "selected"
    with pytest.raises(V10ValidationError, match="declared str"):
        validate_ir_v10("0.10", reference_tamper)


def test_legacy_ir_selection_remains_unchanged() -> None:
    assert _parse("Log('legacy')\n").ir_version == "0.3"
    assert _parse("Prompt('typed', type='OK')\n").ir_version == "0.6"
