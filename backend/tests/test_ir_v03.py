from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from backend.ir_v03 import (
    IRValidationError,
    MAX_EXPRESSION_DEPTH,
    MAX_INTEGER_BITS,
    MAX_IR_SERIALIZED_BYTES,
    validate_ir_v03,
)
from backend.procedure_parser import ProcedureCatalog


def _log_step(**changes: Any) -> dict[str, Any]:
    step = {
        "index": 0,
        "type": "log",
        "line": 1,
        "column": 1,
        "message": "accepted",
        "level": "info",
    }
    step.update(changes)
    return step


def _rejects(steps: Any, path: str | None = None, **metadata: Any) -> IRValidationError:
    with pytest.raises(IRValidationError) as rejected:
        validate_ir_v03("0.3", steps, **metadata)
    assert rejected.value.code == "IR_VALIDATION_FAILED"
    assert set(rejected.value.audit_payload()) == {"code", "path", "message"}
    assert len(rejected.value.path) <= 160
    assert len(rejected.value.message) <= 240
    if path is not None:
        assert rejected.value.path.startswith(path)
    return rejected.value


def test_v05_ir_001_unit_accepts_complete_parser_golden_ir_without_rewriting_input(
    tmp_path: Path,
) -> None:
    procedure = ProcedureCatalog(tmp_path).validate_source(
        "count: int = 1\n"
        "ratio: float = 2\n"
        "enabled: bool = True\n"
        "label: str = 'ready'\n"
        "if enabled:\n"
        "    Log(label, level='warning')\n"
        "else:\n"
        "    Log('disabled')\n"
        "for sample in range(2):\n"
        "    count += sample\n"
        "Telemetry('sim.count', value=count, unit='items')\n"
        "Wait(0)\n"
        "Prompt('Continue?', choices=['yes', 'no'], default='yes')\n"
    )
    original = list(procedure.steps)
    before = copy.deepcopy(original)

    validated = validate_ir_v03("0.3", original)

    assert original == before
    assert validated.steps == before
    assert validated.steps is not original
    validated.steps[0]["line"] = 999
    assert original[0]["line"] != 999
    assert json.loads(validated.canonical_bytes)[0]["index"] == 0
    assert validated.variable_types == {
        "__spell_branch_0": "bool",
        "count": "int",
        "enabled": "bool",
        "label": "str",
        "ratio": "float",
        "sample": "int",
    }


@pytest.mark.parametrize(
    ("steps", "path"),
    [
        pytest.param([{**_log_step(), "extra": True}], "$.steps[0]", id="extra-key"),
        pytest.param(
            [{key: value for key, value in _log_step().items() if key != "line"}],
            "$.steps[0]",
            id="missing-key",
        ),
        pytest.param([_log_step(index=True)], "$.steps[0].index", id="boolean-index"),
        pytest.param([_log_step(index=1)], "$.steps[0].index", id="noncontiguous-index"),
        pytest.param([_log_step(type="shell")], "$.steps[0].type", id="unknown-step"),
        pytest.param([_log_step(line=0)], "$.steps[0].line", id="invalid-line"),
        pytest.param([_log_step(message="")], "$.steps[0].message", id="empty-message"),
        pytest.param([_log_step(level="fatal")], "$.steps[0].level", id="bad-level"),
        pytest.param(
            [{**_log_step(), "x" * 100_000: True}],
            "$.steps[0]",
            id="oversized-field-name",
        ),
        pytest.param(
            [_log_step(message={"expr": "literal", "value": "not-canonical"})],
            "$.steps[0].message",
            id="literal-argument-node",
        ),
    ],
)
def test_v05_ir_001_adversarial_rejects_noncanonical_step_shapes(
    steps: list[dict[str, Any]], path: str
) -> None:
    _rejects(steps, path)


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param({"expr": "literal", "value": float("nan")}, id="nan"),
        pytest.param({"expr": "literal", "value": float("inf")}, id="infinity"),
        pytest.param({"expr": "literal", "value": 1 << MAX_INTEGER_BITS}, id="large-int"),
        pytest.param({"expr": "literal", "value": "x\x00y"}, id="nul-string"),
        pytest.param({"expr": "variable", "name": "missing"}, id="undeclared-read"),
        pytest.param({"expr": "call", "name": "open"}, id="unknown-expression"),
        pytest.param(
            {
                "expr": "unary",
                "operator": [],
                "operand": {"expr": "literal", "value": 1},
            },
            id="unhashable-unary-operator",
        ),
        pytest.param(
            {
                "expr": "binary",
                "operator": "*",
                "left": {"expr": "literal", "value": "x"},
                "right": {"expr": "literal", "value": 2},
            },
            id="bad-binary-types",
        ),
    ],
)
def test_v05_ir_001_adversarial_rejects_unsafe_expressions(
    expression: dict[str, Any],
) -> None:
    step = {
        "index": 0,
        "type": "variable_set",
        "line": 1,
        "column": 1,
        "name": "value",
        "declared_type": "int",
        "expression": expression,
        "declaration": True,
    }
    _rejects([step], "$.steps[0].expression")


def test_v05_ir_001_adversarial_rejects_excessive_expression_depth() -> None:
    expression: dict[str, Any] = {"expr": "literal", "value": True}
    for _ in range(MAX_EXPRESSION_DEPTH + 2):
        expression = {"expr": "unary", "operator": "not", "operand": expression}
    _rejects([_log_step(guard=expression)], "$.steps[0].guard")


def test_v05_ir_001_adversarial_rejects_unguarded_read_after_guarded_declaration() -> None:
    condition = {"expr": "variable", "name": "__spell_branch_0"}
    steps = [
        {
            "index": 0,
            "type": "variable_set",
            "line": 1,
            "column": 1,
            "name": "__spell_branch_0",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": True},
            "declaration": True,
            "internal": True,
        },
        {
            "index": 1,
            "type": "variable_set",
            "line": 2,
            "column": 1,
            "guard": condition,
            "name": "item",
            "declared_type": "int",
            "expression": {"expr": "literal", "value": 1},
            "declaration": True,
        },
        {
            "index": 2,
            "type": "telemetry",
            "line": 3,
            "column": 1,
            "channel": "sim.item",
            "value": {"expr": "variable", "name": "item"},
        },
    ]

    _rejects(steps, "$.steps[2].value")


def test_v05_ir_001_unit_accepts_short_circuit_guarded_variable_flow() -> None:
    outer = {"expr": "variable", "name": "__spell_branch_0"}
    branch = {"expr": "variable", "name": "__spell_branch_1"}
    combined = {"expr": "boolean", "operator": "and", "values": [outer, branch]}
    steps = [
        {
            "index": 0,
            "type": "variable_set",
            "line": 1,
            "column": 1,
            "name": "__spell_branch_0",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": True},
            "declaration": True,
            "internal": True,
        },
        {
            "index": 1,
            "type": "variable_set",
            "line": 2,
            "column": 1,
            "guard": outer,
            "name": "__spell_branch_1",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": True},
            "declaration": True,
            "internal": True,
        },
        {
            "index": 2,
            "type": "log",
            "line": 3,
            "column": 1,
            "guard": combined,
            "message": "accepted",
            "level": "info",
        },
    ]

    assert validate_ir_v03("0.3", steps).steps == steps


def test_v05_ir_001_adversarial_rejects_unavailable_conditional_assignment() -> None:
    condition = {"expr": "variable", "name": "__spell_branch_0"}
    steps = [
        {
            "index": 0,
            "type": "variable_set",
            "line": 1,
            "column": 1,
            "name": "__spell_branch_0",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": True},
            "declaration": True,
            "internal": True,
        },
        {
            "index": 1,
            "type": "variable_set",
            "line": 2,
            "column": 1,
            "guard": condition,
            "name": "item",
            "declared_type": "int",
            "expression": {"expr": "literal", "value": 1},
            "declaration": True,
        },
        {
            "index": 2,
            "type": "variable_set",
            "line": 3,
            "column": 1,
            "name": "item",
            "declared_type": "int",
            "expression": {"expr": "literal", "value": 2},
            "declaration": False,
        },
        {**_log_step(), "index": 3, "line": 4},
    ]

    _rejects(steps, "$.steps[2].name")


def test_v05_ir_001_adversarial_rejects_mutable_user_variable_guard() -> None:
    flag = {"expr": "variable", "name": "flag"}
    steps = [
        {
            "index": 0,
            "type": "variable_set",
            "line": 1,
            "column": 1,
            "name": "flag",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": False},
            "declaration": True,
        },
        {
            "index": 1,
            "type": "variable_set",
            "line": 2,
            "column": 1,
            "guard": flag,
            "name": "item",
            "declared_type": "int",
            "expression": {"expr": "literal", "value": 1},
            "declaration": True,
        },
        {**_log_step(), "index": 2, "line": 3},
    ]

    _rejects(steps, "$.steps[1].guard")


def test_v05_ir_001_unit_accepts_maximum_step_guard_corpus_without_quadratic_copying() -> None:
    branch_count = 9_999
    steps = [
        {
            "index": index,
            "type": "variable_set",
            "line": 1,
            "column": 1,
            "name": f"__spell_branch_{index}",
            "declared_type": "bool",
            "expression": {"expr": "literal", "value": True},
            "declaration": True,
            "internal": True,
        }
        for index in range(branch_count)
    ]
    steps.append(
        {
            **_log_step(),
            "index": branch_count,
            "guard": {
                "expr": "boolean",
                "operator": "and",
                "values": [
                    {"expr": "variable", "name": f"__spell_branch_{index}"}
                    for index in range(branch_count)
                ],
            },
        }
    )

    assert len(validate_ir_v03("0.3", steps).steps) == 10_000


def test_v05_ir_001_adversarial_bounds_internal_branch_suffix() -> None:
    step = {
        "index": 0,
        "type": "variable_set",
        "line": 1,
        "column": 1,
        "name": "__spell_branch_" + "9" * 5_000,
        "declared_type": "bool",
        "expression": {"expr": "literal", "value": True},
        "declaration": True,
        "internal": True,
    }

    _rejects([step], "$.steps[0].name")


def test_v05_ir_001_adversarial_rejects_oversized_serialized_ir() -> None:
    message = "x" * 100_000
    steps = [
        {
            "index": index,
            "type": "log",
            "line": 1,
            "column": 1,
            "message": message,
            "level": "info",
        }
        for index in range(MAX_IR_SERIALIZED_BYTES // len(message) + 1)
    ]
    _rejects(steps, "$.steps")


@pytest.mark.parametrize(
    "step",
    [
        pytest.param(
            {
                "index": 0,
                "type": "prompt",
                "line": 1,
                "column": 1,
                "question": "Continue?",
                "choices": ["yes", "yes"],
                "default": "yes",
            },
            id="duplicate-choices",
        ),
        pytest.param(
            {
                "index": 0,
                "type": "prompt",
                "line": 1,
                "column": 1,
                "question": "Continue?",
                "choices": ["yes"],
                "default": "no",
            },
            id="default-outside-choices",
        ),
    ],
)
def test_v05_ir_001_adversarial_rejects_invalid_prompt_contract(
    step: dict[str, Any],
) -> None:
    _rejects([step], "$.steps[0]")


def test_v05_ir_001_compat_validates_recovery_checkpoint_without_byte_changes(
    tmp_path: Path,
) -> None:
    procedure = ProcedureCatalog(tmp_path).validate_source(
        "count: int = 1\n"
        "ratio: float = 2\n"
        "Prompt('Continue?', choices=['yes'], default='yes')\n"
    )
    steps = json.loads(json.dumps(list(procedure.steps)))
    before = json.dumps(steps, separators=(",", ":"), sort_keys=False).encode()

    validated = validate_ir_v03(
        "0.3",
        steps,
        start_step=2,
        resume_prompt_id="prompt-id",
        checkpoint_variables={"count": 1, "ratio": 2.0},
        expected_total_steps=3,
    )

    assert validated.checkpoint_variables == {"count": 1, "ratio": 2.0}
    assert json.dumps(steps, separators=(",", ":"), sort_keys=False).encode() == before
    _rejects(
        steps,
        "$.checkpoint_variables",
        start_step=2,
        resume_prompt_id="prompt-id",
        checkpoint_variables={"count": 1},
        expected_total_steps=3,
    )


@pytest.mark.parametrize(
    ("version", "metadata", "path"),
    [
        pytest.param("0.4", {}, "$.ir_version", id="wrong-version"),
        pytest.param("0.3", {"start_step": True}, "$.start_step", id="boolean-start"),
        pytest.param("0.3", {"start_step": 2}, "$.start_step", id="past-end"),
        pytest.param("0.3", {"expected_total_steps": 2}, "$.total_steps", id="bad-total"),
        pytest.param(
            "0.3",
            {"resume_prompt_id": "prompt-id"},
            "$.resume_prompt_id",
            id="resume-nonprompt",
        ),
        pytest.param(
            "0.3",
            {"resume_prompt_step": 0},
            "$.resume_prompt_step",
            id="resume-step-without-prompt-id",
        ),
    ],
)
def test_v05_ir_001_unit_rejects_invalid_execution_metadata(
    version: str, metadata: dict[str, Any], path: str
) -> None:
    with pytest.raises(IRValidationError) as rejected:
        validate_ir_v03(version, [_log_step()], **metadata)
    assert rejected.value.path.startswith(path)


def test_v05_ir_001_worker_facing_validation_rejects_unsized_steps() -> None:
    _rejects(None, "$.steps")
