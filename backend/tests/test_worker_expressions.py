import queue
from pathlib import Path

import pytest

from backend.worker import ExpressionEvaluationError, evaluate_expression, worker_main
from backend.procedure_parser import ProcedureCatalog


def test_expression_evaluator_uses_only_serialized_ir_and_checkpoint_variables() -> None:
    expression = {
        "expr": "boolean",
        "operator": "and",
        "values": [
            {
                "expr": "compare",
                "operators": [">="],
                "operands": [
                    {"expr": "variable", "name": "voltage"},
                    {"expr": "literal", "value": 27.5},
                ],
            },
            {"expr": "variable", "name": "enabled"},
        ],
    }

    assert evaluate_expression(expression, {"voltage": 28.1, "enabled": True}) is True


def test_expression_evaluator_short_circuits_guarded_missing_variable() -> None:
    expression = {
        "expr": "boolean",
        "operator": "and",
        "values": [
            {"expr": "literal", "value": False},
            {"expr": "variable", "name": "not_initialized"},
        ],
    }
    assert evaluate_expression(expression, {}) is False


def test_expression_evaluator_short_circuits_chained_comparisons() -> None:
    expression = {
        "expr": "compare",
        "operators": [">", ">"],
        "operands": [
            {"expr": "literal", "value": 1},
            {"expr": "literal", "value": 2},
            {
                "expr": "binary",
                "operator": "/",
                "left": {"expr": "literal", "value": 1},
                "right": {"expr": "literal", "value": 0},
            },
        ],
    }

    assert evaluate_expression(expression, {}) is False


@pytest.mark.parametrize(
    "expression",
    [
        {
            "expr": "binary",
            "operator": "/",
            "left": {"expr": "literal", "value": 1},
            "right": {"expr": "literal", "value": 0},
        },
        {"expr": "variable", "name": "missing"},
        {"expr": "call", "name": "open"},
    ],
)
def test_expression_evaluator_rejects_invalid_runtime_ir(expression: dict) -> None:
    with pytest.raises(ExpressionEvaluationError):
        evaluate_expression(expression, {})


def test_worker_commits_variable_snapshot_with_each_flat_step() -> None:
    control: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()
    steps = [
        {
            "index": 0,
            "line": 1,
            "column": 1,
            "type": "variable_set",
            "name": "count",
            "declared_type": "int",
            "declaration": True,
            "expression": {"expr": "literal", "value": 1},
        },
        {
            "index": 1,
            "line": 2,
            "column": 1,
            "type": "variable_set",
            "name": "count",
            "declared_type": "int",
            "declaration": False,
            "expression": {
                "expr": "binary",
                "operator": "+",
                "left": {"expr": "variable", "name": "count"},
                "right": {"expr": "literal", "value": 1},
            },
        },
        {
            "index": 2,
            "line": 3,
            "column": 1,
            "type": "log",
            "message": "complete",
            "level": "info",
        },
    ]

    worker_main("execution", 1, "0.3", steps, 0, "start", None, {}, control, output)

    messages = []
    while not output.empty():
        messages.append(output.get_nowait())
    commits = [message for message in messages if message["kind"] == "step_commit"]
    assert [commit["variables"]["count"] for commit in commits] == [1, 2, 2]
    assert commits[-1]["next_step"] == 3
    assert messages[-1] == {"kind": "terminal", "generation": 1, "state": "completed"}


def test_worker_restores_checkpointed_variables_at_recovery_step(tmp_path: Path) -> None:
    procedure = ProcedureCatalog(tmp_path).validate_source(
        "count: int = 0\n"
        "count = count + 1\n"
        "Telemetry('sim.count', value=count)\n"
        "count = count + 1\n"
        "Telemetry('sim.count', value=count)\n"
    )
    control: queue.Queue = queue.Queue()
    first_output: queue.Queue = queue.Queue()
    first_steps = list(procedure.steps[:3])
    worker_main(
        "execution",
        1,
        "0.3",
        first_steps,
        0,
        "start",
        None,
        {},
        control,
        first_output,
    )
    first_messages = []
    while not first_output.empty():
        first_messages.append(first_output.get_nowait())
    checkpoint = [
        message for message in first_messages if message["kind"] == "step_commit"
    ][-1]
    assert checkpoint["variables"] == {"count": 1}

    recovered_output: queue.Queue = queue.Queue()
    worker_main(
        "execution",
        2,
        "0.3",
        list(procedure.steps),
        3,
        "recover",
        None,
        checkpoint["variables"],
        control,
        recovered_output,
    )
    recovered_messages = []
    while not recovered_output.empty():
        recovered_messages.append(recovered_output.get_nowait())
    recovered_commits = [
        message for message in recovered_messages if message["kind"] == "step_commit"
    ]
    telemetry = [
        effect
        for commit in recovered_commits
        for effect in commit["effects"]
        if effect["event_type"] == "telemetry.sample"
    ]
    assert recovered_commits[-1]["variables"] == {"count": 2}
    assert telemetry[-1]["payload"]["value"] == 2


def test_worker_executes_flat_branch_loop_and_expanded_call_ir(tmp_path: Path) -> None:
    procedure = ProcedureCatalog(tmp_path).validate_source(
        "enabled: bool = False\n"
        "value: int = 0\n"
        "message: str = 'initial'\n"
        "def emit():\n"
        "    Log(message)\n"
        "if enabled:\n"
        "    message = 'wrong branch'\n"
        "else:\n"
        "    message = 'selected branch'\n"
        "for item in range(3):\n"
        "    value += 1\n"
        "Call(emit)\n"
        "Telemetry('sim.value', value=value)\n"
    )
    control: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()
    worker_main(
        "execution",
        1,
        "0.3",
        list(procedure.steps),
        0,
        "start",
        None,
        {},
        control,
        output,
    )
    messages = []
    while not output.empty():
        messages.append(output.get_nowait())
    commits = [message for message in messages if message["kind"] == "step_commit"]
    effects = [effect for commit in commits for effect in commit["effects"]]
    logs = [effect for effect in effects if effect["event_type"] == "procedure.log"]
    telemetry = [effect for effect in effects if effect["event_type"] == "telemetry.sample"]
    assert logs[0]["payload"]["message"] == "selected branch"
    assert telemetry[0]["payload"]["value"] == 3
    assert commits[-1]["variables"]["value"] == 3
