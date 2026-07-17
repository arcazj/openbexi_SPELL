from __future__ import annotations

import queue
import os
import math
import operator
import time
import uuid
from multiprocessing.queues import Queue
from typing import Any


MAX_INTEGER_BITS = 4_096
MAX_STRING_LENGTH = 100_000


class ExpressionEvaluationError(ValueError):
    pass


def evaluate_expression(expression: Any, variables: dict[str, Any]) -> Any:
    """Evaluate only the serialized expression nodes produced by the parser."""

    if not isinstance(expression, dict) or "expr" not in expression:
        return expression
    kind = expression.get("expr")
    if kind == "literal":
        value = expression.get("value")
    elif kind == "variable":
        name = expression.get("name")
        if not isinstance(name, str) or name not in variables:
            raise ExpressionEvaluationError(f"variable {name!r} has no checkpointed value")
        value = variables[name]
    elif kind == "unary":
        operand = evaluate_expression(expression.get("operand"), variables)
        unary = expression.get("operator")
        if unary == "not" and type(operand) is bool:
            value = not operand
        elif unary in {"+", "-"} and _is_number(operand):
            value = operand if unary == "+" else -operand
        else:
            raise ExpressionEvaluationError(f"invalid unary operation {unary!r}")
    elif kind == "binary":
        left = evaluate_expression(expression.get("left"), variables)
        right = evaluate_expression(expression.get("right"), variables)
        binary = expression.get("operator")
        operations = {
            "+": operator.add,
            "-": operator.sub,
            "*": operator.mul,
            "/": operator.truediv,
            "//": operator.floordiv,
            "%": operator.mod,
        }
        operation = operations.get(binary)
        if operation is None:
            raise ExpressionEvaluationError(f"invalid binary operation {binary!r}")
        if binary == "+" and type(left) is str and type(right) is str:
            value = operation(left, right)
        elif _is_number(left) and _is_number(right):
            try:
                value = operation(left, right)
            except (ArithmeticError, ValueError) as exc:
                raise ExpressionEvaluationError(str(exc)) from exc
        else:
            raise ExpressionEvaluationError(f"invalid operands for {binary}")
    elif kind == "boolean":
        values = expression.get("values")
        if not isinstance(values, list) or not values:
            raise ExpressionEvaluationError("boolean expression requires operands")
        boolean = expression.get("operator")
        if boolean == "and":
            value = True
            for item in values:
                value = evaluate_expression(item, variables)
                if type(value) is not bool:
                    raise ExpressionEvaluationError("and operand is not boolean")
                if not value:
                    break
        elif boolean == "or":
            value = False
            for item in values:
                value = evaluate_expression(item, variables)
                if type(value) is not bool:
                    raise ExpressionEvaluationError("or operand is not boolean")
                if value:
                    break
        else:
            raise ExpressionEvaluationError(f"invalid boolean operation {boolean!r}")
    elif kind == "compare":
        operands = expression.get("operands")
        operators = expression.get("operators")
        if (
            not isinstance(operands, list)
            or not isinstance(operators, list)
            or not operators
            or len(operands) != len(operators) + 1
        ):
            raise ExpressionEvaluationError("malformed comparison")
        comparisons = {
            "==": operator.eq,
            "!=": operator.ne,
            "<": operator.lt,
            "<=": operator.le,
            ">": operator.gt,
            ">=": operator.ge,
        }
        value = True
        left = evaluate_expression(operands[0], variables)
        for index, comparison in enumerate(operators):
            operation = comparisons.get(comparison)
            if operation is None:
                raise ExpressionEvaluationError(f"invalid comparison {comparison!r}")
            right = evaluate_expression(operands[index + 1], variables)
            try:
                if not operation(left, right):
                    value = False
                    break
            except TypeError as exc:
                raise ExpressionEvaluationError(str(exc)) from exc
            left = right
    else:
        raise ExpressionEvaluationError(f"unknown expression node {kind!r}")
    return _bounded_value(value)


def _is_number(value: Any) -> bool:
    return type(value) in {int, float}


def _bounded_value(value: Any) -> Any:
    if type(value) is int and value.bit_length() > MAX_INTEGER_BITS:
        raise ExpressionEvaluationError("integer result exceeds the safety limit")
    if type(value) is float and not math.isfinite(value):
        raise ExpressionEvaluationError("floating-point result must be finite")
    if type(value) is str and len(value) > MAX_STRING_LENGTH:
        raise ExpressionEvaluationError("string result exceeds the safety limit")
    if type(value) not in {bool, float, int, str}:
        raise ExpressionEvaluationError(f"unsupported result type {type(value).__name__}")
    return value


def _matches_type(value: Any, declared_type: str) -> bool:
    if declared_type == "float":
        return type(value) in {int, float}
    return type(value).__name__ == declared_type


def _non_empty_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ExpressionEvaluationError(f"{label} must be a non-empty string")
    return value


def worker_main(
    execution_id: str,
    generation: int,
    steps: list[dict[str, Any]],
    start_step: int,
    start_command_id: str,
    resume_prompt_id: str | None,
    checkpoint_variables: dict[str, Any],
    control: Queue,
    output: Queue,
) -> None:
    """Execute validated IR in a spawned process. Source code never enters this process."""

    def send(kind: str, **fields: Any) -> None:
        output.put({"kind": kind, "generation": generation, **fields})

    variables = dict(checkpoint_variables)
    send(
        "event",
        event_type="worker.started",
        source="worker",
        payload={"generation": generation, "start_step": start_step, "pid": os.getpid()},
    )
    send("state", state="running", command_id=start_command_id)

    def wait_for_control(block: bool = False, timeout: float = 0.0) -> dict[str, Any] | None:
        try:
            return control.get(block=block, timeout=timeout if block else None)
        except queue.Empty:
            return None

    def handle_control(message: dict[str, Any] | None) -> str | None:
        if message is None:
            return None
        command_type = message["type"]
        command_id = message["command_id"]
        if command_type == "abort":
            send("state", state="aborted", command_id=command_id)
            send("terminal", state="aborted")
            return "abort"
        if command_type == "pause":
            send("state", state="paused", command_id=command_id)
            while True:
                followup = wait_for_control(block=True, timeout=0.25)
                if followup is None:
                    continue
                if followup["type"] == "resume":
                    send("state", state="running", command_id=followup["command_id"])
                    return "resume"
                if followup["type"] == "abort":
                    send("state", state="aborted", command_id=followup["command_id"])
                    send("terminal", state="aborted")
                    return "abort"
        return None

    for step_index in range(start_step, len(steps)):
        if handle_control(wait_for_control()) == "abort":
            return
        step = steps[step_index]
        effects: list[dict[str, Any]] = []
        prompt_resolution: dict[str, Any] | None = None
        send(
            "event",
            event_type="step.started",
            source="worker",
            payload={"step_index": step_index, "line": step["line"], "step_type": step["type"]},
        )

        try:
            guard = step.get("guard")
            should_run = True if guard is None else evaluate_expression(guard, variables)
            if type(should_run) is not bool:
                raise ExpressionEvaluationError("step guard is not boolean")

            if should_run and step["type"] == "variable_set":
                value = evaluate_expression(step["expression"], variables)
                if not _matches_type(value, step["declared_type"]):
                    raise ExpressionEvaluationError(
                        f"value for {step['name']} does not match {step['declared_type']}"
                    )
                variables[step["name"]] = (
                    float(value) if step["declared_type"] == "float" and type(value) is int else value
                )
            elif should_run and step["type"] == "log":
                message = _non_empty_string(
                    evaluate_expression(step["message"], variables), "Log message"
                )
                effects.append(
                    {
                        "event_type": "procedure.log",
                        "source": "procedure",
                        "severity": step["level"],
                        "payload": {"message": message, "step_index": step_index},
                    }
                )
            elif should_run and step["type"] == "telemetry":
                channel = _non_empty_string(
                    evaluate_expression(step["channel"], variables), "Telemetry channel"
                )
                telemetry_value = evaluate_expression(step["value"], variables)
                if type(telemetry_value) not in {bool, float, int}:
                    raise ExpressionEvaluationError("Telemetry value must be numeric or boolean")
                effects.append(
                    {
                        "event_type": "telemetry.sample",
                        "source": "simulator",
                        "severity": "info",
                        "payload": {
                            "channel": channel,
                            "value": telemetry_value,
                            "unit": (
                                evaluate_expression(step["unit"], variables)
                                if "unit" in step
                                else None
                            ),
                            "quality": "simulated",
                            "step_index": step_index,
                        },
                    },
                )
            elif should_run and step["type"] == "wait":
                seconds = evaluate_expression(step["seconds"], variables)
                if not _is_number(seconds) or seconds < 0 or seconds > 3600:
                    raise ExpressionEvaluationError("Wait seconds must be between 0 and 3600")
                remaining = float(seconds)
                while remaining > 0:
                    started = time.monotonic()
                    result = handle_control(
                        wait_for_control(block=True, timeout=min(0.05, remaining))
                    )
                    elapsed = time.monotonic() - started
                    if result == "abort":
                        return
                    if result != "resume":
                        remaining = max(0.0, remaining - elapsed)
            elif should_run and step["type"] == "prompt":
                prompt_id = resume_prompt_id or str(uuid.uuid4())
                resume_prompt_id = None
                send(
                    "prompt_opened",
                    prompt_id=prompt_id,
                    step_index=step_index,
                    question=_non_empty_string(
                        evaluate_expression(step["question"], variables), "Prompt question"
                    ),
                    choices=step["choices"],
                    default=step["default"],
                )
                send("state", state="prompting")
                while True:
                    message = wait_for_control(block=True, timeout=0.25)
                    if message is None:
                        continue
                    if message["type"] == "abort":
                        send("state", state="aborted", command_id=message["command_id"])
                        send("terminal", state="aborted")
                        return
                    if message["type"] == "pause":
                        if handle_control(message) == "abort":
                            return
                        send("state", state="prompting")
                        continue
                    if (
                        message["type"] == "prompt_response"
                        and message.get("prompt_id") == prompt_id
                    ):
                        prompt_resolution = {
                            "prompt_id": prompt_id,
                            "response": message["response"],
                            "command_id": message["command_id"],
                        }
                        break
        except ExpressionEvaluationError as exc:
            send(
                "event",
                event_type="procedure.error",
                source="worker",
                severity="error",
                payload={"step_index": step_index, "line": step["line"], "error": str(exc)},
            )
            send("state", state="failed")
            send("terminal", state="failed")
            return

        effects.append(
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {
                    "step_index": step_index,
                    "line": step["line"],
                    "step_type": step["type"],
                    "skipped": not should_run,
                },
            }
        )
        send(
            "step_commit",
            step_index=step_index,
            next_step=step_index + 1,
            effects=effects,
            prompt_resolution=prompt_resolution,
            variables=dict(variables),
        )
        if prompt_resolution is not None:
            send("state", state="running")

    send("state", state="completed")
    send("terminal", state="completed")
