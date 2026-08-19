from __future__ import annotations

import queue
import os
import math
import operator
import time
import uuid
from collections import deque
from multiprocessing.queues import Queue
from typing import Any

from .ir_v03 import IRValidationError, validate_ir_v03
from .ir_v06 import (
    IR_VERSION as V06_IR_VERSION,
    V06ValidationError,
    normalize_prompt_value,
    reject_secret_material,
    validate_ir_v06,
    validate_startproc_declaration,
    validate_user_action_block,
)
from .ir_v07 import (
    IR_VERSION as V07_IR_VERSION,
    V07ValidationError,
    observation_request_for_step,
    validate_ir_v07,
    validate_observation_result,
)
from .ir_v08 import (
    IR_VERSION as V08_IR_VERSION,
    V08ValidationError,
    closed_file_handle_reference,
    data_request_for_step,
    file_handle_reference,
    is_file_handle_reference,
    validate_data_result,
    validate_ir_v08,
)


MAX_INTEGER_BITS = 4_096
MAX_STRING_LENGTH = 100_000
MAX_CHECKPOINT_CONTAINER_DEPTH = 8
MAX_CHECKPOINT_CONTAINER_ITEMS = 1_024
RUNTIME_CONTAINER_NAMES = frozenset({"ARGS", "GLOBALS", "IVARS", "SHARED_DATA"})
WORKER_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TZ",
        "WINDIR",
    }
)


class ExpressionEvaluationError(ValueError):
    pass


def sanitized_worker_environment() -> dict[str, str]:
    """Return the inert runtime subset a spawned procedure worker may inherit."""

    return {
        name: value
        for name, value in os.environ.items()
        if name in WORKER_ENVIRONMENT_ALLOWLIST
    }


def _replace_worker_environment() -> None:
    """Drop inherited service configuration before processing execution IR."""

    retained = sanitized_worker_environment()
    os.environ.clear()
    os.environ.update(retained)


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


def _checkpoint_literal(
    value: Any,
    path: str,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    if budget is None:
        budget = [MAX_CHECKPOINT_CONTAINER_ITEMS]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_CHECKPOINT_CONTAINER_DEPTH:
        raise V06ValidationError(
            "INSPECTION_EDIT_INVALID", path, "variable snapshot exceeds its structural bound"
        )
    if value is None:
        return None
    if type(value) in {bool, float, int, str}:
        try:
            return _bounded_value(value)
        except ExpressionEvaluationError as exc:
            raise V06ValidationError(
                "INSPECTION_EDIT_INVALID", path, "variable snapshot value is outside bounds"
            ) from exc
    if type(value) is list:
        return [
            _checkpoint_literal(
                item, f"{path}[{index}]", depth=depth + 1, budget=budget
            )
            for index, item in enumerate(value)
        ]
    if type(value) is dict:
        canonical: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > MAX_STRING_LENGTH:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID", path, "variable snapshot key is invalid"
                )
            canonical[key] = _checkpoint_literal(
                item, f"{path}.{key}", depth=depth + 1, budget=budget
            )
        return canonical
    raise V06ValidationError(
        "INSPECTION_EDIT_INVALID", path, "variable snapshot contains an unsupported type"
    )


def _literal_type(value: Any) -> str:
    if value is None:
        return "NULL"
    return {
        bool: "BOOLEAN",
        int: "INTEGER",
        float: "FINITE_DECIMAL",
        str: "STRING",
        list: "LIST",
        dict: "MAP",
    }.get(type(value), "UNSUPPORTED")


def _matches_inspection_type(value: Any, declared_type: str) -> bool:
    actual = _literal_type(value)
    return actual == declared_type or (
        declared_type == "FINITE_DECIMAL" and actual == "INTEGER"
    )


def _same_checkpoint_type(previous: Any, current: Any) -> bool:
    previous_type = _literal_type(previous)
    current_type = _literal_type(current)
    return previous_type == current_type or (
        previous_type == "FINITE_DECIMAL" and current_type == "INTEGER"
    )


def _inspection_target(scope: Any, path: Any) -> tuple[str | None, str]:
    prefixes = {
        "LOCAL_VARIABLE": (None, ("variables.", "LOCAL_VARIABLE.")),
        "GLOBAL_VARIABLE": ("GLOBALS", ("GLOBALS.", "GLOBAL_VARIABLE.")),
        "ARGS": ("ARGS", ("ARGS.",)),
        "IVARS": ("IVARS", ("IVARS.",)),
    }
    if type(scope) is not str or scope not in prefixes or type(path) is not str:
        raise V06ValidationError(
            "INSPECTION_EDIT_INVALID", "$.scope", "inspection scope is not editable"
        )
    container, accepted = prefixes[scope]
    for prefix in accepted:
        if path.startswith(prefix):
            name = path[len(prefix) :]
            if name and "." not in name and not name.startswith("__spell_"):
                return container, name
    raise V06ValidationError(
        "INSPECTION_EDIT_INVALID", "$.path", "inspection path is invalid"
    )


def _non_empty_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ExpressionEvaluationError(f"{label} must be a non-empty string")
    return value


def worker_main(
    execution_id: str,
    generation: int,
    ir_version: str,
    steps: list[dict[str, Any]],
    start_step: int,
    start_command_id: str,
    resume_prompt_id: str | None,
    checkpoint_variables: dict[str, Any],
    control: Queue,
    output: Queue,
    resume_prompt_settlement: dict[str, Any] | None = None,
    durable_arguments: dict[str, Any] | None = None,
    safe_point_ack_required: bool = True,
) -> None:
    """Validate and execute data-only IR in a spawned process."""

    _replace_worker_environment()

    def send(kind: str, **fields: Any) -> None:
        output.put({"kind": kind, "generation": generation, **fields})

    try:
        v08_preflight = ir_version == V08_IR_VERSION
        v07_preflight = ir_version == V07_IR_VERSION
        v06_preflight = ir_version in {V06_IR_VERSION, V07_IR_VERSION, V08_IR_VERSION}
        validator = (
            validate_ir_v08
            if v08_preflight
            else validate_ir_v07
            if v07_preflight
            else validate_ir_v06
            if v06_preflight
            else validate_ir_v03
        )
        lexical_checkpoint = checkpoint_variables
        runtime_checkpoint: dict[str, Any] = {}
        if v06_preflight and type(checkpoint_variables) is dict:
            lexical_checkpoint = dict(checkpoint_variables)
            runtime_checkpoint = {
                name: lexical_checkpoint.pop(name)
                for name in RUNTIME_CONTAINER_NAMES
                if name in lexical_checkpoint
            }
        validated_ir = validator(
            ir_version,
            steps,
            start_step=start_step,
            resume_prompt_id=resume_prompt_id,
            checkpoint_variables=lexical_checkpoint,
        )
        if v06_preflight:
            runtime_checkpoint = {
                name: _checkpoint_literal(value, f"$.checkpoint_variables.{name}")
                for name, value in runtime_checkpoint.items()
            }
            for name, value in runtime_checkpoint.items():
                if type(value) is not dict:
                    raise V06ValidationError(
                        "INSPECTION_EDIT_INVALID",
                        f"$.checkpoint_variables.{name}",
                        "runtime container must be an object",
                    )
            checkpoint_arguments = runtime_checkpoint.pop("ARGS", None)
            if checkpoint_arguments is not None:
                if (
                    durable_arguments is not None
                    and durable_arguments != checkpoint_arguments
                ):
                    raise V06ValidationError(
                        "WORKER_RESUME_INVALID",
                        "$.checkpoint_variables.ARGS",
                        "procedure argument bindings conflict",
                    )
                durable_arguments = checkpoint_arguments
        if type(safe_point_ack_required) is not bool:
            raise V06ValidationError(
                "WORKER_RESUME_INVALID",
                "$.safe_point_ack_required",
                "safe-point ACK policy must be Boolean",
            )
        if durable_arguments is not None:
            reject_secret_material(durable_arguments, "$.durable_arguments")
            durable_arguments = validate_startproc_declaration(
                "runtime/arguments",
                arguments=durable_arguments,
            ).arguments
        if resume_prompt_settlement is not None:
            if type(resume_prompt_settlement) is not dict or set(
                resume_prompt_settlement
            ) != {
                "prompt_id",
                "settlement_id",
                "outcome",
                "response",
                "command_id",
            }:
                raise V06ValidationError(
                    "WORKER_RESUME_INVALID",
                    "$.resume_prompt_settlement",
                    "prompt settlement resume fields are invalid",
                )
            if (
                type(resume_prompt_id) is not str
                or resume_prompt_settlement["prompt_id"] != resume_prompt_id
                or type(resume_prompt_settlement["settlement_id"]) is not str
                or not resume_prompt_settlement["settlement_id"]
                or resume_prompt_settlement["outcome"]
                not in {
                    "ANSWERED",
                    "TIMED_OUT",
                    "NO_CONTROLLER",
                    "EXECUTION_TERMINATED",
                    "ERROR",
                    "CANCELLED",
                }
                or (
                    resume_prompt_settlement["command_id"] is not None
                    and type(resume_prompt_settlement["command_id"]) is not str
                )
            ):
                raise V06ValidationError(
                    "WORKER_RESUME_INVALID",
                    "$.resume_prompt_settlement",
                    "prompt settlement resume identity is invalid",
                )
            reject_secret_material(
                resume_prompt_settlement["response"],
                "$.resume_prompt_settlement.response",
            )
            bounded_response = validate_startproc_declaration(
                "runtime/prompt-response",
                arguments={"response": resume_prompt_settlement["response"]},
            ).arguments["response"]
            resume_prompt_settlement = {
                **resume_prompt_settlement,
                "response": bounded_response,
            }
    except (
        IRValidationError,
        V06ValidationError,
        V07ValidationError,
        V08ValidationError,
    ) as exc:
        send(
            "event",
            event_type="worker.ir_rejected",
            source="worker",
            severity="error",
            payload={"phase": "worker_preflight", **exc.audit_payload()},
        )
        send("state", state="failed")
        send("terminal", state="failed")
        return

    steps = validated_ir.steps
    variables = dict(validated_ir.checkpoint_variables)
    variables.update(runtime_checkpoint)
    if durable_arguments is not None:
        variables["ARGS"] = durable_arguments
    v06_runtime = ir_version in {V06_IR_VERSION, V07_IR_VERSION, V08_IR_VERSION}
    file_handle_variables = {
        step["target"]
        for step in steps
        if step.get("type") == "data_operation"
        and step.get("operation") == "OPEN_FILE"
        and type(step.get("target")) is str
    }
    send(
        "event",
        event_type="worker.started",
        source="worker",
        payload={"generation": generation, "start_step": start_step, "pid": os.getpid()},
    )
    send("state", state="running", command_id=start_command_id)

    deferred_controls: deque[dict[str, Any]] = deque()
    completed_prompt_ids: set[str] = set()
    completed_prompt_settlement_ids: set[str] = set()
    completed_startproc_ids: set[str] = set()
    completed_observation_ids: set[str] = set()
    completed_data_ids: set[str] = set()
    applied_user_actions: dict[str, dict[str, Any]] = {}
    applied_inspection_edits: dict[str, dict[str, Any]] = {}
    applied_control_losses: set[str] = set()
    applied_operator_commands: dict[str, tuple[str, dict[str, Any]]] = {}

    operator_control_types = {
        "abort",
        "background",
        "goto",
        "pause",
        "resume",
        "run",
        "skip",
        "step",
        "step_over",
        "stop",
    }

    def emit_operator_application(
        kind: str,
        command_id: str | None,
        **fields: Any,
    ) -> None:
        if type(command_id) is not str or not command_id:
            send(kind, command_id=command_id, **fields)
            return
        payload = {"command_id": command_id, **fields}
        applied_operator_commands[command_id] = (kind, payload)
        send(kind, **payload)

    def replay_operator_application(message: dict[str, Any]) -> bool:
        command_id = message.get("command_id")
        if (
            message.get("type") not in operator_control_types
            or type(command_id) is not str
            or command_id not in applied_operator_commands
        ):
            return False
        kind, cached = applied_operator_commands[command_id]
        payload = dict(cached)
        payload["replayed"] = True
        send(kind, **payload)
        return True

    def receive_control(block: bool = False, timeout: float = 0.0) -> dict[str, Any] | None:
        try:
            return control.get(block=block, timeout=timeout if block else None)
        except queue.Empty:
            return None

    def wait_for_control(block: bool = False, timeout: float = 0.0) -> dict[str, Any] | None:
        if deferred_controls:
            return deferred_controls.popleft()
        return receive_control(block=block, timeout=timeout)

    def send_safe_point(kind: str, step_index: int) -> str | None:
        if not v06_runtime or step_index >= len(steps):
            return None
        token = str(uuid.uuid4())
        send(
            "safe_point",
            safe_point_token=token,
            safe_point_kind=kind,
            step_index=step_index,
            line=steps[step_index]["line"],
            lexical_frame_id=steps[step_index].get("lexical_frame_id"),
            reachability_id=steps[step_index].get("reachability_id"),
            effect_certainty="NO_EFFECT",
        )
        return token

    def await_safe_point_ack(token: str) -> list[dict[str, Any]]:
        pending: list[dict[str, Any]] = []
        while True:
            message = wait_for_control(block=True, timeout=0.25)
            if (
                message is not None
                and message.get("type") == "safe_point_ack"
                and message.get("safe_point_token") == token
            ):
                return pending
            if message is not None:
                pending.append(message)

    def reject_control(message: dict[str, Any], code: str, detail: str) -> None:
        send(
            "command_rejected",
            command_id=message.get("command_id"),
            command_type=message.get("type"),
            code=code,
            detail=detail,
        )

    def apply_user_action(message: dict[str, Any], step_index: int) -> None:
        invocation_id = message.get("invocation_id")
        if type(invocation_id) is str and invocation_id in applied_user_actions:
            replay = dict(applied_user_actions[invocation_id])
            replay["effects"] = []
            replay["replayed"] = True
            send("user_action_settled", **replay)
            return
        try:
            operations = validate_user_action_block(message.get("handler"))
            effects: list[dict[str, Any]] = []
            for operation in operations:
                if operation.operation == "LOG":
                    effects.append(
                        {
                            "event_type": "procedure.user_action_log",
                            "source": "procedure",
                            "severity": operation.payload["severity"],
                            "payload": {
                                "message": operation.payload["message"],
                                "step_index": step_index,
                                "invocation_id": invocation_id,
                            },
                        }
                    )
                    continue
                name = operation.payload["name"]
                declared_type = operation.payload["declared_type"]
                if name in file_handle_variables:
                    raise V06ValidationError(
                        "USER_ACTION_TARGET_INVALID",
                        "$.handler.name",
                        "FileHandle variables are not user-action targets",
                    )
                if name not in validated_ir.variable_types or name not in variables:
                    raise V06ValidationError(
                        "USER_ACTION_TARGET_INVALID", "$.handler.name", "target does not exist"
                    )
                if validated_ir.variable_types[name] != declared_type:
                    raise V06ValidationError(
                        "USER_ACTION_TARGET_INVALID", "$.handler.declared_type", "type changed"
                    )
                variables[name] = operation.payload["value"]
            result = {
                "invocation_id": invocation_id,
                "outcome": "EXECUTED",
                "safe_point_step": step_index,
                "effects": effects,
                "variables": dict(variables),
                "application_id": str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"openbexi-spell:user-action:{execution_id}:{invocation_id}",
                    )
                ),
            }
            if type(invocation_id) is str:
                applied_user_actions[invocation_id] = dict(result)
            send("user_action_settled", **result)
        except V06ValidationError as exc:
            result = {
                "invocation_id": invocation_id,
                "outcome": "REJECTED",
                "safe_point_step": step_index,
                "code": exc.code,
                "detail": exc.message,
                "effects": [],
                "variables": dict(variables),
                "application_id": str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"openbexi-spell:user-action:{execution_id}:{invocation_id}",
                    )
                ),
            }
            if type(invocation_id) is str:
                applied_user_actions[invocation_id] = dict(result)
            send("user_action_settled", **result)

    def apply_inspection_edit(message: dict[str, Any], step_index: int) -> None:
        edit_id = message.get("edit_id")
        if type(edit_id) is str and edit_id in applied_inspection_edits:
            replay = dict(applied_inspection_edits[edit_id])
            replay["replayed"] = True
            send("inspection_edit_applied", **replay)
            return
        try:
            if type(edit_id) is not str or not edit_id:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID", "$.edit_id", "edit identity is invalid"
                )
            snapshot = message.get("variables")
            if type(snapshot) is not dict:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.variables",
                    "authoritative variables are missing",
                )
            if set(snapshot) != set(variables):
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.variables",
                    "variable snapshot structure changed",
                )
            incoming = {
                name: _checkpoint_literal(value, f"$.variables.{name}")
                for name, value in snapshot.items()
            }
            if incoming.get("SHARED_DATA") != variables.get("SHARED_DATA"):
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.variables.SHARED_DATA",
                    "shared data is read-only",
                )
            target_container, target_name = _inspection_target(
                message.get("scope"), message.get("path")
            )
            if target_container is None and target_name in file_handle_variables:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.path",
                    "FileHandle variables are not inspection-edit targets",
                )
            if ir_version == V08_IR_VERSION and target_container == "ARGS":
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.scope",
                    "v0.8 ARGS is immutable after admission",
                )
            declared_edit_type = message.get("declared_type")
            if type(declared_edit_type) is not str:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.declared_type",
                    "inspection type is missing",
                )
            for name, value in incoming.items():
                if name in RUNTIME_CONTAINER_NAMES:
                    continue
                if name in file_handle_variables and is_file_handle_reference(value):
                    if value != variables.get(name):
                        raise V06ValidationError(
                            "INSPECTION_EDIT_INVALID",
                            "$.variables",
                            "FileHandle checkpoint reference changed",
                        )
                    continue
                declared_type = validated_ir.variable_types.get(name)
                if (
                    declared_type is None
                    or name not in variables
                    or not _matches_type(value, declared_type)
                ):
                    raise V06ValidationError(
                        "INSPECTION_EDIT_INVALID",
                        "$.variables",
                        "variable snapshot does not match the pinned IR",
                    )
                if (target_container is not None or name != target_name) and value != variables[name]:
                    raise V06ValidationError(
                        "INSPECTION_EDIT_INVALID",
                        "$.variables",
                        "snapshot changes more than the admitted target",
                    )
            for container_name in ("ARGS", "GLOBALS", "IVARS"):
                previous_container = variables.get(container_name)
                incoming_container = incoming.get(container_name)
                if previous_container is None and incoming_container is None:
                    continue
                if type(previous_container) is not dict or type(incoming_container) is not dict:
                    raise V06ValidationError(
                        "INSPECTION_EDIT_INVALID",
                        f"$.variables.{container_name}",
                        "runtime container is invalid",
                    )
                if set(previous_container) != set(incoming_container):
                    raise V06ValidationError(
                        "INSPECTION_EDIT_INVALID",
                        f"$.variables.{container_name}",
                        "runtime container structure changed",
                    )
                for name, value in incoming_container.items():
                    if not _same_checkpoint_type(previous_container[name], value):
                        raise V06ValidationError(
                            "INSPECTION_EDIT_INVALID",
                            f"$.variables.{container_name}",
                            "runtime container value type changed",
                        )
                    if (
                        target_container != container_name or name != target_name
                    ) and value != previous_container[name]:
                        raise V06ValidationError(
                            "INSPECTION_EDIT_INVALID",
                            "$.variables",
                            "snapshot changes more than the admitted target",
                        )
            target_values = incoming if target_container is None else incoming.get(target_container)
            if type(target_values) is not dict or target_name not in target_values:
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID", "$.path", "inspection target does not exist"
                )
            if not _matches_inspection_type(target_values[target_name], declared_edit_type):
                raise V06ValidationError(
                    "INSPECTION_EDIT_INVALID",
                    "$.declared_type",
                    "inspection value does not match its declared type",
                )
            reject_secret_material(target_values[target_name], "$.variables.target")
            variables.clear()
            variables.update(incoming)
            result = {
                "edit_id": edit_id,
                "outcome": "APPLIED",
                "safe_point_step": step_index,
                "variables": dict(variables),
                "execution_revision": message.get("execution_revision"),
                "application_id": str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"openbexi-spell:inspection-edit:{execution_id}:{edit_id}",
                    )
                ),
            }
        except V06ValidationError as exc:
            result = {
                "edit_id": edit_id,
                "outcome": "REJECTED",
                "safe_point_step": step_index,
                "variables": dict(variables),
                "execution_revision": message.get("execution_revision"),
                "code": exc.code,
                "detail": exc.message,
                "application_id": str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"openbexi-spell:inspection-edit:{execution_id}:{edit_id}",
                    )
                ),
            }
        if type(edit_id) is str:
            applied_inspection_edits[edit_id] = dict(result)
        send("inspection_edit_applied", **result)

    def acknowledge_control_loss(
        message: dict[str, Any], step_index: int
    ) -> str:
        delivery_id = message.get("delivery_id") or message.get("lease_id")
        if type(delivery_id) is not str or not delivery_id:
            reject_control(
                message,
                "CONTROL_LOSS_INVALID",
                "control-loss delivery identity is invalid",
            )
            return "control-loss-invalid"
        replayed = delivery_id in applied_control_losses
        applied_control_losses.add(delivery_id)
        send(
            "control_loss_applied",
            delivery_id=delivery_id,
            lease_id=message.get("lease_id"),
            fencing_token=message.get("fencing_token"),
            safe_point_step=step_index,
            replayed=replayed,
        )
        return delivery_id

    def pause_loop(
        initiating_command_id: str,
        step_index: int,
        control_loss: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if initiating_command_id in applied_operator_commands:
            send("state", state="paused", command_id=initiating_command_id)
        else:
            emit_operator_application(
                "state", initiating_command_id, state="paused"
            )
        if control_loss is not None:
            acknowledge_control_loss(control_loss, step_index)
        pending_followups: deque[dict[str, Any]] = deque()
        while True:
            followup = (
                pending_followups.popleft()
                if pending_followups
                else receive_control(block=True, timeout=0.25)
            )
            if followup is None:
                continue
            if replay_operator_application(followup):
                continue
            command_type = followup.get("type")
            command_id = followup.get("command_id")
            if command_type in {
                "prompt_response",
                "prompt_settlement",
                "startproc_result",
                "observation_result",
                "data_result",
            }:
                deferred_controls.append(followup)
                continue
            if command_type in {"resume", "run"}:
                emit_operator_application(
                    "state", command_id, state="running"
                )
                return {
                    "disposition": "run",
                    "run_budget": None,
                    "target_step": step_index,
                }
            if command_type == "pause":
                emit_operator_application(
                    "state", command_id, state="paused"
                )
                continue
            if command_type == "control_loss":
                acknowledge_control_loss(followup, step_index)
                continue
            if command_type in {"step", "step_over"}:
                target = step_index + 1
                if command_type == "step_over":
                    target = steps[step_index].get("step_over_target", target)
                    if type(target) is not int or target <= step_index or target > len(steps):
                        reject_control(
                            followup,
                            "COMMAND_TARGET_INVALID",
                            "step-over boundary is invalid",
                        )
                        continue
                send("state", state="running")
                return {
                    "disposition": "run",
                    "run_budget": target - step_index,
                    "budget_command_id": command_id,
                    "budget_command_type": command_type,
                    "target_step": step_index,
                }
            if command_type == "skip":
                target = step_index + 1
                if target >= len(steps):
                    reject_control(followup, "COMMAND_TARGET_INVALID", "skip has no successor")
                    continue
                emit_operator_application(
                    "command_applied",
                    command_id,
                    command_type="SKIP",
                    safe_point_step=target,
                    checkpoint_step=target,
                    result={"target_step": target, "state": "PAUSED"},
                )
                step_index = target
                token = send_safe_point("BEFORE_STATEMENT", step_index)
                if token is not None and safe_point_ack_required:
                    pending_followups.extend(await_safe_point_ack(token))
                continue
            if command_type == "goto":
                target = followup.get("target_step")
                if type(target) is not int or target < 0 or target >= len(steps):
                    reject_control(followup, "COMMAND_TARGET_INVALID", "goto target is invalid")
                    continue
                emit_operator_application(
                    "command_applied",
                    command_id,
                    command_type="GOTO",
                    safe_point_step=target,
                    checkpoint_step=target,
                    result={"target_step": target, "state": "PAUSED"},
                )
                step_index = target
                token = send_safe_point("BEFORE_STATEMENT", step_index)
                if token is not None and safe_point_ack_required:
                    pending_followups.extend(await_safe_point_ack(token))
                continue
            if command_type == "background":
                emit_operator_application(
                    "command_applied",
                    command_id,
                    command_type="BACKGROUND",
                    safe_point_step=step_index,
                    result={"ownership_mode": "B"},
                )
                send("state", state="running")
                return {
                    "disposition": "run",
                    "run_budget": None,
                    "target_step": step_index,
                }
            if command_type in {"abort", "stop"}:
                emit_operator_application(
                    "state", command_id, state="aborted"
                )
                send("terminal", state="aborted")
                return {"disposition": "abort"}
            if command_type == "kill":
                reject_control(followup, "KILL_UNSUPPORTED", "hard kill is not supported")
                continue
            if command_type == "user_action":
                apply_user_action(followup, step_index)
                continue
            if command_type == "inspection_edit":
                apply_inspection_edit(followup, step_index)
                continue
            reject_control(followup, "COMMAND_NOT_ALLOWED_IN_STATE", "command is not valid while paused")

    def handle_control(
        message: dict[str, Any] | None,
        step_index: int,
    ) -> dict[str, Any] | None:
        if message is None:
            return None
        if replay_operator_application(message):
            return None
        command_type = message.get("type")
        command_id = message.get("command_id")
        if command_type in {"prompt_response", "prompt_settlement"}:
            prompt_id = message.get("prompt_id")
            settlement_id = message.get("settlement_id")
            if prompt_id in completed_prompt_ids or (
                type(settlement_id) is str
                and settlement_id in completed_prompt_settlement_ids
            ):
                return None
            deferred_controls.append(message)
            return None
        if command_type == "startproc_result":
            if message.get("startproc_id") in completed_startproc_ids:
                return None
            deferred_controls.append(message)
            return None
        if command_type == "observation_result":
            if message.get("request_id") in completed_observation_ids:
                return None
            deferred_controls.append(message)
            return None
        if command_type == "data_result":
            if message.get("request_id") in completed_data_ids:
                return None
            deferred_controls.append(message)
            return None
        if command_type in {"abort", "stop"}:
            emit_operator_application(
                "state", command_id, state="aborted"
            )
            send("terminal", state="aborted")
            return {"disposition": "abort"}
        if command_type == "pause":
            return pause_loop(command_id, step_index)
        if command_type == "control_loss":
            delivery_id = message.get("delivery_id") or message.get("lease_id")
            return pause_loop(
                f"control-loss:{delivery_id}",
                step_index,
                control_loss=message,
            )
        if command_type == "kill":
            reject_control(message, "KILL_UNSUPPORTED", "hard kill is not supported")
            return None
        if command_type == "user_action":
            apply_user_action(message, step_index)
            return None
        if command_type == "inspection_edit":
            apply_inspection_edit(message, step_index)
            return None
        if command_type == "background":
            emit_operator_application(
                "command_applied",
                command_id,
                command_type="BACKGROUND",
                safe_point_step=step_index,
                result={"ownership_mode": "B"},
            )
            return None
        if command_type in {"step", "step_over", "skip", "goto", "run", "resume"}:
            reject_control(message, "COMMAND_NOT_ALLOWED_IN_STATE", "command requires a paused safe point")
        return None

    step_index = start_step
    run_budget: int | None = None
    budget_command_id: str | None = None
    budget_command_type: str | None = None
    while step_index < len(steps):
        safe_point_token = send_safe_point("BEFORE_STATEMENT", step_index)
        pending_controls = (
            await_safe_point_ack(safe_point_token)
            if safe_point_token is not None and safe_point_ack_required
            else []
        )
        directive = None
        for pending_control in [*pending_controls, wait_for_control()]:
            candidate = handle_control(pending_control, step_index)
            if candidate is not None:
                directive = candidate
                break
        if directive is not None and directive["disposition"] == "abort":
            return
        if directive is not None and directive["disposition"] == "run":
            run_budget = directive.get("run_budget")
            budget_command_id = directive.get("budget_command_id")
            budget_command_type = directive.get("budget_command_type")
            if "target_step" in directive:
                step_index = directive["target_step"]
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
                if v06_runtime:
                    send_safe_point("WAIT_BOUNDARY", step_index)
                    send("state", state="waiting")
                remaining = float(seconds)
                while remaining > 0:
                    started = time.monotonic()
                    result = handle_control(
                        wait_for_control(block=True, timeout=min(0.05, remaining)),
                        step_index,
                    )
                    elapsed = time.monotonic() - started
                    if result is not None and result["disposition"] == "abort":
                        return
                    if result is None:
                        remaining = max(0.0, remaining - elapsed)
                if v06_runtime:
                    send("state", state="running")
            elif should_run and step["type"] == "prompt":
                prompt_id = resume_prompt_id or str(uuid.uuid4())
                resume_prompt_id = None
                if (
                    resume_prompt_settlement is not None
                    and resume_prompt_settlement.get("prompt_id") == prompt_id
                ):
                    prompt_resolution = dict(resume_prompt_settlement)
                    resume_prompt_settlement = None
                    completed_prompt_ids.add(prompt_id)
                    settlement_id = prompt_resolution.get("settlement_id")
                    if type(settlement_id) is str:
                        completed_prompt_settlement_ids.add(settlement_id)
                    effects.append(
                        {
                            "event_type": "prompt.settlement_replayed",
                            "source": "worker",
                            "severity": "info",
                            "payload": {
                                "prompt_id": prompt_id,
                                "settlement_id": prompt_resolution.get("settlement_id"),
                                "outcome": prompt_resolution.get("outcome"),
                            },
                        }
                    )
                else:
                    question = _non_empty_string(
                        evaluate_expression(step["question"], variables),
                        "Prompt question",
                    )
                    if v06_runtime:
                        reject_secret_material(question, "$.question")
                    prompt_fields: dict[str, Any] = {
                        "prompt_id": prompt_id,
                        "step_index": step_index,
                        "question": question,
                        "choices": step["choices"],
                        "default": step["default"],
                    }
                    if v06_runtime and "prompt_type" in step:
                        prompt_fields.update(
                            prompt_type=step["prompt_type"],
                            list_mode=step["list_mode"],
                            warning_delay_seconds=step["warning_delay_seconds"],
                            response_timeout_seconds=step["response_timeout_seconds"],
                            no_controller_grace_seconds=step["no_controller_grace_seconds"],
                        )
                    send("prompt_opened", **prompt_fields)
                    send_safe_point("PROMPT_BOUNDARY", step_index)
                    send("state", state="prompting")
                while prompt_resolution is None:
                    message = wait_for_control(block=True, timeout=0.25)
                    if message is None:
                        continue
                    message_type = message.get("type")
                    if message_type == "safe_point_ack":
                        continue
                    if message_type in {"abort", "stop"}:
                        send("state", state="aborted", command_id=message.get("command_id"))
                        send("terminal", state="aborted")
                        return
                    if message_type == "kill":
                        reject_control(message, "KILL_UNSUPPORTED", "hard kill is not supported")
                        continue
                    if message_type == "user_action":
                        apply_user_action(message, step_index)
                        continue
                    if message_type == "inspection_edit":
                        apply_inspection_edit(message, step_index)
                        continue
                    if message_type in {"pause", "control_loss"}:
                        result = handle_control(message, step_index)
                        if result is not None and result["disposition"] == "abort":
                            return
                        send("state", state="prompting")
                        continue
                    if message_type not in {"prompt_response", "prompt_settlement"}:
                        reject_control(
                            message,
                            "COMMAND_NOT_ALLOWED_IN_STATE",
                            "only prompt settlement is accepted at a prompt boundary",
                        )
                        continue
                    if message.get("prompt_id") != prompt_id:
                        reject_control(message, "PROMPT_NOT_OPEN", "prompt identity does not match")
                        continue
                    outcome = message.get("outcome", "ANSWERED")
                    response = message.get("response", message.get("value"))
                    if v06_runtime and "prompt_type" in step and outcome == "ANSWERED":
                        try:
                            response = normalize_prompt_value(
                                step["prompt_type"],
                                response,
                                choices=step["choices"],
                                list_mode=step["list_mode"],
                            )
                        except V06ValidationError as exc:
                            reject_control(message, exc.code, exc.message)
                            continue
                    elif (
                        not v06_runtime
                        and outcome == "ANSWERED"
                        and response not in step["choices"]
                    ):
                        reject_control(message, "PROMPT_VALUE_INVALID", "response is not a choice")
                        continue
                    if outcome not in {
                        "ANSWERED",
                        "CANCELLED",
                        "TIMED_OUT",
                        "NO_CONTROLLER",
                        "EXECUTION_TERMINATED",
                        "ERROR",
                    }:
                        reject_control(message, "PROMPT_OUTCOME_INVALID", "outcome is invalid")
                        continue
                    prompt_resolution = {
                        "prompt_id": prompt_id,
                        "response": response,
                        "outcome": outcome,
                        "settlement_id": message.get("settlement_id"),
                        "command_id": message.get("command_id"),
                    }
                    completed_prompt_ids.add(prompt_id)
                    settlement_id = prompt_resolution.get("settlement_id")
                    if type(settlement_id) is str:
                        completed_prompt_settlement_ids.add(settlement_id)
                    break
            elif should_run and step["type"] == "startproc":
                startproc_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"openbexi-spell:startproc:{execution_id}:{step_index}",
                    )
                )
                send(
                    "startproc_requested",
                    startproc_id=startproc_id,
                    step_index=step_index,
                    child_reference=step["child_reference"],
                    arguments=step["arguments"],
                    arguments_digest=step["arguments_digest"],
                    blocking=step["blocking"],
                    visible=step["visible"],
                    automatic=step["automatic"],
                )
                send("state", state="waiting")
                while True:
                    message = wait_for_control(block=True, timeout=0.25)
                    if message is None:
                        continue
                    message_type = message.get("type")
                    if message_type in {"abort", "stop"}:
                        send("state", state="aborted", command_id=message.get("command_id"))
                        send("terminal", state="aborted")
                        return
                    if message_type == "kill":
                        reject_control(message, "KILL_UNSUPPORTED", "hard kill is not supported")
                        continue
                    if message_type in {"pause", "control_loss"}:
                        result = handle_control(message, step_index)
                        if result is not None and result["disposition"] == "abort":
                            return
                        send("state", state="waiting")
                        continue
                    if message_type == "user_action":
                        apply_user_action(message, step_index)
                        continue
                    if message_type == "inspection_edit":
                        apply_inspection_edit(message, step_index)
                        continue
                    if message_type != "startproc_result" or message.get("startproc_id") != startproc_id:
                        reject_control(message, "STARTPROC_RESULT_INVALID", "child result does not match")
                        continue
                    outcome = message.get("outcome")
                    if outcome != "SETTLED" or type(message.get("child_execution_id")) is not str:
                        raise ExpressionEvaluationError(
                            f"StartProc failed: {message.get('rejection_code', 'ADMISSION_REJECTED')}"
                        )
                    startproc_result = message.get("result") or {}
                    if step["blocking"] and startproc_result.get("outcome") == "CHILD_FAILED":
                        raise ExpressionEvaluationError(
                            f"StartProc child failed: {startproc_result.get('child_state', 'ERROR')}"
                        )
                    effects.append(
                        {
                            "event_type": "procedure.startproc_settled",
                            "source": "worker",
                            "severity": "info",
                            "payload": {
                                "startproc_id": startproc_id,
                                "delivery_revision": message.get(
                                    "delivery_revision", 0
                                ),
                                "child_execution_id": message["child_execution_id"],
                                "blocking": step["blocking"],
                                "step_index": step_index,
                            },
                        }
                    )
                    completed_startproc_ids.add(startproc_id)
                    break
            elif should_run and step["type"] in {"get_tm", "verify", "wait_for"}:
                request = observation_request_for_step(execution_id, step)
                send("observation_requested", **request)
                send_safe_point("WAIT_BOUNDARY", step_index)
                send("state", state="waiting")
                observation_result: dict[str, Any] | None = None
                while observation_result is None:
                    message = wait_for_control(block=True, timeout=0.25)
                    if message is None:
                        continue
                    message_type = message.get("type")
                    if message_type == "safe_point_ack":
                        continue
                    if message_type in {"abort", "stop"}:
                        send("state", state="aborted", command_id=message.get("command_id"))
                        send("terminal", state="aborted")
                        return
                    if message_type == "kill":
                        reject_control(message, "KILL_UNSUPPORTED", "hard kill is not supported")
                        continue
                    if message_type in {"pause", "control_loss"}:
                        result = handle_control(message, step_index)
                        if result is not None and result["disposition"] == "abort":
                            return
                        send("state", state="waiting")
                        continue
                    if message_type == "user_action":
                        apply_user_action(message, step_index)
                        continue
                    if message_type == "inspection_edit":
                        apply_inspection_edit(message, step_index)
                        continue
                    if message_type != "observation_result":
                        reject_control(
                            message,
                            "COMMAND_NOT_ALLOWED_IN_STATE",
                            "only an observation result is accepted at this boundary",
                        )
                        continue
                    if message.get("request_id") != request["request_id"]:
                        reject_control(
                            message,
                            "OBSERVATION_RESULT_INVALID",
                            "observation result identity does not match",
                        )
                        continue
                    candidate = {
                        key: value
                        for key, value in message.items()
                        if key not in {"type", "generation"}
                    }
                    try:
                        observation_result = validate_observation_result(request, candidate)
                    except V07ValidationError as exc:
                        reject_control(message, exc.code, exc.message)
                        continue

                completed_observation_ids.add(request["request_id"])
                outcome = observation_result["outcome"]
                if step["type"] == "get_tm":
                    if outcome != "OK":
                        raise ExpressionEvaluationError(f"GetTM failed with {outcome}")
                    value = observation_result["value"]
                    if not _matches_type(value, step["scalar_type"]):
                        raise ExpressionEvaluationError("GetTM result type changed")
                    variables[step["target"]] = (
                        float(value)
                        if step["scalar_type"] == "float" and type(value) is int
                        else value
                    )
                elif step["type"] == "verify":
                    variables[step["target"]] = outcome
                elif outcome != "SATISFIED":
                    raise ExpressionEvaluationError(f"WaitFor failed with {outcome}")
                effects.append(
                    {
                        "event_type": "procedure.observation_settled",
                        "source": "worker",
                        "severity": "info",
                        "payload": {
                            "request_id": request["request_id"],
                            "operation": request["operation"],
                            "outcome": outcome,
                            "step_index": step_index,
                        },
                    }
                )
                send("state", state="running")
            elif should_run and step["type"] == "data_operation":
                request = data_request_for_step(
                    execution_id,
                    step,
                    variables=variables,
                    worker_generation=generation,
                )
                send("data_requested", **request)
                send_safe_point("WAIT_BOUNDARY", step_index)
                send("state", state="waiting")
                data_result: dict[str, Any] | None = None
                while data_result is None:
                    message = wait_for_control(block=True, timeout=0.25)
                    if message is None:
                        continue
                    message_type = message.get("type")
                    if message_type == "safe_point_ack":
                        continue
                    if message_type in {"abort", "stop"}:
                        send("state", state="aborted", command_id=message.get("command_id"))
                        send("terminal", state="aborted")
                        return
                    if message_type == "kill":
                        reject_control(message, "KILL_UNSUPPORTED", "hard kill is not supported")
                        continue
                    if message_type in {"pause", "control_loss"}:
                        result = handle_control(message, step_index)
                        if result is not None and result["disposition"] == "abort":
                            return
                        send("state", state="waiting")
                        continue
                    if message_type == "user_action":
                        apply_user_action(message, step_index)
                        continue
                    if message_type == "inspection_edit":
                        apply_inspection_edit(message, step_index)
                        continue
                    if message_type != "data_result":
                        reject_control(
                            message,
                            "COMMAND_NOT_ALLOWED_IN_STATE",
                            "only a data result is accepted at this boundary",
                        )
                        continue
                    if message.get("request_id") != request["request_id"]:
                        reject_control(
                            message,
                            "DATA_RESULT_INVALID",
                            "data result identity does not match",
                        )
                        continue
                    candidate = {
                        key: value
                        for key, value in message.items()
                        if key not in {"type", "generation"}
                    }
                    try:
                        data_result = validate_data_result(request, candidate)
                    except V08ValidationError as exc:
                        reject_control(message, exc.code, exc.message)
                        continue

                completed_data_ids.add(request["request_id"])
                if data_result["outcome"] != "OK":
                    raise ExpressionEvaluationError(
                        f"{request['operation']} failed with {data_result['outcome']}"
                    )
                if "target" in step:
                    if "value" not in data_result:
                        raise ExpressionEvaluationError("data result omitted its target value")
                    value = data_result["value"]
                    if not _matches_type(value, step["target_type"]):
                        raise ExpressionEvaluationError("data result type changed")
                    if request["operation"] == "OPEN_FILE":
                        variables[step["target"]] = file_handle_reference(
                            value,
                            execution_id=execution_id,
                            worker_generation=generation,
                            creator_request_id=request["request_id"],
                        )
                    else:
                        variables[step["target"]] = (
                            float(value)
                            if step["target_type"] == "float" and type(value) is int
                            else value
                        )
                if request["operation"] == "CLOSE_FILE":
                    reference = step["parameters"]["handle"]
                    variables[reference["name"]] = closed_file_handle_reference(
                        variables.get(reference["name"])
                    )
                effects.append(
                    {
                        "event_type": "procedure.data_settled",
                        "source": "worker",
                        "severity": "info",
                        "payload": {
                            "request_id": request["request_id"],
                            "operation": request["operation"],
                            "outcome": data_result["outcome"],
                            "step_index": step_index,
                        },
                    }
                )
                send("state", state="running")
        except (
            ExpressionEvaluationError,
            V06ValidationError,
            V07ValidationError,
            V08ValidationError,
        ) as exc:
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

        if v06_runtime:
            safe_kind = (
                "AFTER_PURE_STATEMENT"
                if step["type"] == "variable_set" or not should_run
                else (
                    "CHILD_JOIN_SETTLED"
                    if step["type"] == "startproc" and step["blocking"]
                    else "DRIVER_OPERATION_SETTLED"
                )
            )
            send_safe_point(safe_kind, step_index)
        step_index += 1
        if run_budget is not None:
            run_budget -= 1
            if run_budget == 0:
                emit_operator_application(
                    "command_applied",
                    budget_command_id,
                    command_type=(budget_command_type or "step").upper(),
                    safe_point_step=step_index,
                    result={
                        "target_step": step_index,
                        "state": "PAUSED" if step_index < len(steps) else "FINISHED",
                    },
                )
                if step_index < len(steps):
                    directive = pause_loop(budget_command_id or "", step_index)
                    if directive["disposition"] == "abort":
                        return
                    run_budget = directive.get("run_budget")
                    budget_command_id = directive.get("budget_command_id")
                    budget_command_type = directive.get("budget_command_type")

    send("state", state="completed")
    send("terminal", state="completed")
