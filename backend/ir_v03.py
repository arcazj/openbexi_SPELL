from __future__ import annotations

import hashlib
import json
import keyword
import math
import re
from dataclasses import dataclass
from typing import AbstractSet, Any


IR_VERSION = "0.3"
MAX_EXPRESSION_DEPTH = 64
MAX_EXPRESSION_ITEMS = 20_000
MAX_INTEGER_BITS = 4_096
MAX_CHECKPOINT_SERIALIZED_BYTES = 8_000_000
MAX_IR_STEPS = 10_000
MAX_IR_SERIALIZED_BYTES = 8_000_000
MAX_PROMPT_CHOICE_LENGTH = 200
MAX_STRING_LENGTH = 100_000
MAX_SOURCE_POSITION = 100_001
SUPPORTED_TYPES = frozenset({"bool", "float", "int", "str"})

_EFFECT_STEPS = frozenset({"log", "prompt", "telemetry", "wait"})
_RESERVED_NAMES = frozenset({"Call", "Log", "Prompt", "Telemetry", "Wait", "range"})
_INTERNAL_BRANCH_NAME = re.compile(r"__spell_branch_(0|[1-9][0-9]*)\Z")
_UNSET = object()


class IRValidationError(ValueError):
    """A bounded diagnostic for an untrusted IR payload."""

    code = "IR_VALIDATION_FAILED"

    def __init__(self, path: str, message: str):
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class ValidatedIR:
    steps: list[dict[str, Any]]
    canonical_bytes: bytes
    variable_types: dict[str, str]
    checkpoint_variables: dict[str, Any]


def validate_ir_v03(
    ir_version: Any,
    steps: Any,
    *,
    start_step: Any = 0,
    resume_prompt_id: Any = None,
    resume_prompt_step: Any = _UNSET,
    checkpoint_variables: Any = None,
    expected_total_steps: Any = None,
) -> ValidatedIR:
    """Validate and detach the existing data-only IR 0.3 payload.

    Validation never executes source or expressions and never rewrites the
    caller's object. The returned copy is suitable for an isolated worker.
    """

    validator = _Validator()
    return validator.validate(
        ir_version,
        steps,
        start_step=start_step,
        resume_prompt_id=resume_prompt_id,
        resume_prompt_step=resume_prompt_step,
        checkpoint_variables=checkpoint_variables,
        expected_total_steps=expected_total_steps,
    )


class _Validator:
    def __init__(self) -> None:
        self._budget = 0
        self._types: dict[str, str] = {}
        self._declarations: list[tuple[int, str, str, bool]] = []
        self._conditional_guards: dict[str, bytes] = {}
        self._definite: set[str] = set()
        self._expression_digests: dict[int, bytes] = {}
        self._internal_branches: set[str] = set()
        self._next_internal_branch = 0

    def validate(
        self,
        ir_version: Any,
        steps: Any,
        *,
        start_step: Any,
        resume_prompt_id: Any,
        resume_prompt_step: Any,
        checkpoint_variables: Any,
        expected_total_steps: Any,
    ) -> ValidatedIR:
        if type(ir_version) is not str or ir_version != IR_VERSION:
            self._reject("$.ir_version", "IR version must be exactly 0.3")
        if type(steps) is not list:
            self._reject("$.steps", "steps must be a JSON array")
        if not steps or len(steps) > MAX_IR_STEPS:
            self._reject("$.steps", "step count is outside the accepted range")
        if type(start_step) is not int:
            self._reject("$.start_step", "start step must be an integer")
        if start_step < 0 or start_step > len(steps):
            self._reject("$.start_step", "start step is outside the procedure")
        if expected_total_steps is not None:
            if type(expected_total_steps) is not int:
                self._reject("$.total_steps", "total steps must be an integer")
            if expected_total_steps != len(steps):
                self._reject("$.total_steps", "total steps does not match the IR")

        canonical_steps: list[dict[str, Any]] = []
        has_effect = False
        for index, step in enumerate(steps):
            canonical = self._step(step, index)
            canonical_steps.append(canonical)
            has_effect = has_effect or canonical["type"] in _EFFECT_STEPS
        if not has_effect:
            self._reject("$.steps", "procedure must contain an executable effect step")

        self._budget = 0
        if resume_prompt_id is not None:
            self._string(
                resume_prompt_id,
                "$.resume_prompt_id",
                non_empty=True,
                maximum=200,
            )
            if start_step >= len(canonical_steps):
                self._reject(
                    "$.resume_prompt_id",
                    "resume prompt cannot target the end of a procedure",
                )
            if canonical_steps[start_step]["type"] != "prompt":
                self._reject(
                    "$.resume_prompt_id",
                    "resume prompt must target the current prompt step",
                )
            if resume_prompt_step is not _UNSET and (
                type(resume_prompt_step) is not int
                or resume_prompt_step != start_step
            ):
                self._reject(
                    "$.resume_prompt_step",
                    "stored resume prompt step does not match the current step",
                )
        elif resume_prompt_step is not _UNSET:
            if resume_prompt_step is not None:
                self._reject(
                    "$.resume_prompt_step",
                    "stored resume prompt step requires an open prompt identity",
                )
            if (
                start_step < len(canonical_steps)
                and canonical_steps[start_step]["type"] == "prompt"
            ):
                self._reject(
                    "$.resume_prompt_id",
                    "recovery at a prompt step requires one open prompt record",
                )

        canonical_checkpoint = self._checkpoint(checkpoint_variables, start_step)
        try:
            checkpoint_bytes = json.dumps(
                canonical_checkpoint,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, UnicodeError, ValueError) as exc:
            raise IRValidationError(
                "$.checkpoint_variables",
                "checkpoint cannot be serialized canonically",
            ) from exc
        if len(checkpoint_bytes) > MAX_CHECKPOINT_SERIALIZED_BYTES:
            self._reject(
                "$.checkpoint_variables",
                "serialized checkpoint exceeds the accepted byte limit",
            )
        try:
            canonical_bytes = json.dumps(
                canonical_steps,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
            raise IRValidationError("$.steps", "IR cannot be serialized canonically") from exc
        if len(canonical_bytes) > MAX_IR_SERIALIZED_BYTES:
            self._reject("$.steps", "serialized IR exceeds the accepted byte limit")

        return ValidatedIR(
            steps=canonical_steps,
            canonical_bytes=canonical_bytes,
            variable_types=dict(self._types),
            checkpoint_variables=canonical_checkpoint,
        )

    def _step(self, value: Any, index: int) -> dict[str, Any]:
        path = f"$.steps[{index}]"
        if type(value) is not dict:
            self._reject(path, "step must be a JSON object")
        self._charge(32, path)
        step_type = value.get("type")
        if type(step_type) is not str or len(step_type) > 20 or step_type not in {
            "log",
            "prompt",
            "telemetry",
            "variable_set",
            "wait",
        }:
            self._reject(f"{path}.type", "step type is not supported")

        required = {"index", "type", "line", "column"}
        optional = {"guard"}
        if step_type == "variable_set":
            required |= {"name", "declared_type", "expression", "declaration"}
            optional |= {"internal"}
        elif step_type == "log":
            required |= {"message", "level"}
        elif step_type == "telemetry":
            required |= {"channel", "value"}
            optional |= {"unit"}
        elif step_type == "wait":
            required |= {"seconds"}
        else:
            required |= {"question", "choices", "default"}
        self._keys(value, required, optional, path)

        if type(value["index"]) is not int or value["index"] != index:
            self._reject(f"{path}.index", "step indexes must be contiguous from zero")
        line = self._position(value["line"], f"{path}.line")
        column = self._position(value["column"], f"{path}.column")
        canonical: dict[str, Any] = {
            "index": index,
            "type": step_type,
            "line": line,
            "column": column,
        }
        available = set(self._definite)
        guard_context: frozenset[bytes] = frozenset()
        if "guard" in value:
            guard, guard_type = self._expression(value["guard"], f"{path}.guard", 0)
            if guard_type != "bool":
                self._reject(f"{path}.guard", "step guard must have Boolean type")
            self._check_guard_reads(guard, set(self._definite), f"{path}.guard")
            if not self._is_stable_guard(guard):
                self._reject(
                    f"{path}.guard",
                    "step guard must use immutable internal branch snapshots",
                )
            guard_context = self._guard_context(guard)
            canonical["guard"] = guard

        if step_type == "variable_set":
            self._variable_set(
                value, canonical, index, path, available, guard_context
            )
        elif step_type == "log":
            message, message_type = self._argument(value["message"], f"{path}.message")
            if message_type != "str":
                self._reject(f"{path}.message", "log message must have string type")
            if type(message) is str and not message:
                self._reject(f"{path}.message", "literal log message must not be empty")
            self._check_argument_reads(
                message, available, guard_context, f"{path}.message"
            )
            level = value["level"]
            if (
                type(level) is not str
                or len(level) > 10
                or level not in {"debug", "error", "info", "warning"}
            ):
                self._reject(f"{path}.level", "log level is not supported")
            canonical.update(message=message, level=level)
        elif step_type == "telemetry":
            channel, channel_type = self._argument(value["channel"], f"{path}.channel")
            if channel_type != "str":
                self._reject(f"{path}.channel", "telemetry channel must have string type")
            if type(channel) is str and not channel:
                self._reject(f"{path}.channel", "literal telemetry channel must not be empty")
            self._check_argument_reads(
                channel, available, guard_context, f"{path}.channel"
            )
            sample, sample_type = self._argument(value["value"], f"{path}.value")
            if sample_type not in {"bool", "float", "int"}:
                self._reject(f"{path}.value", "telemetry value must be numeric or Boolean")
            self._check_argument_reads(
                sample, available, guard_context, f"{path}.value"
            )
            canonical.update(channel=channel, value=sample)
            if "unit" in value:
                unit, unit_type = self._argument(value["unit"], f"{path}.unit")
                if unit_type != "str":
                    self._reject(f"{path}.unit", "telemetry unit must have string type")
                self._check_argument_reads(
                    unit, available, guard_context, f"{path}.unit"
                )
                canonical["unit"] = unit
        elif step_type == "wait":
            seconds, seconds_type = self._argument(value["seconds"], f"{path}.seconds")
            if seconds_type not in {"float", "int"}:
                self._reject(f"{path}.seconds", "wait duration must be numeric")
            if type(seconds) in {float, int} and not 0 <= seconds <= 3600:
                self._reject(f"{path}.seconds", "literal wait duration is outside 0 through 3600")
            self._check_argument_reads(
                seconds, available, guard_context, f"{path}.seconds"
            )
            canonical["seconds"] = seconds
        else:
            self._prompt(value, canonical, path)
        return canonical

    def _variable_set(
        self,
        value: dict[str, Any],
        canonical: dict[str, Any],
        index: int,
        path: str,
        available: set[str],
        guard_context: frozenset[bytes],
    ) -> None:
        declaration = value["declaration"]
        if type(declaration) is not bool:
            self._reject(f"{path}.declaration", "declaration marker must be Boolean")
        declared_type = value["declared_type"]
        if (
            type(declared_type) is not str
            or len(declared_type) > 10
            or declared_type not in SUPPORTED_TYPES
        ):
            self._reject(f"{path}.declared_type", "declared type is not supported")
        internal = value.get("internal")
        if internal is not None and internal is not True:
            self._reject(f"{path}.internal", "internal marker must be exactly true")

        name = value["name"]
        if internal is True:
            if not declaration or declared_type != "bool" or type(name) is not str:
                self._reject(path, "internal branch declaration is malformed")
            self._string(name, f"{path}.name", non_empty=True)
            match = _INTERNAL_BRANCH_NAME.fullmatch(name)
            if match is None or match.group(1) != str(self._next_internal_branch):
                self._reject(f"{path}.name", "internal branch identities must be contiguous")
            self._next_internal_branch += 1
            self._internal_branches.add(name)
        else:
            name = self._variable_name(name, f"{path}.name")

        expression, actual_type = self._expression(
            value["expression"], f"{path}.expression", 0
        )
        self._check_reads(
            expression, available, guard_context, f"{path}.expression"
        )
        if not self._assignable(declared_type, actual_type):
            self._reject(f"{path}.expression", "expression type is not assignable")

        existing = self._types.get(name)
        if declaration:
            if existing is not None and existing != declared_type:
                self._reject(f"{path}.declared_type", "variable declaration changes type")
            self._types[name] = declared_type
            self._declarations.append((index, name, declared_type, "guard" not in value))
            if "guard" in canonical:
                if internal is not True and not (
                    declared_type == "int"
                    and expression.get("expr") == "literal"
                    and type(expression.get("value")) is int
                ):
                    self._reject(path, "guarded declaration is not canonical loop IR")
                self._conditional_guards[name] = self._expression_digest(
                    canonical["guard"]
                )
            else:
                self._definite.add(name)
                self._conditional_guards.pop(name, None)
        elif existing is None:
            self._reject(f"{path}.name", "assignment targets an undeclared variable")
        elif existing != declared_type:
            self._reject(f"{path}.declared_type", "assignment changes variable type")
        elif (
            name not in self._definite
            and self._conditional_guards.get(name) not in guard_context
        ):
            self._reject(f"{path}.name", "assignment targets an unavailable variable")

        canonical.update(
            name=name,
            declared_type=declared_type,
            expression=expression,
            declaration=declaration,
        )
        if internal is True:
            canonical["internal"] = True

    def _prompt(
        self, value: dict[str, Any], canonical: dict[str, Any], path: str
    ) -> None:
        question, question_type = self._argument(value["question"], f"{path}.question")
        if question_type != "str":
            self._reject(f"{path}.question", "prompt question must have string type")
        if type(question) is str and not question:
            self._reject(f"{path}.question", "literal prompt question must not be empty")
        available = set(self._definite)
        guard = canonical.get("guard")
        guard_context = (
            self._guard_context(guard) if type(guard) is dict else frozenset()
        )
        self._check_argument_reads(
            question, available, guard_context, f"{path}.question"
        )
        choices = value["choices"]
        if type(choices) is not list or not choices:
            self._reject(f"{path}.choices", "prompt choices must be a non-empty array")
        if len(choices) > MAX_EXPRESSION_ITEMS:
            self._reject(f"{path}.choices", "prompt choice count exceeds the accepted limit")
        canonical_choices: list[str] = []
        seen: set[str] = set()
        for choice_index, choice in enumerate(choices):
            choice_path = f"{path}.choices[{choice_index}]"
            canonical_choice = self._string(
                choice,
                choice_path,
                non_empty=True,
                maximum=MAX_PROMPT_CHOICE_LENGTH,
            )
            if canonical_choice in seen:
                self._reject(choice_path, "prompt choices must be unique")
            seen.add(canonical_choice)
            canonical_choices.append(canonical_choice)
        default = value["default"]
        if default is not None:
            default = self._string(
                default,
                f"{path}.default",
                maximum=MAX_PROMPT_CHOICE_LENGTH,
            )
            if default not in seen:
                self._reject(f"{path}.default", "prompt default must be one of its choices")
        canonical.update(question=question, choices=canonical_choices, default=default)

    def _check_argument_reads(
        self,
        value: Any,
        available: set[str],
        guard_context: frozenset[bytes],
        path: str,
    ) -> None:
        if type(value) is dict:
            self._check_reads(value, available, guard_context, path)

    def _check_guard_reads(
        self,
        expression: dict[str, Any],
        available: set[str],
        path: str,
        prior_context: set[bytes] | None = None,
    ) -> None:
        if prior_context is None:
            prior_context = set()
        if expression["expr"] == "boolean" and expression["operator"] == "and":
            for index, operand in enumerate(expression["values"]):
                operand_path = f"{path}.values[{index}]"
                self._check_guard_reads(
                    operand,
                    available,
                    operand_path,
                    prior_context,
                )
                prior_context.update(self._guard_context(operand))
            return
        self._check_reads(expression, available, prior_context, path)

    def _check_reads(
        self,
        expression: dict[str, Any],
        available: set[str],
        guard_context: AbstractSet[bytes],
        path: str,
    ) -> None:
        kind = expression["expr"]
        if kind == "variable":
            name = expression["name"]
            required_guard = self._conditional_guards.get(name)
            if name not in available and required_guard not in guard_context:
                self._reject(f"{path}.name", "expression reads a variable before it is available")
            return
        if kind == "unary":
            self._check_reads(
                expression["operand"], available, guard_context, f"{path}.operand"
            )
            return
        if kind == "binary":
            self._check_reads(
                expression["left"], available, guard_context, f"{path}.left"
            )
            self._check_reads(
                expression["right"], available, guard_context, f"{path}.right"
            )
            return
        if kind == "boolean":
            for index, operand in enumerate(expression["values"]):
                self._check_reads(
                    operand,
                    available,
                    guard_context,
                    f"{path}.values[{index}]",
                )
            return
        if kind == "compare":
            for index, operand in enumerate(expression["operands"]):
                self._check_reads(
                    operand,
                    available,
                    guard_context,
                    f"{path}.operands[{index}]",
                )

    def _is_stable_guard(self, expression: dict[str, Any]) -> bool:
        kind = expression["expr"]
        if kind == "variable":
            return expression["name"] in self._internal_branches
        if kind == "unary":
            operand = expression["operand"]
            return (
                expression["operator"] == "not"
                and operand["expr"] == "variable"
                and operand["name"] in self._internal_branches
            )
        if kind == "boolean" and expression["operator"] == "and":
            return all(self._is_stable_guard(item) for item in expression["values"])
        return False

    def _guard_context(self, expression: dict[str, Any]) -> frozenset[bytes]:
        keys = {self._expression_digest(expression)}
        if expression["expr"] == "boolean" and expression["operator"] == "and":
            for operand in expression["values"]:
                keys.update(self._guard_context(operand))
        return frozenset(keys)

    def _expression_digest(self, expression: dict[str, Any]) -> bytes:
        identity = id(expression)
        cached = self._expression_digests.get(identity)
        if cached is not None:
            return cached
        kind = expression["expr"]
        parts: list[bytes] = [kind.encode("ascii")]
        if kind == "literal":
            parts.append(
                json.dumps(
                    expression["value"],
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        elif kind == "variable":
            parts.append(expression["name"].encode("utf-8"))
        elif kind == "unary":
            parts.extend(
                (
                    expression["operator"].encode("ascii"),
                    self._expression_digest(expression["operand"]),
                )
            )
        elif kind == "binary":
            parts.extend(
                (
                    expression["operator"].encode("ascii"),
                    self._expression_digest(expression["left"]),
                    self._expression_digest(expression["right"]),
                )
            )
        elif kind == "boolean":
            parts.append(expression["operator"].encode("ascii"))
            parts.extend(self._expression_digest(item) for item in expression["values"])
        else:
            parts.extend(operator.encode("ascii") for operator in expression["operators"])
            parts.extend(self._expression_digest(item) for item in expression["operands"])
        digest = hashlib.sha256(b"\x00".join(parts)).digest()
        self._expression_digests[identity] = digest
        return digest

    def _argument(self, value: Any, path: str) -> tuple[Any, str]:
        if type(value) is dict:
            expression, expression_type = self._expression(value, path, 0)
            if expression["expr"] == "literal":
                self._reject(path, "literal step arguments must use canonical scalar form")
            return expression, expression_type
        scalar = self._scalar(value, path)
        return scalar, type(scalar).__name__

    def _expression(
        self, value: Any, path: str, depth: int
    ) -> tuple[dict[str, Any], str]:
        if depth > MAX_EXPRESSION_DEPTH:
            self._reject(path, "expression depth exceeds the accepted limit")
        if type(value) is not dict:
            self._reject(path, "expression must be a JSON object")
        self._charge(16, path)
        kind = value.get("expr")
        if type(kind) is not str or len(kind) > 10:
            self._reject(f"{path}.expr", "expression kind must be a string")
        if kind == "literal":
            self._keys(value, {"expr", "value"}, set(), path)
            literal = self._scalar(value["value"], f"{path}.value")
            return {"expr": "literal", "value": literal}, type(literal).__name__
        if kind == "variable":
            self._keys(value, {"expr", "name"}, set(), path)
            name = value["name"]
            if type(name) is str and name.startswith("__spell_branch_"):
                self._string(name, f"{path}.name", non_empty=True)
                if _INTERNAL_BRANCH_NAME.fullmatch(name) is None:
                    self._reject(f"{path}.name", "internal branch identity is malformed")
            else:
                name = self._variable_name(name, f"{path}.name")
            declared_type = self._types.get(name)
            if declared_type is None:
                self._reject(f"{path}.name", "expression reads an undeclared variable")
            return {"expr": "variable", "name": name}, declared_type
        if kind == "unary":
            self._keys(value, {"expr", "operator", "operand"}, set(), path)
            operator = value["operator"]
            if type(operator) is not str or len(operator) > 3:
                self._reject(f"{path}.operator", "unary operator must be a string")
            operand, operand_type = self._expression(
                value["operand"], f"{path}.operand", depth + 1
            )
            if operator == "not" and operand_type == "bool":
                result_type = "bool"
            elif operator in {"+", "-"} and operand_type in {"float", "int"}:
                result_type = operand_type
            else:
                self._reject(f"{path}.operator", "unary operator or operand type is invalid")
            return {"expr": "unary", "operator": operator, "operand": operand}, result_type
        if kind == "binary":
            self._keys(value, {"expr", "operator", "left", "right"}, set(), path)
            operator = value["operator"]
            if (
                type(operator) is not str
                or len(operator) > 2
                or operator not in {"+", "-", "*", "/", "//", "%"}
            ):
                self._reject(f"{path}.operator", "binary operator is not supported")
            left, left_type = self._expression(value["left"], f"{path}.left", depth + 1)
            right, right_type = self._expression(
                value["right"], f"{path}.right", depth + 1
            )
            if operator == "+" and left_type == right_type == "str":
                result_type = "str"
            elif left_type in {"float", "int"} and right_type in {"float", "int"}:
                result_type = (
                    "float" if operator == "/" or "float" in {left_type, right_type} else "int"
                )
            else:
                self._reject(path, "binary operand types are incompatible")
            return {
                "expr": "binary",
                "operator": operator,
                "left": left,
                "right": right,
            }, result_type
        if kind == "boolean":
            self._keys(value, {"expr", "operator", "values"}, set(), path)
            operator = value["operator"]
            operands = value["values"]
            if (
                type(operator) is not str
                or len(operator) > 3
                or operator not in {"and", "or"}
            ):
                self._reject(f"{path}.operator", "Boolean operator is not supported")
            if type(operands) is not list or not 2 <= len(operands) <= MAX_EXPRESSION_ITEMS:
                self._reject(f"{path}.values", "Boolean expression operand count is invalid")
            canonical_operands: list[dict[str, Any]] = []
            for item_index, item in enumerate(operands):
                operand, operand_type = self._expression(
                    item, f"{path}.values[{item_index}]", depth + 1
                )
                if operand_type != "bool":
                    self._reject(
                        f"{path}.values[{item_index}]",
                        "Boolean operand must have Boolean type",
                    )
                canonical_operands.append(operand)
            return {
                "expr": "boolean",
                "operator": operator,
                "values": canonical_operands,
            }, "bool"
        if kind == "compare":
            self._keys(value, {"expr", "operators", "operands"}, set(), path)
            operators = value["operators"]
            operands = value["operands"]
            if (
                type(operators) is not list
                or not operators
                or len(operators) > MAX_EXPRESSION_ITEMS
                or type(operands) is not list
                or len(operands) != len(operators) + 1
            ):
                self._reject(path, "comparison shape is invalid")
            canonical_operators: list[str] = []
            for operator_index, operator in enumerate(operators):
                if type(operator) is not str or len(operator) > 2 or operator not in {
                    "!=",
                    "<",
                    "<=",
                    "==",
                    ">",
                    ">=",
                }:
                    self._reject(
                        f"{path}.operators[{operator_index}]",
                        "comparison operator is not supported",
                    )
                canonical_operators.append(operator)
            canonical_operands: list[dict[str, Any]] = []
            operand_types: list[str] = []
            for operand_index, operand_value in enumerate(operands):
                operand, operand_type = self._expression(
                    operand_value, f"{path}.operands[{operand_index}]", depth + 1
                )
                canonical_operands.append(operand)
                operand_types.append(operand_type)
            for operator_index, operator in enumerate(canonical_operators):
                left_type = operand_types[operator_index]
                right_type = operand_types[operator_index + 1]
                numeric = left_type in {"float", "int"} and right_type in {"float", "int"}
                if not numeric and left_type != right_type:
                    self._reject(path, "comparison operand types are incompatible")
                if operator in {"<", "<=", ">", ">="} and left_type == "bool":
                    self._reject(path, "Boolean ordering is not supported")
            return {
                "expr": "compare",
                "operators": canonical_operators,
                "operands": canonical_operands,
            }, "bool"
        self._reject(f"{path}.expr", "expression kind is not supported")

    def _checkpoint(self, value: Any, start_step: int) -> dict[str, Any]:
        if value is None:
            value = {}
        if type(value) is not dict:
            self._reject("$.checkpoint_variables", "checkpoint variables must be an object")
        allowed: dict[str, str] = {}
        required: set[str] = set()
        for index, name, declared_type, unconditional in self._declarations:
            if index >= start_step:
                continue
            allowed[name] = declared_type
            if unconditional:
                required.add(name)
        if len(value) > len(allowed):
            self._reject(
                "$.checkpoint_variables",
                "checkpoint contains more variables than are available",
            )
        for name in value:
            self._string(name, "$.checkpoint_variables", non_empty=True)
        canonical: dict[str, Any] = {}
        for variable_index, name in enumerate(sorted(value)):
            path = f"$.checkpoint_variables[{variable_index}]"
            expected_type = allowed.get(name)
            if expected_type is None:
                self._reject(path, "checkpoint contains a variable unavailable at start step")
            scalar = self._scalar(value[name], path)
            if type(scalar).__name__ != expected_type:
                self._reject(path, "checkpoint value does not match its declared type")
            canonical[name] = scalar
        if not required.issubset(canonical):
            self._reject(
                "$.checkpoint_variables",
                "checkpoint omits a required variable at the start step",
            )
        return canonical

    def _scalar(self, value: Any, path: str) -> bool | float | int | str:
        if type(value) is bool:
            self._charge(5, path)
            return value
        if type(value) is int:
            if value.bit_length() > MAX_INTEGER_BITS:
                self._reject(path, "integer exceeds the accepted bit limit")
            self._charge(max(1, len(str(value))), path)
            return value
        if type(value) is float:
            if not math.isfinite(value):
                self._reject(path, "floating-point value must be finite")
            self._charge(24, path)
            return value
        if type(value) is str:
            return self._string(value, path)
        self._reject(path, "value must be a supported JSON scalar")

    def _string(
        self,
        value: Any,
        path: str,
        *,
        non_empty: bool = False,
        maximum: int = MAX_STRING_LENGTH,
    ) -> str:
        if type(value) is not str:
            self._reject(path, "value must be a string")
        if non_empty and not value:
            self._reject(path, "string must not be empty")
        if len(value) > maximum:
            self._reject(path, "string exceeds the accepted length limit")
        if "\x00" in value:
            self._reject(path, "string contains U+0000")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise IRValidationError(path, "string is not valid UTF-8") from exc
        self._charge(len(encoded) + 2, path)
        return value

    def _variable_name(self, value: Any, path: str) -> str:
        name = self._string(value, path, non_empty=True)
        if (
            not name.isidentifier()
            or keyword.iskeyword(name)
            or name.startswith("__")
            or name in _RESERVED_NAMES
        ):
            self._reject(path, "variable name is not accepted by IR 0.3")
        return name

    def _position(self, value: Any, path: str) -> int:
        if type(value) is not int or not 1 <= value <= MAX_SOURCE_POSITION:
            self._reject(path, "source position is outside the accepted range")
        return value

    @staticmethod
    def _assignable(target: str, actual: str) -> bool:
        return actual == target or (target == "float" and actual == "int")

    def _keys(
        self,
        value: dict[Any, Any],
        required: set[str],
        optional: set[str],
        path: str,
    ) -> None:
        if len(value) > len(required) + len(optional):
            self._reject(path, "object fields do not match the IR 0.3 schema")
        if any(type(key) is not str or len(key) > 32 for key in value):
            self._reject(path, "object fields do not match the IR 0.3 schema")
        keys = set(value)
        if keys - (required | optional) or required - keys:
            self._reject(path, "object fields do not match the IR 0.3 schema")

    def _charge(self, amount: int, path: str) -> None:
        self._budget += amount
        if self._budget > MAX_IR_SERIALIZED_BYTES:
            self._reject(path, "IR exceeds the accepted validation budget")

    @staticmethod
    def _reject(path: str, message: str) -> None:
        raise IRValidationError(path, message)
