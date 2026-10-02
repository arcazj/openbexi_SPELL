"""Bounded integer operations admitted only by the IR 0.17 validator.

The projection is validation-only. Workers receive the original closed nodes;
older IR validators continue to reject them.
"""
from __future__ import annotations

from typing import Any, Mapping

MAX_INTEGER_BITS = 4096
MAX_POWER_EXPONENT = 4096
INTEGER_OPERATORS = frozenset({"**", "&", "|"})
_MAX_WALK_DEPTH = 128
_MAX_WALK_ITEMS = 1_000_000


class CoreV17Error(ValueError):
    def __init__(self, path: str, message: str):
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message}")


def _walk(value: Any):
    stack = [(value, "$", 0)]
    visited = 0
    while stack:
        item, path, depth = stack.pop()
        visited += 1
        if depth > _MAX_WALK_DEPTH or visited > _MAX_WALK_ITEMS:
            raise CoreV17Error(path, "core expression structure exceeds its bound")
        yield item, path
        if type(item) is dict:
            stack.extend((child, f"{path}.{key}", depth + 1) for key, child in item.items())
        elif type(item) is list:
            stack.extend((child, f"{path}[{index}]", depth + 1) for index, child in enumerate(item))


def has_core_expressions(value: Any) -> bool:
    return any(type(item) is dict and item.get("expr") == "integer_binary"
               for item, _ in _walk(value))


def _literal_integer(expression: Any) -> int | None:
    sign = 1
    for _ in range(65):
        if type(expression) is not dict:
            return None
        if expression.get("expr") == "literal":
            value = expression.get("value")
            return sign * value if type(value) is int else None
        if (expression.get("expr") != "unary"
                or type(expression.get("operator")) is not str
                or expression["operator"] not in {"+", "-"}):
            return None
        if expression["operator"] == "-":
            sign = -sign
        expression = expression.get("operand")
    return None


def _validate_node(node: dict[str, Any], path: str) -> None:
    if set(node) != {"expr", "operator", "left", "right"}:
        raise CoreV17Error(path, "integer expression fields differ")
    if type(node["operator"]) is not str or node["operator"] not in INTEGER_OPERATORS:
        raise CoreV17Error(path, "integer operator is unsupported")
    for field in ("left", "right"):
        if type(node[field]) is not dict or type(node[field].get("expr")) is not str:
            raise CoreV17Error(f"{path}.{field}", "integer operand must be a typed expression")
    exponent = _literal_integer(node["right"])
    if node["operator"] == "**" and exponent is not None and not 0 <= exponent <= MAX_POWER_EXPONENT:
        raise CoreV17Error(f"{path}.right", "power exponent must be 0 through 4096")


def project_core_expressions(value: Any) -> Any:
    """Detach and project closed integer nodes for existing type/order checks."""
    for item, path in _walk(value):
        if type(item) is dict and item.get("expr") == "integer_binary":
            _validate_node(item, path)

    def project(item: Any) -> Any:
        if type(item) is list:
            return [project(child) for child in item]
        if type(item) is dict:
            result = {key: project(child) for key, child in item.items()}
            if item.get("expr") == "integer_binary":
                result["expr"] = "binary"
                result["operator"] = "+"
            return result
        return item

    return project(value)


def validate_core_expression_types(value: Any, variable_types: Mapping[str, str]) -> None:
    """Require integer operands after the independent base IR validation."""
    def expression_type(expression: dict[str, Any], path: str) -> str | None:
        kind = expression.get("expr")
        if kind == "literal":
            return type(expression.get("value")).__name__
        if kind == "variable":
            return variable_types.get(expression.get("name"))
        if kind == "unary":
            if expression.get("operator") == "not":
                return "bool"
            return expression_type(expression["operand"], f"{path}.operand")
        if kind in {"compare", "boolean"}:
            return "bool"
        if kind in {"binary", "integer_binary"}:
            left = expression_type(expression["left"], f"{path}.left")
            right = expression_type(expression["right"], f"{path}.right")
            if kind == "integer_binary":
                _validate_node(expression, path)
                if left != "int" or right != "int":
                    raise CoreV17Error(path, "integer operators require int operands, not bool or float")
                return "int"
            if expression.get("operator") == "/" or "float" in {left, right}:
                return "float"
            return left
        return None

    for item, path in _walk(value):
        if type(item) is dict and item.get("expr") == "integer_binary":
            expression_type(item, path)


def _bounded_integer(value: Any) -> int:
    if type(value) is not int:
        raise CoreV17Error("$.value", "integer operators require int operands, not bool or float")
    if value.bit_length() > MAX_INTEGER_BITS:
        raise CoreV17Error("$.value", "integer result exceeds the safety limit")
    return value


def _checked_multiply(left: int, right: int) -> int:
    if left and right and left.bit_length() + right.bit_length() - 1 > MAX_INTEGER_BITS:
        raise CoreV17Error("$.value", "integer result exceeds the safety limit")
    # A product whose lower bound fits can allocate at most 4097 result bits.
    return _bounded_integer(left * right)


def evaluate_integer_binary(operator: str, left: Any, right: Any) -> int:
    """Evaluate one closed operation without executing submitted source."""
    left, right = _bounded_integer(left), _bounded_integer(right)
    if operator == "&":
        return _bounded_integer(left & right)
    if operator == "|":
        return _bounded_integer(left | right)
    if operator != "**":
        raise CoreV17Error("$.operator", "integer operator is unsupported")
    if not 0 <= right <= MAX_POWER_EXPONENT:
        raise CoreV17Error("$.right", "power exponent must be 0 through 4096")
    result = 1
    factor = left
    remaining = right
    while remaining:
        if remaining & 1:
            result = _checked_multiply(result, factor)
        remaining >>= 1
        if remaining:
            factor = _checked_multiply(factor, factor)
    return result
