from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProcedureValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Procedure:
    id: str
    name: str
    description: str
    path: Path
    sha256: str
    steps: tuple[dict[str, Any], ...]

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "sha256": self.sha256,
            "step_count": len(self.steps),
        }


class ProcedureCatalog:
    """Parses a deliberately small call-only Python syntax without executing source."""

    _calls = {"Log", "Telemetry", "Wait", "Prompt"}

    def __init__(self, directory: Path):
        self.directory = directory

    def list(self) -> list[Procedure]:
        if not self.directory.exists():
            return []
        return [self.parse(path) for path in sorted(self.directory.glob("*.spell.py"))]

    def get(self, procedure_id: str) -> Procedure:
        for procedure in self.list():
            if procedure.id == procedure_id:
                return procedure
        raise KeyError(procedure_id)

    def parse(self, path: Path) -> Procedure:
        source = path.read_text(encoding="utf-8")
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        try:
            tree = ast.parse(source, filename=str(path), mode="exec")
        except SyntaxError as exc:
            raise ProcedureValidationError(f"{path.name}:{exc.lineno}: {exc.msg}") from exc

        description = ""
        statements = list(tree.body)
        if statements and isinstance(statements[0], ast.Expr) and isinstance(
            statements[0].value, ast.Constant
        ) and isinstance(statements[0].value.value, str):
            description = statements.pop(0).value.value.strip()

        steps: list[dict[str, Any]] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                self._reject(path, statement, "only top-level step calls are allowed")
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id not in self._calls:
                self._reject(path, statement, "step must be Log, Telemetry, Wait, or Prompt")
            if any(keyword.arg is None for keyword in call.keywords):
                self._reject(path, statement, "keyword expansion is not allowed")
            args = [self._literal(path, arg) for arg in call.args]
            kwargs = {keyword.arg: self._literal(path, keyword.value) for keyword in call.keywords}
            steps.append(self._make_step(path, statement, index, call.func.id, args, kwargs))

        if not steps:
            raise ProcedureValidationError(f"{path.name}: procedure contains no steps")
        procedure_id = path.name.removesuffix(".spell.py")
        return Procedure(
            id=procedure_id,
            name=procedure_id.replace("_", " ").title(),
            description=description,
            path=path,
            sha256=digest,
            steps=tuple(steps),
        )

    def _literal(self, path: Path, node: ast.AST) -> Any:
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError) as exc:
            self._reject(path, node, "arguments must be literal values")
            raise AssertionError from exc
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
            return list(value)
        self._reject(path, node, "unsupported literal argument")

    def _make_step(
        self,
        path: Path,
        node: ast.AST,
        index: int,
        name: str,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        allowed: dict[str, set[str]] = {
            "Log": {"message", "level"},
            "Telemetry": {"channel", "value", "unit"},
            "Wait": {"seconds"},
            "Prompt": {"question", "choices", "default"},
        }
        positional = {
            "Log": ["message"],
            "Telemetry": ["channel"],
            "Wait": ["seconds"],
            "Prompt": ["question"],
        }[name]
        if len(args) > len(positional):
            self._reject(path, node, f"too many positional arguments for {name}")
        values = dict(kwargs)
        if set(values) - allowed[name]:
            self._reject(path, node, f"unsupported keyword for {name}")
        for key, value in zip(positional, args):
            if key in values:
                self._reject(path, node, f"duplicate argument {key}")
            values[key] = value

        required = positional[0]
        if required not in values:
            self._reject(path, node, f"missing argument {required}")
        step: dict[str, Any] = {"index": index, "type": name.lower(), "line": node.lineno}
        step.update(values)
        self._validate_step(path, node, step)
        return step

    def _validate_step(self, path: Path, node: ast.AST, step: dict[str, Any]) -> None:
        kind = step["type"]
        if kind == "log":
            if not isinstance(step["message"], str) or not step["message"]:
                self._reject(path, node, "Log message must be a non-empty string")
            level = step.setdefault("level", "info")
            if level not in {"debug", "info", "warning", "error"}:
                self._reject(path, node, "invalid Log level")
        elif kind == "telemetry":
            if not isinstance(step["channel"], str) or not step["channel"]:
                self._reject(path, node, "Telemetry channel must be a non-empty string")
            value = step.setdefault("value", 0.0)
            if not isinstance(value, (int, float, bool)):
                self._reject(path, node, "Telemetry value must be numeric or boolean")
            if "unit" in step and not isinstance(step["unit"], str):
                self._reject(path, node, "Telemetry unit must be a string")
        elif kind == "wait":
            seconds = step["seconds"]
            if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
                self._reject(path, node, "Wait seconds must be numeric")
            if seconds < 0 or seconds > 3600:
                self._reject(path, node, "Wait seconds must be between 0 and 3600")
        elif kind == "prompt":
            if not isinstance(step["question"], str) or not step["question"]:
                self._reject(path, node, "Prompt question must be a non-empty string")
            choices = step.setdefault("choices", ["continue"])
            if not isinstance(choices, list) or not choices or not all(
                isinstance(item, str) and item for item in choices
            ):
                self._reject(path, node, "Prompt choices must be non-empty strings")
            default = step.setdefault("default", None)
            if default is not None and default not in choices:
                self._reject(path, node, "Prompt default must be one of its choices")

    @staticmethod
    def _reject(path: Path, node: ast.AST, message: str) -> None:
        raise ProcedureValidationError(f"{path.name}:{getattr(node, 'lineno', '?')}: {message}")
