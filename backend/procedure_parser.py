from __future__ import annotations

import ast
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .ir_v03 import IR_VERSION, IRValidationError, validate_ir_v03


SUPPORTED_TYPES = {"bool", "float", "int", "str"}
MAX_CALL_DEPTH = 16
MAX_AST_DEPTH = 64
MAX_AST_NODES = 20_000
MAX_SOURCE_BYTES = 100_000
MAX_INTEGER_BITS = 4_096
MAX_LOOP_ITERATIONS = 1_000
MAX_IR_STEPS = 10_000
MAX_IR_SERIALIZED_BYTES = 8_000_000
MAX_PROMPT_CHOICE_LENGTH = 200


@dataclass(frozen=True)
class ProcedureDiagnostic:
    code: str
    message: str
    line: int | None
    column: int | None
    severity: str = "error"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProcedureValidationError(ValueError):
    def __init__(self, source_name: str, diagnostics: list[ProcedureDiagnostic]):
        self.source_name = source_name
        self.diagnostics = tuple(diagnostics)
        first = diagnostics[0]
        location = f"{first.line or '?'}:{first.column or '?'}"
        super().__init__(f"{source_name}:{location}: {first.message} [{first.code}]")


@dataclass(frozen=True)
class Procedure:
    id: str
    name: str
    description: str
    path: Path
    source: str
    sha256: str
    steps: tuple[dict[str, Any], ...]
    ir_version: str = IR_VERSION

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "sha256": self.sha256,
            "step_count": len(self.steps),
            "ir_version": self.ir_version,
        }


class ProcedureCatalog:
    """Compile the v0.3 safe language to data-only, checkpointable IR."""

    _step_calls = {"Log", "Telemetry", "Wait", "Prompt"}

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
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise ProcedureValidationError(
                path.name,
                [
                    ProcedureDiagnostic(
                        code="SPELL005",
                        message=f"source exceeds the {MAX_SOURCE_BYTES}-byte limit",
                        line=None,
                        column=None,
                    )
                ],
            )
        with path.open("rb") as source_file:
            source_bytes = source_file.read(MAX_SOURCE_BYTES + 1)
        if len(source_bytes) > MAX_SOURCE_BYTES:
            raise ProcedureValidationError(
                path.name,
                [
                    ProcedureDiagnostic(
                        code="SPELL005",
                        message=f"source exceeds the {MAX_SOURCE_BYTES}-byte limit",
                        line=None,
                        column=None,
                    )
                ],
            )
        try:
            source = source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProcedureValidationError(
                path.name,
                [
                    ProcedureDiagnostic(
                        code="SPELL004",
                        message="source is not valid UTF-8",
                        line=None,
                        column=None,
                    )
                ],
            ) from exc
        return self.validate_source(source, path.name, path=path)

    def validate_source(
        self,
        source: str,
        source_name: str = "submitted.spell.py",
        *,
        path: Path | None = None,
    ) -> Procedure:
        """Validate source without executing it and return its compiled procedure IR."""

        try:
            source_bytes = source.encode("utf-8")
        except UnicodeEncodeError as exc:
            prefix = source[: exc.start]
            line = prefix.count("\n") + 1
            previous_newline = prefix.rfind("\n")
            column = exc.start + 1 if previous_newline < 0 else exc.start - previous_newline
            diagnostic = ProcedureDiagnostic(
                code="SPELL004",
                message="source contains an invalid Unicode scalar value",
                line=line,
                column=column,
            )
            raise ProcedureValidationError(source_name, [diagnostic]) from exc
        if len(source_bytes) > MAX_SOURCE_BYTES:
            diagnostic = ProcedureDiagnostic(
                code="SPELL005",
                message=f"source exceeds the {MAX_SOURCE_BYTES}-byte limit",
                line=None,
                column=None,
            )
            raise ProcedureValidationError(source_name, [diagnostic])

        try:
            tree = ast.parse(source, filename=source_name, mode="exec")
        except RecursionError as exc:
            diagnostic = ProcedureDiagnostic(
                code="SPELL003",
                message=f"syntax nesting exceeds the {MAX_AST_DEPTH} level limit",
                line=None,
                column=None,
            )
            raise ProcedureValidationError(source_name, [diagnostic]) from exc
        except SyntaxError as exc:
            diagnostic = ProcedureDiagnostic(
                code="SPELL001",
                message=exc.msg,
                line=exc.lineno,
                column=exc.offset,
            )
            raise ProcedureValidationError(source_name, [diagnostic]) from exc

        self._validate_ast_complexity(tree, source_name)
        compiler = _Compiler(source_name)
        try:
            description, steps = compiler.compile(tree)
        except RecursionError as exc:
            diagnostic = ProcedureDiagnostic(
                code="SPELL003",
                message=f"syntax nesting exceeds the {MAX_AST_DEPTH} level limit",
                line=None,
                column=None,
            )
            raise ProcedureValidationError(source_name, [diagnostic]) from exc
        try:
            validated_ir = validate_ir_v03(IR_VERSION, steps)
        except IRValidationError as exc:
            diagnostic = ProcedureDiagnostic(
                code="SPELL105",
                message=f"compiled IR failed independent validation at {exc.path}",
                line=None,
                column=None,
            )
            raise ProcedureValidationError(source_name, [diagnostic]) from exc
        digest = hashlib.sha256(source_bytes).hexdigest()
        procedure_id = source_name.removesuffix(".spell.py")
        return Procedure(
            id=procedure_id,
            name=procedure_id.replace("_", " ").title(),
            description=description,
            path=path or Path(source_name),
            source=source,
            sha256=digest,
            steps=tuple(validated_ir.steps),
        )

    @staticmethod
    def _validate_ast_complexity(tree: ast.AST, source_name: str) -> None:
        stack: list[tuple[ast.AST, int]] = [(tree, 0)]
        node_count = 0
        while stack:
            node, depth = stack.pop()
            node_count += 1
            if node_count > MAX_AST_NODES:
                raise ProcedureValidationError(
                    source_name,
                    [
                        ProcedureDiagnostic(
                            code="SPELL002",
                            message=f"syntax tree exceeds the {MAX_AST_NODES} node limit",
                            line=getattr(node, "lineno", None),
                            column=(getattr(node, "col_offset", -1) + 1) or None,
                        )
                    ],
                )
            if depth > MAX_AST_DEPTH:
                raise ProcedureValidationError(
                    source_name,
                    [
                        ProcedureDiagnostic(
                            code="SPELL003",
                            message=f"syntax nesting exceeds the {MAX_AST_DEPTH} level limit",
                            line=getattr(node, "lineno", None),
                            column=(getattr(node, "col_offset", -1) + 1) or None,
                        )
                    ],
                )
            stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))


class _Compiler:
    _step_calls = {"Log", "Telemetry", "Wait", "Prompt"}

    def __init__(self, source_name: str):
        self.source_name = source_name
        self.functions: dict[str, ast.FunctionDef] = {}
        self.types: dict[str, str] = {}
        self.steps: list[dict[str, Any]] = []
        self.serialized_ir_bytes = 2
        self.branch_counter = 0
        self.called_functions: set[str] = set()

    def compile(self, tree: ast.Module) -> tuple[str, list[dict[str, Any]]]:
        statements = list(tree.body)
        description = ""
        if statements and self._is_docstring(statements[0]):
            docstring = statements.pop(0)
            description = docstring.value.value.strip()  # type: ignore[union-attr]
            self._validate_persistable_string(
                docstring, description, "procedure description"
            )

        executable: list[ast.stmt] = []
        for statement in statements:
            if isinstance(statement, ast.FunctionDef):
                self._register_function(statement)
            else:
                executable.append(statement)

        self._compile_block(executable, guard=None, call_stack=(), top_level=True)
        unused_functions = set(self.functions) - self.called_functions
        if unused_functions:
            function_name = sorted(unused_functions)[0]
            self._reject(
                self.functions[function_name],
                "SPELL203",
                f"local function {function_name} is never called",
            )
        if not any(step["type"] in {"log", "telemetry", "wait", "prompt"} for step in self.steps):
            self._reject(tree, "SPELL101", "procedure contains no executable steps")
        if len(self.steps) > MAX_IR_STEPS:
            self._reject(
                tree,
                "SPELL102",
                f"compiled procedure exceeds the {MAX_IR_STEPS} step limit",
            )
        for index, step in enumerate(self.steps):
            step["index"] = index
        return description, self.steps

    @staticmethod
    def _is_docstring(statement: ast.stmt) -> bool:
        return (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )

    def _register_function(self, node: ast.FunctionDef) -> None:
        if node.name.startswith("__") or node.name in {"Call", "range", *self._step_calls}:
            self._reject(node, "SPELL201", f"reserved function name {node.name}")
        if node.name in self.functions or node.name in self._step_calls or node.name == "Call":
            self._reject(node, "SPELL201", f"duplicate or reserved function name {node.name}")
        if (
            node.decorator_list
            or node.args.args
            or node.args.posonlyargs
            or node.args.kwonlyargs
            or node.args.vararg is not None
            or node.args.kwarg is not None
            or node.returns is not None
        ):
            self._reject(node, "SPELL202", "local functions must be undecorated and zero-argument")
        self.functions[node.name] = node

    def _compile_block(
        self,
        statements: list[ast.stmt],
        *,
        guard: dict[str, Any] | None,
        call_stack: tuple[str, ...],
        top_level: bool = False,
    ) -> None:
        seen_executable = False
        for statement in statements:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.AnnAssign):
                if not top_level or seen_executable or guard is not None or call_stack:
                    self._reject(
                        statement,
                        "SPELL301",
                        "typed declarations must precede executable top-level statements",
                    )
                self._compile_declaration(statement)
                continue
            seen_executable = True
            if isinstance(statement, ast.Assign):
                self._compile_assignment(statement, guard)
            elif isinstance(statement, ast.AugAssign):
                self._compile_augmented_assignment(statement, guard)
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                self._compile_call(statement, guard, call_stack)
            elif isinstance(statement, ast.If):
                self._compile_if(statement, guard, call_stack)
            elif isinstance(statement, ast.For):
                self._compile_for(statement, guard, call_stack)
            else:
                self._reject(
                    statement,
                    "SPELL103",
                    "only declarations, assignments, steps, if/else, bounded range loops, and local calls are allowed",
                )

    def _compile_declaration(self, node: ast.AnnAssign) -> None:
        if not isinstance(node.target, ast.Name) or not isinstance(node.annotation, ast.Name):
            self._reject(node, "SPELL302", "declaration must use `name: type = expression`")
        name = node.target.id
        declared_type = node.annotation.id
        self._validate_variable_name(node.target, name)
        if declared_type not in SUPPORTED_TYPES:
            self._reject(node.annotation, "SPELL303", f"unsupported type {declared_type}")
        if name in self.types:
            self._reject(node.target, "SPELL304", f"variable {name} is already declared")
        if node.value is None:
            self._reject(node, "SPELL305", "declarations require an initializer")
        expression, actual_type = self._expression(node.value)
        self._require_assignable(node.value, declared_type, actual_type)
        self.types[name] = declared_type
        self._append(
            node,
            "variable_set",
            name=name,
            declared_type=declared_type,
            expression=expression,
            declaration=True,
        )

    def _compile_assignment(self, node: ast.Assign, guard: dict[str, Any] | None) -> None:
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            self._reject(node, "SPELL306", "assignment requires one simple variable target")
        target = node.targets[0]
        self._validate_variable_name(target, target.id)
        declared_type = self._declared_type(target)
        expression, actual_type = self._expression(node.value)
        self._require_assignable(node.value, declared_type, actual_type)
        self._append(
            node,
            "variable_set",
            guard=guard,
            name=target.id,
            declared_type=declared_type,
            expression=expression,
            declaration=False,
        )

    def _compile_augmented_assignment(
        self, node: ast.AugAssign, guard: dict[str, Any] | None
    ) -> None:
        if not isinstance(node.target, ast.Name):
            self._reject(node, "SPELL307", "augmented assignment requires a simple variable target")
        self._validate_variable_name(node.target, node.target.id)
        declared_type = self._declared_type(node.target)
        synthetic = ast.BinOp(left=node.target, op=node.op, right=node.value)
        ast.copy_location(synthetic, node)
        expression, actual_type = self._expression(synthetic)
        self._require_assignable(node, declared_type, actual_type)
        self._append(
            node,
            "variable_set",
            guard=guard,
            name=node.target.id,
            declared_type=declared_type,
            expression=expression,
            declaration=False,
        )

    def _compile_call(
        self,
        node: ast.Expr,
        guard: dict[str, Any] | None,
        call_stack: tuple[str, ...],
    ) -> None:
        call = node.value
        assert isinstance(call, ast.Call)
        if not isinstance(call.func, ast.Name):
            self._reject(call, "SPELL401", "attribute and dynamic calls are not allowed")
        name = call.func.id
        if name in self._step_calls:
            self._compile_step(node, name, call, guard)
            return
        if name == "Call":
            function_name = self._local_call_target(call)
            self._expand_local_call(node, function_name, guard, call_stack)
            return
        if name in self.functions and not call.args and not call.keywords:
            self._expand_local_call(node, name, guard, call_stack)
            return
        self._reject(call, "SPELL402", "call must be a supported step or zero-argument local call")

    def _local_call_target(self, call: ast.Call) -> str:
        if call.keywords or len(call.args) != 1:
            self._reject(call, "SPELL403", "Call requires exactly one local function name")
        target = call.args[0]
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            self._validate_persistable_string(target, target.value, "local call target")
            return target.value
        self._reject(target, "SPELL403", "Call target must be a function name or string")

    def _expand_local_call(
        self,
        node: ast.AST,
        function_name: str,
        guard: dict[str, Any] | None,
        call_stack: tuple[str, ...],
    ) -> None:
        function = self.functions.get(function_name)
        if function is None:
            self._reject(node, "SPELL404", f"unknown local function {function_name}")
        if function_name in call_stack:
            chain = " -> ".join((*call_stack, function_name))
            self._reject(node, "SPELL405", f"recursive local call rejected: {chain}")
        if len(call_stack) >= MAX_CALL_DEPTH:
            self._reject(node, "SPELL406", f"local call depth exceeds {MAX_CALL_DEPTH}")
        self.called_functions.add(function_name)
        self._compile_block(
            function.body,
            guard=guard,
            call_stack=(*call_stack, function_name),
        )

    def _compile_step(
        self,
        node: ast.Expr,
        name: str,
        call: ast.Call,
        guard: dict[str, Any] | None,
    ) -> None:
        if any(keyword.arg is None for keyword in call.keywords):
            self._reject(call, "SPELL407", "keyword expansion is not allowed")
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
        if len(call.args) > len(positional):
            self._reject(call, "SPELL408", f"too many positional arguments for {name}")
        values = {keyword.arg: keyword.value for keyword in call.keywords}
        if set(values) - allowed[name]:
            self._reject(call, "SPELL409", f"unsupported keyword for {name}")
        for key, value in zip(positional, call.args):
            if key in values:
                self._reject(call, "SPELL410", f"duplicate argument {key}")
            values[key] = value
        required = positional[0]
        if required not in values:
            self._reject(call, "SPELL411", f"missing argument {required}")

        step: dict[str, Any] = {}
        if name == "Log":
            step["message"] = self._typed_argument(values["message"], {"str"}, "Log message")
            self._require_non_empty_literal(values["message"], step["message"], "Log message")
            step["level"] = self._literal_choice(
                values.get("level"), "info", {"debug", "info", "warning", "error"}, "Log level"
            )
        elif name == "Telemetry":
            step["channel"] = self._typed_argument(
                values["channel"], {"str"}, "Telemetry channel"
            )
            self._require_non_empty_literal(
                values["channel"], step["channel"], "Telemetry channel"
            )
            value_node = values.get("value", ast.Constant(value=0.0))
            step["value"] = self._typed_argument(
                value_node, {"bool", "float", "int"}, "Telemetry value"
            )
            if "unit" in values:
                step["unit"] = self._typed_argument(
                    values["unit"], {"str"}, "Telemetry unit"
                )
        elif name == "Wait":
            step["seconds"] = self._typed_argument(
                values["seconds"], {"float", "int"}, "Wait seconds"
            )
            if isinstance(step["seconds"], (int, float)) and not isinstance(step["seconds"], bool):
                if step["seconds"] < 0 or step["seconds"] > 3600:
                    self._reject(values["seconds"], "SPELL412", "Wait seconds must be 0 through 3600")
        else:
            step["question"] = self._typed_argument(
                values["question"], {"str"}, "Prompt question"
            )
            self._require_non_empty_literal(
                values["question"], step["question"], "Prompt question"
            )
            choices = self._literal_string_list(values.get("choices"), ["continue"], "Prompt choices")
            default = self._literal_optional_string(values.get("default"), None, "Prompt default")
            if any(len(choice) > MAX_PROMPT_CHOICE_LENGTH for choice in choices):
                self._reject(
                    values.get("choices", node),
                    "SPELL715",
                    f"Prompt choices must be at most {MAX_PROMPT_CHOICE_LENGTH} characters",
                )
            if len(set(choices)) != len(choices):
                self._reject(
                    values.get("choices", node),
                    "SPELL708",
                    "Prompt choices must be unique",
                )
            if default is not None and len(default) > MAX_PROMPT_CHOICE_LENGTH:
                self._reject(
                    values["default"],
                    "SPELL715",
                    f"Prompt default must be at most {MAX_PROMPT_CHOICE_LENGTH} characters",
                )
            if default is not None and default not in choices:
                self._reject(values["default"], "SPELL413", "Prompt default must be one of its choices")
            step["choices"] = choices
            step["default"] = default
        self._append(node, name.lower(), guard=guard, **step)

    def _compile_if(
        self,
        node: ast.If,
        outer_guard: dict[str, Any] | None,
        call_stack: tuple[str, ...],
    ) -> None:
        condition, condition_type = self._expression(node.test)
        if condition_type != "bool":
            self._reject(node.test, "SPELL501", "if condition must be boolean")
        branch_name = f"__spell_branch_{self.branch_counter}"
        self.branch_counter += 1
        self.types[branch_name] = "bool"
        self._append(
            node,
            "variable_set",
            guard=outer_guard,
            name=branch_name,
            declared_type="bool",
            expression=condition,
            declaration=True,
            internal=True,
        )
        branch_expression = {"expr": "variable", "name": branch_name}
        then_guard = self._combine_guards(outer_guard, branch_expression)
        else_guard = self._combine_guards(
            outer_guard, {"expr": "unary", "operator": "not", "operand": branch_expression}
        )
        self._compile_block(node.body, guard=then_guard, call_stack=call_stack)
        self._compile_block(node.orelse, guard=else_guard, call_stack=call_stack)

    def _compile_for(
        self,
        node: ast.For,
        guard: dict[str, Any] | None,
        call_stack: tuple[str, ...],
    ) -> None:
        if node.orelse:
            self._reject(node, "SPELL601", "for/else is not supported")
        if not isinstance(node.target, ast.Name):
            self._reject(node.target, "SPELL602", "loop target must be a simple variable")
        self._validate_variable_name(node.target, node.target.id)
        values = self._literal_range(node.iter)
        if len(values) == 0:
            self._reject(node.iter, "SPELL607", "range loops must execute at least once")
        existing_type = self.types.get(node.target.id)
        if existing_type is not None and existing_type != "int":
            self._reject(node.target, "SPELL603", "range loop variable must have type int")
        self.types[node.target.id] = "int"
        for index, value in enumerate(values):
            self._append(
                node,
                "variable_set",
                guard=guard,
                name=node.target.id,
                declared_type="int",
                expression={"expr": "literal", "value": value},
                declaration=existing_type is None and index == 0,
            )
            self._compile_block(node.body, guard=guard, call_stack=call_stack)
            if len(self.steps) > MAX_IR_STEPS:
                self._reject(node, "SPELL102", f"compiled procedure exceeds {MAX_IR_STEPS} steps")
        if existing_type is None:
            self.types.pop(node.target.id, None)

    def _literal_range(self, node: ast.AST) -> range:
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "range"
            and not node.keywords
            and 1 <= len(node.args) <= 3
        ):
            self._reject(node, "SPELL604", "loops require range with one to three literal integers")
        args: list[int] = []
        for argument in node.args:
            try:
                value = ast.literal_eval(argument)
            except (ValueError, TypeError):
                self._reject(argument, "SPELL604", "range arguments must be literal integers")
            if isinstance(value, bool) or not isinstance(value, int):
                self._reject(argument, "SPELL604", "range arguments must be literal integers")
            if value.bit_length() > MAX_INTEGER_BITS:
                self._reject(
                    argument,
                    "SPELL714",
                    f"range integer literal exceeds the {MAX_INTEGER_BITS}-bit safety limit",
                )
            args.append(value)
        try:
            result = range(*args)
        except ValueError as exc:
            self._reject(node, "SPELL605", str(exc))
        try:
            iteration_count = len(result)
        except OverflowError:
            self._reject(node, "SPELL606", f"range exceeds {MAX_LOOP_ITERATIONS} iterations")
        if iteration_count > MAX_LOOP_ITERATIONS:
            self._reject(node, "SPELL606", f"range exceeds {MAX_LOOP_ITERATIONS} iterations")
        return result

    def _expression(self, node: ast.AST) -> tuple[dict[str, Any], str]:
        if isinstance(node, ast.Constant) and type(node.value) in {bool, float, int, str}:
            if type(node.value) is int and node.value.bit_length() > MAX_INTEGER_BITS:
                self._reject(node, "SPELL714", "integer literal exceeds the safety limit")
            if type(node.value) is float and not math.isfinite(node.value):
                self._reject(node, "SPELL714", "floating-point literal must be finite")
            if type(node.value) is str:
                self._validate_persistable_string(node, node.value, "string literal")
                if len(node.value) > 100_000:
                    self._reject(node, "SPELL714", "string literal exceeds the safety limit")
            return {"expr": "literal", "value": node.value}, type(node.value).__name__
        if isinstance(node, ast.Name):
            self._validate_variable_name(node, node.id)
            return {"expr": "variable", "name": node.id}, self._declared_type(node)
        if isinstance(node, ast.UnaryOp):
            operand, operand_type = self._expression(node.operand)
            if isinstance(node.op, ast.Not):
                if operand_type != "bool":
                    self._reject(node, "SPELL701", "not requires a boolean operand")
                return {"expr": "unary", "operator": "not", "operand": operand}, "bool"
            if isinstance(node.op, (ast.UAdd, ast.USub)) and operand_type in {"int", "float"}:
                operator = "+" if isinstance(node.op, ast.UAdd) else "-"
                return {"expr": "unary", "operator": operator, "operand": operand}, operand_type
            self._reject(node, "SPELL702", "unsupported unary expression")
        if isinstance(node, ast.BinOp):
            left, left_type = self._expression(node.left)
            right, right_type = self._expression(node.right)
            operator = self._binary_operator(node.op)
            result_type = self._binary_result_type(node, operator, left_type, right_type)
            return {
                "expr": "binary",
                "operator": operator,
                "left": left,
                "right": right,
            }, result_type
        if isinstance(node, ast.BoolOp):
            values = [self._expression(value) for value in node.values]
            if any(value_type != "bool" for _, value_type in values):
                self._reject(node, "SPELL703", "and/or operands must be boolean")
            return {
                "expr": "boolean",
                "operator": "and" if isinstance(node.op, ast.And) else "or",
                "values": [value for value, _ in values],
            }, "bool"
        if isinstance(node, ast.Compare):
            expressions = [self._expression(node.left), *(self._expression(item) for item in node.comparators)]
            operators = [self._comparison_operator(operator) for operator in node.ops]
            for index, operator in enumerate(operators):
                left_type = expressions[index][1]
                right_type = expressions[index + 1][1]
                numeric = left_type in {"int", "float"} and right_type in {"int", "float"}
                same = left_type == right_type
                if not (numeric or same):
                    self._reject(node, "SPELL704", f"incompatible comparison types {left_type} and {right_type}")
                if operator in {"<", "<=", ">", ">="} and left_type == "bool":
                    self._reject(node, "SPELL704", "boolean ordering is not supported")
            return {
                "expr": "compare",
                "operators": operators,
                "operands": [value for value, _ in expressions],
            }, "bool"
        self._reject(node, "SPELL705", "unsupported expression")

    def _typed_argument(self, node: ast.AST, allowed: set[str], label: str) -> Any:
        expression, expression_type = self._expression(node)
        if expression_type not in allowed:
            self._reject(node, "SPELL706", f"{label} must have type {' or '.join(sorted(allowed))}")
        if expression["expr"] == "literal":
            return expression["value"]
        return expression

    def _literal_choice(
        self,
        node: ast.AST | None,
        default: str,
        allowed: set[str],
        label: str,
    ) -> str:
        if node is None:
            return default
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError):
            self._reject(node, "SPELL707", f"{label} must be a literal string")
        if not isinstance(value, str) or value not in allowed:
            self._reject(node, "SPELL707", f"invalid {label}")
        return value

    def _require_non_empty_literal(self, node: ast.AST, value: Any, label: str) -> None:
        if isinstance(value, str) and not value:
            self._reject(node, "SPELL713", f"{label} must be a non-empty string")

    def _literal_string_list(
        self, node: ast.AST | None, default: list[str], label: str
    ) -> list[str]:
        if node is None:
            return default
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError):
            self._reject(node, "SPELL708", f"{label} must be a literal list of strings")
        if not isinstance(value, (list, tuple)) or not value or not all(
            isinstance(item, str) and item for item in value
        ):
            self._reject(node, "SPELL708", f"{label} must contain non-empty strings")
        for item in value:
            self._validate_persistable_string(node, item, label)
        return list(value)

    def _literal_optional_string(
        self, node: ast.AST | None, default: str | None, label: str
    ) -> str | None:
        if node is None:
            return default
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError):
            self._reject(node, "SPELL709", f"{label} must be a literal string or None")
        if value is not None and not isinstance(value, str):
            self._reject(node, "SPELL709", f"{label} must be a literal string or None")
        if value is not None:
            self._validate_persistable_string(node, value, label)
        return value

    def _validate_persistable_string(
        self, node: ast.AST, value: str, label: str
    ) -> None:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            self._reject(
                node,
                "SPELL716",
                f"{label} contains an invalid Unicode scalar value",
            )
        if "\x00" in value:
            self._reject(node, "SPELL716", f"{label} contains U+0000")

    @staticmethod
    def _combine_guards(
        outer: dict[str, Any] | None, inner: dict[str, Any]
    ) -> dict[str, Any]:
        if outer is None:
            return inner
        return {"expr": "boolean", "operator": "and", "values": [outer, inner]}

    def _declared_type(self, node: ast.Name) -> str:
        declared_type = self.types.get(node.id)
        if declared_type is None:
            self._reject(node, "SPELL308", f"variable {node.id} is not declared")
        return declared_type

    def _validate_variable_name(self, node: ast.AST, name: str) -> None:
        if name.startswith("__") or name in self._step_calls or name in {"Call", "range"}:
            self._reject(node, "SPELL309", f"reserved variable name {name}")

    def _require_assignable(self, node: ast.AST, target: str, actual: str) -> None:
        if actual != target and not (target == "float" and actual == "int"):
            self._reject(node, "SPELL310", f"cannot assign {actual} expression to {target}")

    def _binary_operator(self, operator: ast.operator) -> str:
        operators = {
            ast.Add: "+",
            ast.Sub: "-",
            ast.Mult: "*",
            ast.Div: "/",
            ast.FloorDiv: "//",
            ast.Mod: "%",
        }
        value = operators.get(type(operator))
        if value is None:
            self._reject(operator, "SPELL710", "unsupported binary operator")
        return value

    def _binary_result_type(
        self, node: ast.AST, operator: str, left: str, right: str
    ) -> str:
        if operator == "+" and left == right == "str":
            return "str"
        if left not in {"int", "float"} or right not in {"int", "float"}:
            self._reject(node, "SPELL711", f"operator {operator} requires numeric operands")
        if operator == "/" or "float" in {left, right}:
            return "float"
        return "int"

    def _comparison_operator(self, operator: ast.cmpop) -> str:
        operators = {
            ast.Eq: "==",
            ast.NotEq: "!=",
            ast.Lt: "<",
            ast.LtE: "<=",
            ast.Gt: ">",
            ast.GtE: ">=",
        }
        value = operators.get(type(operator))
        if value is None:
            self._reject(operator, "SPELL712", "only equality and ordering comparisons are supported")
        return value

    def _append(
        self,
        node: ast.AST,
        step_type: str,
        *,
        guard: dict[str, Any] | None = None,
        **fields: Any,
    ) -> None:
        if len(self.steps) >= MAX_IR_STEPS:
            self._reject(
                node,
                "SPELL102",
                f"compiled procedure exceeds the {MAX_IR_STEPS} step limit",
            )
        step: dict[str, Any] = {
            "index": len(self.steps),
            "type": step_type,
            "line": getattr(node, "lineno", 1),
            "column": getattr(node, "col_offset", 0) + 1,
        }
        if guard is not None:
            step["guard"] = guard
        step.update(fields)
        serialized_size = len(
            json.dumps(step, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        projected_size = self.serialized_ir_bytes + serialized_size
        if self.steps:
            projected_size += 1
        if projected_size > MAX_IR_SERIALIZED_BYTES:
            self._reject(
                node,
                "SPELL104",
                "compiled procedure exceeds the "
                f"{MAX_IR_SERIALIZED_BYTES}-byte serialized IR limit",
            )
        self.serialized_ir_bytes = projected_size
        self.steps.append(step)

    def _reject(self, node: ast.AST, code: str, message: str) -> None:
        raise ProcedureValidationError(
            self.source_name,
            [
                ProcedureDiagnostic(
                    code=code,
                    message=message,
                    line=getattr(node, "lineno", None),
                    column=(getattr(node, "col_offset", -1) + 1) or None,
                )
            ],
        )
