"""Deterministic, non-executing language services for v0.9 authoring."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .development_domain import DevelopmentError, canonical_json_bytes, normalize_path
from .procedure_parser import MAX_SOURCE_BYTES, ProcedureCatalog, ProcedureValidationError


TOOL_VERSION = "spell-development-analysis/0.9"
LANGUAGE_PROFILE = "spell-restricted-ast/0.9"
MAX_DIAGNOSTICS_PER_FILE = 1000
MAX_OUTLINE_ITEMS = 5000
MAX_COMPLETION_ITEMS = 500
MAX_AST_NODES = 20_000
MAX_AST_DEPTH = 64
_PROCEDURE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_METADATA_HEADER = re.compile(
    r"^# @(?P<name>procedure|display-name|description|language-profile|"
    r"dictionary-reference|tm-reference|tc-reference) (?P<value>[^\r\n]+)$"
)


def _procedure_headers(
    source: str,
) -> tuple[dict[str, str] | None, list[tuple[str, str, int]], list[dict[str, Any]]]:
    values: dict[str, str] = {}
    issues: list[tuple[str, str, int]] = []
    outline: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), 1):
        if not line.startswith("# @"):
            continue
        match = _METADATA_HEADER.fullmatch(line)
        if match is None:
            issues.append(("V09_HEADER_INVALID", "procedure metadata header is invalid", line_number))
            continue
        name = match.group("name")
        value = match.group("value").strip()
        if not value or len(value.encode("utf-8")) > 512:
            issues.append(("V09_HEADER_INVALID", "procedure metadata value is invalid", line_number))
            continue
        if name in {"procedure", "display-name", "description", "language-profile"}:
            if name in values:
                issues.append(("V09_HEADER_DUPLICATE", f"duplicate @{name} header", line_number))
            else:
                values[name] = value
        outline_kind = {
            "procedure": "HEADER",
            "display-name": "HEADER",
            "description": "HEADER",
            "language-profile": "HEADER",
            "dictionary-reference": "DICTIONARY_REFERENCE",
            "tm-reference": "TM_REFERENCE",
            "tc-reference": "TC_REFERENCE",
        }[name]
        outline.append(
            {"kind": outline_kind, "name": value, "line": line_number, "column": 1}
        )
    procedure_id = values.get("procedure")
    if procedure_id is None:
        issues.append(("V09_PROCEDURE_ID_REQUIRED", "a stable # @procedure header is required", 1))
    else:
        parts = procedure_id.split("/")
        if (
            len(procedure_id) > 200
            or len(parts) > 16
            or any(_PROCEDURE_SEGMENT.fullmatch(part) is None for part in parts)
        ):
            issues.append(("V09_PROCEDURE_ID_INVALID", "stable procedure id is invalid", 1))
    profile = values.get("language-profile")
    if profile is not None and profile != LANGUAGE_PROFILE:
        issues.append(("V09_LANGUAGE_PROFILE", "procedure language profile is unsupported", 1))
    return (values if not issues else None), issues, outline


@dataclass(frozen=True)
class AnalysisResult:
    diagnostics: tuple[dict[str, Any], ...]
    outline: tuple[dict[str, Any], ...]
    completions: tuple[dict[str, Any], ...]
    compiled: dict[str, dict[str, Any]]
    input_digests: dict[str, str]
    metadata: dict[str, str] | None = None


def _diagnostic(
    *,
    workspace_revision: int,
    source_digest: str,
    source_path: str,
    code: str,
    message: str,
    line: int | None,
    column: int | None,
    severity: str = "error",
) -> dict[str, Any]:
    start_line = max(1, line or 1)
    start_column = max(1, column or 1)
    identity = canonical_json_bytes(
        {
            "code": code,
            "source_digest": source_digest,
            "source_path": source_path,
            "span": [start_line, start_column, start_line, start_column],
            "tool_version": TOOL_VERSION,
            "workspace_revision": workspace_revision,
        }
    )
    return {
        "diagnostic_id": hashlib.sha256(identity).hexdigest(),
        "code": code,
        "severity": severity.upper(),
        "source_path": source_path,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": start_line,
        "end_column": start_column,
        "language_profile": LANGUAGE_PROFILE,
        "message": message[:2000],
        "remediation_ref": f"spell://diagnostics/{code}",
        "tool_version": TOOL_VERSION,
    }


def _outline(tree: ast.AST, steps: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "FUNCTION"
            name = node.name
            for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                items.append(
                    {
                        "kind": "ARGUMENT",
                        "name": argument.arg,
                        "line": int(getattr(argument, "lineno", getattr(node, "lineno", 1))),
                        "column": int(getattr(argument, "col_offset", 0)) + 1,
                    }
                )
        elif isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            for name in names:
                items.append(
                    {
                        "kind": "LOCAL_VARIABLE",
                        "name": name,
                        "line": int(getattr(node, "lineno", 1)),
                        "column": int(getattr(node, "col_offset", 0)) + 1,
                    }
                )
            continue
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            kind = (
                "GOTO_LABEL"
                if node.func.id == "Label"
                else "TM_REFERENCE"
                if node.func.id == "GetTM"
                else "DICTIONARY_REFERENCE"
                if "Dictionary" in node.func.id
                else "SPELL_CALL"
            )
            name = node.func.id
        else:
            continue
        items.append(
            {
                "kind": kind,
                "name": name,
                "line": int(getattr(node, "lineno", 1)),
                "column": int(getattr(node, "col_offset", 0)) + 1,
            }
        )
    for index, step in enumerate(steps):
        items.append(
            {
                "kind": "STEP",
                "name": str(step.get("type", "step")),
                "line": int(step.get("line") or 1),
                "column": 1,
                "step_index": index,
            }
        )
    return sorted(
        items[:MAX_OUTLINE_ITEMS],
        key=lambda item: (item["line"], item["column"], item["kind"], item["name"]),
    )


def _completions(tree: ast.AST) -> list[dict[str, Any]]:
    builtins = {
        "Log",
        "Telemetry",
        "Wait",
        "Prompt",
        "StartProc",
        "GetTM",
        "Verify",
        "WaitFor",
        "CreateDictionary",
        "LoadDictionary",
        "SaveDictionary",
        "DataContainer",
        "Var",
        "GetSharedData",
        "SetSharedData",
        "OpenFile",
        "ReadFile",
        "WriteFile",
        "CloseFile",
    }
    symbols = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id
    }
    result = []
    for label in sorted(builtins | symbols)[:MAX_COMPLETION_ITEMS]:
        result.append(
            {
                "label": label,
                "kind": "SPELL_CALL" if label in builtins else "SYMBOL",
                "insert_text": label,
                "sort_text": label.casefold(),
            }
        )
    return result


def analyze_source(
    source: str,
    source_path: str,
    *,
    workspace_revision: int,
) -> AnalysisResult:
    path = normalize_path(source_path)
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DevelopmentError("procedure source is not valid UTF-8") from exc
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if len(source_bytes) > MAX_SOURCE_BYTES:
        diagnostic = _diagnostic(
            workspace_revision=workspace_revision,
            source_digest=source_digest,
            source_path=path,
            code="SPELL005",
            message=f"source exceeds the {MAX_SOURCE_BYTES}-byte limit",
            line=1,
            column=1,
        )
        return AnalysisResult(
            diagnostics=(diagnostic,),
            outline=(),
            completions=(),
            compiled={},
            input_digests={path: source_digest},
            metadata=None,
        )
    diagnostics: list[dict[str, Any]] = []
    compiled: dict[str, dict[str, Any]] = {}
    outline: list[dict[str, Any]] = []
    completions: list[dict[str, Any]] = []
    metadata, header_issues, header_outline = _procedure_headers(source)
    for code, message, line in header_issues[:MAX_DIAGNOSTICS_PER_FILE]:
        diagnostics.append(
            _diagnostic(
                workspace_revision=workspace_revision,
                source_digest=source_digest,
                source_path=path,
                code=code,
                message=message,
                line=line,
                column=1,
            )
        )
    try:
        tree = ast.parse(source, filename=path, mode="exec")
    except (RecursionError, SyntaxError):
        tree = None
    try:
        procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
            source,
            path,
        )
    except ProcedureValidationError as exc:
        for item in exc.diagnostics[:MAX_DIAGNOSTICS_PER_FILE]:
            diagnostics.append(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=source_digest,
                    source_path=path,
                    code=item.code,
                    message=item.message,
                    line=item.line,
                    column=item.column,
                    severity=item.severity,
                )
            )
    else:
        if metadata is not None:
            compiled[path] = {
                "description": metadata.get("description", procedure.description),
                "display_name": metadata.get(
                    "display-name", metadata["procedure"].replace("_", " ").title()
                ),
                "ir_version": procedure.ir_version,
                "procedure_id": metadata["procedure"],
                "source": procedure.source,
                "source_sha256": procedure.sha256,
                "steps": list(procedure.steps),
                "user_actions": list(procedure.user_actions),
            }
        if tree is not None:
            outline = [*header_outline, *_outline(tree, procedure.steps)]
            completions = _completions(tree)
    return AnalysisResult(
        diagnostics=tuple(diagnostics),
        outline=tuple(outline),
        completions=tuple(completions),
        compiled=compiled,
        input_digests={path: source_digest},
        metadata=metadata,
    )


def analyze_library_source(
    source: str,
    source_path: str,
    *,
    workspace_revision: int,
) -> AnalysisResult:
    path = normalize_path(source_path)
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DevelopmentError("library source is not valid UTF-8") from exc
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if len(source_bytes) > MAX_SOURCE_BYTES:
        return AnalysisResult(
            diagnostics=(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=source_digest,
                    source_path=path,
                    code="LIBRARY_SOURCE_LIMIT",
                    message=f"library source exceeds the {MAX_SOURCE_BYTES}-byte limit",
                    line=1,
                    column=1,
                ),
            ),
            outline=(),
            completions=(),
            compiled={},
            input_digests={path: source_digest},
        )
    try:
        tree = ast.parse(source, filename=path, mode="exec")
    except (RecursionError, SyntaxError) as exc:
        return AnalysisResult(
            diagnostics=(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=source_digest,
                    source_path=path,
                    code="LIBRARY_SYNTAX_INVALID",
                    message="library source is not valid restricted Python syntax",
                    line=getattr(exc, "lineno", 1),
                    column=getattr(exc, "offset", 1),
                ),
            ),
            outline=(),
            completions=(),
            compiled={},
            input_digests={path: source_digest},
        )
    nodes = list(ast.walk(tree))
    diagnostics: list[dict[str, Any]] = []
    if len(nodes) > MAX_AST_NODES:
        diagnostics.append(
            _diagnostic(
                workspace_revision=workspace_revision,
                source_digest=source_digest,
                source_path=path,
                code="LIBRARY_AST_NODE_LIMIT",
                message=f"library syntax tree exceeds {MAX_AST_NODES} nodes",
                line=1,
                column=1,
            )
        )
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    deepest = 1
    while stack:
        node, depth = stack.pop()
        deepest = max(deepest, depth)
        if deepest > MAX_AST_DEPTH:
            break
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    if deepest > MAX_AST_DEPTH:
        diagnostics.append(
            _diagnostic(
                workspace_revision=workspace_revision,
                source_digest=source_digest,
                source_path=path,
                code="LIBRARY_AST_DEPTH_LIMIT",
                message=f"library syntax tree exceeds depth {MAX_AST_DEPTH}",
                line=1,
                column=1,
            )
        )
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            diagnostics.append(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=source_digest,
                    source_path=path,
                    code="LIBRARY_IMPORT_FORBIDDEN",
                    message="library imports are not loaded by static language services",
                    line=getattr(node, "lineno", 1),
                    column=int(getattr(node, "col_offset", 0)) + 1,
                )
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ):
            diagnostics.append(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=source_digest,
                    source_path=path,
                    code="LIBRARY_DYNAMIC_EXECUTION_FORBIDDEN",
                    message="dynamic execution constructs are not allowed in libraries",
                    line=getattr(node, "lineno", 1),
                    column=int(getattr(node, "col_offset", 0)) + 1,
                )
            )
    diagnostics = sorted(
        diagnostics[:MAX_DIAGNOSTICS_PER_FILE],
        key=lambda item: (
            item["source_path"],
            item["start_line"],
            item["start_column"],
            item["code"],
        ),
    )
    return AnalysisResult(
        diagnostics=tuple(diagnostics),
        outline=tuple(_outline(tree, ())),
        completions=tuple(_completions(tree)),
        compiled={},
        input_digests={path: source_digest},
    )


def analyze_resources(
    resources: Iterable[Mapping[str, Any]],
    *,
    workspace_revision: int,
    scope: str,
    scope_path: str | None = None,
) -> AnalysisResult:
    selected_path = normalize_path(scope_path) if scope_path is not None else None
    diagnostics: list[dict[str, Any]] = []
    outline: list[dict[str, Any]] = []
    completions: list[dict[str, Any]] = []
    compiled: dict[str, dict[str, Any]] = {}
    input_digests: dict[str, str] = {}
    for resource in sorted(resources, key=lambda item: str(item["path"]).encode("utf-8")):
        path = normalize_path(resource["path"])
        if selected_path is not None:
            if scope == "FILE" and path != selected_path:
                continue
            if scope == "FOLDER" and not (
                path == selected_path or path.startswith(selected_path + "/")
            ):
                continue
        if resource["kind"] not in {"PROCEDURE", "LIBRARY"}:
            continue
        content = resource["content"]
        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError:
            digest = hashlib.sha256(content).hexdigest()
            diagnostics.append(
                _diagnostic(
                    workspace_revision=workspace_revision,
                    source_digest=digest,
                    source_path=path,
                    code="SPELL004",
                    message="source is not valid UTF-8",
                    line=1,
                    column=1,
                )
            )
            input_digests[path] = digest
            continue
        result = (
            analyze_library_source(
                source, path, workspace_revision=workspace_revision
            )
            if resource["kind"] == "LIBRARY"
            else analyze_source(source, path, workspace_revision=workspace_revision)
        )
        diagnostics.extend(result.diagnostics)
        outline.extend({**item, "source_path": path} for item in result.outline)
        completions.extend(result.completions)
        compiled.update(result.compiled)
        input_digests.update(result.input_digests)
    diagnostics.sort(
        key=lambda item: (
            item["source_path"],
            item["start_line"],
            item["start_column"],
            item["severity"],
            item["code"],
            item["diagnostic_id"],
        )
    )
    unique_completions = {item["label"]: item for item in completions}
    return AnalysisResult(
        diagnostics=tuple(diagnostics),
        outline=tuple(outline[:MAX_OUTLINE_ITEMS]),
        completions=tuple(
            unique_completions[key]
            for key in sorted(unique_completions)[:MAX_COMPLETION_ITEMS]
        ),
        compiled=compiled,
        input_digests=input_digests,
        metadata=None,
    )


__all__ = [
    "AnalysisResult",
    "LANGUAGE_PROFILE",
    "TOOL_VERSION",
    "analyze_library_source",
    "analyze_resources",
    "analyze_source",
]
