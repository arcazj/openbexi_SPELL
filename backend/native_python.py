"""Explicit, source-bound CPython profile; existing SPELL IR remains closed."""
from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import Any

from .ir_v03 import IRValidationError, ValidatedIR

IR_VERSION = "python/1"
LANGUAGE_PROFILE = "python-stdlib/3.13"
PYTHON_VERSION = "3.13.14"
MAX_SOURCE_BYTES = 100_000
MAX_OUTPUT_BYTES = 262_144
MAX_PROTOCOL_BYTES = 2_000_000
MAX_RUN_SECONDS = 30
MAX_JOB_SECONDS = 300
PROFILE_HEADER = re.compile(r"(?m)^#\s*@language-profile\s+python-stdlib/3\.13\s*$")
SOURCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.py\Z")
RESULT_TYPES = {"python_completed": "bool", "python_exit_code": "int",
                "python_stdout_lines": "int", "python_stderr_lines": "int"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def has_profile(source: str) -> bool:
    return PROFILE_HEADER.search(source[:4096]) is not None


def script_step(source: str, source_name: str) -> dict[str, Any]:
    if type(source) is not str or not has_profile(source):
        raise IRValidationError("$.source", "the explicit Python profile is required")
    try:
        raw = source.encode("utf-8")
    except UnicodeError as exc:
        raise IRValidationError("$.source", "source is not valid UTF-8") from exc
    if len(raw) > MAX_SOURCE_BYTES or "\x00" in source:
        raise IRValidationError("$.source", "Python source exceeds its bound or contains NUL")
    if type(source_name) is not str or SOURCE_NAME.fullmatch(source_name) is None:
        raise IRValidationError("$.source_name", "Python source filename is invalid")
    try:
        tree = ast.parse(source, filename=source_name)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise IRValidationError("$.source", "Python source has invalid syntax") from exc
    pending = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 20_000 or depth > 64:
            raise IRValidationError("$.source", "Python AST exceeds its complexity bound")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return {"index": 0, "type": "python_script", "line": 1, "column": 1,
            "guard": None, "source": source, "source_name": source_name,
            "source_sha256": hashlib.sha256(raw).hexdigest(), "runtime_profile": LANGUAGE_PROFILE,
            "lexical_frame_id": "root", "lexical_frame_path": ["root"],
            "reachability_id": "root:step:0", "step_over_target": 1,
            "call_boundary_id": None, "labels": []}


def validate_ir(ir_version: Any, steps: Any, *, start_step: Any = 0,
                resume_prompt_id: Any = None, resume_prompt_step: Any = None,
                checkpoint_variables: Any = None, expected_total_steps: Any = None) -> ValidatedIR:
    if ir_version != IR_VERSION or type(steps) is not list or len(steps) != 1 or type(steps[0]) is not dict:
        raise IRValidationError("$.steps", "Python IR must contain exactly one source-bound script")
    step = steps[0]
    expected = script_step(step.get("source"), step.get("source_name"))
    if canonical(step) != canonical(expected):
        raise IRValidationError("$.steps[0]", "Python script metadata or source digest differs")
    if type(start_step) is not int or start_step not in {0, 1}:
        raise IRValidationError("$.start_step", "Python position must be a script boundary")
    if resume_prompt_id is not None or resume_prompt_step is not None:
        raise IRValidationError("$.resume_prompt_id", "Python scripts do not contain SPELL prompts")
    if expected_total_steps is not None and (type(expected_total_steps) is not int or expected_total_steps != 1):
        raise IRValidationError("$.total_steps", "Python script total steps differs")
    checkpoint = {} if checkpoint_variables is None else checkpoint_variables
    if type(checkpoint) is not dict or (start_step == 0 and checkpoint):
        raise IRValidationError("$.checkpoint_variables", "Python execution cannot resume live objects")
    if start_step == 1:
        if set(checkpoint) != set(RESULT_TYPES):
            raise IRValidationError("$.checkpoint_variables", "Python result fields differ")
        if any(type(checkpoint[name]).__name__ != kind for name, kind in RESULT_TYPES.items()):
            raise IRValidationError("$.checkpoint_variables", "Python result types differ")
        if checkpoint["python_completed"] is not True or checkpoint["python_exit_code"] != 0:
            raise IRValidationError("$.checkpoint_variables", "Python success checkpoint is invalid")
        if any(not 0 <= checkpoint[name] <= 1000 for name in ("python_stdout_lines", "python_stderr_lines")):
            raise IRValidationError("$.checkpoint_variables", "Python output counts exceed their bound")
    return ValidatedIR([expected], canonical([expected]), dict(RESULT_TYPES), dict(checkpoint))
