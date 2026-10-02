"""Composite, bounded IR for the explicitly scoped 2.4.4 v0.17 profile.

Native Prompt results are atomic. A private validation projection introduces a
result slot *after* its prompt; no synthetic assignment is executed or stored.
"""
from __future__ import annotations

import json
from typing import Any

from .ir_v03 import ValidatedIR
from .ir_v06 import (
    MAX_PROMPT_WARNING_DELAY_SECONDS, V06_STEP_TARGET_FIELDS,
    _validate_step_target_metadata, validate_ir_v06,
)
from .ir_v07 import validate_ir_v07
from .ir_v10 import V10ValidationError, validate_ir_v10
from .language_conformance_v17 import ALL_SELECTION, CASESET_SHA256, canonical_bytes

IR_VERSION = "0.17"
_BASE = {"index", "type", "line", "column", "guard", *V06_STEP_TARGET_FIELDS}


class V17ValidationError(V10ValidationError):
    pass


def _reject(path: str, message: str) -> None:
    raise V17ValidationError("IR_VALIDATION_FAILED", path, message)


def validate_ir_v17(ir_version: Any, steps: Any, *, start_step: Any = 0,
                    resume_prompt_id: Any = None, resume_prompt_step: Any = None,
                    checkpoint_variables: Any = None, expected_total_steps: Any = None) -> ValidatedIR:
    from .core_v17 import has_core_expressions, project_core_expressions, validate_core_expression_types
    from .prompt_v17 import RESPONSE_FIELDS, native_prompt_result_type, validate_native_prompt_step

    if ir_version != IR_VERSION or type(steps) is not list or not steps:
        _reject("$.ir_version", "expected nonempty IR 0.17")
    try:
        encoded = canonical_bytes(steps)
        if len(encoded) > 8_000_000 or len(steps) > 10_000:
            _reject("$.steps", "IR exceeds its bounded size")
        canonical = json.loads(encoded)
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, V17ValidationError):
            raise
        raise V17ValidationError("IR_VALIDATION_FAILED", "$.steps", "IR is not canonical finite JSON") from exc
    if type(start_step) is not int or not 0 <= start_step <= len(canonical):
        _reject("$.start_step", "start step is outside the procedure")
    if expected_total_steps is not None and (type(expected_total_steps) is not int or expected_total_steps != len(canonical)):
        _reject("$.total_steps", "total steps does not match the IR")
    if resume_prompt_step is not None and (type(resume_prompt_step) is not int or resume_prompt_step != start_step):
        _reject("$.resume_prompt_step", "resume prompt step differs from start step")

    projections: list[dict[str, Any]] = []
    positions: list[int] = []
    seen_reachability: set[str] = set()
    seen_labels: set[tuple[str, str]] = set()
    native = has_core_expressions(canonical)
    for index, raw in enumerate(canonical):
        path = f"$.steps[{index}]"
        if type(raw) is not dict or type(raw.get("index")) is not int or raw["index"] != index:
            _reject(path, "step indexes must be contiguous")
        if type(raw.get("type")) is not str:
            _reject(path + ".type", "instruction type must be a string")
        _validate_step_target_metadata(raw, index, len(canonical), seen_reachability=seen_reachability, seen_labels=seen_labels)
        projected = {key: value for key, value in raw.items() if key not in V06_STEP_TARGET_FIELDS}
        positions.append(len(projections))
        shadow = None
        if raw.get("type") == "language_check":
            if set(raw) - (_BASE | {"selection", "target", "target_type", "cases_sha256"}):
                _reject(path, "unknown language selection field")
            if raw.get("cases_sha256") != CASESET_SHA256 or "selection" not in raw:
                _reject(path, "language selection registry identity differs")
            selection = raw["selection"]
            variable = (type(selection) is dict and set(selection) == {"expr", "name"}
                        and selection.get("expr") == "variable" and type(selection.get("name")) is str)
            if not (type(selection) is int or variable):
                _reject(path + ".selection", "selection must be an integer literal or variable")
            if type(selection) is int and not 0 <= selection <= ALL_SELECTION:
                _reject(path + ".selection", "selection is outside the closed registry")
            projected.pop("cases_sha256")
            projected.pop("selection")
            projected.update(type="reference_example", example={"expr": "binary", "operator": "+",
                "left": selection if variable else {"expr": "literal", "value": selection},
                "right": {"expr": "literal", "value": 0}})
            native = True
        elif raw.get("type") == "display":
            if set(raw) - (_BASE | {"message", "level"}) or not {"message", "level"} <= set(raw):
                _reject(path, "Display fields are invalid")
            if type(raw["level"]) is not str or raw["level"] not in {"info", "warning", "error"}:
                _reject(path + ".level", "Display severity is invalid")
            projected["type"] = "log"
            if projected["message"] == "":
                projected["message"] = "empty Display validation projection"
            native = True
        elif raw.get("type") == "prompt" and "prompt_profile" in raw:
            fields = validate_native_prompt_step(raw, path)
            allowed = _BASE | set(fields) | RESPONSE_FIELDS
            if set(raw) - allowed:
                _reject(path, "unknown native Prompt field")
            if set(raw) & RESPONSE_FIELDS:
                if not RESPONSE_FIELDS <= set(raw):
                    _reject(path, "native Prompt binding fields are incomplete")
                fields.update({key: raw[key] for key in RESPONSE_FIELDS})
            canonical[index] = {**raw, **fields}
            projected = {key: value for key, value in canonical[index].items()
                         if key not in V06_STEP_TARGET_FIELDS | {"prompt_profile", "response_target", "response_target_type", "response_target_declaration"}}
            # Native validation above owns the seven-day duration bound. The
            # private legacy projection checks question reads and declaration
            # shape within its historical one-day warning limit; it is never
            # executed and the canonical native duration is restored unchanged.
            if projected["warning_delay_seconds"] is not None:
                projected["warning_delay_seconds"] = min(
                    projected["warning_delay_seconds"], MAX_PROMPT_WARNING_DELAY_SECONDS)
            if "response_target" in fields:
                declared = fields["response_target_type"]
                if type(declared) is not str or declared != native_prompt_result_type(fields["prompt_type"], fields["list_mode"]) or type(fields.get("response_target_declaration")) is not bool:
                    _reject(path, "native Prompt binding metadata is invalid")
                if fields["response_target_declaration"] and "guard" in raw:
                    _reject(path, "native Prompt cannot declare a variable in a guarded branch")
                shadow = {key: value for key, value in projected.items() if key in {"line", "column", "guard"}}
                shadow.update(type="variable_set", name=fields["response_target"], declared_type=declared,
                    declaration=fields["response_target_declaration"], expression={"expr": "literal", "value": {"str": "", "int": 0, "float": 0.0}[declared]})
            native = True
        projected["index"] = len(projections)
        projections.append(projected)
        if shadow is not None:
            shadow["index"] = len(projections)
            projections.append(shadow)
    positions.append(len(projections))
    if not native:
        _reject("$.steps", "IR 0.17 requires a v0.17 capability")
    # Original lexical metadata was independently checked above. Projection
    # indexes include private result declarations, so use private contiguous
    # metadata rather than presenting old indexes to earlier validators.
    for index, projected in enumerate(projections):
        projected.update(lexical_frame_id="root", lexical_frame_path=["root"],
            reachability_id=f"v17-validation-{index}", step_over_target=index + 1,
            call_boundary_id=None, labels=[])
    # Validate using the unchanged prior profiles, including read order and the
    # original prompt question, then independently check new operand types.
    projected_core = project_core_expressions(projections)
    kinds = {step["type"] for step in projections}
    if kinds & {"build_tc", "send_tc", "data_operation", "file_operation", "environment_operation"}:
        _reject("$.steps", "IR 0.17 does not mix this service capability")
    validator, version = ((validate_ir_v10, "0.10") if "reference_example" in kinds else
        (validate_ir_v07, "0.7") if kinds & {"get_tm", "verify", "wait_for"} else (validate_ir_v06, "0.6"))
    try:
        metadata = {"start_step": positions[start_step], "resume_prompt_id": resume_prompt_id,
                    "checkpoint_variables": checkpoint_variables, "expected_total_steps": len(projections)}
        if resume_prompt_step is not None:
            metadata["resume_prompt_step"] = positions[resume_prompt_step]
        validated = validator(version, projected_core, **metadata)
        validate_core_expression_types(canonical, validated.variable_types)
    except ValueError as exc:
        if isinstance(exc, V17ValidationError):
            raise
        raise V17ValidationError(getattr(exc, "code", "IR_VALIDATION_FAILED"), getattr(exc, "path", "$.steps"), getattr(exc, "message", str(exc))) from exc
    for index, raw in enumerate(canonical):
        if raw.get("type") == "language_check" and type(raw["selection"]) is dict:
            if validated.variable_types.get(raw["selection"]["name"]) != "int":
                _reject(f"$.steps[{index}].selection", "language selection variable must be int")
    return ValidatedIR(canonical, canonical_bytes(canonical), validated.variable_types, validated.checkpoint_variables)
