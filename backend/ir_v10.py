"""Bounded IR additions for the SPELL 2.4.4 reference-example runner.

IR 0.10 deliberately adds two closed operations to the existing data-only
runtime: a typed LIST prompt may store its selected index, and a selected
reference example may be evaluated by the deterministic simulator registry.
It does not execute reference-manual text or arbitrary Python.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .ir_v03 import ValidatedIR
from .ir_v06 import V06_STEP_TARGET_FIELDS, V06ValidationError, validate_ir_v06
from .ir_v07 import V07ValidationError, validate_ir_v07
from .ir_v08 import V08ValidationError, validate_ir_v08


IR_VERSION = "0.10"
MAX_IR_SERIALIZED_BYTES = 8_000_000
MIN_REFERENCE_EXAMPLE = 1
MAX_REFERENCE_EXAMPLE = 195

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_BASE_FIELDS = frozenset(
    {"index", "type", "line", "column", "guard", *V06_STEP_TARGET_FIELDS}
)


class V10ValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _reject(path: str, message: str, code: str = "IR_VALIDATION_FAILED") -> None:
    raise V10ValidationError(code, path, message)


def _canonical(value: Any, path: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(encoded) > MAX_IR_SERIALIZED_BYTES:
            _reject(path, "serialized value exceeds the accepted byte limit")
        return json.loads(encoded.decode("ascii"))
    except V10ValidationError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise V10ValidationError(
            "IR_VALIDATION_FAILED", path, "value is not canonical finite JSON"
        ) from exc


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(path, "variable target is invalid")
    return value


def _exact_keys(
    value: dict[str, Any], required: set[str], optional: set[str], path: str
) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        _reject(path, f"missing field {sorted(missing)[0]}")
    if unknown:
        _reject(path, f"unknown field {sorted(unknown)[0]}")


def validate_ir_v10(
    ir_version: Any,
    steps: Any,
    *,
    start_step: Any = 0,
    resume_prompt_id: Any = None,
    resume_prompt_step: Any = None,
    checkpoint_variables: Any = None,
    expected_total_steps: Any = None,
) -> ValidatedIR:
    """Validate and detach IR 0.10 without executing source or example code."""

    if ir_version != IR_VERSION:
        _reject("$.ir_version", "IR version must be exactly 0.10")
    if type(steps) is not list or not steps:
        _reject("$.steps", "steps must be a nonempty array")

    canonical_steps = _canonical(steps, "$.steps")
    projected: list[dict[str, Any]] = []
    special: dict[int, dict[str, Any]] = {}
    has_reference_example = False
    has_data = False
    has_v07 = False

    for index, raw in enumerate(canonical_steps):
        path = f"$.steps[{index}]"
        if type(raw) is not dict:
            _reject(path, "step must be an object")
        if raw.get("index") != index:
            _reject(f"{path}.index", "indexes must be contiguous")
        step_type = raw.get("type")
        has_data = has_data or step_type == "data_operation"
        has_v07 = has_v07 or step_type in {"get_tm", "verify", "wait_for"}

        if step_type == "prompt" and "response_target" in raw:
            if "response_target_type" not in raw:
                _reject(path, "prompt response target type is missing")
            target = _identifier(raw["response_target"], f"{path}.response_target")
            if raw["response_target_type"] != "int":
                _reject(
                    f"{path}.response_target_type",
                    "v0.10 menu prompts store an integer LIST index",
                )
            if raw.get("prompt_type") != "LIST" or raw.get("list_mode") != "INDEX":
                _reject(path, "response target requires a LIST prompt in INDEX mode")
            projected.append(
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"response_target", "response_target_type"}
                }
            )
            special[index] = {**raw, "response_target": target}
            continue

        if step_type == "reference_example":
            required = (set(_BASE_FIELDS) - {"guard"}) | {
                "example",
                "target",
                "target_type",
            }
            _exact_keys(raw, required, {"guard"}, path)
            target = _identifier(raw["target"], f"{path}.target")
            if raw["target_type"] != "str":
                _reject(f"{path}.target_type", "reference result target must be str")
            example = raw["example"]
            if type(example) is int and not (
                MIN_REFERENCE_EXAMPLE <= example <= MAX_REFERENCE_EXAMPLE
            ):
                _reject(f"{path}.example", "reference example must be 1 through 195")
            if type(example) is float or type(example) is bool:
                _reject(f"{path}.example", "reference example must evaluate to int")
            projection = {
                key: value for key, value in raw.items() if key in _BASE_FIELDS
            }
            projection.update(
                type="telemetry",
                channel="spell.v10.reference-example.selection",
                value=example,
            )
            projected.append(projection)
            special[index] = {**raw, "target": target}
            has_reference_example = True
            continue

        projected.append(raw)

    if not has_reference_example:
        _reject("$.steps", "IR 0.10 requires a reference_example step")

    metadata: dict[str, Any] = {}
    if resume_prompt_step is not None:
        metadata["resume_prompt_step"] = resume_prompt_step
    try:
        if has_data:
            validated = validate_ir_v08(
                "0.8",
                projected,
                start_step=start_step,
                resume_prompt_id=resume_prompt_id,
                checkpoint_variables=checkpoint_variables,
                expected_total_steps=expected_total_steps,
                **metadata,
            )
        elif has_v07:
            validated = validate_ir_v07(
                "0.7",
                projected,
                start_step=start_step,
                resume_prompt_id=resume_prompt_id,
                checkpoint_variables=checkpoint_variables,
                expected_total_steps=expected_total_steps,
                **metadata,
            )
        else:
            validated = validate_ir_v06(
                "0.6",
                projected,
                start_step=start_step,
                resume_prompt_id=resume_prompt_id,
                checkpoint_variables=checkpoint_variables,
                expected_total_steps=expected_total_steps,
                **metadata,
            )
    except (V06ValidationError, V07ValidationError, V08ValidationError) as exc:
        raise V10ValidationError(exc.code, exc.path, exc.message) from exc

    for index, raw in special.items():
        if raw["type"] == "prompt":
            target = raw["response_target"]
            if validated.variable_types.get(target) != "int":
                _reject(
                    f"$.steps[{index}].response_target",
                    "prompt response target must name a declared int variable",
                )
        else:
            target = raw["target"]
            if validated.variable_types.get(target) != "str":
                _reject(
                    f"$.steps[{index}].target",
                    "reference result target must name a declared str variable",
                )

    restored = [special.get(index, step) for index, step in enumerate(validated.steps)]
    encoded = json.dumps(
        restored,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > MAX_IR_SERIALIZED_BYTES:
        _reject("$.steps", "serialized IR exceeds the accepted byte limit")
    return ValidatedIR(
        restored,
        encoded,
        validated.variable_types,
        validated.checkpoint_variables,
    )


__all__ = [
    "IR_VERSION",
    "MAX_REFERENCE_EXAMPLE",
    "MIN_REFERENCE_EXAMPLE",
    "V10ValidationError",
    "validate_ir_v10",
]
