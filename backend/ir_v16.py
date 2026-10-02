"""Closed, source-bound language-check selection; all earlier IR stays intact."""
from __future__ import annotations

import json
from typing import Any

from .ir_v03 import ValidatedIR
from .ir_v10 import V10ValidationError, validate_ir_v10
from .language_conformance_v16 import CASES, canonical_bytes, digest

IR_VERSION = "0.16"
CASESET_SHA256 = digest(canonical_bytes(CASES))
ALL_SELECTION = 195 + len(CASES)


class V16ValidationError(V10ValidationError):
    pass


def validate_ir_v16(ir_version: Any, steps: Any, **metadata: Any) -> ValidatedIR:
    if ir_version != IR_VERSION or type(steps) is not list or not steps:
        raise V16ValidationError("IR_VALIDATION_FAILED", "$.ir_version", "expected nonempty IR 0.16")
    try:
        encoded = canonical_bytes(steps)
        if len(encoded) > 8_000_000:
            raise ValueError("size")
        detached = json.loads(encoded)
    except (ValueError, TypeError, RecursionError) as exc:
        raise V16ValidationError("IR_VALIDATION_FAILED", "$.steps", "IR is not bounded canonical JSON") from exc
    special = {}
    for index, step in enumerate(detached):
        if type(step) is not dict or step.get("type") != "language_check":
            continue
        if step.get("cases_sha256") != CASESET_SHA256 or "selection" not in step or "example" in step:
            raise V16ValidationError("IR_VALIDATION_FAILED", f"$.steps[{index}]", "language selection identity is invalid")
        selection = step["selection"]
        variable_selection = (type(selection) is dict and set(selection) == {"expr", "name"}
                              and selection.get("expr") == "variable" and type(selection.get("name")) is str)
        if not (type(selection) is int or variable_selection):
            raise V16ValidationError("IR_VALIDATION_FAILED", f"$.steps[{index}].selection", "selection must be an int literal or variable")
        if type(selection) is int and not 0 <= selection <= ALL_SELECTION:
            raise V16ValidationError("IR_VALIDATION_FAILED", f"$.steps[{index}].selection", "selection is outside the closed registry")
        special[index] = dict(step)
        projected = dict(step)
        projected.pop("cases_sha256")
        projected.pop("selection")
        projected["type"] = "reference_example"
        # Force validation of the exact int expression without applying the old
        # example-number range to the larger, zero-based selection registry.
        projected["example"] = {"expr": "binary", "operator": "+", "left": selection, "right": 0}
        # IR expressions require literal wrappers, unlike top-level arguments.
        if type(selection) is not dict:
            projected["example"]["left"] = {"expr": "literal", "value": selection}
        projected["example"]["right"] = {"expr": "literal", "value": 0}
        detached[index] = projected
    if not special:
        raise V16ValidationError("IR_VALIDATION_FAILED", "$.steps", "IR 0.16 requires a language selection")
    validated = validate_ir_v10("0.10", detached, **metadata)
    for index, step in special.items():
        selection = step["selection"]
        if type(selection) is dict and validated.variable_types.get(selection["name"]) != "int":
            raise V16ValidationError("IR_VALIDATION_FAILED", f"$.steps[{index}].selection", "selection variable must be int")
    restored = [special.get(index, step) for index, step in enumerate(validated.steps)]
    return ValidatedIR(restored, canonical_bytes(restored), validated.variable_types, validated.checkpoint_variables)
