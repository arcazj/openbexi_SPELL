"""Bounded native SPELL 2.4.4 Prompt declarations and returned values.

Section 4.12 wins over the contradictory Appendix B timeout summary. Earlier
IR and the lowercase project prompt interface keep their existing behavior.
"""
from __future__ import annotations

import math
import re
from decimal import Decimal
from typing import Any, Mapping

from .ir_v06 import (
    PROMPT_TYPES, V06ValidationError, normalize_prompt_value, validate_prompt_declaration,
)

PROMPT_PROFILE = "spell-lrm244/0.17"
MAX_TIMEOUT_SECONDS = 604_800
PROMPT_FIELDS = frozenset({
    "prompt_profile", "prompt_type", "question", "choices", "default", "list_mode",
    "warning_delay_seconds", "response_timeout_seconds", "no_controller_grace_seconds",
})
RESPONSE_FIELDS = frozenset({"response_target", "response_target_type", "response_target_declaration"})


class NativePromptError(V06ValidationError):
    pass


def _reject(message: str, path: str = "$.prompt", code: str = "NATIVE_PROMPT_INVALID") -> None:
    raise NativePromptError(code, path, message)


def native_prompt_result_type(prompt_type: str, list_mode: str | None = None) -> str:
    return "float" if prompt_type == "NUM" else "int" if prompt_type == "LIST" and list_mode == "INDEX" else "str"


def _duration(value: Any, path: str) -> float | None:
    if value is None:
        return None
    if type(value) not in {int, float} or not 0 <= value <= MAX_TIMEOUT_SECONDS or not math.isfinite(value):
        _reject("Timeout must be finite seconds from zero through seven days", path)
    return float(value) if value else None


def normalize_native_prompt_response(step: Mapping[str, Any], response: Any) -> Any:
    """Return the canonical durable wire value; NUM remains decimal text."""
    prompt_type = step["prompt_type"]
    if type(prompt_type) is not str or prompt_type not in PROMPT_TYPES:
        _reject("Native prompt type is invalid")
    if prompt_type == "NUM":
        if type(response) not in {str, int, float}:
            _reject("NUM requires a finite base-10 number", code="PROMPT_VALUE_INVALID")
        text = str(response)
        if len(text) > 128 or (type(response) is str and re.fullmatch(r"[+-]?(?:\d+(?:\.\d+)?|\.\d+)", text) is None):
            _reject("NUM requires bounded base-10 data", code="PROMPT_VALUE_INVALID")
        try:
            number = float(text)
            if not math.isfinite(number) or (number == 0 and Decimal(text) != 0):
                raise ValueError
        except (ValueError, OverflowError):
            _reject("NUM is outside the finite float result profile", code="PROMPT_VALUE_INVALID")
    value = normalize_prompt_value(prompt_type, response,
                                   choices=step.get("choices", ()), list_mode=step.get("list_mode"))
    if prompt_type == "NUM" and len(value) > 128:
        _reject("NUM canonical decimal exceeds the bounded wire profile", code="PROMPT_VALUE_INVALID")
    if prompt_type != "NUM" and native_prompt_result_type(prompt_type, step.get("list_mode")) == "str" and type(value) is not str:
        _reject("Native prompt result must be a string", code="PROMPT_VALUE_INVALID")
    return value


def normalize_native_prompt_declaration(
    question: Any, *, prompt_type: str = "OK", choices: Any = None,
    default: Any = None, timeout_seconds: Any = None,
) -> dict[str, Any]:
    """Convert native source options into canonical typed IR fields.

The parser supplies one of LIST, LIST|NUM or LIST|ALPHA, never a numeric mask.
List source strings are split only for KEY mode, at their first colon.
"""
    mode = None
    if type(prompt_type) is not str:
        _reject("Native prompt type must be an exact type token")
    if prompt_type in {"LIST", "LIST|NUM", "LIST|ALPHA"}:
        mode = {"LIST": "KEY", "LIST|NUM": "INDEX", "LIST|ALPHA": "VALUE"}[prompt_type]
        prompt_type = "LIST"
        if type(choices) is not list or not choices or len(choices) > 1_000 or any(type(item) is not str for item in choices):
            _reject("Native LIST requires one through 1000 string options")
        if mode == "KEY":
            parsed = []
            for item in choices:
                key, delimiter, label = item.partition(":")
                if not delimiter:
                    _reject("LIST options require key:label strings")
                parsed.append({"key": key.strip(), "label": label})
            choices = parsed
        elif mode == "VALUE":
            choices = [{"value": item, "label": item} for item in choices]
    timeout = _duration(timeout_seconds, "$.Timeout")
    spec = validate_prompt_declaration(
        "dynamic question" if type(question) is dict else question,
        prompt_type=prompt_type, choices=choices, default=default, list_mode=mode,
    )
    fields = spec.as_ir_fields()
    fields.update(prompt_profile=PROMPT_PROFILE, question=question)
    if default is not None:
        fields["default"] = normalize_native_prompt_response(fields, default)
    if timeout is None:
        fields["default"] = None
    fields["warning_delay_seconds"] = timeout if fields["default"] is None else None
    fields["response_timeout_seconds"] = timeout if fields["default"] is not None else None
    return fields


def validate_native_prompt_step(raw: Mapping[str, Any], path: str = "$.prompt") -> dict[str, Any]:
    """Validate canonical prompt fields independently of parser normalization.

Outer instruction keys, metadata, expressions and target binding are owned by
the versioned IR validator. This function does not evaluate source expressions.
"""
    if raw.get("prompt_profile") != PROMPT_PROFILE or not PROMPT_FIELDS <= raw.keys():
        _reject("Native prompt profile or fields are missing", path)
    spec = validate_prompt_declaration(
        "dynamic question" if type(raw["question"]) is dict else raw["question"],
        prompt_type=raw["prompt_type"], choices=raw["choices"], default=raw["default"],
        list_mode=raw["list_mode"],
    )
    result = spec.as_ir_fields()
    result.update(prompt_profile=PROMPT_PROFILE, question=raw["question"])
    warning = _duration(raw["warning_delay_seconds"], path + ".warning_delay_seconds")
    deadline = _duration(raw["response_timeout_seconds"], path + ".response_timeout_seconds")
    if raw["no_controller_grace_seconds"] is not None:
        _reject("Native source cannot override controller-loss policy", path)
    if warning is not None and deadline is not None:
        _reject("Native timeout must warn or settle, not both", path)
    if (raw["default"] is not None) != (deadline is not None):
        _reject("Native default requires a positive response timeout", path)
    if raw["prompt_type"] == "LIST" and raw["list_mode"] == "VALUE" and any(type(item["value"]) is not str for item in spec.choices):
        _reject("Native LIST value options must be strings", path)
    if raw["default"] is not None:
        result["default"] = normalize_native_prompt_response(raw, raw["default"])
    result.update(warning_delay_seconds=warning, response_timeout_seconds=deadline)
    if any(result[key] != raw[key] or type(result[key]) is not type(raw[key]) for key in ("prompt_type", "choices", "default", "list_mode")):
        _reject("Native prompt fields must be canonical", path)
    return result


def native_prompt_result(step: Mapping[str, Any], settlement: Mapping[str, Any]) -> Any:
    outcome = settlement.get("outcome")
    if outcome != "ANSWERED":
        code = "PROMPT_CANCELLED" if outcome == "CANCELLED" else "PROMPT_NO_RESULT"
        _reject("Native prompt settled without an answer", code=code)
    response = normalize_native_prompt_response(step, settlement.get("response", settlement.get("value")))
    return float(response) if step["prompt_type"] == "NUM" else response
