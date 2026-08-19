"""Closed IR additions for deterministic v0.11 telecommand simulation.

IR 0.11 carries catalog command construction and simulator-only send intent.
It contains data, expressions, and bounded modifiers only; no driver endpoint,
credential, callable, source text, or provider object can cross this boundary.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from typing import Any, Mapping

from .ir_v03 import ValidatedIR
from .ir_v06 import V06_STEP_TARGET_FIELDS, V06ValidationError, validate_ir_v06


IR_VERSION = "0.11"
MAX_IR_SERIALIZED_BYTES = 8_000_000
MAX_COMMAND_ARGUMENT_BYTES = 64_000
MAX_PROVIDER_DETAIL_BYTES = 16_000
MAX_GROUP_ELEMENTS = 16
MAX_INTEGER_BITS = 4_096

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_PROMPT_ID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:v0.11:ordinary-prompt"
)
_BASE_FIELDS = frozenset(
    {"index", "type", "line", "column", "guard", *V06_STEP_TARGET_FIELDS}
)
_BOOLEAN_MODIFIERS = frozenset(
    {
        "load_only",
        "confirm",
        "confirm_critical",
        "group",
        "block",
        "adjust_limits",
        "prompt_user",
    }
)
_DURATION_MODIFIERS = frozenset(
    {"timeout_seconds", "send_delay_seconds", "verification_delay_seconds", "tolerance"}
)
_TIME_MODIFIERS = frozenset({"time", "release_time"})
_MODIFIER_FIELDS = frozenset(
    {
        *_BOOLEAN_MODIFIERS,
        *_DURATION_MODIFIERS,
        *_TIME_MODIFIERS,
        "additional_info",
        "verification",
        "on_failure",
        "per_command",
    }
)


class V11ValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _reject(path: str, message: str, code: str = "IR_VALIDATION_FAILED") -> None:
    raise V11ValidationError(code, path, message)


def ordinary_prompt_id(execution_id: str, step_index: int) -> str:
    """Return the stable identity for an ordinary v0.11 Prompt invocation."""

    if type(execution_id) is not str or not execution_id:
        raise ValueError("execution identity must be non-empty text")
    if type(step_index) is not int or step_index < 0:
        raise ValueError("prompt step index must be a non-negative integer")
    return str(
        uuid.uuid5(
            _PROMPT_ID_NAMESPACE,
            f"{execution_id}:{step_index}",
        )
    )


def _expression_variable_names(value: Any) -> set[str]:
    names: set[str] = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if item.get("expr") == "variable" and type(item.get("name")) is str:
                names.add(item["name"])
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return names


def telecommand_dependency_variables(steps: Any) -> frozenset[str]:
    """Find scalar variables that can affect any v0.11 command request."""

    if type(steps) is not list:
        return frozenset()
    dependencies: set[str] = set()
    assignments: list[dict[str, Any]] = []
    for step in steps:
        if type(step) is not dict:
            continue
        if step.get("type") in {"build_tc", "send_tc"}:
            dependencies.update(_expression_variable_names(step))
        if step.get("type") == "build_tc" and type(step.get("target")) is str:
            dependencies.add(step["target"])
        if step.get("type") == "variable_set" and type(step.get("name")) is str:
            assignments.append(step)

    changed = True
    while changed:
        changed = False
        for step in assignments:
            if step["name"] not in dependencies:
                continue
            inherited = _expression_variable_names(
                {
                    "expression": step.get("expression"),
                    "guard": step.get("guard"),
                }
            )
            previous_size = len(dependencies)
            dependencies.update(inherited)
            changed = changed or len(dependencies) != previous_size
    return frozenset(dependencies)


def _canonical(value: Any, path: str, maximum: int = MAX_IR_SERIALIZED_BYTES) -> Any:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(encoded) > maximum:
            _reject(path, "canonical JSON exceeds the accepted byte limit", "BOUND_EXCEEDED")
        return json.loads(encoded.decode("ascii"))
    except V11ValidationError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise V11ValidationError(
            "IR_VALIDATION_FAILED", path, "value must be finite canonical JSON"
        ) from exc


def _bounded_numbers(value: Any, path: str) -> None:
    if type(value) is int:
        if value.bit_length() > MAX_INTEGER_BITS:
            _reject(
                path,
                f"integer exceeds the {MAX_INTEGER_BITS}-bit safety limit",
                "BOUND_EXCEEDED",
            )
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _bounded_numbers(item, f"{path}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            _bounded_numbers(item, f"{path}.{key}")


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(path, "variable name is invalid")
    return value


def _exact_keys(
    value: Mapping[str, Any],
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str],
    path: str,
) -> None:
    keys = set(value)
    missing = set(required) - keys
    unknown = keys - set(required) - set(optional)
    if missing:
        _reject(path, f"missing field {sorted(missing)[0]}")
    if unknown:
        _reject(path, f"unknown field {sorted(unknown)[0]}")


def _string_reference(value: Any, path: str) -> Any:
    if type(value) is str and value:
        return value
    if type(value) is not dict:
        _reject(path, "command reference must be a non-empty string or string variable")
    _exact_keys(value, {"expr", "name"}, set(), path)
    if value.get("expr") not in {"variable", "telecommand_item"}:
        _reject(path, "command expression must be a direct string variable")
    _identifier(value.get("name"), f"{path}.name")
    return value


def _arguments(value: Any, path: str) -> Any:
    value = _canonical(value, path, MAX_COMMAND_ARGUMENT_BYTES)
    _bounded_numbers(value, path)
    if type(value) not in {dict, list}:
        _reject(path, "command arguments must be an object or list")
    if len(value) > 64:
        _reject(path, "command arguments exceed the 64-entry limit", "BOUND_EXCEEDED")
    return value


def _time_value(value: Any, path: str) -> Any:
    if type(value) is str:
        if not value or len(value) > 80:
            _reject(path, "time string is empty or exceeds 80 characters")
        return value
    if type(value) is int and value.bit_length() > MAX_INTEGER_BITS:
        _reject(
            path,
            f"integer exceeds the {MAX_INTEGER_BITS}-bit safety limit",
            "BOUND_EXCEEDED",
        )
    try:
        valid_number = (
            type(value) in {int, float}
            and math.isfinite(float(value))
            and value >= 0
        )
    except OverflowError:
        valid_number = False
    if not valid_number:
        _reject(path, "time value must be a non-negative finite number or string")
    return value


def _modifier_conflict(value: Mapping[str, Any]) -> str | None:
    if value.get("load_only") is True and "verification" in value:
        return "LoadOnly conflicts with verification"
    if value.get("load_only") is True and "release_time" in value:
        return "LoadOnly conflicts with ReleaseTime"
    if value.get("adjust_limits") is True and "verification" not in value:
        return "AdjLimits requires verification"
    return None


def _modifiers(value: Any, path: str) -> dict[str, Any]:
    value = _canonical(value, path, MAX_PROVIDER_DETAIL_BYTES)
    _bounded_numbers(value, path)
    if type(value) is not dict:
        _reject(path, "modifiers must be an object")
    unknown = set(value) - _MODIFIER_FIELDS
    if unknown:
        _reject(path, f"unknown modifier {sorted(unknown)[0]}")
    for name in _BOOLEAN_MODIFIERS:
        if name in value and type(value[name]) is not bool:
            _reject(f"{path}.{name}", "modifier must be Boolean")
    for name in _DURATION_MODIFIERS:
        if name in value:
            item = value[name]
            try:
                valid_duration = (
                    type(item) in {int, float}
                    and math.isfinite(float(item))
                    and item >= 0
                )
            except OverflowError:
                valid_duration = False
            if not valid_duration:
                _reject(f"{path}.{name}", "modifier must be a non-negative finite number")
    for name in _TIME_MODIFIERS:
        if name in value:
            _time_value(value[name], f"{path}.{name}")
    if "on_failure" in value and value["on_failure"] not in {
        "ABORT",
        "CANCEL",
        "CONTINUE",
    }:
        _reject(f"{path}.on_failure", "unsupported failure action")
    if "additional_info" in value and type(value["additional_info"]) is not dict:
        _reject(f"{path}.additional_info", "provider detail must be an object")
    if "verification" in value:
        verification = value["verification"]
        if type(verification) is not list or not 1 <= len(verification) <= 8:
            _reject(f"{path}.verification", "verification must contain 1 through 8 conditions")
    conflict = _modifier_conflict(value)
    if conflict is not None:
        _reject(path, conflict)
    if "per_command" in value:
        per_command = value["per_command"]
        if type(per_command) is not dict or len(per_command) > MAX_GROUP_ELEMENTS:
            _reject(f"{path}.per_command", "per-command modifiers must be a bounded object")
        for key, override in per_command.items():
            if type(key) is not str or not key:
                _reject(f"{path}.per_command", "per-command key must be non-empty text")
            if type(override) is not dict:
                _reject(f"{path}.per_command.{key}", "per-command override must be an object")
            if "per_command" in override:
                _reject(f"{path}.per_command.{key}", "nested per-command modifiers are forbidden")
            _modifiers(override, f"{path}.per_command.{key}")
    if value.get("block") is True and value.get("group") is False:
        _reject(path, "block intent cannot explicitly disable grouping")
    return value


def _effective_modifier_conflict(
    global_modifiers: Mapping[str, Any],
    item_modifiers: Mapping[str, Any],
    override: Mapping[str, Any] | None = None,
) -> str | None:
    effective = {
        key: value
        for key, value in global_modifiers.items()
        if key not in {"group", "block", "per_command"}
    }
    effective.update(item_modifiers)
    if override is not None:
        effective.update(override)
    return _modifier_conflict(effective)


def _selector(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        _reject(path, "selector must be an object")
    _exact_keys(value, {"kind", "value"}, set(), path)
    kind = value.get("kind")
    selected = value.get("value")
    if kind in {"command", "sequence"}:
        selected = _string_reference(selected, f"{path}.value")
    elif kind == "group":
        if type(selected) is not list or not 1 <= len(selected) <= MAX_GROUP_ELEMENTS:
            _reject(
                f"{path}.value",
                f"group must contain 1 through {MAX_GROUP_ELEMENTS} command references",
            )
        selected = [
            _string_reference(item, f"{path}.value[{index}]")
            for index, item in enumerate(selected)
        ]
    else:
        _reject(f"{path}.kind", "selector kind must be command, sequence, or group")
    return {"kind": kind, "value": selected}


def validate_ir_v11(
    ir_version: Any,
    steps: Any,
    *,
    start_step: Any = 0,
    resume_prompt_id: Any = None,
    resume_prompt_step: Any = None,
    checkpoint_variables: Any = None,
    expected_total_steps: Any = None,
) -> ValidatedIR:
    """Validate and detach simulator-only BuildTC and Send intent."""

    if ir_version != IR_VERSION:
        _reject("$.ir_version", "IR version must be exactly 0.11")
    if type(steps) is not list or not steps:
        _reject("$.steps", "steps must be a nonempty array")

    canonical_steps = _canonical(steps, "$.steps")
    projected: list[dict[str, Any]] = []
    special: dict[int, dict[str, Any]] = {}
    has_v11 = False
    has_reference = False
    has_data = False
    has_v07 = False

    for index, raw in enumerate(canonical_steps):
        path = f"$.steps[{index}]"
        if type(raw) is not dict:
            _reject(path, "step must be an object")
        if raw.get("index") != index:
            _reject(f"{path}.index", "indexes must be contiguous")
        step_type = raw.get("type")
        has_reference = has_reference or step_type == "reference_example"
        has_data = has_data or step_type == "data_operation"
        has_v07 = has_v07 or step_type in {"get_tm", "verify", "wait_for"}

        if step_type == "build_tc":
            required = (set(_BASE_FIELDS) - {"guard"}) | {
                "command",
                "arguments",
                "modifiers",
                "target",
                "target_type",
                "target_declaration",
            }
            _exact_keys(raw, required, {"guard"}, path)
            target = _identifier(raw["target"], f"{path}.target")
            if raw["target_type"] != "str" or type(raw["target_declaration"]) is not bool:
                _reject(path, "BuildTC target metadata is invalid")
            command = _string_reference(raw["command"], f"{path}.command")
            if type(command) is not str:
                _reject(
                    f"{path}.command",
                    "BuildTC command must be a literal catalog name",
                )
            arguments = _arguments(raw["arguments"], f"{path}.arguments")
            modifiers = _modifiers(raw["modifiers"], f"{path}.modifiers")
            unsupported_controls = set(modifiers) & {"group", "block", "per_command"}
            if unsupported_controls:
                _reject(
                    f"{path}.modifiers",
                    f"BuildTC does not accept {sorted(unsupported_controls)[0]}",
                )
            projection = {key: value for key, value in raw.items() if key in _BASE_FIELDS}
            projection.update(
                type="telemetry",
                channel="spell.v11.telecommand.build",
                value=0.0,
            )
            projected.append(projection)
            special[index] = {
                **raw,
                "command": command,
                "arguments": arguments,
                "modifiers": modifiers,
                "target": target,
            }
            has_v11 = True
            continue

        if step_type == "send_tc":
            required = (set(_BASE_FIELDS) - {"guard"}) | {"selector", "arguments", "modifiers"}
            _exact_keys(raw, required, {"guard"}, path)
            selector = _selector(raw["selector"], f"{path}.selector")
            arguments = _arguments(raw["arguments"], f"{path}.arguments")
            modifiers = _modifiers(raw["modifiers"], f"{path}.modifiers")
            if selector["kind"] != "command" and arguments:
                _reject(f"{path}.arguments", "args are accepted only with a command selector")
            if "group" in modifiers and (
                modifiers["group"] is not True or selector["kind"] != "group"
            ):
                _reject(
                    f"{path}.modifiers.group",
                    "Group modifier must be True and is only valid with a group selector",
                )
            if modifiers.get("block") is True and selector["kind"] != "group":
                _reject(
                    f"{path}.modifiers.block",
                    "Block=True is only valid with a group selector",
                )
            if (
                selector["kind"] == "command"
                and type(selector["value"]) is dict
                and selector["value"].get("expr") == "telecommand_item"
                and arguments
            ):
                _reject(
                    f"{path}.arguments",
                    "args cannot accompany a prebuilt telecommand item",
                )
            projection = {key: value for key, value in raw.items() if key in _BASE_FIELDS}
            projection.update(
                type="telemetry",
                channel="spell.v11.telecommand.intent",
                value=0.0,
            )
            projected.append(projection)
            special[index] = {
                **raw,
                "selector": selector,
                "arguments": arguments,
                "modifiers": modifiers,
            }
            has_v11 = True
            continue

        projected.append(raw)

    if not has_v11:
        _reject("$.steps", "IR 0.11 requires a build_tc or send_tc step")
    if has_reference or has_data or has_v07:
        _reject(
            "$.steps",
            "IR 0.11 telecommand procedures cannot mix reference, observation, or data-service steps",
            "IR_CAPABILITY_MIX_FORBIDDEN",
        )

    telecommand_prompt_resume = False
    if resume_prompt_id is not None:
        candidate_step = start_step if resume_prompt_step is None else resume_prompt_step
        if (
            type(resume_prompt_id) is str
            and 1 <= len(resume_prompt_id) <= 64
            and type(candidate_step) is int
            and candidate_step == start_step
            and 0 <= candidate_step < len(canonical_steps)
            and candidate_step in special
            and special[candidate_step]["type"] == "send_tc"
        ):
            telecommand_prompt_resume = True
    metadata: dict[str, Any] = {}
    if resume_prompt_step is not None and not telecommand_prompt_resume:
        metadata["resume_prompt_step"] = resume_prompt_step
    try:
        validated = validate_ir_v06(
            "0.6",
            projected,
            start_step=start_step,
            resume_prompt_id=(None if telecommand_prompt_resume else resume_prompt_id),
            checkpoint_variables=checkpoint_variables,
            expected_total_steps=expected_total_steps,
            **metadata,
        )
    except V06ValidationError as exc:
        raise V11ValidationError(exc.code, exc.path, exc.message) from exc

    telecommand_item_targets = {
        raw["target"] for raw in special.values() if raw["type"] == "build_tc"
    }
    for index, raw in special.items():
        if raw["type"] == "build_tc" and validated.variable_types.get(raw["target"]) != "str":
            _reject(f"$.steps[{index}].target", "BuildTC target must resolve to a string slot")
        references: list[tuple[Any, str]] = []
        if raw["type"] == "build_tc":
            references.append((raw["command"], f"$.steps[{index}].command"))
        else:
            selector = raw["selector"]
            values = selector["value"] if selector["kind"] == "group" else [selector["value"]]
            references.extend(
                (value, f"$.steps[{index}].selector.value[{item_index}]")
                for item_index, value in enumerate(values)
            )
        for reference, path in references:
            if type(reference) is not dict:
                continue
            name = reference["name"]
            if validated.variable_types.get(name) != "str":
                _reject(
                    f"{path}.name",
                    "telecommand reference must name a declared string variable",
                    "IR_VARIABLE_REFERENCE_INVALID",
                )
            if (
                reference.get("expr") == "telecommand_item"
                and name not in telecommand_item_targets
            ):
                _reject(
                    f"{path}.name",
                    "telecommand item reference is not bound by BuildTC",
                    "IR_VARIABLE_REFERENCE_INVALID",
                )

    item_definitions: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for index, raw in special.items():
        if raw["type"] == "build_tc":
            definition = (raw["command"], raw["modifiers"])
            if raw.get("guard") is None:
                item_definitions[raw["target"]] = [definition]
            else:
                item_definitions.setdefault(raw["target"], []).append(definition)
            continue
        selector = raw["selector"]
        if selector["kind"] == "sequence":
            continue
        selected = (
            selector["value"]
            if selector["kind"] == "group"
            else [selector["value"]]
        )
        per_command = raw["modifiers"].get("per_command", {})
        for ordinal, reference in enumerate(selected):
            if (
                type(reference) is dict
                and reference.get("expr") == "telecommand_item"
            ):
                candidates = item_definitions.get(reference["name"], [])
                if not candidates:
                    _reject(
                        f"$.steps[{index}].selector.value",
                        "telecommand item is used before its BuildTC binding",
                        "IR_VARIABLE_REFERENCE_INVALID",
                    )
            elif type(reference) is str:
                candidates = [(reference, {})]
            else:
                candidates = [(None, {})]
            for command_name, item_modifiers in candidates:
                matching_keys = [
                    key
                    for key in (str(ordinal), command_name)
                    if key is not None and key in per_command
                ]
                if len(matching_keys) > 1:
                    _reject(
                        f"$.steps[{index}].modifiers.per_command",
                        "command is configured by both ordinal and name",
                    )
                override = (
                    per_command[matching_keys[0]] if matching_keys else None
                )
                conflict = _effective_modifier_conflict(
                    raw["modifiers"], item_modifiers, override
                )
                if conflict is not None:
                    _reject(
                        f"$.steps[{index}].modifiers",
                        f"effective command modifiers conflict: {conflict}",
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
        _reject("$.steps", "serialized IR exceeds the accepted byte limit", "BOUND_EXCEEDED")
    return ValidatedIR(
        restored,
        encoded,
        validated.variable_types,
        validated.checkpoint_variables,
    )


__all__ = [
    "IR_VERSION",
    "MAX_GROUP_ELEMENTS",
    "V11ValidationError",
    "validate_ir_v11",
]
