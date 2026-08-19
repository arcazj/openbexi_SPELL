"""Closed, data-only procedure IR additions for v0.7 observations.

The module deliberately keeps procedure workers unaware of driver, repository,
or condition-service implementations.  A worker can only emit a canonical
request and consume a canonical, typed result.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from typing import Any, Mapping, Protocol

from .condition_engine import ConditionContractError, ConditionPlan
from .ir_v03 import ValidatedIR
from .ir_v06 import (
    V06_STEP_TARGET_FIELDS,
    V06ValidationError,
    reject_secret_material,
    validate_ir_v06,
)


IR_VERSION = "0.7"
REQUEST_SCHEMA_VERSION = "spell.v07.observation-request/1"
RESULT_SCHEMA_VERSION = "spell.v07.observation-result/1"

MAX_GET_TM_TIMEOUT_SECONDS = 3_600
MAX_VERIFY_DELAY_SECONDS = 86_400
MAX_VERIFY_TIMEOUT_SECONDS = 604_800
MAX_VERIFY_RETRY_COUNT = 1_000
MAX_VERIFY_RETRY_INTERVAL_SECONDS = 86_400
MAX_WAITFOR_SECONDS = 604_800
MAX_WAITFOR_TIMEOUT_SECONDS = 604_800
MAX_RESULT_BYTES = 1_000_000

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_OPERATION_BY_STEP = {
    "get_tm": "GET_TM",
    "verify": "VERIFY",
    "wait_for": "WAIT_FOR",
}
_GET_TM_OUTCOMES = frozenset(
    {
        "OK",
        "NOT_FOUND",
        "NOT_AVAILABLE",
        "DEADLINE_EXCEEDED",
        "CANCELLED",
        "GAP",
        "STALE_GENERATION",
        "CLOCK_UNCERTAIN",
        "CONTRACT_MISMATCH",
        "INTERNAL",
    }
)
_VERIFY_OUTCOMES = frozenset(
    {"TRUE", "FALSE", "INDETERMINATE", "TIMED_OUT", "CANCELLED", "REJECTED"}
)
_WAITFOR_OUTCOMES = frozenset({"SATISFIED", "TIMED_OUT", "CANCELLED", "FAILED"})
_BASE_STEP_FIELDS = frozenset(
    {"index", "type", "line", "column", "guard", *V06_STEP_TARGET_FIELDS}
)
_REQUEST_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:v0.7:observation-request"
)


class V07ValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class ObservationRuntime(Protocol):
    """Minimal injectable backend broker used by :class:`Supervisor`."""

    def resolve(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ObservationAnchorProvider(Protocol):
    """Atomic repository cursor capture used before a GET_TM NEXT request."""

    def telemetry_anchor(self, context_id: str, item_id: str) -> Mapping[str, Any]: ...


def _reject(code: str, path: str, message: str) -> None:
    raise V07ValidationError(code, path, message)


def _exact_keys(
    value: Mapping[str, Any],
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str],
    path: str,
) -> None:
    keys = set(value)
    missing = set(required) - keys
    extra = keys - set(required) - set(optional)
    if missing:
        _reject("IR_VALIDATION_FAILED", path, f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        _reject("IR_VALIDATION_FAILED", path, f"unknown fields: {', '.join(sorted(extra))}")


def _json_detach(value: Any, path: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(encoded) > MAX_RESULT_BYTES:
            _reject("BOUND_EXCEEDED", path, "serialized value exceeds the accepted byte limit")
        return json.loads(encoded.decode("ascii"))
    except V07ValidationError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise V07ValidationError(
            "IR_VALIDATION_FAILED", path, "value must be finite JSON data"
        ) from exc


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject("IR_VALIDATION_FAILED", path, "must be a bounded ASCII identifier")
    return value


def _duration(
    value: Any,
    path: str,
    *,
    maximum: float,
    positive: bool = False,
) -> int | float:
    if type(value) not in {int, float} or not math.isfinite(value):
        _reject("IR_VALIDATION_FAILED", path, "must be a finite numeric duration")
    minimum = 0 < value if positive else 0 <= value
    if not minimum or value > maximum:
        qualifier = "greater than zero and" if positive else "nonnegative and"
        _reject(
            "IR_VALIDATION_FAILED",
            path,
            f"must be {qualifier} no greater than {maximum:g} seconds",
        )
    return value


def _canonical_rfc3339(value: Any, path: str) -> str:
    if type(value) is not str or _RFC3339.fullmatch(value) is None:
        _reject("IR_VALIDATION_FAILED", path, "must be an RFC 3339 timestamp with an offset")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise V07ValidationError(
            "IR_VALIDATION_FAILED", path, "must be a valid RFC 3339 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject("IR_VALIDATION_FAILED", path, "must include an explicit UTC offset")
    fraction = re.search(r"\.(\d+)(?=Z|[+-]\d{2}:\d{2}\Z)", value)
    if fraction and len(fraction.group(1)) > 6 and any(
        digit != "0" for digit in fraction.group(1)[6:]
    ):
        parsed += timedelta(microseconds=1)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_condition(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        _reject("CONDITION_PLAN_INVALID", path, "condition must be a literal object")
    try:
        return ConditionPlan.from_dict(value).as_dict()
    except ConditionContractError as exc:
        raise V07ValidationError(
            "CONDITION_PLAN_INVALID", f"{path}.{exc.path}", exc.message
        ) from exc


def _projection_base(step: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in step.items()
        if key in _BASE_STEP_FIELDS and key != "type"
    }


def _target_projection(step: Mapping[str, Any]) -> dict[str, Any]:
    projected = _projection_base(step)
    target = {"expr": "variable", "name": step["target"]}
    if step["type"] == "verify" or step.get("scalar_type") == "str":
        projected.update(type="log", message=target, level="info")
    else:
        projected.update(type="telemetry", channel="v07.target.probe", value=target)
    return projected


def _wait_projection(step: Mapping[str, Any]) -> dict[str, Any]:
    projected = _projection_base(step)
    projected.update(type="wait", seconds=0)
    return projected


def _validate_get_tm(step: dict[str, Any], path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_keys(
        step,
        _BASE_STEP_FIELDS - {"guard"}
        | {"item_id", "target", "scalar_type", "field", "mode", "timeout_seconds"},
        {"guard"},
        path,
    )
    step["item_id"] = _identifier(step["item_id"], f"{path}.item_id")
    scalar_type = step.get("scalar_type")
    if scalar_type not in {"float", "int", "bool", "str"}:
        _reject("IR_VALIDATION_FAILED", f"{path}.scalar_type", "unsupported scalar type")
    if step.get("field") not in {"ENGINEERING", "RAW"}:
        _reject("IR_VALIDATION_FAILED", f"{path}.field", "field must be ENGINEERING or RAW")
    if step.get("mode") not in {"CURRENT", "NEXT"}:
        _reject("IR_VALIDATION_FAILED", f"{path}.mode", "mode must be CURRENT or NEXT")
    step["timeout_seconds"] = _duration(
        step.get("timeout_seconds"),
        f"{path}.timeout_seconds",
        maximum=MAX_GET_TM_TIMEOUT_SECONDS,
        positive=True,
    )
    return step, _target_projection(step)


def _validate_verify(step: dict[str, Any], path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_keys(
        step,
        _BASE_STEP_FIELDS - {"guard"}
        | {
            "condition",
            "target",
            "delay_seconds",
            "timeout_seconds",
            "retry_count",
            "retry_interval_seconds",
        },
        {"guard"},
        path,
    )
    step["condition"] = _canonical_condition(step.get("condition"), f"{path}.condition")
    step["delay_seconds"] = _duration(
        step.get("delay_seconds"),
        f"{path}.delay_seconds",
        maximum=MAX_VERIFY_DELAY_SECONDS,
    )
    step["timeout_seconds"] = _duration(
        step.get("timeout_seconds"),
        f"{path}.timeout_seconds",
        maximum=MAX_VERIFY_TIMEOUT_SECONDS,
        positive=True,
    )
    if step["delay_seconds"] > step["timeout_seconds"]:
        _reject(
            "IR_VALIDATION_FAILED",
            f"{path}.delay_seconds",
            "delay cannot exceed the total timeout",
        )
    if type(step.get("retry_count")) is not int or not 0 <= step["retry_count"] <= MAX_VERIFY_RETRY_COUNT:
        _reject("IR_VALIDATION_FAILED", f"{path}.retry_count", "retry count is outside bounds")
    step["retry_interval_seconds"] = _duration(
        step.get("retry_interval_seconds"),
        f"{path}.retry_interval_seconds",
        maximum=MAX_VERIFY_RETRY_INTERVAL_SECONDS,
    )
    return step, _target_projection(step)


def _validate_wait_for(step: dict[str, Any], path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    target_fields = {"seconds", "at", "condition"} & set(step)
    if len(target_fields) != 1:
        _reject(
            "IR_VALIDATION_FAILED",
            path,
            "WaitFor requires exactly one of seconds, at, or condition",
        )
    required = (_BASE_STEP_FIELDS - {"guard"}) | target_fields
    optional = {"guard"}
    if "condition" in target_fields:
        required |= {"timeout_seconds"}
    _exact_keys(step, required, optional, path)
    if "seconds" in step:
        step["seconds"] = _duration(
            step["seconds"], f"{path}.seconds", maximum=MAX_WAITFOR_SECONDS
        )
    elif "at" in step:
        step["at"] = _canonical_rfc3339(step["at"], f"{path}.at")
    else:
        step["condition"] = _canonical_condition(step["condition"], f"{path}.condition")
        step["timeout_seconds"] = _duration(
            step["timeout_seconds"],
            f"{path}.timeout_seconds",
            maximum=MAX_WAITFOR_TIMEOUT_SECONDS,
            positive=True,
        )
    return step, _wait_projection(step)


def validate_ir_v07(
    ir_version: Any,
    steps: Any,
    *,
    start_step: Any = 0,
    resume_prompt_id: Any = None,
    resume_prompt_step: Any = None,
    checkpoint_variables: Any = None,
    expected_total_steps: Any = None,
) -> ValidatedIR:
    """Validate v0.7 while retaining every v0.6 control-flow invariant."""

    if ir_version != IR_VERSION:
        _reject("IR_VALIDATION_FAILED", "$.ir_version", "IR version must be exactly 0.7")
    if type(steps) is not list or not steps:
        _reject("IR_VALIDATION_FAILED", "$.steps", "steps must be a nonempty array")

    canonical_candidates: list[dict[str, Any] | None] = []
    projected: list[dict[str, Any]] = []
    has_v07_step = False
    for index, raw in enumerate(steps):
        path = f"$.steps[{index}]"
        if type(raw) is not dict:
            _reject("IR_VALIDATION_FAILED", path, "step must be an object")
        step = _json_detach(raw, path)
        if step.get("index") != index:
            _reject("IR_VALIDATION_FAILED", f"{path}.index", "indexes must be contiguous")
        step_type = step.get("type")
        if step_type == "get_tm":
            canonical, projection = _validate_get_tm(step, path)
        elif step_type == "verify":
            canonical, projection = _validate_verify(step, path)
        elif step_type == "wait_for":
            canonical, projection = _validate_wait_for(step, path)
        else:
            canonical, projection = None, step
        has_v07_step = has_v07_step or canonical is not None
        canonical_candidates.append(canonical)
        projected.append(projection)
    if not has_v07_step:
        _reject("IR_VALIDATION_FAILED", "$.steps", "IR 0.7 requires an observation step")

    metadata: dict[str, Any] = {}
    if resume_prompt_step is not None:
        metadata["resume_prompt_step"] = resume_prompt_step
    try:
        validated = validate_ir_v06(
            "0.6",
            projected,
            start_step=start_step,
            resume_prompt_id=resume_prompt_id,
            checkpoint_variables=checkpoint_variables,
            expected_total_steps=expected_total_steps,
            **metadata,
        )
    except V06ValidationError as exc:
        raise V07ValidationError(exc.code, exc.path, exc.message) from exc

    for index, step in enumerate(canonical_candidates):
        if step is None or step["type"] not in {"get_tm", "verify"}:
            continue
        expected_type = step["scalar_type"] if step["type"] == "get_tm" else "str"
        if validated.variable_types.get(step["target"]) != expected_type:
            _reject(
                "IR_VALIDATION_FAILED",
                f"$.steps[{index}].target",
                f"target must have exact declared type {expected_type}",
            )

    canonical = [
        candidate if candidate is not None else validated.steps[index]
        for index, candidate in enumerate(canonical_candidates)
    ]
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > 8_000_000:
        _reject("IR_VALIDATION_FAILED", "$.steps", "serialized IR exceeds accepted bytes")
    return ValidatedIR(
        canonical,
        encoded,
        validated.variable_types,
        validated.checkpoint_variables,
    )


def observation_request_id(execution_id: str, step_index: int) -> str:
    if type(execution_id) is not str or not execution_id or len(execution_id) > 200:
        _reject("OBSERVATION_REQUEST_INVALID", "$.execution_id", "execution identity is invalid")
    if type(step_index) is not int or step_index < 0:
        _reject("OBSERVATION_REQUEST_INVALID", "$.step_index", "step index is invalid")
    return str(uuid.uuid5(_REQUEST_NAMESPACE, f"{execution_id}:{step_index}"))


def observation_request_for_step(execution_id: str, step: Mapping[str, Any]) -> dict[str, Any]:
    step_type = step.get("type")
    operation = _OPERATION_BY_STEP.get(step_type)
    if operation is None or type(step.get("index")) is not int:
        _reject("OBSERVATION_REQUEST_INVALID", "$.step", "step is not an observation step")
    excluded = {
        "index",
        "type",
        "line",
        "column",
        "guard",
        "target",
        *V06_STEP_TARGET_FIELDS,
    }
    parameters = {key: value for key, value in step.items() if key not in excluded}
    request = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": observation_request_id(execution_id, step["index"]),
        "execution_id": execution_id,
        "step_index": step["index"],
        "operation": operation,
        "parameters": parameters,
    }
    reject_secret_material(request, "$.observation_request")
    return _json_detach(request, "$.observation_request")


def validate_observation_request(
    step: Mapping[str, Any], request: Any, *, execution_id: str | None = None
) -> dict[str, Any]:
    if type(request) is not dict:
        _reject("OBSERVATION_REQUEST_INVALID", "$", "request must be an object")
    canonical = _json_detach(request, "$.observation_request")
    _exact_keys(
        canonical,
        {"schema_version", "request_id", "execution_id", "step_index", "operation", "parameters"},
        set(),
        "$.observation_request",
    )
    expected = observation_request_for_step(execution_id or canonical.get("execution_id"), step)
    if canonical != expected:
        _reject(
            "OBSERVATION_REQUEST_INVALID",
            "$.observation_request",
            "request does not match the immutable execution step",
        )
    return canonical


def _canonical_decimal(value: Any, path: str, *, positive: bool = False) -> str:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        _reject("OBSERVATION_ANCHOR_INVALID", path, "must be a canonical decimal string")
    number = int(value)
    if number >= 2**64 or (positive and number == 0):
        _reject("OBSERVATION_ANCHOR_INVALID", path, "cursor is outside UINT64 bounds")
    return value


def _canonical_next_deadline(
    request: Mapping[str, Any], requested_at_unix_ns: Any, deadline_at_unix_ns: Any
) -> tuple[str, str]:
    requested = _canonical_decimal(
        requested_at_unix_ns, "$.requested_at_unix_ns"
    )
    deadline = _canonical_decimal(
        deadline_at_unix_ns, "$.deadline_at_unix_ns", positive=True
    )
    try:
        timeout_decimal = Decimal(
            str(request["parameters"]["timeout_seconds"])
        ) * Decimal(1_000_000_000)
        timeout_ns = int(timeout_decimal.to_integral_value(rounding=ROUND_CEILING))
    except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
        raise V07ValidationError(
            "OBSERVATION_REQUEST_INVALID",
            "$.parameters.timeout_seconds",
            "NEXT timeout is invalid",
        ) from exc
    if timeout_ns <= 0 or int(deadline) - int(requested) != timeout_ns:
        _reject(
            "OBSERVATION_REQUEST_INVALID",
            "$.deadline_at_unix_ns",
            "NEXT deadline does not match the immutable request timeout",
        )
    return requested, deadline


def unavailable_observation_anchor(error_code: str) -> dict[str, str]:
    if type(error_code) is not str or _ERROR_CODE.fullmatch(error_code) is None:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor.error_code", "error code is invalid")
    return {"status": "UNAVAILABLE", "error_code": error_code}


def canonicalize_observation_anchor(
    request: Mapping[str, Any], context_id: str, raw_anchor: Any
) -> dict[str, Any]:
    if (
        request.get("operation") != "GET_TM"
        or request.get("parameters", {}).get("mode") != "NEXT"
    ):
        _reject(
            "OBSERVATION_ANCHOR_INVALID",
            "$.anchor",
            "only GET_TM NEXT accepts a start anchor",
        )
    if type(context_id) is not str or not context_id or len(context_id) > 100:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor.context_id", "context is invalid")
    if type(raw_anchor) is not dict:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor", "anchor must be an object")
    anchor = _json_detach(raw_anchor, "$.anchor")
    if anchor.get("status") == "UNAVAILABLE":
        _exact_keys(anchor, {"status", "error_code"}, set(), "$.anchor")
        return unavailable_observation_anchor(anchor["error_code"])
    required = {
        "context_id",
        "context_generation_id",
        "stream_epoch",
        "projection_sequence",
        "item_id",
        "source_id",
        "source_epoch",
        "source_sequence",
        "sample_id",
    }
    _exact_keys(anchor, required, set(), "$.anchor")
    if anchor["context_id"] != context_id:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor.context_id", "context identity mismatch")
    if anchor["item_id"] != request["parameters"]["item_id"]:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor.item_id", "item identity mismatch")
    for field in (
        "context_generation_id",
        "stream_epoch",
        "item_id",
        "source_id",
        "source_epoch",
    ):
        anchor[field] = _identifier(anchor[field], f"$.anchor.{field}")
    anchor["projection_sequence"] = _canonical_decimal(
        anchor["projection_sequence"], "$.anchor.projection_sequence"
    )
    anchor["source_sequence"] = _canonical_decimal(
        anchor["source_sequence"], "$.anchor.source_sequence", positive=True
    )
    if type(anchor["sample_id"]) is not str or re.fullmatch(
        r"[0-9a-f]{64}", anchor["sample_id"]
    ) is None:
        _reject("OBSERVATION_ANCHOR_INVALID", "$.anchor.sample_id", "sample digest is invalid")
    reject_secret_material(anchor, "$.anchor")
    return anchor


def bind_observation_anchor(
    request: Mapping[str, Any],
    context_id: str,
    raw_anchor: Any,
    *,
    requested_at_unix_ns: str,
    deadline_at_unix_ns: str,
) -> dict[str, Any]:
    base = _json_detach(request, "$.observation_request")
    _exact_keys(
        base,
        {"schema_version", "request_id", "execution_id", "step_index", "operation", "parameters"},
        set(),
        "$.observation_request",
    )
    anchor = canonicalize_observation_anchor(base, context_id, raw_anchor)
    requested, deadline = _canonical_next_deadline(
        base, requested_at_unix_ns, deadline_at_unix_ns
    )
    anchored = {
        **base,
        "anchor": anchor,
        "requested_at_unix_ns": requested,
        "deadline_at_unix_ns": deadline,
    }
    digest = hashlib.sha256(
        json.dumps(
            anchored,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    return {**anchored, "request_digest": digest}


def validate_anchored_observation_request(
    step: Mapping[str, Any],
    request: Any,
    *,
    execution_id: str,
    context_id: str,
) -> dict[str, Any]:
    if type(request) is not dict:
        _reject("OBSERVATION_REQUEST_INVALID", "$", "request must be an object")
    detached = _json_detach(request, "$.observation_request")
    _exact_keys(
        detached,
        {
            "schema_version",
            "request_id",
            "execution_id",
            "step_index",
            "operation",
            "parameters",
            "anchor",
            "requested_at_unix_ns",
            "deadline_at_unix_ns",
            "request_digest",
        },
        set(),
        "$.observation_request",
    )
    base = {
        key: value
        for key, value in detached.items()
        if key
        not in {
            "anchor",
            "requested_at_unix_ns",
            "deadline_at_unix_ns",
            "request_digest",
        }
    }
    base = validate_observation_request(step, base, execution_id=execution_id)
    expected = bind_observation_anchor(
        base,
        context_id,
        detached["anchor"],
        requested_at_unix_ns=detached["requested_at_unix_ns"],
        deadline_at_unix_ns=detached["deadline_at_unix_ns"],
    )
    if detached != expected:
        _reject(
            "OBSERVATION_REQUEST_INVALID",
            "$.observation_request.request_digest",
            "anchored request digest mismatch",
        )
    return detached


def _bounded_result_value(value: Any, scalar_type: str, path: str) -> Any:
    if scalar_type == "float":
        if type(value) not in {int, float} or not math.isfinite(value):
            _reject("OBSERVATION_RESULT_INVALID", path, "value must be finite numeric data")
        return float(value)
    if scalar_type == "int":
        if type(value) is not int or not -(2**63) <= value < 2**64:
            _reject("OBSERVATION_RESULT_INVALID", path, "value must be an INT64 or UINT64")
        return value
    if scalar_type == "bool":
        if type(value) is not bool:
            _reject("OBSERVATION_RESULT_INVALID", path, "value must be Boolean")
        return value
    if scalar_type == "str":
        if type(value) is not str or len(value.encode("utf-8")) > 65_536:
            _reject("OBSERVATION_RESULT_INVALID", path, "value must be a bounded string")
        return value
    _reject("OBSERVATION_RESULT_INVALID", path, "result scalar type is unsupported")


def canonicalize_observation_result(
    request: Mapping[str, Any], raw_result: Any
) -> dict[str, Any]:
    """Attach request identity to a runtime result and enforce its typed outcome."""

    if type(raw_result) is not dict:
        _reject("OBSERVATION_RESULT_INVALID", "$.result", "result must be an object")
    detached = _json_detach(raw_result, "$.result")
    identity = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_id": request.get("request_id"),
        "execution_id": request.get("execution_id"),
        "step_index": request.get("step_index"),
        "operation": request.get("operation"),
    }
    if "request_digest" in request:
        identity["request_digest"] = request["request_digest"]
    full_identity = set(identity) <= set(detached)
    result = detached if full_identity else {**identity, **detached}
    required = set(identity) | {"outcome"}
    optional = {"value", "evidence", "error_code", "error_message", "request_digest"}
    _exact_keys(result, required, optional, "$.result")
    for key, expected in identity.items():
        if result.get(key) != expected:
            _reject("OBSERVATION_RESULT_INVALID", f"$.result.{key}", "result identity mismatch")
    if "request_digest" in result and (
        type(result["request_digest"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", result["request_digest"]) is None
    ):
        _reject("OBSERVATION_RESULT_INVALID", "$.result.request_digest", "request digest is invalid")

    operation = request.get("operation")
    outcome = result.get("outcome")
    allowed = {
        "GET_TM": _GET_TM_OUTCOMES,
        "VERIFY": _VERIFY_OUTCOMES,
        "WAIT_FOR": _WAITFOR_OUTCOMES,
    }.get(operation)
    if allowed is None or outcome not in allowed:
        _reject("OBSERVATION_RESULT_INVALID", "$.result.outcome", "typed outcome is invalid")
    if operation == "GET_TM" and outcome == "OK":
        if "value" not in result:
            _reject("OBSERVATION_RESULT_INVALID", "$.result.value", "OK requires a value")
        result["value"] = _bounded_result_value(
            result["value"], request["parameters"]["scalar_type"], "$.result.value"
        )
    elif "value" in result:
        _reject("OBSERVATION_RESULT_INVALID", "$.result.value", "outcome does not permit a value")
    if "error_code" in result and (
        type(result["error_code"]) is not str
        or _ERROR_CODE.fullmatch(result["error_code"]) is None
    ):
        _reject("OBSERVATION_RESULT_INVALID", "$.result.error_code", "error code is invalid")
    if "error_message" in result and (
        type(result["error_message"]) is not str or len(result["error_message"]) > 240
    ):
        _reject("OBSERVATION_RESULT_INVALID", "$.result.error_message", "error message is invalid")
    if "evidence" in result and type(result["evidence"]) is not dict:
        _reject("OBSERVATION_RESULT_INVALID", "$.result.evidence", "evidence must be an object")
    reject_secret_material(result, "$.observation_result")
    return _json_detach(result, "$.observation_result")


def validate_observation_result(
    request: Mapping[str, Any], result: Any
) -> dict[str, Any]:
    if type(result) is not dict or not {
        "schema_version",
        "request_id",
        "execution_id",
        "step_index",
        "operation",
    } <= set(result):
        _reject("OBSERVATION_RESULT_INVALID", "$.result", "result envelope is incomplete")
    return canonicalize_observation_result(request, result)


def unavailable_observation_result(
    request: Mapping[str, Any], error_code: str
) -> dict[str, Any]:
    outcome = {
        "GET_TM": "NOT_AVAILABLE",
        "VERIFY": "REJECTED",
        "WAIT_FOR": "FAILED",
    }[request["operation"]]
    return canonicalize_observation_result(
        request,
        {
            "outcome": outcome,
            "error_code": error_code,
            "error_message": "observation runtime could not settle the request",
        },
    )


__all__ = [
    "IR_VERSION",
    "ObservationAnchorProvider",
    "ObservationRuntime",
    "V07ValidationError",
    "bind_observation_anchor",
    "canonicalize_observation_anchor",
    "canonicalize_observation_result",
    "observation_request_for_step",
    "observation_request_id",
    "unavailable_observation_anchor",
    "unavailable_observation_result",
    "validate_anchored_observation_request",
    "validate_ir_v07",
    "validate_observation_request",
    "validate_observation_result",
]
