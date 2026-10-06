"""Validate native prompt evidence without confusing wire values and results."""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import math

from backend.prompt_v17 import (
    MAX_TIMEOUT_SECONDS, PROMPT_PROFILE, native_prompt_result,
    normalize_native_prompt_response,
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identifier(value):
    return type(value) is str and 0 < len(value) <= 200 and value == value.strip()


def _time(value):
    _require(type(value) is str, "native prompt timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("native prompt timestamp is invalid") from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None,
             "native prompt timestamp has no timezone")
    return parsed


def validate_native_prompt_action(prompt, action, operator_audit, *, execution_id,
                                  expected_prompt_id=None):
    """Return the typed result after checking the canonical durable settlement.

    Audit rows are exported by the execution-scoped report API without an
    execution_id field. Bind the report's execution to its prompt, then join
    the audit's aggregate, prompt and settlement identities exactly.
    """
    _require(type(prompt) is dict and type(action) is dict
             and type(operator_audit) is list, "native prompt evidence is malformed")
    _require(prompt.get("prompt_profile") == PROMPT_PROFILE
             and type(prompt.get("settings")) is dict
             and prompt["settings"].get("PROMPT_PROFILE") == PROMPT_PROFILE,
             "native prompt profile differs")
    prompt_id = prompt.get("id")
    _require(_identifier(execution_id) and prompt.get("execution_id") == execution_id
             and _identifier(prompt_id)
             and (expected_prompt_id is None or prompt_id == expected_prompt_id),
             "native prompt execution or prompt identity differs")
    kind = action.get("action")
    _require(type(kind) is str and kind in {"answer", "await_default", "abort"}, "native prompt action is invalid")
    settlement = prompt.get("settlement")
    _require(prompt.get("state") == "SETTLED" and type(settlement) is dict
             and _identifier(settlement.get("id")) and _identifier(settlement.get("actor")),
             "native prompt lacks a durable settlement")
    automatic = kind == "await_default"
    _require((settlement["actor"] == "operator-reconciler") == automatic,
             "native prompt settlement actor differs")
    outcome = "CANCELLED" if kind == "abort" else "ANSWERED"
    _require(settlement.get("outcome") == outcome, "native prompt settlement outcome differs")
    if kind == "abort":
        _require(settlement.get("value") is None, "aborted native prompt returned a value")
        result = None
    else:
        _require("value" in action, "native prompt action value is missing")
        fields = {"prompt_type": prompt.get("type"), "choices": prompt.get("options"),
                  "list_mode": prompt.get("list_mode")}
        expected_wire = normalize_native_prompt_response(fields, action.get("value"))
        wire = settlement.get("value")
        _require(_canonical(wire) == _canonical(normalize_native_prompt_response(fields, wire))
                 and _canonical(wire) == _canonical(expected_wire),
                 "native prompt canonical wire value differs")
        result = native_prompt_result(fields, settlement)
        expected_result = native_prompt_result(fields, {"outcome": "ANSWERED", "value": expected_wire})
        _require(_canonical(result) == _canonical(expected_result), "native prompt typed result differs")
        if automatic:
            _require(_canonical(prompt.get("default")) == _canonical(expected_wire),
                     "native automatic default differs")
            timeout = prompt["settings"].get("PROMPT_RESPONSE_TIMEOUT")
            _require(type(timeout) in {int, float} and 0 < timeout <= MAX_TIMEOUT_SECONDS
                     and math.isfinite(timeout), "native default lacks a positive response timeout")
            opened, deadline, settled = (_time(prompt.get("opened_at")),
                _time(prompt.get("response_deadline")), _time(settlement.get("settled_at")))
            _require(deadline - opened == timedelta(seconds=timeout) and settled >= deadline,
                     "native automatic settlement precedes or changes its deadline")
    matching = [row for row in operator_audit if type(row) is dict
        and row.get("event_type") == "prompt.settled"
        and (row.get("aggregate_id") == prompt_id or
             (type(row.get("payload")) is dict and row["payload"].get("prompt_id") == prompt_id))]
    _require(len(matching) == 1, "native prompt must have exactly one settlement audit")
    audit = matching[0]
    payload = audit.get("payload")
    _require(audit.get("aggregate_type") == "operator_prompt" and audit.get("aggregate_id") == prompt_id
             and audit.get("actor") == settlement["actor"] and type(payload) is dict
             and payload.get("prompt_id") == prompt_id
             and payload.get("settlement_id") == settlement["id"],
             "native prompt settlement audit identity differs")
    _require(payload.get("outcome") == (outcome if automatic else "ACCEPTED_SETTLEMENT")
             and (automatic or payload.get("settlement_outcome") == outcome),
             "native prompt settlement audit outcome differs")
    _require(_time(audit.get("created_at")) == _time(settlement.get("settled_at")),
             "native prompt settlement audit timestamp differs")
    return result
