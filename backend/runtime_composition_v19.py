"""Authority helpers for the bounded observation/command profile.

An accepted observation is a read-time snapshot, not a promise about telemetry
freshness when a later command executes. Legacy profiles keep their contracts.
"""
from __future__ import annotations

from typing import Any, Mapping

from .ir_v07 import canonicalize_observation_result
from .runtime_composition_v18 import telecommand_dependency_variables as v18_dependencies


OBSERVATION_STEP_TYPES = frozenset({"get_tm", "verify", "wait_for"})


def command_observation_dependencies(steps: list[dict[str, Any]], index: int) -> tuple[int, ...]:
    """Static authoritative observation inputs to this command's guard."""
    prefix = [step for step in steps[:index] if step.get("type") not in {"send_tc", "build_tc"}]
    needed = v18_dependencies([*prefix, steps[index]])
    return tuple(position for position, step in enumerate(steps[:index])
        if (step.get("type") == "wait_for" and "condition" in step) or
        (step.get("type") in {"get_tm", "verify"} and step.get("target") in needed))


def telecommand_dependency_variables(steps: Any) -> frozenset[str]:
    """Protect observation authority and scalars controlling command dispatch."""
    if type(steps) is not list:
        return frozenset()
    bindings = [
        {"type": "variable_set", "name": step["target"],
         "expression": None, "guard": step.get("guard")}
        for step in steps
        if type(step) is dict and step.get("type") in {"get_tm", "verify"}
        and type(step.get("target")) is str
    ]
    # A read/wait remains mandatory even when the following Send is unguarded.
    # Private command-shaped roots feed the inherited dependency walker only;
    # they are never compiled, persisted or executed as instructions.
    roots = [
        {"type": "send_tc", "guard": step.get("guard"),
         "observation_target": {"expr": "variable", "name": step["target"]}
         if type(step.get("target")) is str else None}
        for step in steps
        if type(step) is dict and step.get("type") in OBSERVATION_STEP_TYPES
    ]
    # In configured DSS mode a closed language selection can dispatch real
    # commands. Protect the selection and guard before the broker is entered.
    roots.extend({"type": "send_tc", "guard": step.get("guard"),
                  "language_selection": step.get("selection")}
                 for step in steps if type(step) is dict
                 and step.get("type") == "language_check")
    return v18_dependencies([*steps, *bindings, *roots])


def filter_observation_result(
    request: Mapping[str, Any], result: dict[str, Any], *,
    expected_policy_revision: str | None,
) -> dict[str, Any]:
    """Accept GetTM values only with the server's explicit read-time evidence.

The resolver, not the worker, supplies this evidence. Filtering happens before
the durable result is published; replay never reevaluates an older snapshot.
"""
    if request["operation"] != "GET_TM" or result["outcome"] != "OK":
        return result
    evidence = result.get("evidence")
    required = {"validity": "VALID", "quality": "GOOD", "freshness": "FRESH",
                "synchronization_state": "COMPLETE"}
    accepted = (
        type(evidence) is dict
        and type(expected_policy_revision) is str and bool(expected_policy_revision)
        and evidence.get("freshness_policy_revision") == expected_policy_revision
        and all(evidence.get(key) == value for key, value in required.items())
    )
    if accepted:
        return result
    return canonicalize_observation_result(request, {
        "outcome": "NOT_AVAILABLE",
        "error_code": "V19_SAMPLE_NOT_ACCEPTABLE",
        "error_message": "read-time quality or freshness evidence is not acceptable",
        **({"evidence": evidence} if type(evidence) is dict else {}),
    })


def observation_checkpoint_variables(
    step: Mapping[str, Any], variables: Mapping[str, Any], result: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive a successful checkpoint from a separately validated result.

Callers bind request and result identities first. A failed GetTM/WaitFor has no
advancing checkpoint; Verify replaces its prior outcome even on failure.
"""
    expected = dict(variables)
    kind = step.get("type")
    outcome = result.get("outcome")
    if kind == "get_tm":
        if outcome != "OK":
            raise ValueError(f"GetTM failed with {outcome}")
        value = result.get("value")
        scalar_type = step["scalar_type"]
        valid = (type(value) is bool if scalar_type == "bool" else
                 type(value) is int if scalar_type == "int" else
                 type(value) in {int, float} if scalar_type == "float" else
                 type(value) is str if scalar_type == "str" else False)
        if not valid:
            raise ValueError("GetTM result type changed")
        expected[step["target"]] = float(value) if scalar_type == "float" else value
    elif kind == "verify":
        if outcome not in {"TRUE", "FALSE", "INDETERMINATE", "TIMED_OUT", "CANCELLED", "REJECTED"}:
            raise ValueError("Verify outcome is invalid")
        expected[step["target"]] = outcome
    elif kind == "wait_for":
        if outcome != "SATISFIED":
            raise ValueError(f"WaitFor failed with {outcome}")
    else:
        raise ValueError("step is not an observation")
    return expected
