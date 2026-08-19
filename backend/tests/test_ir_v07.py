from __future__ import annotations

import copy

import pytest

from backend.ir_v07 import (
    V07ValidationError,
    bind_observation_anchor,
    canonicalize_observation_result,
    observation_request_for_step,
    validate_anchored_observation_request,
    validate_observation_result,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


def _condition() -> dict:
    return {
        "condition_plan_id": "plan.power",
        "root": {
            "type": "PREDICATE",
            "node_id": "bus-ok",
            "operator": "GE",
            "left": {
                "kind": "TELEMETRY",
                "item_id": "TM.POWER.BUS",
                "catalog_digest": "a" * 64,
                "scalar_type": "FINITE_DOUBLE",
                "value_field": "ENGINEERING",
            },
            "right": {
                "kind": "LITERAL",
                "value": {"type": "FINITE_DOUBLE", "value": 27.5},
            },
        },
    }


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "v07.spell.py"
    )


def test_parser_selects_v07_and_canonicalizes_all_observation_steps() -> None:
    procedure = _parse(
        "reading: float = 0.0\n"
        "verification: str = ''\n"
        "GetTM('TM.POWER.BUS', target=reading, scalar_type='float', mode='NEXT')\n"
        f"Verify(condition={_condition()!r}, target=verification, delay=1, "
        "timeout=10, retry_count=2, retry_interval=0.5)\n"
        "WaitFor(at='2026-08-16T15:30:00-04:00')\n"
    )

    assert procedure.ir_version == "0.7"
    get_tm, verify, wait_for = procedure.steps[2:]
    assert get_tm["type"] == "get_tm"
    assert get_tm["field"] == "ENGINEERING"
    assert get_tm["mode"] == "NEXT"
    assert get_tm["timeout_seconds"] == 30
    assert verify["condition"]["schema_version"] == "spell.v07.condition-plan/1"
    assert len(verify["condition"]["condition_plan_digest"]) == 64
    assert verify["retry_interval_seconds"] == 0.5
    assert wait_for == {
        **{key: wait_for[key] for key in wait_for if key != "at"},
        "at": "2026-08-16T19:30:00Z",
    }


def test_absolute_wait_fraction_is_ceiled_before_runtime_dispatch() -> None:
    procedure = _parse("WaitFor(at='2026-08-16T19:30:00.123456789Z')\n")
    step = procedure.steps[0]

    assert step["at"] == "2026-08-16T19:30:00.123457Z"
    request = observation_request_for_step("execution-precision", step)
    assert request["parameters"] == {"at": "2026-08-16T19:30:00.123457Z"}


def test_legacy_parser_version_selection_is_unchanged() -> None:
    assert _parse('Log("legacy")\n').ir_version == "0.3"
    assert _parse('Prompt("typed", type="OK")\n').ir_version == "0.6"


@pytest.mark.parametrize(
    "source",
    [
        "reading: int = 0\nGetTM('TM.A', target=reading, scalar_type='float')\n",
        "reading: float = 0.0\nGetTM('TM.A', target='reading', scalar_type='float')\n",
        "WaitFor(seconds=1, at='2026-08-16T00:00:00Z')\n",
        "WaitFor(condition={'condition_plan_id': 'x', 'root': {} })\n",
        "WaitFor(at='2026-08-16 00:00:00')\n",
        "status: str = ''\nVerify(condition={'expression': '__import__(\"os\")'}, target=status)\n",
    ],
)
def test_parser_rejects_ambiguous_or_executable_observation_inputs(source: str) -> None:
    with pytest.raises(ProcedureValidationError):
        _parse(source)


def test_request_identity_and_result_types_are_closed_and_deterministic() -> None:
    procedure = _parse(
        "reading: float = 0.0\n"
        "GetTM('TM.POWER.BUS', target=reading, scalar_type='float')\n"
    )
    step = procedure.steps[1]
    first = observation_request_for_step("execution-1", step)
    second = observation_request_for_step("execution-1", copy.deepcopy(step))
    assert first == second
    assert first["parameters"] == {
        "field": "ENGINEERING",
        "item_id": "TM.POWER.BUS",
        "mode": "CURRENT",
        "scalar_type": "float",
        "timeout_seconds": 30,
    }

    result = canonicalize_observation_result(
        first,
        {"outcome": "OK", "value": 28, "evidence": {"sample_id": "a" * 64}},
    )
    assert result["value"] == 28.0
    assert validate_observation_result(first, result) == result

    with pytest.raises(V07ValidationError, match="value must be finite numeric"):
        canonicalize_observation_result(first, {"outcome": "OK", "value": "28"})
    with pytest.raises(V07ValidationError, match="unknown fields"):
        canonicalize_observation_result(
            first, {"outcome": "OK", "value": 28.0, "expression": "1 + 1"}
        )


def test_next_anchor_is_canonical_and_bound_into_the_result_identity() -> None:
    procedure = _parse(
        "reading: int = 0\n"
        "GetTM('TM.COUNT', target=reading, scalar_type='int', mode='NEXT')\n"
    )
    request = observation_request_for_step("execution-1", procedure.steps[1])
    anchored = bind_observation_anchor(
        request,
        "simulator",
        {
            "context_id": "simulator",
            "context_generation_id": "context-generation-1",
            "stream_epoch": "stream-epoch-1",
            "projection_sequence": "17",
            "item_id": "TM.COUNT",
            "source_id": "simulator",
            "source_epoch": "source-epoch-1",
            "source_sequence": "9",
            "sample_id": "c" * 64,
        },
        requested_at_unix_ns="1800000000000000000",
        deadline_at_unix_ns="1800000030000000000",
    )
    result = canonicalize_observation_result(
        anchored, {"outcome": "OK", "value": 10}
    )
    assert len(anchored["request_digest"]) == 64
    assert result["request_digest"] == anchored["request_digest"]

    changed = copy.deepcopy(anchored)
    changed["anchor"]["source_sequence"] = "10"
    with pytest.raises(V07ValidationError, match="digest mismatch"):
        validate_anchored_observation_request(
            procedure.steps[1],
            changed,
            execution_id="execution-1",
            context_id="simulator",
        )
