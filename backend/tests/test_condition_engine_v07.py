from __future__ import annotations

import pytest

from backend.condition_engine import (
    ComparisonOperator,
    ConditionContractError,
    ConditionPlan,
    ConditionSnapshot,
    LiteralOperand,
    LogicalNode,
    LogicalOperator,
    PredicateNode,
    QualityFreshnessPolicy,
    SampleEvidence,
    ScalarType,
    TelemetryOperand,
    TruthValue,
    TypedScalar,
    ValueField,
    evaluate_condition,
    sample_id_for,
)


CATALOG_DIGEST = "a" * 64


def scalar(kind: ScalarType, value):
    return TypedScalar(kind, value)


def sample(
    item_id: str,
    value: TypedScalar,
    *,
    cursor: int = 9,
    suffix: str = "1",
    quality: str = "GOOD",
    validity: str = "VALID",
    freshness: str = "FRESH",
    has_gap: bool = False,
    synchronized: bool = True,
) -> SampleEvidence:
    sequence = int(suffix, 16)
    return SampleEvidence(
        sample_id=sample_id_for("simulator", "epoch-1", item_id, sequence),
        item_id=item_id,
        catalog_digest=CATALOG_DIGEST,
        source_id="simulator",
        source_epoch="epoch-1",
        source_sequence=sequence,
        snapshot_cursor=cursor,
        raw_value=value,
        engineering_value=value,
        unit="count",
        validity=validity,
        quality=quality,
        freshness=freshness,
        has_gap=has_gap,
        synchronized=synchronized,
    )


def tm(item_id: str, kind: ScalarType) -> TelemetryOperand:
    return TelemetryOperand(item_id, CATALOG_DIGEST, kind, ValueField.ENGINEERING)


def policy() -> QualityFreshnessPolicy:
    return QualityFreshnessPolicy("flight-default", "revision-1")


def test_typed_scalar_wire_round_trip_is_canonical_and_rejects_ambiguity() -> None:
    values = (
        TypedScalar(ScalarType.BOOLEAN, True),
        TypedScalar(ScalarType.INT64, -(2**63)),
        TypedScalar(ScalarType.UINT64, 2**64 - 1),
        TypedScalar(ScalarType.FINITE_DOUBLE, 1.25),
        TypedScalar(ScalarType.STRING, "MODE_A"),
        TypedScalar(ScalarType.BYTES, b"\x00\xff"),
    )
    assert tuple(TypedScalar.from_dict(value.as_dict()) for value in values) == values
    assert values[1].as_dict()["value"] == str(-(2**63))
    assert values[2].as_dict()["value"] == str(2**64 - 1)
    assert values[-1].as_dict()["value"] == "AP8="

    with pytest.raises(ConditionContractError, match="NON_CANONICAL_INTEGER"):
        TypedScalar.from_dict({"type": "INT64", "value": 1})
    with pytest.raises(ConditionContractError, match="NON_FINITE"):
        TypedScalar(ScalarType.FINITE_DOUBLE, float("nan"))
    with pytest.raises(ConditionContractError, match="UNKNOWN_FIELD"):
        TypedScalar.from_dict({"type": "INT64", "value": "1", "expression": "1+0"})


def test_plan_round_trip_binds_identity_tree_and_typed_operands() -> None:
    plan = ConditionPlan(
        "plan.power",
        PredicateNode(
            "bus-eq",
            ComparisonOperator.EQ,
            tm("TM.POWER.BUS", ScalarType.FINITE_DOUBLE),
            LiteralOperand(scalar(ScalarType.INT64, 28)),
            scalar(ScalarType.FINITE_DOUBLE, 0.25),
        ),
    )
    wire = plan.as_dict()
    restored = ConditionPlan.from_dict(wire)
    assert restored == plan
    assert restored.condition_plan_digest == plan.condition_plan_digest

    wire["root"]["operator"] = "NE"
    with pytest.raises(ConditionContractError, match="plan digest mismatch"):
        ConditionPlan.from_dict(wire)


def test_numeric_tolerance_and_tm_to_tm_use_one_atomic_snapshot() -> None:
    plan = ConditionPlan(
        "plan.tm-to-tm",
        LogicalNode(
            "root",
            LogicalOperator.AND,
            (
                PredicateNode(
                    "near",
                    ComparisonOperator.EQ,
                    tm("TM.A", ScalarType.FINITE_DOUBLE),
                    LiteralOperand(scalar(ScalarType.INT64, 10)),
                    scalar(ScalarType.FINITE_DOUBLE, 0.1),
                ),
                PredicateNode(
                    "ordered",
                    ComparisonOperator.LT,
                    tm("TM.A", ScalarType.FINITE_DOUBLE),
                    tm("TM.B", ScalarType.FINITE_DOUBLE),
                ),
            ),
        ),
    )
    snapshot = ConditionSnapshot(
        9,
        (
            sample("TM.A", scalar(ScalarType.FINITE_DOUBLE, 10.05), suffix="1"),
            sample("TM.B", scalar(ScalarType.FINITE_DOUBLE, 11.0), suffix="2"),
        ),
    )
    result = evaluate_condition(plan, snapshot, policy())
    assert result.composite_result is TruthValue.TRUE
    assert [leaf.result for leaf in result.leaf_results] == [TruthValue.TRUE, TruthValue.TRUE]
    assert result.snapshot_cursor == 9
    expected_ids = (
        sample_id_for("simulator", "epoch-1", "TM.A", 1),
        sample_id_for("simulator", "epoch-1", "TM.B", 2),
    )
    assert result.consumed_sample_ids == expected_ids
    assert result.as_dict()["leaf_results"][1]["right_typed_value_or_sample_id"]["sample_id"] == expected_ids[1]
    assert len(result.result_digest) == 64


def test_kleene_and_or_never_turn_missing_or_stale_evidence_into_false() -> None:
    missing = PredicateNode(
        "missing",
        ComparisonOperator.EQ,
        tm("TM.MISSING", ScalarType.INT64),
        LiteralOperand(scalar(ScalarType.INT64, 1)),
    )
    false_leaf = PredicateNode(
        "false",
        ComparisonOperator.GT,
        tm("TM.VALUE", ScalarType.INT64),
        LiteralOperand(scalar(ScalarType.INT64, 10)),
    )
    stale_leaf = PredicateNode(
        "stale",
        ComparisonOperator.EQ,
        tm("TM.STALE", ScalarType.INT64),
        LiteralOperand(scalar(ScalarType.INT64, 5)),
    )
    snapshot = ConditionSnapshot(
        9,
        (
            sample("TM.VALUE", scalar(ScalarType.INT64, 2), suffix="1"),
            sample("TM.STALE", scalar(ScalarType.INT64, 5), suffix="2", freshness="STALE"),
        ),
    )
    and_result = evaluate_condition(
        ConditionPlan("plan.and", LogicalNode("and", LogicalOperator.AND, (missing, false_leaf))),
        snapshot,
        policy(),
    )
    or_result = evaluate_condition(
        ConditionPlan("plan.or", LogicalNode("or", LogicalOperator.OR, (false_leaf, stale_leaf))),
        snapshot,
        policy(),
    )
    assert and_result.composite_result is TruthValue.FALSE
    assert or_result.composite_result is TruthValue.INDETERMINATE
    assert {leaf.reason for leaf in or_result.leaf_results} == {
        "COMPARISON_FALSE",
        "FRESHNESS_UNACCEPTABLE",
    }


@pytest.mark.parametrize(
    ("sample_kwargs", "expected_reason"),
    [
        ({"validity": "INVALID"}, "VALIDITY_UNACCEPTABLE"),
        ({"quality": "BAD"}, "QUALITY_UNACCEPTABLE"),
        ({"freshness": "STALE"}, "FRESHNESS_UNACCEPTABLE"),
        ({"has_gap": True}, "SOURCE_GAP"),
        ({"synchronized": False}, "UNSYNCHRONIZED"),
    ],
)
def test_sample_acceptability_matrix_is_indeterminate(sample_kwargs, expected_reason) -> None:
    plan = ConditionPlan(
        "plan.matrix",
        PredicateNode(
            "leaf",
            ComparisonOperator.EQ,
            tm("TM.VALUE", ScalarType.INT64),
            LiteralOperand(scalar(ScalarType.INT64, 1)),
        ),
    )
    result = evaluate_condition(
        plan,
        ConditionSnapshot(9, (sample("TM.VALUE", scalar(ScalarType.INT64, 1), **sample_kwargs),)),
        policy(),
    )
    assert result.composite_result is TruthValue.INDETERMINATE
    assert result.leaf_results[0].reason == expected_reason
    assert result.consumed_sample_ids == (
        sample_id_for("simulator", "epoch-1", "TM.VALUE", 1),
    )


def test_catalog_or_scalar_contract_mismatch_rejects_the_attempt() -> None:
    plan = ConditionPlan(
        "plan.mismatch",
        PredicateNode(
            "leaf",
            ComparisonOperator.EQ,
            tm("TM.VALUE", ScalarType.INT64),
            LiteralOperand(scalar(ScalarType.INT64, 1)),
        ),
    )
    wrong_catalog_sample = SampleEvidence(
        **{
            **sample("TM.VALUE", scalar(ScalarType.INT64, 1)).__dict__,
            "catalog_digest": "b" * 64,
        }
    )
    wrong_catalog = evaluate_condition(plan, ConditionSnapshot(9, (wrong_catalog_sample,)), policy())
    wrong_type = evaluate_condition(
        plan,
        ConditionSnapshot(9, (sample("TM.VALUE", scalar(ScalarType.UINT64, 1)),)),
        policy(),
    )
    assert wrong_catalog.composite_result is TruthValue.REJECTED
    assert wrong_catalog.leaf_results[0].reason == "CATALOG_MISMATCH"
    assert wrong_type.composite_result is TruthValue.REJECTED
    assert wrong_type.leaf_results[0].reason == "SAMPLE_TYPE_MISMATCH"


def test_plan_validation_is_closed_world_typed_and_bounded() -> None:
    generic_expression = {
        "condition_plan_id": "bad-plan",
        "root": {"type": "EXPRESSION", "node_id": "root", "expression": "eval('x')"},
    }
    with pytest.raises(ConditionContractError, match="INVALID_NODE_TYPE"):
        ConditionPlan.from_dict(generic_expression)
    with pytest.raises(ConditionContractError, match="UNORDERABLE_TYPE"):
        PredicateNode(
            "bad-order",
            ComparisonOperator.GT,
            LiteralOperand(scalar(ScalarType.BOOLEAN, True)),
            LiteralOperand(scalar(ScalarType.BOOLEAN, False)),
        )
    with pytest.raises(ConditionContractError, match="INVALID_TOLERANCE"):
        PredicateNode(
            "bad-tolerance",
            ComparisonOperator.EQ,
            LiteralOperand(scalar(ScalarType.INT64, 1)),
            LiteralOperand(scalar(ScalarType.INT64, 1)),
            scalar(ScalarType.INT64, -1),
        )

    leaf = {
        "type": "PREDICATE",
        "node_id": "leaf",
        "operator": "EQ",
        "left": {"kind": "LITERAL", "value": {"type": "INT64", "value": "1"}},
        "right": {"kind": "LITERAL", "value": {"type": "INT64", "value": "1"}},
    }
    root = leaf
    for depth in range(17):
        root = {"type": "AND", "node_id": f"node-{depth}", "children": [root, leaf | {"node_id": f"sibling-{depth}"}]}
    with pytest.raises(ConditionContractError, match="DEPTH_EXCEEDED"):
        ConditionPlan.from_dict({"condition_plan_id": "too-deep", "root": root})


def test_snapshot_rejects_mixed_cursor_or_duplicate_sample_evidence() -> None:
    with pytest.raises(ConditionContractError, match="sample cursor does not match"):
        ConditionSnapshot(10, (sample("TM.A", scalar(ScalarType.INT64, 1), cursor=9),))
    item = sample("TM.A", scalar(ScalarType.INT64, 1), suffix="1")
    with pytest.raises(ConditionContractError, match="DUPLICATE_SAMPLE"):
        ConditionSnapshot(9, (item, item))
