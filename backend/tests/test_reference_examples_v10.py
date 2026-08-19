from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from backend.reference_examples_v10 import (
    MAX_EXAMPLES,
    REFERENCE_CONTRACT_SHA256,
    REFERENCE_SOURCE_SHA256,
    REFERENCE_VARIANT_CONTRACT_SHA256,
    ReferenceContractError,
    ReferenceExampleError,
    ReferenceExampleRegistry,
    ReferenceExecutionError,
    default_contract_path,
    default_variant_contract_path,
    execute_reference_example,
    load_reference_contract,
    load_reference_variant_contract,
)


@pytest.fixture(scope="module")
def registry() -> ReferenceExampleRegistry:
    return ReferenceExampleRegistry.from_contract()


def test_contract_is_exactly_the_195_item_reference_matrix(
    registry: ReferenceExampleRegistry,
) -> None:
    contracts = load_reference_contract()
    variant_contracts = load_reference_variant_contract(example_contracts=contracts)

    assert registry.example_numbers == tuple(range(1, MAX_EXAMPLES + 1))
    assert len(contracts) == MAX_EXAMPLES
    assert len({case.artifact_id for case in contracts}) == MAX_EXAMPLES
    assert len({case.body_span_sha256 for case in contracts}) == MAX_EXAMPLES
    assert all(case.required_assertion_count >= 1 for case in contracts)
    assert all(case.required_capabilities for case in contracts)
    assert all(case.expected_effects for case in contracts)
    assert len(variant_contracts) == MAX_EXAMPLES
    assert sum(len(case.variants) for case in variant_contracts) == 257
    assert sum(len(case.variants) > 1 for case in variant_contracts) == 46


@pytest.mark.parametrize("example_number", range(1, MAX_EXAMPLES + 1))
def test_every_reference_example_passes_a_bounded_semantic_oracle(
    registry: ReferenceExampleRegistry, example_number: int
) -> None:
    contract = registry.contract(example_number)
    result = registry.execute(example_number)

    assert result.example_number == example_number
    assert result.artifact_id == f"CMP-LRM244-EXAMPLE-{example_number:03d}"
    assert result.semantic_family == contract.semantic_family
    assert result.handler_family == contract.handler_family
    assert result.execution_mode == "BOUNDED_ADAPTATION"
    assert result.passed, [item.as_dict() for item in result.assertions if not item.passed]
    assert result.status == "PASS"
    assert len(result.assertions) >= contract.required_assertion_count
    assert all(item.passed for item in result.assertions)
    assert not any(
        item.assertion_id.startswith("runtime.contract_assertion_floor_")
        for item in result.assertions
    )
    assert 0 < len(result.trace) <= 64
    assert tuple(item.effect_id for item in result.effect_proofs) == contract.expected_effects
    variant_contract = registry.variant_contract(example_number)
    assert tuple(item.variant_id for item in result.variant_proofs) == tuple(
        item.variant_id for item in variant_contract.variants
    )
    passed_assertions = {
        item.assertion_id for item in result.assertions if item.passed
    }
    trace_sequences = {item.sequence for item in result.trace}
    assert all(item.assertion_ids for item in result.effect_proofs)
    assert all(item.trace_sequences for item in result.effect_proofs)
    assert all(
        set(item.assertion_ids) <= passed_assertions
        and set(item.trace_sequences) <= trace_sequences
        for item in result.effect_proofs
    )
    assert all(
        item.status == "PASS" and item.assertion_ids and item.trace_sequences
        for item in result.variant_proofs
    )
    assert all(
        set(item.assertion_ids) <= passed_assertions
        and set(item.trace_sequences) <= trace_sequences
        for item in result.variant_proofs
    )
    if len(result.variant_proofs) > 1:
        assert sum(len(item.assertion_ids) for item in result.variant_proofs) == len(
            {value for item in result.variant_proofs for value in item.assertion_ids}
        )
        assert sum(len(item.trace_sequences) for item in result.variant_proofs) == len(
            {value for item in result.variant_proofs for value in item.trace_sequences}
        )
    assert len(result.evidence_digest) == 64
    assert json.loads(json.dumps(result.as_event_payload()))["passed"] is True


def test_every_example_result_is_deterministic(registry: ReferenceExampleRegistry) -> None:
    first = [registry.execute(number).evidence_digest for number in registry.example_numbers]
    second = [registry.execute(number).evidence_digest for number in registry.example_numbers]

    assert first == second
    assert len(set(first)) == MAX_EXAMPLES


def test_example_52_proves_the_documented_wrong_string_comparison(
    registry: ReferenceExampleRegistry,
) -> None:
    result = registry.execute(52)
    assertions = {item.assertion_id: item for item in result.assertions}
    diagnostics = [event for event in result.trace if event.operation == "ExpectedDiagnostic"]

    assert result.passed
    assert assertions["wrong_code.comparison_is_false"].actual is False
    assert diagnostics[0].output == "STRING_LITERAL_NOT_TELEMETRY_REFERENCE"


def test_example_60_independently_executes_command_name_and_command_item_forms(
    registry: ReferenceExampleRegistry,
) -> None:
    result = registry.execute(60)
    proofs = {item.variant_id: item for item in result.variant_proofs}
    sends = [item for item in result.trace if item.operation == "Send"]

    assert [item.inputs["source_form"] for item in sends] == [
        "command-name",
        "command-item",
    ]
    assert [item.variant_id for item in sends] == [
        "V10-LRM244-EXAMPLE-060-VARIANT-01",
        "V10-LRM244-EXAMPLE-060-VARIANT-02",
    ]
    assert proofs[sends[0].variant_id].assertion_ids == (
        "variant.example_060.subcase_01",
    )
    assert proofs[sends[1].variant_id].assertion_ids == (
        "variant.example_060.subcase_02",
    )
    assert proofs[sends[0].variant_id].trace_sequences == (sends[0].sequence,)
    assert proofs[sends[1].variant_id].trace_sequences == (sends[1].sequence,)


@pytest.mark.parametrize("example_number", [61, 62, 66, 68, 70, 74])
def test_telecommand_source_variants_have_distinct_send_evidence(
    registry: ReferenceExampleRegistry, example_number: int
) -> None:
    result = registry.execute(example_number)
    sends = [item for item in result.trace if item.operation == "Send"]

    assert len(sends) == len(result.variant_proofs) >= 2
    assert len({item.inputs["source_form"] for item in sends}) == len(sends)
    assert {item.variant_id for item in sends} == {
        item.variant_id for item in result.variant_proofs
    }
    assert all(item.output["live_dispatch"] is False for item in sends)


def test_telecommand_variant_semantics_are_not_collapsed(
    registry: ReferenceExampleRegistry,
) -> None:
    sends = {
        number: [
            item
            for item in registry.execute(number).trace
            if item.operation == "Send"
        ]
        for number in (61, 62, 66, 68, 70, 74)
    }

    assert [item.output["modifiers"]["time_tag"]["kind"] for item in sends[61]] == [
        "NOW_PLUS_DURATION",
        "ABSOLUTE_STRING",
    ]
    assert [
        item.output["modifiers"]["release_time"]["kind"] for item in sends[62]
    ] == ["NOW_PLUS_DURATION", "ABSOLUTE_STRING"]
    assert [
        item.output["modifiers"]["argument_source"] for item in sends[66]
    ] == ["TC_ITEM", "ARGS_MODIFIER"]
    assert sends[68][1].output["modifiers"]["monitoring"] == "SEQUENTIAL"
    assert [item.output["modifiers"]["group"] for item in sends[70]] == [False, True]
    assert [item.output["command_count"] for item in sends[74]] == [1, 3]
    assert {
        item.output["modifiers"]["send_delay_seconds"] for item in sends[74]
    } == {60}


def test_example_195_queries_real_bundled_tm_tc_catalog_with_negative_oracle(
    registry: ReferenceExampleRegistry,
) -> None:
    result = registry.execute(195)
    event = next(item for item in result.trace if item.operation == "TMTCLookup")
    output = event.output
    identity = output["catalog_identity"]
    tm_entry = output["tm"]["entries"][0]
    tc_entry = output["tc"]["entries"][0]

    assert result.passed
    assert output["tm"]["outcome"] == "OK"
    assert output["tc"]["outcome"] == "OK"
    assert output["negative_lookup"]["outcome"] == "NOT_FOUND"
    assert tm_entry["item_id"] == "TM.POWER.BUS_VOLTAGE"
    assert tm_entry["direction"] == "TM"
    assert tc_entry["item_id"] == "TC.SIMULATOR.RESET"
    assert tc_entry["direction"] == "TC"
    assert output["tm"]["filters"] == {
        "Name": "TM.POWER.BUS_VOLTAGE",
        "Type": "TM",
        "Source": identity["catalog_id"],
        "Begin": "TM.POWER.A",
        "End": "TM.POWER.Z",
    }
    assert output["tm"]["filters"]["Begin"] <= tm_entry["item_id"] <= output["tm"]["filters"]["End"]
    assert tm_entry["catalog_digest"] == identity["catalog_digest"]
    assert tc_entry["catalog_digest"] == identity["catalog_digest"]


def test_worker_facing_api_is_stable() -> None:
    result = execute_reference_example(195)

    assert result.passed
    assert result.summary.startswith("Example 195: PASS")
    assert result.as_event_payload()["schema_version"] == "spell.v10.reference-example-result/1"
    assert issubclass(ReferenceContractError, ReferenceExampleError)
    assert issubclass(ReferenceExecutionError, ReferenceExampleError)


@pytest.mark.parametrize("selection", [0, 196, True, "195", None])
def test_invalid_example_selection_fails_closed(
    registry: ReferenceExampleRegistry, selection: object
) -> None:
    with pytest.raises(ReferenceExecutionError, match="1..195"):
        registry.execute(selection)  # type: ignore[arg-type]


def test_contract_source_pin_fails_closed(tmp_path: Path) -> None:
    payload = json.loads(default_contract_path().read_text(encoding="utf-8"))
    assert payload["authority"]["sha256"] == REFERENCE_SOURCE_SHA256
    payload["authority"]["sha256"] = "0" * 64
    tampered = tmp_path / "tampered-contract.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferenceContractError, match="different language reference"):
        load_reference_contract(tampered)


def test_contract_content_is_bound_to_the_frozen_matrix_digest(tmp_path: Path) -> None:
    canonical = default_contract_path().read_bytes()
    assert hashlib.sha256(canonical).hexdigest() == REFERENCE_CONTRACT_SHA256
    payload = json.loads(canonical)
    payload["examples"][0]["source"]["body_sha256"] = "0" * 64
    tampered = tmp_path / "tampered-body-hash.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferenceContractError, match="frozen v0.10 matrix digest"):
        load_reference_contract(tampered)


def test_variant_contract_content_is_bound_to_the_frozen_digest(tmp_path: Path) -> None:
    canonical = default_variant_contract_path().read_bytes()
    assert hashlib.sha256(canonical).hexdigest() == REFERENCE_VARIANT_CONTRACT_SHA256
    payload = json.loads(canonical)
    payload["examples"][0]["variants"][0]["slug"] = "tampered-semantic-case"
    tampered = tmp_path / "tampered-variant-contract.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferenceContractError, match="frozen v0.10 digest"):
        load_reference_variant_contract(tampered)


def test_contract_semantic_family_and_assertion_count_are_frozen(tmp_path: Path) -> None:
    payload = json.loads(default_contract_path().read_text(encoding="utf-8"))
    payload["examples"][0]["semantic_family"] = "spell.time"
    family_tamper = tmp_path / "tampered-family.json"
    family_tamper.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ReferenceContractError, match="frozen example map"):
        load_reference_contract(family_tamper)

    payload = json.loads(default_contract_path().read_text(encoding="utf-8"))
    payload["examples"][0]["oracle"]["required_assertion_count"] = 1
    count_tamper = tmp_path / "tampered-assertion-count.json"
    count_tamper.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ReferenceContractError, match="expected effect count"):
        load_reference_contract(count_tamper)


def test_effect_coverage_cannot_be_substituted_or_padded() -> None:
    contracts = list(load_reference_contract())
    contracts[0] = replace(
        contracts[0],
        expected_effects=("TIME_VALUE_ASSERTED",),
        required_assertion_count=1,
    )

    with pytest.raises(ReferenceExecutionError, match="did not prove expected effect"):
        ReferenceExampleRegistry(contracts).execute(1)


def test_evidence_digest_binds_source_adaptation_and_oracle_identity() -> None:
    contracts = list(load_reference_contract())
    variant_contracts = load_reference_variant_contract(example_contracts=contracts)
    canonical = ReferenceExampleRegistry(contracts, variant_contracts).execute(1)
    contracts[0] = replace(
        contracts[0],
        body_span_sha256="0" * 64,
        normalized_span_sha256="1" * 64,
        adaptation_id="tampered-adaptation",
        oracle_id="tampered-oracle",
        success_criteria="tampered criteria",
    )
    tampered = ReferenceExampleRegistry(contracts, variant_contracts).execute(1)

    assert tampered.passed
    assert tampered.evidence_digest != canonical.evidence_digest


def test_variant_evidence_is_required_and_contract_digest_is_frozen() -> None:
    contracts = load_reference_contract()
    variant_contracts = list(load_reference_variant_contract(example_contracts=contracts))
    example_60 = variant_contracts[59]
    first, second = example_60.variants
    variant_contracts[59] = replace(
        example_60,
        variants=(
            replace(first, required_trace_operation="MissingSendEvidence"),
            second,
        ),
    )

    with pytest.raises(ReferenceExecutionError, match="lacks passed assertion and trace evidence"):
        ReferenceExampleRegistry(contracts, variant_contracts).execute(60)

    assert hashlib.sha256(default_variant_contract_path().read_bytes()).hexdigest() == (
        REFERENCE_VARIANT_CONTRACT_SHA256
    )


def test_contract_missing_example_fails_closed(tmp_path: Path) -> None:
    payload = json.loads(default_contract_path().read_text(encoding="utf-8"))
    payload["examples"].pop()
    payload["example_count"] = 194
    tampered = tmp_path / "missing-example.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReferenceContractError, match="exactly 195"):
        load_reference_contract(tampered)


def test_runtime_contains_no_dynamic_code_execution_or_import() -> None:
    source_path = Path(__file__).resolve().parents[1] / "reference_examples_v10.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"compile", "eval", "exec", "__import__"}
    }

    assert forbidden_calls == set()
