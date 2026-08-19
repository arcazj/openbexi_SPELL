"""Traceability checks for the v0.10 Language Reference example contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from contracts.v10.generate_language_reference_variant_matrix import (
    EXAMPLE_CHUNKS_SHA256,
    MULTIPLE_VARIANTS,
    RAW_EXTRACTION_SHA256,
    binding_digest as variant_binding_digest,
    build as build_variant_matrix,
    encode_contract as encode_variant_contract,
)


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "contracts" / "v10" / "language_reference_example_matrix.json"
VARIANT_MATRIX_PATH = ROOT / "contracts" / "v10" / "language_reference_variant_matrix.json"
RAW_EXAMPLES_PATH = ROOT / ".qualification" / "v010" / "lrm244-examples-raw.json"
EXAMPLE_CHUNKS_PATH = ROOT / "var" / "v010_spell_reference" / "example_chunks.txt"
INVENTORY_PATH = (
    ROOT
    / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
    / "requirements"
    / "compatibility"
    / "COMPATIBILITY_SOURCE_INVENTORY.json"
)
LEDGER_PATH = (
    ROOT
    / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
    / "requirements"
    / "compatibility"
    / "COMPATIBILITY_LEDGER.json"
)
AUTHORITY_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
FIXTURE_PROFILE = "V10-LRM244-DETERMINISTIC-SIMULATOR-1"
EXPECTED_FAMILIES = {
    "alarms.query",
    "catalog.tm_tc_lookup",
    "commanding.build",
    "commanding.send",
    "database.dictionary",
    "database.spacecraft",
    "filesystem.virtual",
    "ground.parameter",
    "limits.mutation",
    "limits.query",
    "memory.simulator",
    "procedure.child_execution",
    "procedure.control",
    "python.comments",
    "python.control_flow",
    "python.expressions",
    "python.indentation",
    "python.line_continuation",
    "python.local_functions",
    "python.procedure_import",
    "python.values_and_containers",
    "ranging.simulator",
    "resources.state",
    "shared_data.state",
    "spell.modifiers_and_recovery",
    "spell.time",
    "telemetry.acquisition",
    "telemetry.condition_composition",
    "telemetry.verification",
    "ui.display_workspace",
    "ui.messages",
    "ui.prompt",
    "wait.conditions",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {token}")
        ),
    )
    assert isinstance(value, dict)
    return value


def binding_digest(examples: list[dict[str, Any]]) -> str:
    bindings = [
        {
            "example_number": row["example_number"],
            "compatibility_artifact_id": row["compatibility_artifact_id"],
            "page": row["source"]["page"],
            "body_sha256": row["source"]["body_sha256"],
            "normalized_span_sha256": row["source"]["normalized_span_sha256"],
            "semantic_family": row["semantic_family"],
            "adaptation_id": row["adaptation"]["adaptation_id"],
            "oracle_id": row["oracle"]["oracle_id"],
        }
        for row in examples
    ]
    encoded = json.dumps(
        bindings, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def test_contract_is_bound_to_the_approved_reference_without_execution_claims() -> None:
    matrix = load(MATRIX_PATH)
    assert matrix["schema_version"] == "spell.v10.language-reference-example-matrix/1"
    assert matrix["contract_id"] == "V10-LRM244-EXAMPLE-MATRIX"
    assert matrix["release"] == "v0.10.0"
    assert matrix["status"] == "implementation_and_qualification_input"
    assert matrix["implementation_claim"] is False
    assert matrix["qualification_result_claim"] == "NOT_RECORDED_IN_THIS_CONTRACT"
    assert matrix["authority"] == {
        "source_code": "LRM244",
        "title": "SPELL - Language Reference - 2.4.4",
        "version": "2.4.4",
        "sha256": AUTHORITY_SHA256,
        "page_count": 118,
        "reviewed_pages": ["1-118"],
        "compatibility_inventory_id": "local-v0.4-seven-source-exhaustive-disposition",
        "body_hash_scope": (
            "UTF-8 SHA-256 of the raw extracted per-example layout-text body, "
            "including its example heading"
        ),
        "normalized_span_hash_scope": (
            "UTF-8 SHA-256 of normalized pypdf-layout text from the exact example "
            "body heading to the next example or numbered-section heading on the "
            "cited page"
        ),
        "body_text_embedded": False,
    }
    assert matrix["adaptation_policy"] == {
        "fixture_profile": FIXTURE_PROFILE,
        "raw_examples_executable_claim": False,
        "source_semantics_must_be_preserved": True,
        "source_corrections_require_trace": True,
        "one_result_per_example_required": True,
        "allowed_result_states": ["PASS", "FAIL"],
        "delivery_gate": {
            "required_pass": 195,
            "allowed_fail": 0,
            "allowed_skip": 0,
            "allowed_xfail": 0,
            "allowed_unresolved": 0,
        },
    }


def test_examples_are_exactly_one_through_195_with_unique_stable_identities() -> None:
    matrix = load(MATRIX_PATH)
    examples = matrix["examples"]
    assert matrix["example_count"] == len(examples) == 195
    assert [row["example_number"] for row in examples] == list(range(1, 196))
    assert [row["compatibility_artifact_id"] for row in examples] == [
        f"CMP-LRM244-EXAMPLE-{number:03d}" for number in range(1, 196)
    ]
    assert [row["adaptation"]["adaptation_id"] for row in examples] == [
        f"V10-LRM244-EXAMPLE-{number:03d}-ADAPTATION"
        for number in range(1, 196)
    ]
    assert [row["oracle"]["oracle_id"] for row in examples] == [
        f"V10-LRM244-EXAMPLE-{number:03d}-ORACLE" for number in range(1, 196)
    ]
    assert len({row["source"]["body_sha256"] for row in examples}) == 195
    assert len({row["source"]["normalized_span_sha256"] for row in examples}) == 195
    assert matrix["example_bindings_sha256"] == binding_digest(examples)


def test_every_example_is_bound_to_the_existing_compatibility_inventory() -> None:
    matrix = load(MATRIX_PATH)
    inventory = load(INVENTORY_PATH)
    ledger = load(LEDGER_PATH)
    sources = [
        source for source in inventory["sources"] if source["source_code"] == "LRM244"
    ]
    assert len(sources) == 1
    authority = sources[0]
    assert authority["source_hash"] == matrix["authority"]["sha256"]
    assert authority["source_title"] == matrix["authority"]["title"]
    assert authority["source_version"] == matrix["authority"]["version"]
    assert authority["page_count"] == matrix["authority"]["page_count"]

    source_examples = {
        item["ArtifactId"]: item
        for item in authority["artifacts"]
        if item["Kind"] == "Example"
    }
    assert len(source_examples) == 195
    assert set(source_examples) == {
        row["compatibility_artifact_id"] for row in matrix["examples"]
    }
    ledger_examples = {
        row["ArtifactId"]: row
        for row in ledger["rows"]
        if re.fullmatch(r"CMP-LRM244-EXAMPLE-\d{3}", row["ArtifactId"])
    }
    assert set(ledger_examples) == set(source_examples)
    for row in matrix["examples"]:
        source_row = source_examples[row["compatibility_artifact_id"]]
        ledger_row = ledger_examples[row["compatibility_artifact_id"]]
        assert row["display_title"] == source_row["PublicName"]
        assert row["source"]["title"] == source_row["PublicName"]
        assert str(row["source"]["page"]) == source_row["Pages"]
        assert row["source"]["body_included"] is False
        assert re.fullmatch(r"[0-9a-f]{64}", row["source"]["body_sha256"])
        assert re.fullmatch(r"[0-9a-f]{64}", row["source"]["normalized_span_sha256"])
        assert (
            f"source-span-sha256={row['source']['normalized_span_sha256']}"
            in ledger_row["SignatureOrGrammar"]
        )


def test_every_example_has_an_explicit_adaptation_ambiguity_and_oracle() -> None:
    matrix = load(MATRIX_PATH)
    observed_families: set[str] = set()
    for row in matrix["examples"]:
        observed_families.add(row["semantic_family"])
        capabilities = row["required_capabilities"]
        assert capabilities == sorted(set(capabilities))
        assert capabilities
        assert all(re.fullmatch(r"[a-z][a-z0-9_.]*", item) for item in capabilities)

        adaptation = row["adaptation"]
        assert adaptation["disposition"] == "EXECUTABLE_SEMANTIC_ADAPTATION_REQUIRED"
        assert adaptation["fixture_profile"] == FIXTURE_PROFILE
        assert adaptation["raw_snippet_executable_claim"] is False
        actions = adaptation["normalization_actions"]
        assert actions == sorted(set(actions))
        assert "BIND_DETERMINISTIC_FIXTURES" in actions
        assert "WRAP_WITH_SEMANTIC_ASSERTIONS" in actions

        ambiguity = row["ambiguity"]
        codes = ambiguity["codes"]
        assert codes == sorted(set(codes))
        assert ambiguity["present"] is bool(codes)
        assert ambiguity["resolution"].strip()

        oracle = row["oracle"]
        assert re.fullmatch(r"[a-z][a-z0-9_]*", oracle["mode"])
        effects = oracle["expected_effects"]
        assert effects == sorted(set(effects))
        assert effects
        assert all(re.fullmatch(r"[A-Z][A-Z0-9_]*", item) for item in effects)
        assert oracle["required_assertion_count"] == len(effects)
        assert oracle["success_criteria"].strip()
        assert not re.search(
            r"\b(?:TODO|TBD|UNRESOLVED|XFAIL)\b", oracle["success_criteria"]
        )

    assert observed_families == EXPECTED_FAMILIES


def test_known_ambiguous_and_negative_source_examples_are_not_overclaimed() -> None:
    examples = {
        row["example_number"]: row for row in load(MATRIX_PATH)["examples"]
    }
    assert examples[24]["ambiguity"]["codes"] == ["LEGACY_PYTHON_SYNTAX"]
    assert examples[41]["ambiguity"]["codes"] == [
        "ILLUSTRATIVE_OUTPUT_MIXED_WITH_CODE",
        "OUTPUT_OR_DATA_ONLY",
    ]
    assert examples[52]["ambiguity"]["codes"] == ["NEGATIVE_DEMONSTRATION"]
    assert "NEGATIVE_LITERAL_SEMANTICS_ASSERTED" in examples[52]["oracle"][
        "expected_effects"
    ]
    assert "TERMINAL_OPERATIONS_COLOCATED" in examples[131]["ambiguity"]["codes"]
    assert "TITLE_BODY_MISMATCH" in examples[163]["ambiguity"]["codes"]
    assert "SOURCE_SYNTAX_ANOMALY" in examples[191]["ambiguity"]["codes"]
    assert examples[195]["semantic_family"] == "catalog.tm_tc_lookup"
    assert examples[195]["source"]["normalized_span_sha256"] == (
        "365590805279816ca592055bb5ff7ae16a0c62341af1a66ca7a0bb618d06a498"
    )
    assert examples[195]["required_capabilities"] == [
        "catalog.filter",
        "catalog.provenance",
        "catalog.tm_tc_lookup",
        "memory.range_filter",
        "python.dictionary",
    ]
    assert examples[195]["oracle"]["expected_effects"] == [
        "FILTER_BOUNDARIES_ASSERTED",
        "TM_TC_CATALOG_PROVENANCE_ASSERTED",
        "TM_TC_CATALOG_VALUES_EXTRACTED",
    ]


def test_variant_matrix_is_generated_from_the_pinned_source_authorities() -> None:
    published = load(VARIANT_MATRIX_PATH)
    assert published["authority"] == {
        "source_sha256": AUTHORITY_SHA256,
        "raw_extraction_sha256": RAW_EXTRACTION_SHA256,
        "example_chunks_sha256": EXAMPLE_CHUNKS_SHA256,
        "body_text_embedded": False,
    }
    assert published["execution_policy"] == {
        "raw_snippet_execution_claim": False,
        "semantic_adaptation_required": True,
        "passed_assertion_per_variant_required": True,
        "trace_event_per_variant_required": True,
        "distinct_evidence_within_multiple_variant_examples_required": True,
    }
    if RAW_EXAMPLES_PATH.is_file() and EXAMPLE_CHUNKS_PATH.is_file():
        expected = build_variant_matrix(
            RAW_EXAMPLES_PATH, EXAMPLE_CHUNKS_PATH, MATRIX_PATH
        )
        assert VARIANT_MATRIX_PATH.read_bytes() == encode_variant_contract(expected)
        assert hashlib.sha256(RAW_EXAMPLES_PATH.read_bytes()).hexdigest() == (
            RAW_EXTRACTION_SHA256
        )
        assert hashlib.sha256(EXAMPLE_CHUNKS_PATH.read_bytes()).hexdigest() == (
            EXAMPLE_CHUNKS_SHA256
        )


def test_variant_matrix_has_195_rows_and_explicit_stable_variant_bindings() -> None:
    matrix = load(MATRIX_PATH)
    variant_matrix = load(VARIANT_MATRIX_PATH)
    rows = variant_matrix["examples"]
    source_rows = {row["example_number"]: row for row in matrix["examples"]}

    assert variant_matrix["schema_version"] == "spell.v10.language-reference-variant-matrix/1"
    assert variant_matrix["example_count"] == len(rows) == 195
    assert variant_matrix["multiple_variant_example_count"] == len(MULTIPLE_VARIANTS) == 46
    assert variant_matrix["variant_count"] == sum(row["variant_count"] for row in rows) == 257
    assert [row["example_number"] for row in rows] == list(range(1, 196))
    assert variant_matrix["variant_bindings_sha256"] == variant_binding_digest(rows)

    variant_ids: set[str] = set()
    subcase_ids: set[str] = set()
    oracle_ids: set[str] = set()
    test_ids: set[str] = set()
    multiple_numbers: set[int] = set()
    for row in rows:
        number = row["example_number"]
        source = source_rows[number]
        assert row["artifact_id"] == f"CMP-LRM244-EXAMPLE-{number:03d}"
        assert row["source"] == {
            "page": source["source"]["page"],
            "body_sha256": source["source"]["body_sha256"],
            "normalized_span_sha256": source["source"]["normalized_span_sha256"],
            "body_included": False,
        }
        assert row["adaptation_id"] == source["adaptation"]["adaptation_id"]
        assert row["example_oracle_id"] == source["oracle"]["oracle_id"]
        assert row["variant_count"] == len(row["variants"])
        is_multiple = row["classification"] == "MULTIPLE_DOCUMENTED_VARIANTS"
        if is_multiple:
            multiple_numbers.add(number)
            assert len(row["variants"]) >= 2
        else:
            assert row["classification"] == "SINGLE_DOCUMENTED_SEMANTIC_CASE"
            assert len(row["variants"]) == 1
        for ordinal, variant_row in enumerate(row["variants"], 1):
            prefix = f"V10-LRM244-EXAMPLE-{number:03d}-VARIANT-{ordinal:02d}"
            assert variant_row["variant_id"] == prefix
            assert variant_row["subcase_id"] == (
                f"V10-LRM244-EXAMPLE-{number:03d}-SUBCASE-{ordinal:02d}"
            )
            assert variant_row["adapter_id"] == f"{prefix}-ADAPTER"
            assert variant_row["oracle_id"] == f"{prefix}-ORACLE"
            assert variant_row["test_id"] == f"{prefix}-TEST"
            assert variant_row["required_assertion_id"] == (
                f"variant.example_{number:03d}.subcase_{ordinal:02d}"
            )
            assert variant_row["required_trace_operation"]
            assert variant_row["raw_snippet_executable_claim"] is False
            assert variant_row["source_anchor_occurrences"] >= 1
            assert re.fullmatch(r"[0-9a-f]{64}", variant_row["source_anchor_sha256"])
            variant_ids.add(variant_row["variant_id"])
            subcase_ids.add(variant_row["subcase_id"])
            oracle_ids.add(variant_row["oracle_id"])
            test_ids.add(variant_row["test_id"])

    assert multiple_numbers == set(MULTIPLE_VARIANTS)
    assert all(
        len(values) == variant_matrix["variant_count"]
        for values in (variant_ids, subcase_ids, oracle_ids, test_ids)
    )


def test_example_60_variant_contract_binds_both_documented_send_forms() -> None:
    example_60 = load(VARIANT_MATRIX_PATH)["examples"][59]

    assert [item["slug"] for item in example_60["variants"]] == [
        "command-name",
        "command-item",
    ]
    assert [item["classification"] for item in example_60["variants"]] == [
        "DOCUMENTED_ARGUMENT_FORM",
        "DOCUMENTED_ARGUMENT_FORM",
    ]
    assert {item["required_trace_operation"] for item in example_60["variants"]} == {
        "Send"
    }
