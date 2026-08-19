"""Execute and publish the deterministic 195-example v0.10 qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from backend.development_analysis import analyze_source
from backend.procedure_parser import ProcedureCatalog
from backend.reference_examples_v10 import (
    REFERENCE_SOURCE_SHA256,
    ReferenceExampleRegistry,
    load_reference_contract,
    load_reference_variant_contract,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "v10" / "language_reference_example_matrix.json"
VARIANT_CONTRACT = ROOT / "contracts" / "v10" / "language_reference_variant_matrix.json"
PROCEDURES = ROOT / "procedures"
RUNNER = PROCEDURES / "language_reference_244.spell.py"
DEFAULT_OUTPUT = ROOT / "artifacts" / "v0.10" / "reference-examples.json"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def encode_qualification(value: object) -> bytes:
    """Serialize published qualification evidence with deterministic LF bytes."""

    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def qualify() -> dict[str, object]:
    contract = load_reference_contract(CONTRACT)
    variant_contract = load_reference_variant_contract(
        VARIANT_CONTRACT, example_contracts=contract
    )
    catalog = ProcedureCatalog(PROCEDURES).list()
    if len(catalog) != 1 or catalog[0].id != "language_reference_244":
        raise RuntimeError("v0.10 must expose exactly the reference-example runner")
    runner = catalog[0]
    if runner.ir_version != "0.10":
        raise RuntimeError("reference-example runner did not compile to IR 0.10")
    analysis = analyze_source(
        runner.source,
        "language_reference_244.spell.py",
        workspace_revision=1,
    )
    if analysis.diagnostics or tuple(analysis.compiled) != (
        "language_reference_244.spell.py",
    ):
        raise RuntimeError("reference-example runner did not pass the language service")

    registry = ReferenceExampleRegistry(contract, variant_contract)
    results = [registry.execute(item.example_number) for item in contract]
    pass_count = sum(result.passed for result in results)
    if pass_count != 195:
        failed = [result.example_number for result in results if not result.passed]
        raise RuntimeError(f"reference examples failed: {failed}")
    expected_variant_ids = [
        variant.variant_id for row in variant_contract for variant in row.variants
    ]
    proved_variant_ids = [
        proof.variant_id for result in results for proof in result.variant_proofs
    ]
    if proved_variant_ids != expected_variant_ids:
        raise RuntimeError("reference variant proof coverage differs from the contract")
    for result in results:
        passed_assertions = {
            item.assertion_id for item in result.assertions if item.passed
        }
        trace_sequences = {item.sequence for item in result.trace}
        if any(
            proof.status != "PASS"
            or not proof.assertion_ids
            or not proof.trace_sequences
            or not set(proof.assertion_ids) <= passed_assertions
            or not set(proof.trace_sequences) <= trace_sequences
            for proof in result.variant_proofs
        ):
            raise RuntimeError(
                f"reference example {result.example_number} has incomplete variant proof evidence"
            )
        if len(result.variant_proofs) > 1:
            assertion_ids = [
                value for proof in result.variant_proofs for value in proof.assertion_ids
            ]
            trace_ids = [
                value for proof in result.variant_proofs for value in proof.trace_sequences
            ]
            if len(assertion_ids) != len(set(assertion_ids)) or len(trace_ids) != len(set(trace_ids)):
                raise RuntimeError(
                    f"reference example {result.example_number} reuses variant proof evidence"
                )
    core: dict[str, object] = {
        "schema_version": "spell.v10.reference-example-qualification/1",
        "release": "v0.10.0",
        "authority_sha256": REFERENCE_SOURCE_SHA256,
        "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
        "variant_contract_sha256": hashlib.sha256(VARIANT_CONTRACT.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
        "language_profile": "spell-lrm244-adapter/0.10",
        "ir_version": runner.ir_version,
        "execution_mode": "BOUNDED_DETERMINISTIC_SIMULATOR_ADAPTATION",
        "raw_snippet_execution_claim": False,
        "summary": {
            "total": 195,
            "passed": pass_count,
            "failed": 0,
            "skipped": 0,
            "xfailed": 0,
            "unresolved": 0,
        },
        "variant_summary": {
            "total": len(expected_variant_ids),
            "passed": len(proved_variant_ids),
            "failed": 0,
            "unproved": 0,
            "multiple_variant_examples": sum(
                len(row.variants) > 1 for row in variant_contract
            ),
        },
        "results": [result.as_dict() for result in results],
    }
    return {
        **core,
        "content_binding_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = qualify()
    encoded = encode_qualification(result)
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            raise SystemExit("v0.10 reference-example qualification is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded)
    variant_summary = result["variant_summary"]
    if not isinstance(variant_summary, dict):
        raise RuntimeError("qualification variant summary is invalid")
    print(
        "v0.10-reference-qualification=PASS "
        "total=195 passed=195 failed=0 skipped=0 xfailed=0 unresolved=0 "
        f"variants={variant_summary['total']} "
        f"variants_passed={variant_summary['passed']} "
        f"multiple_variant_examples={variant_summary['multiple_variant_examples']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
