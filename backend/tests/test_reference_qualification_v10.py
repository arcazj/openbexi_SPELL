from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from backend.development_service import SUPPORTED_BUNDLE_IR_SCHEMA_VERSIONS
from backend.procedure_parser import ProcedureCatalog
from contracts.v10 import (
    generate_language_reference_example_matrix as contract_generator,
    generate_language_reference_variant_matrix as variant_contract_generator,
)
from contracts.v10.generate_language_reference_example_matrix import encode_contract
from scripts import generate_reference_runner_v10 as runner_generator
from scripts import qualify_reference_examples_v10 as qualification_generator
from scripts.generate_reference_runner_v10 import OUTPUT, render
from scripts.qualify_reference_examples_v10 import (
    DEFAULT_OUTPUT,
    encode_qualification,
    qualify,
)


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "contracts" / "v10" / "language_reference_example_matrix.json"
VARIANT_MATRIX = ROOT / "contracts" / "v10" / "language_reference_variant_matrix.json"


def test_generated_runner_is_current_and_is_the_only_bundled_procedure() -> None:
    assert OUTPUT.read_bytes() == render().encode("ascii")
    assert sorted(
        path.relative_to(ROOT / "procedures").as_posix()
        for path in (ROOT / "procedures").rglob("*.spell.py")
    ) == ["language_reference_244.spell.py"]

    procedures = ProcedureCatalog(ROOT / "procedures").list()
    assert [(item.id, item.ir_version) for item in procedures] == [
        ("language_reference_244", "0.10")
    ]
    assert "0.10" not in SUPPORTED_BUNDLE_IR_SCHEMA_VERSIONS

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for pattern in (
        "**/__pycache__",
        "**/__pycache__/**",
        "**/*.pyc",
        "**/*.pyo",
        "**/*.pyd",
    ):
        assert dockerignore.count(pattern) == 1


def test_generated_v10_text_artifacts_are_byte_stable_lf() -> None:
    matrix_bytes = MATRIX.read_bytes()
    variant_matrix_bytes = VARIANT_MATRIX.read_bytes()
    runner_bytes = OUTPUT.read_bytes()
    qualification_bytes = DEFAULT_OUTPUT.read_bytes()

    assert matrix_bytes == encode_contract(json.loads(matrix_bytes))
    assert variant_matrix_bytes == variant_contract_generator.encode_contract(
        json.loads(variant_matrix_bytes)
    )
    assert runner_bytes == render().encode("ascii")
    assert qualification_bytes == encode_qualification(qualify())
    for raw in (matrix_bytes, variant_matrix_bytes, runner_bytes, qualification_bytes):
        assert b"\r" not in raw
        assert raw.endswith(b"\n")


def test_contract_generator_check_rejects_crlf_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "contract.json"
    payload = {"release": "v0.10.0"}
    expected = encode_contract(payload)
    monkeypatch.setattr(contract_generator, "build", lambda *_: payload)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate-language-reference-example-matrix",
            "--raw",
            "raw.json",
            "--inventory",
            "inventory.json",
            "--ledger",
            "ledger.json",
            "--output",
            str(output),
            "--check",
        ],
    )

    output.write_bytes(expected)
    contract_generator.main()
    output.write_bytes(expected.replace(b"\n", b"\r\n"))
    with pytest.raises(SystemExit, match="contract is stale"):
        contract_generator.main()


def test_variant_contract_generator_check_rejects_crlf_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "variant-contract.json"
    payload = {"release": "v0.10.0"}
    expected = variant_contract_generator.encode_contract(payload)
    monkeypatch.setattr(variant_contract_generator, "build", lambda *_: payload)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate-language-reference-variant-matrix",
            "--raw",
            "raw.json",
            "--chunks",
            "chunks.txt",
            "--example-matrix",
            "matrix.json",
            "--output",
            str(output),
            "--check",
        ],
    )

    output.write_bytes(expected)
    variant_contract_generator.main()
    output.write_bytes(expected.replace(b"\n", b"\r\n"))
    with pytest.raises(SystemExit, match="variant contract is stale"):
        variant_contract_generator.main()


def test_runner_and_qualification_checks_reject_crlf_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_output = tmp_path / "runner.spell.py"
    runner_text = "first\nsecond\n"
    monkeypatch.setattr(runner_generator, "OUTPUT", runner_output)
    monkeypatch.setattr(runner_generator, "render", lambda: runner_text)
    monkeypatch.setattr(sys, "argv", ["generate-reference-runner", "--check"])
    runner_output.write_bytes(runner_text.encode("ascii"))
    assert runner_generator.main() == 0
    runner_output.write_bytes(runner_text.replace("\n", "\r\n").encode("ascii"))
    with pytest.raises(SystemExit, match="runner is stale"):
        runner_generator.main()

    qualification_output = tmp_path / "qualification.json"
    qualification = {
        "summary": {"total": 195, "passed": 195},
        "variant_summary": {
            "total": 257,
            "passed": 257,
            "multiple_variant_examples": 46,
        },
    }
    expected = qualification_generator.encode_qualification(qualification)
    monkeypatch.setattr(qualification_generator, "DEFAULT_OUTPUT", qualification_output)
    monkeypatch.setattr(qualification_generator, "qualify", lambda: qualification)
    monkeypatch.setattr(sys, "argv", ["qualify-reference-examples", "--check"])
    qualification_output.write_bytes(expected)
    assert qualification_generator.main() == 0
    qualification_output.write_bytes(expected.replace(b"\n", b"\r\n"))
    with pytest.raises(SystemExit, match="qualification is stale"):
        qualification_generator.main()


def test_published_reference_qualification_is_current_and_exact() -> None:
    published = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    expected = qualify()

    assert published == expected
    assert published["summary"] == {
        "total": 195,
        "passed": 195,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "unresolved": 0,
    }
    assert len(published["results"]) == 195
    assert [item["example_number"] for item in published["results"]] == list(
        range(1, 196)
    )
    assert all(item["status"] == "PASS" for item in published["results"])
    assert published["variant_summary"] == {
        "total": 257,
        "passed": 257,
        "failed": 0,
        "unproved": 0,
        "multiple_variant_examples": 46,
    }
    assert sum(len(item["variant_proofs"]) for item in published["results"]) == 257
    assert all(
        proof["status"] == "PASS"
        and proof["assertion_ids"]
        and proof["trace_sequences"]
        for item in published["results"]
        for proof in item["variant_proofs"]
    )


def test_qualification_rejects_a_result_with_missing_variant_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_registry = qualification_generator.ReferenceExampleRegistry

    class MissingProofRegistry:
        def __init__(self, contracts: object, variants: object) -> None:
            self._registry = real_registry(contracts, variants)  # type: ignore[arg-type]

        def execute(self, example_number: int) -> object:
            result = self._registry.execute(example_number)
            if example_number == 60:
                return replace(result, variant_proofs=result.variant_proofs[:-1])
            return result

    monkeypatch.setattr(
        qualification_generator, "ReferenceExampleRegistry", MissingProofRegistry
    )
    with pytest.raises(RuntimeError, match="variant proof coverage differs"):
        qualification_generator.qualify()
