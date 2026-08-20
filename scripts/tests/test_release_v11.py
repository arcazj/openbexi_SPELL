from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts import release_v11 as release
from scripts.validate_release_evidence_v11 import (
    tag_message,
    validate_qualification,
)


def _passing_gates() -> dict[str, dict]:
    gates: dict[str, dict] = {}
    for gate_id, expected in release.EXPECTED_GATES.items():
        tests = expected.get("tests", expected.get("minimum_tests", 8))
        skipped = expected["skipped"]
        gates[gate_id] = {
            "tests": tests,
            "passed": tests - skipped,
            "failures": 0,
            "errors": 0,
            "skipped": skipped,
            "duration_seconds": 1.0,
        }
    return gates


def test_repository_policy_and_pinned_evidence_validate() -> None:
    result = release.validate_repository(release.ROOT)
    assert result["candidate_commit"] == "e15d3314f9b97eb43d5d5057c8f1ba614844e0e7"
    assert result["accepted_predecessor_tag"] == "v0.10.0"
    assert (
        result["accepted_predecessor_commit"]
        == "c33d1893d90f9d42c36eedd19cb83f079bf39a9f"
    )
    assert len(result["reference_hashes"]) == 8
    assert len(result["evidence_hashes"]) == 9


def test_reference_directory_is_exact_and_all_inputs_are_mandatory() -> None:
    policy = release.load_policy()
    declared = {row["path"] for row in policy["reference_inputs"]}
    actual = {
        path.relative_to(release.ROOT).as_posix()
        for path in (release.ROOT / "SPELL_DOCUMENTATION").rglob("*")
        if path.is_file()
    }
    assert actual == declared
    assert all(row["role"].startswith("mandatory-") for row in policy["reference_inputs"])


def test_package_inventory_includes_v11_and_excludes_legacy_or_prior_artifacts() -> None:
    names = {path.relative_to(release.ROOT).as_posix() for path in release.package_files()}
    assert "backend/ir_v10.py" in names
    assert "backend/ir_v11.py" in names
    assert "backend/telecommand_runtime_v11.py" in names
    assert "contracts/v11/telecommand_catalog.json" in names
    assert "contracts/v11/telecommand_execution.json" in names
    assert "procedures/language_reference_244.spell.py" in names
    assert any(
        name.startswith("artifacts/v0.11/browser-e2e/results/")
        and name.endswith("-evidence.json")
        for name in names
    )
    assert not any(name.startswith("SPELL_DOCUMENTATION/") for name in names)
    assert not any(name.startswith("tools/") for name in names)
    assert not any(name.startswith("artifacts/v0.10/") for name in names)
    assert not any("v12" in name.casefold() for name in names)
    assert not any(Path(name).suffix.casefold() in {".pdf", ".zip", ".png"} for name in names)


def test_source_fingerprint_is_stable_and_excludes_generated_release_outputs() -> None:
    first = release.source_fingerprint()
    second = release.source_fingerprint()
    assert first == second
    assert len(first) == 64
    names = {path.relative_to(release.ROOT).as_posix() for path in release.source_files()}
    assert release.QUALIFICATION_PATH.as_posix() not in names
    assert release.RELEASE_MANIFEST_PATH.as_posix() not in names
    assert release.PACKAGE_PATH.as_posix() not in names


def test_archive_construction_is_byte_reproducible() -> None:
    paths = release.package_files()
    first = release.archive_bytes(release.ROOT, paths)
    second = release.archive_bytes(release.ROOT, paths)
    assert first == second
    assert first.startswith(b"\x1f\x8b")


def test_parse_junit_counts_pass_fail_error_and_skip(tmp_path: Path) -> None:
    path = tmp_path / "capture.xml"
    path.write_text(
        "<testsuite><testcase name=\"pass\" time=\"1.25\"/>"
        "<testcase name=\"skip\"><skipped/></testcase>"
        "<testcase name=\"fail\"><failure/></testcase>"
        "<testcase name=\"error\"><error/></testcase></testsuite>",
        encoding="utf-8",
    )
    assert release.parse_junit(path) == {
        "tests": 4,
        "passed": 1,
        "failures": 1,
        "errors": 1,
        "skipped": 1,
        "duration_seconds": 1.25,
    }


def test_gate_inventory_accepts_only_exact_resolved_results() -> None:
    gates = _passing_gates()
    release.validate_gate_results(gates)

    mutation = copy.deepcopy(gates)
    mutation["backend_postgresql"]["passed"] -= 1
    mutation["backend_postgresql"]["failures"] = 1
    with pytest.raises(release.ReleaseV11Error, match="gate failed"):
        release.validate_gate_results(mutation)


def test_gate_inventory_rejects_missing_and_extra_gate_ids() -> None:
    gates = _passing_gates()
    gates.pop("documentation")
    with pytest.raises(release.ReleaseV11Error, match="inventory differs"):
        release.validate_gate_results(gates)

    gates = _passing_gates()
    gates["unapproved"] = copy.deepcopy(gates["documentation"])
    with pytest.raises(release.ReleaseV11Error, match="inventory differs"):
        release.validate_gate_results(gates)


def test_gate_inventory_rejects_changed_counts_or_unresolved_skips() -> None:
    gates = _passing_gates()
    gates["backend_full"]["tests"] += 1
    gates["backend_full"]["passed"] += 1
    with pytest.raises(release.ReleaseV11Error, match="test count differs"):
        release.validate_gate_results(gates)

    gates = _passing_gates()
    gates["backend_compose"]["skipped"] = 1
    gates["backend_compose"]["passed"] -= 1
    with pytest.raises(release.ReleaseV11Error, match="skip count differs"):
        release.validate_gate_results(gates)


def test_release_tag_message_is_exact_and_contains_required_nonclaims() -> None:
    manifest = {
        "qualified_commit": "a" * 40,
        "source_fingerprint_sha256": "b" * 64,
        "package_sha256": "c" * 64,
    }
    message = tag_message(manifest)
    assert message.startswith("SPELL v0.11.0\n\nDecision: ACCEPTED\n")
    assert "Accepted exceptions: None\n" in message
    assert "Operational authorization: None\n" in message
    assert "Cryptographic signature: Not claimed\n" in message
    assert message.count("Package SHA-256:") == 1


def test_release_policy_rejects_unknown_top_level_fields(tmp_path: Path) -> None:
    policy = release.load_policy()
    policy["unapproved"] = True
    destination = tmp_path / release.POLICY_PATH
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(release.ReleaseV11Error, match="fields differ"):
        release.load_policy(tmp_path)


def test_qualification_validation_is_positive_or_fails_closed_before_publication() -> None:
    if not (release.ROOT / release.QUALIFICATION_PATH).is_file():
        with pytest.raises(release.ReleaseV11Error, match="qualification"):
            validate_qualification(release.ROOT)
        return
    manifest = validate_qualification(release.ROOT)
    assert manifest["decision"]["gate"] == "PASS"
