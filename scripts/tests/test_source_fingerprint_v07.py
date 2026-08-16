from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from scripts import source_fingerprint_v07 as fingerprint


ROOT = Path(__file__).resolve().parents[2]


def _minimal_source_tree(root: Path) -> Path:
    for relative in fingerprint.FINGERPRINT_TREES:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in fingerprint.FINGERPRINT_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"fixture:{relative}\n".encode("ascii"))
    (root / "backend/payload.py").write_text("VALUE = 1\n", encoding="ascii")
    return root


def test_v07_source_fingerprint_is_bounded_deterministic_and_sensitive(
    tmp_path: Path,
) -> None:
    root = _minimal_source_tree(tmp_path / "source")
    first = fingerprint.source_fingerprint_v07(root)
    second = fingerprint.source_fingerprint_v07(root)
    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first)

    ignored = root / "backend/.pytest_cache/result"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("not source\n", encoding="ascii")
    assert fingerprint.source_fingerprint_v07(root) == first

    (root / "backend/payload.py").write_text("VALUE = 2\n", encoding="ascii")
    assert fingerprint.source_fingerprint_v07(root) != first


def test_v07_source_fingerprint_includes_gate_0a_and_contract_inputs() -> None:
    inputs = {
        path.relative_to(ROOT).as_posix()
        for path in fingerprint.source_fingerprint_inputs_v07(ROOT)
    }
    assert "SPELL_v0.7_Pre-Implementation.md" in inputs
    assert (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v07_gate_0a.py"
    ) in inputs
    assert (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.7-gate-0a.json"
    ) in inputs
    assert "contracts/v07/manifest.json" in inputs
    for relative in (
        "SPELL_v0.7_Gate_0B.md",
        "SPELL_v0.7_Release.md",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v07_gate_0b.py",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v07_gate_0b.py",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.7-gate-0b.json",
        "artifacts/v0.7/work-package/schema.json",
        "scripts/accepted_v06_release_v07.py",
        "scripts/audit_supply_chain_v07.ps1",
        "scripts/assert_accepted_v06_release_v07.ps1",
        "scripts/build_reproducible_v07.py",
        "scripts/create_release_qualification_v07.py",
        "scripts/generate_sbom_v07.ps1",
        "scripts/package-v07.Dockerfile",
        "scripts/package-v07.Dockerfile.dockerignore",
        "scripts/package_release_v07.ps1",
        "scripts/qualification-v07.Dockerfile",
        "scripts/qualification-v07.Dockerfile.dockerignore",
        "scripts/qualify_candidate_v07.ps1",
        "scripts/qualify_release_v07.ps1",
        "scripts/seed_observation_v07.py",
        "scripts/source_fingerprint_v07.py",
        "scripts/validate_candidate_evidence_v07.py",
        "scripts/validate_release_evidence_v07.py",
        "scripts/tests/test_accepted_v06_release_v07.py",
        "scripts/tests/test_create_release_qualification_v07.py",
        "scripts/tests/test_qualification_image_v07.py",
        "scripts/tests/test_qualify_release_v07.py",
        "scripts/tests/test_release_v07.py",
        "scripts/tests/test_seed_observation_v07.py",
        "scripts/tests/test_source_fingerprint_v07.py",
        "scripts/tests/test_validate_candidate_evidence_v07.py",
        "scripts/tests/test_validate_release_evidence_v07.py",
    ):
        assert relative in inputs


def test_v07_source_fingerprint_excludes_transient_qualification_captures(
    tmp_path: Path,
) -> None:
    root = _minimal_source_tree(tmp_path / "source")
    baseline = fingerprint.source_fingerprint_v07(root)
    capture = root / "frontend/artifacts/v0.7/.qualification/run/browser/proof.json"
    capture.parent.mkdir(parents=True)
    capture.write_text('{"transient":true}\n', encoding="ascii")
    assert fingerprint.source_fingerprint_v07(root) == baseline


def test_v07_source_fingerprint_rejects_link_inputs(tmp_path: Path) -> None:
    root = _minimal_source_tree(tmp_path / "source")
    target = root / "backend/payload.py"
    link = root / "backend/linked.py"
    try:
        os.symlink(target, link)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="link or reparse point"):
        fingerprint.source_fingerprint_v07(root)


def test_v07_source_fingerprint_rejects_paths_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside\n", encoding="ascii")
    assert fingerprint.path_has_link_or_reparse_v07(root, outside)
