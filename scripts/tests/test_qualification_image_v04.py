from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_v04_qualification_image_receives_the_complete_gate_zero_input_tree() -> None:
    dockerfile = (ROOT / "scripts/qualification.Dockerfile").read_text(encoding="utf-8")
    dedicated_ignore = (
        ROOT / "scripts/qualification.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")
    product_ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert "COPY NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI " in dockerfile
    assert "COPY SPELL-DOCUMENTATION " in dockerfile
    assert "SPELL_DOCUMENTATION_REVIEW.md" in dockerfile
    assert "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/**" in product_ignore
    assert "SPELL-DOCUMENTATION" in product_ignore.splitlines()
    assert "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI" not in dedicated_ignore
    assert "SPELL-DOCUMENTATION" not in dedicated_ignore
    for excluded in (".git", ".env", ".venv", "artifacts", "*.zip"):
        assert excluded in dedicated_ignore


def test_product_build_context_excludes_only_intermediate_v04_evidence() -> None:
    entries = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())

    assert {
        "*.iml",
        "artifacts/v04-plan.json",
        "artifacts/v0.4/.qualification",
        "artifacts/v0.4/browser",
        "artifacts/v0.4/performance-*.json",
        "artifacts/v0.4/driver-projection-*.png",
    } <= entries
    assert "artifacts/v0.4" not in entries
    assert "artifacts/v0.4/tests" not in entries
    assert "artifacts/v0.4/sbom" not in entries
    assert "artifacts/v0.4/provenance" not in entries


def test_every_gate_zero_recipe_target_exists_in_the_source_tree() -> None:
    for relative in (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_HUMAN_APPROVAL_LEDGER.json",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_READINESS_REPORT.json",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.4.json",
        "SPELL_DOCUMENTATION_REVIEW.md",
        "SPELL-DOCUMENTATION/SPELL - Language Reference - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL - Driver Development Manual - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL - GUI User Manual - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL - Development Environment Manual - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL - Server Manual - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL - Build Manual - 2.4.4.pdf",
        "SPELL-DOCUMENTATION/SPELL-GUI-4.0.2-Build-Instructions.pdf",
        "SPELL_v0.4_Pre-Implementation.md",
        "Test_and_Integration.md",
    ):
        path = ROOT / relative
        assert path.is_file() and not path.is_symlink(), relative


def test_qualification_image_installs_hash_locked_generator_requirements() -> None:
    dockerfile = (ROOT / "scripts/qualification.Dockerfile").read_text(encoding="utf-8")

    assert "COPY contracts/generator-requirements.hashes.lock" in dockerfile
    assert "RUN python -m pip install --require-hashes" in dockerfile
    assert "-r /tmp/generator-requirements.hashes.lock" in dockerfile
