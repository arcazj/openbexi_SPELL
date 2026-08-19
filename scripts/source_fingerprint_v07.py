"""Compute the source fingerprint for the bounded SPELL v0.7 release."""

from __future__ import annotations

import argparse
import hashlib
import stat
from pathlib import Path


FINGERPRINT_TREES = (
    "backend",
    "frontend",
    "procedures",
    "proxy",
    "scripts",
    "security",
    "contracts",
    "driver_host",
    "spell",
)

FINGERPRINT_FILES = (
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "compose.yaml",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "PROMPT_Instructions.md",
    "PROMPT_History.md",
    "PROJECT_ROADMAP.md",
    "VERSION_TIMELINE.md",
    "Test_and_Integration.md",
    "PROVENANCE.md",
    "SPELL_v0.4_Pre-Implementation.md",
    "SPELL_v0.4_Release.md",
    "SPELL_v0.5_Pre-Implementation.md",
    "SPELL_v0.5_Gate_0B.md",
    "SPELL_v0.5_Release.md",
    "SPELL_v0.6_Pre-Implementation.md",
    "SPELL_v0.6_Gate_0B.md",
    "SPELL_v0.6_Release.md",
    "SPELL_v0.7_Pre-Implementation.md",
    "SPELL_v0.7_Gate_0B.md",
    "SPELL_v0.7_Release.md",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v05_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v05_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v05_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v05_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v06_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v06_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v07_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v07_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v07_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v07_gate_0b.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.5-gate-0a.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.5-gate-0b.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.6-gate-0a.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.6-gate-0b.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.7-gate-0a.json",
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
)

EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".qualification",
    ".vite",
    "coverage",
    "dist",
    "htmlcov",
    "node_modules",
    "playwright-report",
    "test-results",
}


def is_link_or_reparse_v07(path: Path) -> bool:
    """Return true for POSIX links and Windows reparse-point inputs."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def path_has_link_or_reparse_v07(root: Path, path: Path) -> bool:
    """Inspect each lexical component from root through path without resolving it."""

    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError:
        return True
    cursor = lexical_root
    if is_link_or_reparse_v07(cursor):
        return True
    for part in relative.parts:
        cursor /= part
        if is_link_or_reparse_v07(cursor):
            return True
    return False


def source_fingerprint_inputs_v07(root: Path) -> list[Path]:
    source_root = root.resolve()
    paths: list[Path] = []
    for relative_tree in FINGERPRINT_TREES:
        tree = source_root / relative_tree
        if not tree.is_dir() or path_has_link_or_reparse_v07(source_root, tree):
            raise FileNotFoundError(
                f"required v0.7 fingerprint tree is missing: {relative_tree}"
            )
        for path in tree.rglob("*"):
            relative = path.relative_to(source_root)
            if EXCLUDED_PARTS.intersection(relative.parts):
                continue
            if path_has_link_or_reparse_v07(source_root, path):
                raise ValueError(
                    "v0.7 fingerprint input must not be a link or reparse point: "
                    f"{relative.as_posix()}"
                )
            if path.is_file():
                paths.append(path)

    for relative_file in FINGERPRINT_FILES:
        path = source_root / relative_file
        if not path.is_file() or path_has_link_or_reparse_v07(source_root, path):
            raise FileNotFoundError(
                f"required v0.7 fingerprint file is missing: {relative_file}"
            )
        paths.append(path)

    return sorted(
        set(paths), key=lambda path: path.relative_to(source_root).as_posix()
    )


def source_fingerprint_v07(root: Path) -> str:
    source_root = root.resolve()
    digest = hashlib.sha256()
    for path in source_fingerprint_inputs_v07(source_root):
        digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    print(source_fingerprint_v07(args.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
