"""Compute the isolated v0.4 qualification and package source fingerprint."""

from __future__ import annotations

import argparse
import hashlib
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
    "PROMPT_Instructions.md",
    "SPELL_v0.4_Pre-Implementation.md",
    "Test_and_Integration.md",
    "PROVENANCE.md",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_HUMAN_APPROVAL_LEDGER.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_READINESS_REPORT.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.4.json",
)
FINGERPRINT_EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".vite",
    "coverage",
    "dist",
    "htmlcov",
    "node_modules",
    "playwright-report",
    "test-results",
}


def source_fingerprint_inputs_v04(root: Path) -> list[Path]:
    """Return every regular source input in canonical archive-name order."""

    source_root = root.resolve()
    paths: list[Path] = []
    for relative_tree in FINGERPRINT_TREES:
        tree = source_root / relative_tree
        if not tree.is_dir() or tree.is_symlink():
            raise FileNotFoundError(
                f"required v0.4 fingerprint tree is missing: {relative_tree}"
            )
        for path in tree.rglob("*"):
            relative = path.relative_to(source_root)
            if FINGERPRINT_EXCLUDED_PARTS.intersection(relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(
                    f"v0.4 fingerprint input must not be a symlink: {relative.as_posix()}"
                )
            if path.is_file():
                paths.append(path)

    for relative_file in FINGERPRINT_FILES:
        path = source_root / relative_file
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(
                f"required v0.4 fingerprint file is missing: {relative_file}"
            )
        paths.append(path)

    return sorted(
        set(paths), key=lambda path: path.relative_to(source_root).as_posix()
    )


def source_fingerprint_v04(root: Path) -> str:
    """Hash path names and bytes without reading Git or writing artifacts."""

    source_root = root.resolve()
    digest = hashlib.sha256()
    for path in source_fingerprint_inputs_v04(source_root):
        digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(source_fingerprint_v04(args.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
