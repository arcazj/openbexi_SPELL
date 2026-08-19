from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATED_DOCUMENTATION = ROOT / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
RELEASE_DOCUMENTATION = GENERATED_DOCUMENTATION / "releases"
LEGACY_DOCUMENTATION = ROOT / "SPELL_DOCUMENTATION"

EXPECTED_RELEASE_RECORDS = {
    "SPELL_v0.1_Pre-Implementation.md",
    "SPELL_v0.2_Release.md",
    "SPELL_v0.3_Pre-Implementation.md",
    "SPELL_v0.3_Release.md",
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
    "SPELL_v0.8_Pre-Implementation.md",
    "SPELL_v0.8_Gate_0B.md",
    "SPELL_v0.8_Release.md",
    "SPELL_v0.9_Pre-Implementation.md",
    "SPELL_v0.9_Gate_0B.md",
    "SPELL_v0.9_Release.md",
    "SPELL_v0.10_Implementation.md",
    "SPELL_v0.11_Pre-Implementation.md",
    "SPELL_v0.11_Implementation.md",
}
EXPECTED_LEGACY_MANUALS = {
    "SPELL_DEV_Manual.pdf",
    "SPELL_Language_Manual.pdf",
}


def _files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*") if path.is_file()))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_generated_and_legacy_documentation_trees_are_separate() -> None:
    assert GENERATED_DOCUMENTATION.is_dir()
    assert LEGACY_DOCUMENTATION.is_dir()

    generated_files = _files(GENERATED_DOCUMENTATION)
    legacy_files = _files(LEGACY_DOCUMENTATION)

    assert generated_files
    assert EXPECTED_LEGACY_MANUALS <= {path.name for path in legacy_files}
    assert all(path.parent == LEGACY_DOCUMENTATION for path in legacy_files)
    assert all(path.suffix.lower() in {".pdf", ".zip"} for path in legacy_files)

    generated_relative_paths = {
        path.relative_to(GENERATED_DOCUMENTATION) for path in generated_files
    }
    legacy_relative_paths = {
        path.relative_to(LEGACY_DOCUMENTATION) for path in legacy_files
    }
    assert generated_relative_paths.isdisjoint(legacy_relative_paths)

    generated_digests = {_sha256(path) for path in generated_files}
    legacy_digests = {_sha256(path) for path in legacy_files}
    assert generated_digests.isdisjoint(legacy_digests)


def test_release_records_are_kept_under_generated_documentation() -> None:
    assert RELEASE_DOCUMENTATION.is_dir()
    assert (RELEASE_DOCUMENTATION / "README.md").is_file()
    assert not tuple(ROOT.glob("SPELL_v*.md"))

    release_records = {
        path.name for path in RELEASE_DOCUMENTATION.glob("SPELL_v*.md")
    }
    assert release_records == EXPECTED_RELEASE_RECORDS
