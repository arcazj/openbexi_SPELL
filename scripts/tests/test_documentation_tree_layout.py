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
}
EXPECTED_REFERENCE_MANUAL_SHA256 = {
    "SPELL - Development Environment Manual - 2.4.4.pdf": (
        "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81"
    ),
    "SPELL - Driver Development Manual - 2.4.4.pdf": (
        "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5"
    ),
    "SPELL - GUI User Manual - 2.4.4.pdf": (
        "1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6"
    ),
    "SPELL - Language Reference - 2.4.4.pdf": (
        "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
    ),
    "SPELL - Server Manual - 2.4.4.pdf": (
        "ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9"
    ),
    "SPELL_DEV_Manual.pdf": (
        "94c1443646e22f3692ac25d2ef570ff437d83c38b71082e7077b4a322e5fb94f"
    ),
    "SPELL_Language_Manual.pdf": (
        "f2f3e72e62692eeabb287b704878240012062f894b52a10570b8f42199c233fb"
    ),
}
EXPECTED_LEGACY_ARCHIVES = {"SPELL2.6.10-src.zip"}


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
    legacy_names = {path.name for path in legacy_files}
    assert EXPECTED_REFERENCE_MANUAL_SHA256.keys() <= legacy_names
    assert EXPECTED_LEGACY_ARCHIVES <= legacy_names
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
    for manual_name, expected_digest in EXPECTED_REFERENCE_MANUAL_SHA256.items():
        assert _sha256(LEGACY_DOCUMENTATION / manual_name) == expected_digest


def test_project_policy_makes_reference_manuals_mandatory() -> None:
    instructions = " ".join(
        (ROOT / "PROMPT_Instructions.md").read_text(encoding="utf-8").split()
    )
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    source_authority = (
        GENERATED_DOCUMENTATION / "SOURCE_AUTHORITY.md"
    ).read_text(encoding="utf-8")

    assert (
        "Every document stored under `SPELL_DOCUMENTATION/`, now or later, "
        "is a mandatory source-reference input"
    ) in instructions
    assert (
        "Every document under `SPELL_DOCUMENTATION/` is a required source "
        "reference"
    ) in readme
    for manual_name in EXPECTED_REFERENCE_MANUAL_SHA256:
        assert manual_name in source_authority


def test_release_records_are_kept_under_generated_documentation() -> None:
    assert RELEASE_DOCUMENTATION.is_dir()
    assert (RELEASE_DOCUMENTATION / "README.md").is_file()
    assert not tuple(ROOT.glob("SPELL_v*.md"))

    release_records = {
        path.name for path in RELEASE_DOCUMENTATION.glob("SPELL_v*.md")
    }
    assert release_records == EXPECTED_RELEASE_RECORDS
