from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import accepted_v05_release_v06 as accepted


ROOT = Path(__file__).resolve().parents[2]


def _detached_v05_fixture(tmp_path: Path) -> Path:
    checkout = tmp_path / "accepted-v05"
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", "--quiet", str(ROOT), str(checkout)],
        check=True,
        timeout=60,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "checkout", "--detach", "--quiet", "v0.5.0"],
        check=True,
        timeout=60,
    )
    for relative in (accepted.V05_ARCHIVE_RELATIVE, accepted.V05_SIDECAR_RELATIVE):
        destination = checkout / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return checkout


def test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact() -> None:
    result = accepted.validate_accepted_v05_release(ROOT)

    assert result.archive_sha256 == accepted.V05_ARCHIVE_SHA256
    assert result.sidecar_sha256 == accepted.V05_SIDECAR_SHA256
    assert result.tag_object == accepted.V05_TAG_OBJECT
    assert result.tag_archive_claim == accepted.V05_TAG_ARCHIVE_CLAIM


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        (accepted.V05_ARCHIVE_RELATIVE, "archive SHA-256 differs"),
        (accepted.V05_SIDECAR_RELATIVE, "sidecar bytes differ"),
    ],
)
def test_accepted_v05_external_pair_rejects_byte_mutation(
    tmp_path: Path,
    relative: str,
    message: str,
) -> None:
    checkout = _detached_v05_fixture(tmp_path)
    path = checkout / relative
    raw = bytearray(path.read_bytes())
    raw[0] ^= 1
    path.write_bytes(raw)

    with pytest.raises(accepted.AcceptedV05ReleaseError, match=message):
        accepted.validate_accepted_v05_release(checkout)


def test_accepted_v05_tag_claim_rejects_raw_object_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_git = accepted._git

    def mutated_git(root: Path, *arguments: str) -> bytes:
        raw = original_git(root, *arguments)
        if arguments[:2] == ("cat-file", "tag"):
            return raw.replace(
                accepted.V05_TAG_ARCHIVE_CLAIM.encode("ascii"),
                b"Final archive SHA-256: " + b"0" * 64,
            )
        return raw

    monkeypatch.setattr(accepted, "_git", mutated_git)
    with pytest.raises(
        accepted.AcceptedV05ReleaseError,
        match="tag final-archive claim differs",
    ):
        accepted.validate_accepted_v05_release(ROOT)


def test_every_v06_release_phase_invokes_the_shared_accepted_v05_assertion() -> None:
    for relative in (
        "scripts/qualify_release_v06.ps1",
        "scripts/generate_sbom_v06.ps1",
        "scripts/audit_supply_chain_v06.ps1",
        "scripts/package_release_v06.ps1",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "assert_accepted_v05_release_v06.ps1" in source
    candidate = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    assert "accepted_v05_release_v06.py" in candidate
    assert accepted.V05_ARCHIVE_SHA256 in candidate


def test_package_stages_the_exact_accepted_pair_into_both_independent_exports() -> None:
    source = (ROOT / "scripts/package_release_v06.ps1").read_text(encoding="utf-8")

    assert "function Stage-AcceptedV05ExternalRelease" in source
    assert "Stage-AcceptedV05ExternalRelease $export" in source
    assert source.count("assert_accepted_v05_release_v06.ps1") >= 3
