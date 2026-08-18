from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import accepted_v07_release_v08 as accepted


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL_ASSERTION = ROOT / "scripts/assert_accepted_v07_release_v08.ps1"


def _detached_v07_fixture(tmp_path: Path) -> Path:
    checkout = tmp_path / "accepted-v07"
    subprocess.run(
        [
            "git",
            "clone",
            "--shared",
            "--no-checkout",
            "--quiet",
            str(ROOT),
            str(checkout),
        ],
        check=True,
        timeout=60,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "checkout",
            "--detach",
            "--quiet",
            accepted.V07_TAG_REF,
        ],
        check=True,
        timeout=60,
    )
    return checkout


def test_accepted_v07_tag_blobs_archive_and_sidecar_are_exact() -> None:
    result = accepted.validate_accepted_v07_release(ROOT)

    assert result.tag_object == accepted.V07_TAG_OBJECT
    assert result.raw_tag_object_sha256 == accepted.V07_RAW_TAG_SHA256
    assert result.tag_commit == accepted.V07_RELEASE_COMMIT
    assert result.qualified_source_commit == accepted.V07_QUALIFIED_SOURCE_COMMIT
    assert result.archive_sha256 == accepted.V07_ARCHIVE_SHA256
    assert result.sidecar_sha256 == accepted.V07_SIDECAR_SHA256
    assert result.tagged_blobs == accepted.V07_TAGGED_BLOBS


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        (accepted.V07_ARCHIVE_RELATIVE, "workspace archive SHA-256 differs"),
        (accepted.V07_SIDECAR_RELATIVE, "workspace sidecar bytes differ"),
    ],
)
def test_accepted_v07_external_pair_rejects_byte_mutation(
    tmp_path: Path,
    relative: str,
    message: str,
) -> None:
    checkout = _detached_v07_fixture(tmp_path)
    path = checkout / relative
    raw = bytearray(path.read_bytes())
    raw[0] ^= 1
    path.write_bytes(raw)

    with pytest.raises(accepted.AcceptedV07ReleaseError, match=message):
        accepted.validate_accepted_v07_release(checkout)


def test_accepted_v07_rejects_raw_tag_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_git = accepted._git

    def mutated_git(root: Path, *arguments: str) -> bytes:
        raw = original_git(root, *arguments)
        if arguments[:2] == ("cat-file", "tag"):
            return raw.replace(b"Decision: ACCEPTED", b"Decision: REJECTED", 1)
        return raw

    monkeypatch.setattr(accepted, "_git", mutated_git)
    with pytest.raises(
        accepted.AcceptedV07ReleaseError,
        match="raw tag object SHA-256 differs",
    ):
        accepted.validate_accepted_v07_release(ROOT)


def test_accepted_v07_rejects_tagged_blob_payload_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_git = accepted._git
    release_blob = accepted.V07_TAGGED_BLOBS["SPELL_v0.7_Release.md"]["object_id"]

    def mutated_git(root: Path, *arguments: str) -> bytes:
        raw = original_git(root, *arguments)
        if arguments == ("cat-file", "blob", release_blob):
            return raw + b"\n"
        return raw

    monkeypatch.setattr(accepted, "_git", mutated_git)
    with pytest.raises(
        accepted.AcceptedV07ReleaseError,
        match="tagged blob SHA-256 differs: SPELL_v0.7_Release.md",
    ):
        accepted.validate_accepted_v07_release(ROOT)


def test_accepted_v07_cli_emits_one_canonical_json_object(capsys) -> None:
    assert accepted.main(["--root", str(ROOT)]) == 0
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    payload = json.loads(output)
    assert payload["tag_ref"] == accepted.V07_TAG_REF
    assert payload["tagged_blobs"] == accepted.V07_TAGGED_BLOBS


def test_v08_powershell_assertion_is_parseable_and_reuses_canonical_validator() -> None:
    source = POWERSHELL_ASSERTION.read_text(encoding="utf-8")
    assert "accepted_v07_release_v08.py" in source
    assert "assert_release_toolchain_v04.ps1" in source
    assert "$env:SPELL_RELEASE_PYTHON_EXE" in source
    assert "& $pythonPath -I $validator" in source
    assert "Get-Command" not in source
    for binding in (
        accepted.V07_TAG_OBJECT,
        accepted.V07_RAW_TAG_SHA256,
        accepted.V07_RELEASE_COMMIT,
        accepted.V07_ARCHIVE_SHA256,
        accepted.V07_SIDECAR_SHA256,
    ):
        assert binding in source

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell parser is unavailable")
    escaped = str(POWERSHELL_ASSERTION).replace("'", "''")
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$tokens=$null;$errors=$null;"
                f"[void][Management.Automation.Language.Parser]::ParseFile('{escaped}',"
                "[ref]$tokens,[ref]$errors);"
                "if($errors.Count){$errors|% Message;exit 1}"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    asserted = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(POWERSHELL_ASSERTION),
            "-Root",
            str(ROOT),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert asserted.returncode == 0, asserted.stdout + asserted.stderr
    assert json.loads(asserted.stdout)["tag_object"] == accepted.V07_TAG_OBJECT
