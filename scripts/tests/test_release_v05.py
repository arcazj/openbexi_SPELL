from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import build_reproducible_v05 as release


def test_v05_archive_bytes_are_deterministic_and_normalized(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "probe.py"
    source.parent.mkdir()
    source.write_text("print('bounded')\n", encoding="ascii")

    first = release._archive_bytes(tmp_path, [source])
    second = release._archive_bytes(tmp_path, [source])

    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


@pytest.mark.parametrize(
    "relative",
    [
        "artifacts/v0.4/gate-1.json",
        "legacy.zip",
        "runtime.sqlite",
        "secrets/value.json",
        "client.key",
    ],
)
def test_v05_package_rejects_forbidden_paths(relative: str) -> None:
    with pytest.raises(ValueError):
        release._validate_path(Path(relative))


def test_v05_package_rejects_private_key_bytes(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "probe.txt"
    source.parent.mkdir()
    source.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n")

    with pytest.raises(ValueError, match="secret material"):
        release._archive_bytes(tmp_path, [source])


def test_v05_scanner_literal_contract_matches_every_live_source_file() -> None:
    for relative, literals in release.SECRET_SCANNER_LITERAL_CONTRACT.items():
        raw = (release.ROOT / relative).read_bytes()
        assert all(raw.count(literal) == 1 for literal in literals)
        release._validate_bytes(Path(relative), raw)


@pytest.mark.parametrize(
    "relative",
    sorted(release.SECRET_SCANNER_LITERAL_CONTRACT),
)
def test_v05_scanner_literal_contract_rejects_path_and_byte_mutations(
    relative: str,
) -> None:
    raw = (release.ROOT / relative).read_bytes()
    literal = release.SECRET_SCANNER_LITERAL_CONTRACT[relative][0]
    mutated_literal = literal[:-1] + b" " + literal[-1:]

    with pytest.raises(ValueError, match="literal contract differs"):
        release._validate_bytes(
            Path(relative), raw.replace(literal, mutated_literal, 1)
        )
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(Path("scripts/unapproved-scanner.py"), literal)
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path(relative),
            raw
            + b"\n"
            + release.PEM_PRIVATE_KEY_BEGIN
            + b"\nreal-payload\n-----END PRIVATE KEY-----\n",
        )


def test_v05_package_scans_canonical_candidate_canaries_structurally() -> None:
    for relative in (
        release.WORK_PACKAGE_MANIFEST,
        "artifacts/v0.5/work-package/tests/tooling.xml",
    ):
        path = release.ROOT / relative
        release._validate_bytes(Path(relative), path.read_bytes())


def test_v05_package_rejects_duplicate_or_mislocated_evidence_canaries() -> None:
    from scripts.validate_candidate_evidence_v05 import TOOLING_SYNTHETIC_NODES
    from scripts.validate_release_evidence_v05 import CANONICAL_XML_DECLARATION

    manifest_path = release.ROOT / release.WORK_PACKAGE_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["suites"]["tooling"]["collected_nodes"].append(
        TOOLING_SYNTHETIC_NODES[0]
    )
    with pytest.raises(ValueError, match="synthetic tooling node"):
        release._validate_bytes(
            Path(release.WORK_PACKAGE_MANIFEST),
            json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
        )

    tooling_relative = "artifacts/v0.5/work-package/tests/tooling.xml"
    tooling_raw = (release.ROOT / tooling_relative).read_bytes()
    root = ET.fromstring(tooling_raw)
    duplicated = False
    for parent in root.iter():
        for child in list(parent):
            expected_name = TOOLING_SYNTHETIC_NODES[0].rsplit("::", 1)[1]
            if child.tag == "testcase" and child.get("name") == expected_name:
                parent.append(copy.deepcopy(child))
                duplicated = True
                break
        if duplicated:
            break
    assert duplicated
    with pytest.raises(ValueError, match="inventory differs"):
        release._validate_bytes(
            Path(tooling_relative),
            CANONICAL_XML_DECLARATION + ET.tostring(root),
        )
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path("artifacts/v0.5/final/tests/not-tooling.xml"), tooling_raw
        )


def test_current_v05_product_package_fingerprint_is_constructible() -> None:
    digest = release.product_package_sha256_v05(release.ROOT)
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_v05_package_publication_is_a_rollback_transaction() -> None:
    package = (release.ROOT / "scripts/package_release_v05.ps1").read_text(
        encoding="utf-8"
    )

    assert "existing v0.5 package publication is incomplete" in package
    assert "$backupRelease" in package and "$backupSidecar" in package
    assert "refusing to use unsafe v0.5 package publication path" in package
    assert "published v0.5 package pair failed final verification" in package
    assert '[ValidateSet("None", "AfterArchivePublication")]' in package
    assert package.count("$TestOnlyFault") == 2
    for state in (
        "$releaseBackedUp",
        "$sidecarBackedUp",
        "$releasePublished",
        "$sidecarPublished",
    ):
        assert state in package
    assert "rollback was incomplete; recovery files retained" in package

    backup_release = package.index(
        "Move-Item -LiteralPath $Release -Destination $BackupRelease"
    )
    backup_sidecar = package.index(
        "Move-Item -LiteralPath $Sidecar -Destination $BackupSidecar"
    )
    publish_release = package.index(
        "Move-Item -LiteralPath $StagedRelease -Destination $Release"
    )
    injected_failure = package.index(
        'if ($TestOnlyFault -cne "None")', publish_release
    )
    publish_sidecar = package.index(
        "Move-Item -LiteralPath $StagedSidecar -Destination $Sidecar"
    )
    final_verification = package.index(
        "published v0.5 package pair failed final verification"
    )
    rollback = package.index("\n    catch {", publish_sidecar)
    remove_release = package.index(
        "Remove-Item -LiteralPath $Release -Force", rollback
    )
    remove_sidecar = package.index(
        "Remove-Item -LiteralPath $Sidecar -Force", rollback
    )
    restore_release = package.rindex(
        "Move-Item -LiteralPath $BackupRelease -Destination $Release"
    )
    restore_sidecar = package.rindex(
        "Move-Item -LiteralPath $BackupSidecar -Destination $Sidecar"
    )

    assert backup_release < backup_sidecar < publish_release < publish_sidecar
    assert publish_release < injected_failure < publish_sidecar
    assert publish_sidecar < final_verification < rollback
    assert (
        rollback
        < remove_release
        < remove_sidecar
        < restore_release
        < restore_sidecar
    )
    assert package.count("$rollbackErrors.Add(") == 4

    function_cleanup = package[package.index("function Publish-V05PackagePair") :]
    assert "foreach ($path in @($StagedRelease, $StagedSidecar))" in function_cleanup
    final_cleanup = package.rsplit("\nfinally {", 1)[1]
    assert '$first, "$first.sha256", $second, "$second.sha256"' in final_cleanup
    assert "$stagedRelease" not in final_cleanup
    assert "$stagedSidecar" not in final_cleanup
    assert "$backupRelease" not in final_cleanup
    assert "$backupSidecar" not in final_cleanup


def test_v05_package_publication_fault_rolls_back_executably(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    package_script = release.ROOT / "scripts/package_release_v05.ps1"
    harness = tmp_path / "invoke-package-transaction.ps1"
    harness.write_text(
        r'''param(
  [Parameter(Mandatory = $true)] [string]$PackageScript,
  [Parameter(Mandatory = $true)] [string]$WorkRoot,
  [Parameter(Mandatory = $true)] [string]$ExpectedHash
)
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
  $PackageScript, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw "package script does not parse" }
$definitions = @($ast.FindAll({
  param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq "Publish-V05PackagePair"
}, $true))
if ($definitions.Count -ne 1) { throw "package transaction function differs" }
Invoke-Expression $definitions[0].Extent.Text

$caught = $null
try {
  Publish-V05PackagePair `
    -SourceRelease (Join-Path $WorkRoot "source.tar.gz") `
    -StagedRelease (Join-Path $WorkRoot "staged.tar.gz") `
    -StagedSidecar (Join-Path $WorkRoot "staged.tar.gz.sha256") `
    -Release (Join-Path $WorkRoot "openbexi-spell-v0.5.0.tar.gz") `
    -Sidecar (Join-Path $WorkRoot "openbexi-spell-v0.5.0.tar.gz.sha256") `
    -BackupRelease (Join-Path $WorkRoot "backup.tar.gz") `
    -BackupSidecar (Join-Path $WorkRoot "backup.tar.gz.sha256") `
    -ExpectedHash $ExpectedHash `
    -TestOnlyFault "AfterArchivePublication"
}
catch { $caught = $_.Exception.Message }
if ($caught -cne "injected v0.5 package publication failure") {
  throw "package fault hook did not fail at the required checkpoint: $caught"
}
Write-Output "FAULT_ROLLBACK_PASS"
''',
        encoding="utf-8",
    )

    new_archive = b"new deterministic package bytes\n"
    expected_hash = hashlib.sha256(new_archive).hexdigest()
    old_archive = b"previous canonical package bytes\n"
    old_sidecar = b"previous canonical sidecar\n"
    for existing_pair in (False, True):
        work_root = tmp_path / ("existing" if existing_pair else "empty")
        work_root.mkdir()
        (work_root / "source.tar.gz").write_bytes(new_archive)
        release_path = work_root / "openbexi-spell-v0.5.0.tar.gz"
        sidecar_path = work_root / "openbexi-spell-v0.5.0.tar.gz.sha256"
        if existing_pair:
            release_path.write_bytes(old_archive)
            sidecar_path.write_bytes(old_sidecar)

        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
                "-PackageScript",
                str(package_script),
                "-WorkRoot",
                str(work_root),
                "-ExpectedHash",
                expected_hash,
            ],
            cwd=tmp_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert completed.stdout.strip() == "FAULT_ROLLBACK_PASS"

        if existing_pair:
            assert release_path.read_bytes() == old_archive
            assert sidecar_path.read_bytes() == old_sidecar
        else:
            assert not release_path.exists()
            assert not sidecar_path.exists()
        for transient in (
            "staged.tar.gz",
            "staged.tar.gz.sha256",
            "backup.tar.gz",
            "backup.tar.gz.sha256",
        ):
            assert not (work_root / transient).exists()
