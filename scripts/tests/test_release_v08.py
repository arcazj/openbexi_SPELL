from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import build_reproducible_v08 as release


def test_v08_reparse_detector_recognizes_windows_file_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG,
        st_file_attributes=reparse_flag,
    )
    monkeypatch.setattr(Path, "lstat", lambda _path: metadata)

    assert release.path_has_link_or_reparse_v08(Path("root"), Path("root/file"))


def test_v08_archive_bytes_are_deterministic_and_normalized(tmp_path: Path) -> None:
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
        "artifacts/v0.7/release-qualification.json",
        "legacy.zip",
        "runtime.sqlite",
        "secrets/value.json",
        "client.key",
    ],
)
def test_v08_package_rejects_forbidden_paths(relative: str) -> None:
    with pytest.raises(ValueError):
        release._validate_path(Path(relative))


def test_v08_package_rejects_private_key_bytes(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "probe.txt"
    source.parent.mkdir()
    source.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n")

    with pytest.raises(ValueError, match="secret material"):
        release._archive_bytes(tmp_path, [source])


def test_v08_scanner_literal_contract_matches_every_live_source_file() -> None:
    for relative, literals in release.SECRET_SCANNER_LITERAL_CONTRACT.items():
        raw = (release.ROOT / relative).read_bytes()
        assert all(raw.count(literal) == 1 for literal in literals)
        release._validate_bytes(Path(relative), raw)


@pytest.mark.parametrize(
    "relative",
    sorted(release.SECRET_SCANNER_LITERAL_CONTRACT),
)
def test_v08_scanner_literal_contract_rejects_path_and_byte_mutations(
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


def _evidence_canary_xml(
    nodes: tuple[str, ...], *, duplicate: bool = False
) -> bytes:
    from scripts import validate_release_evidence_v08 as evidence

    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        tests=str(len(nodes) + int(duplicate)),
        skipped="0",
        failures="0",
        errors="0",
    )
    for index, node in enumerate(nodes):
        module, name = node.split(".py::", 1)
        ET.SubElement(
            suite,
            "testcase",
            classname=module.replace("/", "."),
            name=name,
        )
        if duplicate and index == 0:
            ET.SubElement(
                suite,
                "testcase",
                classname=module.replace("/", "."),
                name=name,
            )
    return evidence.CANONICAL_XML_DECLARATION + ET.tostring(root, encoding="utf-8")


def test_v08_package_scans_candidate_manifest_and_tooling_structurally() -> None:
    from scripts import validate_release_evidence_v08 as evidence

    assert release.BACKEND_SECRET_EVIDENCE_PATHS == set(
        evidence.BACKEND_SECRET_CAPTURE_PATHS
    )
    release._validate_bytes(Path(release.WORK_PACKAGE_MANIFEST), b'{"bounded":true}\n')
    release._validate_bytes(
        Path("artifacts/v0.8/work-package/tests/tooling.xml"),
        _evidence_canary_xml(evidence.FINAL_TOOLING_SECRET_TESTCASE_NODES),
    )
    release._validate_bytes(
        Path("artifacts/v0.8/final/tests/backend-postgresql.xml"),
        _evidence_canary_xml(evidence.BACKEND_SECRET_CANARY_NODES),
    )


def test_v08_package_rejects_duplicate_or_mislocated_evidence_canaries() -> None:
    from scripts import validate_release_evidence_v08 as evidence

    tooling_relative = "artifacts/v0.8/work-package/tests/tooling.xml"
    with pytest.raises(ValueError, match="inventory differs"):
        release._validate_bytes(
            Path(tooling_relative),
            _evidence_canary_xml(
                evidence.FINAL_TOOLING_SECRET_TESTCASE_NODES, duplicate=True
            ),
        )
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path("artifacts/v0.8/final/tests/not-tooling.xml"),
            _evidence_canary_xml(evidence.FINAL_TOOLING_SECRET_TESTCASE_NODES),
        )

    backend_relative = "artifacts/v0.8/final/tests/backend-postgresql.xml"
    with pytest.raises(ValueError, match="inventory differs"):
        release._validate_bytes(
            Path(backend_relative),
            _evidence_canary_xml(
                evidence.BACKEND_SECRET_CANARY_NODES, duplicate=True
            ),
        )
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path("artifacts/v0.8/final/tests/backend-docker-host.xml"),
            _evidence_canary_xml(evidence.BACKEND_SECRET_CANARY_NODES),
        )


def test_current_v08_product_package_fingerprint_is_constructible() -> None:
    missing = [
        relative
        for relative in release.FINGERPRINT_FILES
        if not (release.ROOT / relative).is_file()
    ]
    if missing:
        with pytest.raises(FileNotFoundError):
            release.product_package_sha256_v08(release.ROOT)
        return
    digest = release.product_package_sha256_v08(release.ROOT)
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_v08_fingerprint_image_uses_a_current_source_context_policy() -> None:
    dockerfile = (release.ROOT / "scripts/package-v08.Dockerfile").read_text(
        encoding="utf-8"
    )
    ignore = (
        release.ROOT / "scripts/package-v08.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")

    assert "COPY . /workspace" in dockerfile
    ignore_lines = ignore.splitlines()
    assert "artifacts/v0.8" in ignore_lines
    assert ignore_lines.index("artifacts/v0.8") < ignore_lines.index(
        "!artifacts/v0.8/"
    )
    assert ignore_lines.index("!artifacts/v0.8/work-package/") < ignore_lines.index(
        "!artifacts/v0.8/work-package/schema.json"
    )
    assert "SPELL-DOCUMENTATION" in ignore.splitlines()
    assert "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI" not in ignore
    assert "SPELL_v0.8_Gate_0B.md" not in ignore


def test_v08_host_python_producers_require_locked_isolated_mode() -> None:
    audit = (release.ROOT / "scripts/audit_supply_chain_v08.ps1").read_text(
        encoding="utf-8"
    )
    package = (release.ROOT / "scripts/package_release_v08.ps1").read_text(
        encoding="utf-8"
    )

    assert audit.count("& $PythonExe -I ") == 2
    assert (
        '& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v08.py")'
        in audit
    )
    assert (
        '& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v04.py")'
        in audit
    )
    assert "& $PythonExe (Join-Path" not in audit

    assert package.count("& $PythonExe -I ") == 1
    assert (
        '& $PythonExe -I (Join-Path $BuildRoot "scripts/build_reproducible_v08.py")'
        in package
    )
    assert "& $PythonExe (Join-Path" not in package


def test_v08_package_publication_is_a_rollback_transaction() -> None:
    package = (release.ROOT / "scripts/package_release_v08.ps1").read_text(
        encoding="utf-8"
    )

    assert "existing v0.8 package publication is incomplete" in package
    assert "$backupRelease" in package and "$backupSidecar" in package
    assert "refusing to use unsafe v0.8 package publication path" in package
    assert "published v0.8 package pair failed final verification" in package
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
        "published v0.8 package pair failed final verification"
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

    function_cleanup = package[package.index("function Publish-V08PackagePair") :]
    assert "foreach ($path in @($StagedRelease, $StagedSidecar))" in function_cleanup
    final_cleanup = package.rsplit("\nfinally {", 1)[1]
    assert "Remove-Item -LiteralPath $scratchRoot -Recurse -Force" in final_cleanup
    assert "$stagedRelease" not in final_cleanup
    assert "$stagedSidecar" not in final_cleanup
    assert "$backupRelease" not in final_cleanup
    assert "$backupSidecar" not in final_cleanup


def test_v08_package_build_outputs_use_owned_qualification_scratch() -> None:
    package = (release.ROOT / "scripts/package_release_v08.ps1").read_text(
        encoding="utf-8"
    )

    assert '$qualificationRoot = Join-Path $artifactRoot ".qualification"' in package
    assert '$scratchRoot = Join-Path $qualificationRoot "package-$runId"' in package
    assert '$first = Join-Path $scratchRoot "package-a.tar.gz"' in package
    assert '$second = Join-Path $scratchRoot "package-b.tar.gz"' in package
    assert '$first = Join-Path $artifactRoot ".package-' not in package
    assert '$second = Join-Path $artifactRoot ".package-' not in package
    assert "v0.8 package scratch path already exists" in package
    assert "v0.8 package scratch directory is unsafe" in package
    assert "refusing v0.8 package scratch cleanup containing a reparse point" in package

    create = package.index("New-Item -ItemType Directory -Path $scratchRoot")
    ownership = package.index("$scratchOwned = $true", create)
    first_build = package.index("$a = Invoke-PackageBuild $exportA $exportFirst")
    second_build = package.index("$b = Invoke-PackageBuild $exportB $exportSecond")
    cleanup = package.index(
        "Remove-Item -LiteralPath $scratchRoot -Recurse -Force", second_build
    )
    assert create < ownership < first_build < second_build < cleanup
    assert 'git -C $root rev-parse --verify "HEAD^{commit}"' in package
    assert "git -C $root worktree add --detach $exportA $releaseCommit" in package
    assert "git -C $root worktree add --detach $exportB $releaseCommit" in package
    assert "independent package export commit differs from the explicit source freeze" in package
    assert "Stage-AcceptedV07ExternalRelease" not in package
    assert (
        'assert_accepted_v07_release_v08.ps1") -Root $export'
        in package
    )
    assert "$a.release_commit -cne $releaseCommit" in package
    assert "independent_export_count = 2" in package


def test_v08_package_publication_fault_rolls_back_executably(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    package_script = release.ROOT / "scripts/package_release_v08.ps1"
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
$firstAssignments = @($ast.FindAll({
  param($node)
  $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$first'
}, $true))
$secondAssignments = @($ast.FindAll({
  param($node)
  $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$second'
}, $true))
if (
  $firstAssignments.Count -ne 1 -or
  $firstAssignments[0].Right.Extent.Text -cne 'Join-Path $scratchRoot "package-a.tar.gz"' -or
  $secondAssignments.Count -ne 1 -or
  $secondAssignments[0].Right.Extent.Text -cne 'Join-Path $scratchRoot "package-b.tar.gz"'
) { throw "package build outputs are not isolated in qualification scratch" }
$definitions = @($ast.FindAll({
  param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq "Publish-V08PackagePair"
}, $true))
if ($definitions.Count -ne 1) { throw "package transaction function differs" }
Invoke-Expression $definitions[0].Extent.Text

$caught = $null
try {
  Publish-V08PackagePair `
    -SourceRelease (Join-Path $WorkRoot "source.tar.gz") `
    -StagedRelease (Join-Path $WorkRoot "staged.tar.gz") `
    -StagedSidecar (Join-Path $WorkRoot "staged.tar.gz.sha256") `
    -Release (Join-Path $WorkRoot "openbexi-spell-v0.8.0.tar.gz") `
    -Sidecar (Join-Path $WorkRoot "openbexi-spell-v0.8.0.tar.gz.sha256") `
    -BackupRelease (Join-Path $WorkRoot "backup.tar.gz") `
    -BackupSidecar (Join-Path $WorkRoot "backup.tar.gz.sha256") `
    -ExpectedHash $ExpectedHash `
    -TestOnlyFault "AfterArchivePublication"
}
catch { $caught = $_.Exception.Message }
if ($caught -cne "injected v0.8 package publication failure") {
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
        release_path = work_root / "openbexi-spell-v0.8.0.tar.gz"
        sidecar_path = work_root / "openbexi-spell-v0.8.0.tar.gz.sha256"
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
