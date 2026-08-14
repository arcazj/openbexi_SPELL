from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "qualify_release_v05.ps1"


def test_v05_final_runner_parses_as_powershell() -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell parser is unavailable")
    escaped = str(RUNNER).replace("'", "''")
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


def test_v05_final_runner_freezes_source_and_never_qualifies_live_bytes() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '[string]$SourceCommit = "HEAD"' in runner
    assert 'git status --porcelain=v1 --untracked-files=all' in runner
    assert 'git archive --format=zip --output=$archivePath $resolvedSource' in runner
    assert 'Expand-Archive -LiteralPath $archivePath -DestinationPath $sourceRoot' in runner
    assert '"scripts/qualification-v05.Dockerfile"' in runner
    assert '"scripts/qualification-v05.Dockerfile.dockerignore"' in runner
    assert '-f $qualificationDockerfile -t $qualificationTag $sourceRoot' in runner
    assert 'Python 3.13.14' in runner
    assert "aefa658ce01d49a7879d0471b50425ac3bcf9e2d" in runner
    assert "ef26e53f5ecccabef1fff03ec86d71b0c93edd2b" in runner
    assert "802b3aa602e209cca204a4d17e1e71eb65cec408d59f575b0b3269d2424d771b" in runner
    assert "fa97a356d4d76ed4650e04f73785b02ffe3f4b4d5c3655869c0a9ba2d7aff66a" in runner
    assert "328ecc2e76375a745ad007e1e15eba14652a4e7d23064fe77640c342fa8f7098" in runner
    assert "$candidateToolingNodes.Count -ne 334" in runner
    assert "final tooling inventory omits an immutable candidate node" in runner
    assert "qualification.Dockerfile\" -t $qualificationTag ." not in runner


def test_v05_final_runner_normalizes_only_collected_node_paths() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '$separator = $line.IndexOf("::", [StringComparison]::Ordinal)' in runner
    assert (
        "$line.Substring(0, $separator).Replace('\\', '/') + "
        "$line.Substring($separator)"
    ) in runner
    assert "([string]$_).Replace('\\', '/')" not in runner


def test_v05_final_runner_flattens_every_collected_inventory_explicitly() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert "return ,$items" not in runner
    assert "return ,$nodes" not in runner
    assert "return ,$values" not in runner
    assert '[string[]]$backendNodes = @(Get-CollectedNodes "backend/tests"' in runner
    assert '[string[]]$driverNodes = @(Get-CollectedNodes "driver_host/tests"' in runner
    assert '[string[]]$toolingNodes = @(Get-CollectedNodes "scripts/tests"' in runner
    assert "[string[]]$mockNodes = @(" in runner
    assert "[string[]]$realNodes = @(" in runner


def test_v05_final_runner_stages_only_ledger_bound_external_manuals() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert "78c419f898bbc719e9e1134f8e57aa0352a07cd2b4d21644658f3f74237c56ad" in runner
    assert runner.count('2.4.4.pdf" = "') == 6
    assert '"SPELL-GUI-4.0.2-Build-Instructions.pdf" = "' in runner
    assert 'Get-ManualLedgerMap (Join-Path $sourceRoot "SPELL_DOCUMENTATION_REVIEW.md")' in runner
    assert '$externalManualSource = Join-Path $root "SPELL-DOCUMENTATION"' in runner
    assert '$stagedManualRoot = Join-Path $sourceRoot "SPELL-DOCUMENTATION"' in runner
    assert "external-manual source hash differs" in runner
    assert "staged external-manual hash differs" in runner


def test_v05_final_runner_enforces_full_bijections_and_skip_contracts() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert runner.count("Assert-JUnitContract") >= 7
    assert "backend SQLite" in runner
    assert "backend PostgreSQL" in runner
    assert "driver host" in runner
    assert '"tooling"' in runner
    assert "frontend unit collection/run bijection" in runner
    assert "mocked browser" in runner
    assert "real browser" in runner
    assert runner.count("backend/tests/test_migrations.py::") >= 4
    assert runner.count("backend/tests/test_driver_isolation.py::") >= 4
    assert "Windows-only tooling node inventory differs" in runner
    assert "Merge-JUnit @($postgresBaseXml, $postgresRuntimeXml)" in runner
    assert "Merge-JUnit @($toolingBaseXml, $toolingHostXml)" in runner
    assert 'SPELL_TEST_DATABASE_URL=$applicationUrl' in runner
    assert 'SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl' in runner
    assert 'POSTGRES_DB=spell_test' in runner
    assert "spell_migration_test" in runner
    assert "Normalize-BrowserJUnit" in runner
    assert 'Assert-JUnitContract $toolingXml $toolingNodes @() "tooling" 36' in runner
    assert '$suite.SetAttribute("tests", [string]$reportedTests)' in runner
    assert "SubtestCount = $reportedTests - $nodes.Count" in runner


def test_v05_final_runner_captures_exact_eight_suite_contract() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    match = re.search(r"\$finalSuiteIds = @\((.*?)\n\)", runner, re.DOTALL)
    assert match is not None
    suite_ids = re.findall(r'"([a-z_]+)"', match.group(1))

    assert suite_ids == [
        "backend_sqlite",
        "backend_postgresql",
        "driver_host",
        "tooling",
        "frontend_unit",
        "frontend_build",
        "browser_mocked",
        "browser_real",
    ]
    for name in (
        "backend-sqlite.xml",
        "backend-postgresql.xml",
        "driver-host.xml",
        "tooling.xml",
        "frontend-unit.json",
        "frontend-build.json",
        "browser-mocked.xml",
        "browser-real.xml",
    ):
        assert name in runner
    assert 'schema_version = "spell.v05.frontend-build/1"' in runner
    assert 'command = @("npm", "run", "build")' in runner
    assert "Get-TreeDigest" in runner
    assert "subtest_count = [int]$Result.SubtestCount" in runner
    assert "test_count = [int]$vitest.numTotalTests; subtest_count = 0" in runner


def test_v05_final_runner_binds_gate_source_product_and_candidate_evidence() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert 'schema_version = "spell.v05.final-qualification/1"' in runner
    assert "source_fingerprint_sha256 = $sourceFingerprint" in runner
    assert "product_package_sha256 = $productPackageSha256" in runner
    assert "work_package = [ordered]@{" in runner
    assert "gate_0b = [ordered]@{" in runner
    assert "toolchain = $finalToolchain" in runner
    assert "qualification_image_id = [string]$script:QualificationImage" in runner
    assert "Assert-FinalToolchain $summary.toolchain" in runner
    assert "final qualification toolchain immutable binding differs" in runner
    assert "evidence_sha256 = Get-LowerSha256" in runner
    assert "validator_sha256 = Get-LowerSha256" in runner
    assert "candidate_commit = $candidateCommit" in runner
    assert "Gate 0B success marker differs" in runner
    assert "accepted_exceptions = @()" in runner
    assert "secrets_retained = $false" in runner


def test_v05_final_runner_only_publishes_final_after_cleanup_and_validation() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    cleanup = runner.index("$qualificationResourcesTornDown = $cleanupFailures.Count -eq 0")
    stage_validation = runner.index("$validatedSummary = Assert-FinalPublication $publicationStage")
    publish = runner.index("Move-Item -LiteralPath $publicationStage -Destination $canonicalFinal")
    published_validation = runner.index("$published = Assert-FinalPublication $canonicalFinal")

    assert cleanup < stage_validation < publish < published_validation
    assert 'Join-Path $artifactRoot ".qualification/final-$runId"' in runner
    assert 'Join-Path $artifactRoot "final"' in runner
    assert 'Join-Path $root "artifacts/v0.5/final"' in runner
    assert "release-qualification.json" not in runner
    assert "validate_release_evidence_v05.py --root" not in runner
    assert "artifacts/v0.4/.qualification" not in runner
    assert "artifacts/v0.4/browser" not in runner
    assert "Remove-Item -LiteralPath $canonicalFinal -Recurse -Force" in runner
    assert "Move-Item -LiteralPath $publicationBackup -Destination $canonicalFinal" in runner


def test_v05_final_runner_tears_down_only_owned_resources() -> None:
    runner = RUNNER.read_text(encoding="utf-8").casefold()

    assert "com.docker.compose.project=$project" in runner
    assert "$script:composeexe = $composeexe" in runner
    assert "invoke-composecleanup @(" in runner
    assert '"-p", $browserproject' in runner
    assert '"down",' in runner
    assert '"--remove-orphans"' in runner
    assert "foreach ($ownerproject in @($project, $browserproject))" in runner
    assert "$env:spell_db_password = $browserdbpassword" in runner
    assert "remove-newruntimeresources" in runner
    assert "runtime test resources remain" in runner
    assert '"container", "prune"' not in runner
    assert '"image", "prune"' not in runner
    assert '"system", "prune"' not in runner
    assert "stop-process -name" not in runner
    assert "taskkill" not in runner
