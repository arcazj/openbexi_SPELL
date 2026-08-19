from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "qualify_release_v09.ps1"
QUALIFICATION_IGNORE = ROOT / "scripts" / "qualification-v09.Dockerfile.dockerignore"


def test_v09_final_runner_parses_as_powershell() -> None:
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


def test_v09_final_runner_isolates_every_locked_host_python_producer() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    invocations = [
        line.strip()
        for line in runner.splitlines()
        if "& $lockedPython " in line
    ]

    assert len(invocations) == 14
    assert sum(" --version" in line for line in invocations) == 1
    assert all(
        " -I " in line or " --version" in line
        for line in invocations
    )


def test_v09_final_tooling_mounts_external_manuals_without_baking_them() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    ignore = QUALIFICATION_IGNORE.read_text(encoding="utf-8")

    assert "SPELL-DOCUMENTATION" in ignore.splitlines()
    assert "[string[]]$Mounts = @()" in runner
    assert 'foreach ($mount in $Mounts) { $create += @("--mount", $mount) }' in runner
    assert (
        'type=bind,source=$stagedManualRoot,'
        'target=/qualification-source/SPELL-DOCUMENTATION,readonly'
        in runner
    )
    assert '$toolingArguments $toolingBaseXml -Mounts @($manualEvidenceMount)' in runner


def test_v09_final_runner_binds_and_cleans_the_offline_package_proof() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    for marker in (
        "sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48",
        "sha256:89924b46ec81c1c0eb0055a7d72790b8067a16a5d0d0512e8117a01aa4a5d7ee",
        "$script:Volumes.Add($offlineCacheVolume)",
        "pinned offline Playwright image is not preinstalled",
        "cannot seed the verified offline npm cache",
        "cp /source/package.json /source/package-lock.json /tmp/work/",
        '$env:SPELL_V09_OFFLINE_PROOF = "1"',
        '$env:SPELL_V09_OFFLINE_SOURCE_ROOT = $sourceRoot',
        '$env:SPELL_V09_OFFLINE_QUALIFICATION_IMAGE = $script:QualificationImage',
        "$savedOfflineEnvironment = [ordered]@{}",
        "$savedOfflineEnvironment = $null",
        "$toolingOfflineXml = Join-Path $captureRoot \"tooling-offline.xml\"",
    ):
        assert marker in runner


def test_v09_final_runner_enforces_dual_network_none_bundle_builders() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    for marker in (
        'Get-BrowserComposeImageId "bundle-builder-a"',
        'Get-BrowserComposeImageId "bundle-builder-b"',
        'Assert-BrowserComposeServiceNetworkNone "bundle-builder-a"',
        'Assert-BrowserComposeServiceNetworkNone "bundle-builder-b"',
        "bundle builders do not share the exact backend image",
        '{{.HostConfig.NetworkMode}}',
        'if ($networkMode.Trim() -cne "none")',
    ):
        assert marker in runner
    node = (
        "backend/tests/test_driver_isolation.py::"
        "test_live_bundle_builders_are_networkless_independent_and_reproducible"
    )
    assert runner.count(f'"{node}"') == 2
    assert "@runtimeNodes -q" in runner


def test_v09_final_runner_freezes_source_and_never_qualifies_live_bytes() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '[string]$SourceCommit = "HEAD"' in runner
    assert 'git status --porcelain=v1 --untracked-files=all' in runner
    assert 'git archive --format=zip --output=$archivePath $resolvedSource' in runner
    assert 'Expand-Archive -LiteralPath $archivePath -DestinationPath $sourceRoot' in runner
    assert '"scripts/qualification-v09.Dockerfile"' in runner
    assert '"scripts/qualification-v09.Dockerfile.dockerignore"' in runner
    assert '-f $qualificationDockerfile -t $qualificationTag $sourceRoot' in runner
    assert 'Python 3.13.14' in runner
    assert '$candidateCommit = [string]$candidateEvidence.source.commit' in runner
    assert '$gate0aCommit = "92f3b4b82908d44e28b9506749e498386a428c27"' in runner
    assert "aefa658ce01d49a7879d0471b50425ac3bcf9e2d" not in runner
    assert "ef26e53f5ecccabef1fff03ec86d71b0c93edd2b" not in runner
    assert "candidateEvidence.suites.tooling.inventory_sha256" in runner
    assert "final tooling inventory omits an immutable candidate node" in runner
    assert "qualification.Dockerfile\" -t $qualificationTag ." not in runner
    assert 'Join-Path $env:TEMP "openbexi-spell-v05-py313-site"' in runner
    assert "openbexi-spell-v09-py313-site" not in runner


def test_v09_final_runner_normalizes_only_collected_node_paths() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '$separator = $line.IndexOf("::", [StringComparison]::Ordinal)' in runner
    assert (
        "$line.Substring(0, $separator).Replace('\\', '/') + "
        "$line.Substring($separator)"
    ) in runner
    assert "([string]$_).Replace('\\', '/')" not in runner


def test_v09_final_runner_flattens_every_collected_inventory_explicitly() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert "return ,$items" not in runner
    assert "return ,$nodes" not in runner
    assert "return ,$values" not in runner
    assert '[string[]]$backendNodes = @(Get-CollectedNodes "backend/tests"' in runner
    assert '[string[]]$driverNodes = @(Get-CollectedNodes "driver_host/tests"' in runner
    assert '[string[]]$toolingNodes = @(Get-CollectedNodes "scripts/tests"' in runner
    assert "[string[]]$mockNodes = @(" in runner
    assert "[string[]]$realNodes = @(" in runner


def test_v09_final_runner_uses_native_argv_without_inline_subprocess_replay() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    snippets = re.findall(
        r"\$[A-Za-z]+(?:Code|Probe) = @'\n(.*?)\n'@",
        runner,
        re.DOTALL,
    )

    assert len(snippets) == 4
    for snippet in snippets:
        tree = ast.parse(snippet)
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
            for node in ast.walk(tree)
        )
    assert '$create += @($script:QualificationImage, "python", "-m", "pytest")' in runner
    assert "$soakCode" not in runner


def test_v09_final_runner_accepts_leaf_playwright_suites() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '$children = $Suite.PSObject.Properties["suites"]' in runner
    assert "if ($null -ne $children)" in runner
    assert "foreach ($child in @($children.Value))" in runner
    assert "foreach ($child in @($Suite.suites))" not in runner


def test_v09_final_runner_accepts_intentional_empty_skip_inventories() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    boundaries = (
        ("function Get-OrdinalStrings", "function Assert-ExactSet", "[object[]]$Values"),
        ("function Assert-ExactSet", "function Assert-ExactProperties", "[object[]]$Expected"),
        ("function Assert-JUnitContract", "function New-JUnitSuiteDeclaration", "[string[]]$AllowedSkips"),
        ("function New-JUnitSuiteDeclaration", "function Assert-FinalToolchain", "[string[]]$AllowedSkips"),
    )
    for start, end, parameter in boundaries:
        function = runner[runner.index(start) : runner.index(end)]
        assert "[AllowEmptyCollection()]" in function
        assert parameter in function
    assert "SkippedNodes = [string[]]@(Get-OrdinalStrings $skips.ToArray())" in runner
    assert 'Assert-JUnitContract $postgresXml $postgresNodes @() "backend PostgreSQL"' in runner
    assert 'Assert-JUnitContract $dockerHostXml $runtimeNodes @() "backend Docker host"' in runner
    assert 'Assert-JUnitContract $driverXml $driverNodes @() "driver host"' in runner
    assert 'Assert-JUnitContract $toolingXml $toolingNodes @() "tooling" 36' in runner


def test_v09_final_runner_stages_only_ledger_bound_external_manuals() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert "78c419f898bbc719e9e1134f8e57aa0352a07cd2b4d21644658f3f74237c56ad" in runner
    assert runner.count('2.4.4.pdf" = "') == 6
    assert '"SPELL-GUI-4.0.2-Build-Instructions.pdf" = "' in runner
    assert 'Get-ManualLedgerMap (Join-Path $sourceRoot "SPELL_DOCUMENTATION_REVIEW.md")' in runner
    assert '$externalManualSource = Join-Path $root "SPELL-DOCUMENTATION"' in runner
    assert '$stagedManualRoot = Join-Path $sourceRoot "SPELL-DOCUMENTATION"' in runner
    assert "$manualLedger.Count -ne 7" in runner
    assert "external-manual source hash differs" in runner
    assert "staged external-manual hash differs" in runner
    assert runner.index("$stagedManualRoot =") < runner.index(
        "$qualificationDockerfile ="
    )


def test_v09_final_runner_probes_exact_manual_and_schema_bytes_in_image() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    ignore_lines = QUALIFICATION_IGNORE.read_text(encoding="utf-8").splitlines()
    manual_mount = (
        'type=bind,source=$stagedManualRoot,'
        'target=/qualification-source/SPELL-DOCUMENTATION,readonly'
    )
    probe_start = runner.index("$imageInputProbeResult =")
    probe_end = runner.index(
        'Assert-NativeSuccess "qualification image input probe failed"', probe_start
    )
    probe = runner[probe_start:probe_end]

    assert '"artifacts/v0.9/work-package/schema.json"' in runner
    assert "$schemaBinding = $candidateEvidence.toolchain.files_sha256" in runner
    assert "frozen candidate schema binding differs" in runner
    assert runner.count(f'$manualEvidenceMount = "{manual_mount}"') == 1
    assert runner.index("$manualEvidenceMount =") < probe_start
    assert "--mount $manualEvidenceMount --entrypoint python" in probe
    assert '$imageInputHashes["SPELL-DOCUMENTATION/$($entry.Key)"]' in runner
    assert "actual_manuals != expected_manuals or len(expected_manuals) != 7" in runner
    assert 'print("qualification-inputs=PASS files=8")' in runner
    assert '"qualification-inputs=PASS files=8"' in runner
    assert "exec(base64.b64decode(sys.argv.pop(1)))" in runner
    assert "expected = json.loads(base64.b64decode(sys.argv[1]))" in runner
    assert "[Convert]::ToBase64String(" in runner
    assert "$imageInputHashesPayload = [Convert]::ToBase64String(" in runner
    assert (
        "-c $imageInputProbeLauncher $imageInputProbePayload `\n"
        "    $imageInputHashesPayload"
    ) in runner
    assert "-c $imageInputProbe (" not in runner
    assert ignore_lines.index("artifacts/v0.9") < ignore_lines.index(
        "!artifacts/v0.9/"
    )
    assert ignore_lines.index("!artifacts/v0.9/") < ignore_lines.index(
        "artifacts/v0.9/*"
    )
    assert ignore_lines.index("artifacts/v0.9/work-package/*") < ignore_lines.index(
        "!artifacts/v0.9/work-package/schema.json"
    )


def test_v09_final_runner_enforces_full_bijections_and_skip_contracts() -> None:
    from scripts import validate_release_evidence_v09 as release_validator

    runner = RUNNER.read_text(encoding="utf-8")
    skip_block = runner.split("$sqliteAllowedSkips = @(", 1)[1].split("\n)", 1)[0]
    runner_sqlite_skips = tuple(re.findall(r'"(backend/tests/[^\"]+)"', skip_block))

    assert runner.count("Assert-JUnitContract") >= 7
    assert "backend SQLite" in runner
    assert "backend PostgreSQL" in runner
    assert "driver host" in runner
    assert '"tooling"' in runner
    assert "frontend unit collection/run bijection" in runner
    assert "mocked browser" in runner
    assert "real browser" in runner
    assert runner_sqlite_skips == release_validator.SQLITE_ALLOWED_SKIPS
    assert runner.count("backend/tests/test_migrations.py::") >= 5
    assert runner.count("backend/tests/test_driver_isolation.py::") >= 4
    assert (
        "backend/tests/test_data_migration_recovery_v08.py::"
        "test_v0007_postgresql_schema_and_fingerprint_match_sqlite_contract"
    ) in runner
    assert "host-only tooling node inventory differs" in runner
    assert "$hostToolingNodes.Count -ne 30" in runner
    assert (
        'scripts/tests/test_release_v09.py::'
        "test_v09_package_scans_candidate_manifest_and_tooling_structurally"
    ) in runner
    assert (
        'scripts/tests/test_release_v09.py::'
        "test_v09_package_rejects_duplicate_or_mislocated_evidence_canaries"
    ) in runner
    assert (
        'scripts/tests/test_release_v09.py::'
        "test_v09_package_publication_fault_rolls_back_executably"
    ) in runner
    assert (
        'scripts/tests/test_validate_release_evidence_v09.py::'
        "test_require_tag_validates_real_annotated_object_target_markers_and_sidecar"
    ) in runner
    for node in (
        "scripts/tests/test_qualify_release_v07.py::"
        "test_v07_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v07.py::"
        "test_v07_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v07.py::"
        "test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v06.py::"
        "test_v06_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v06.py::"
        "test_v06_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v06.py::"
        "test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
    ):
        assert node in runner
    assert "$postgresXml = $postgresBaseXml" in runner
    assert "$dockerHostXml = $postgresRuntimeXml" in runner
    assert (
        "foreach ($node in @($hostToolingNodes) + @($offlineToolingNodes) + @($rootExternalToolingNodes) + "
        "@($v05ExportToolingNodes) + @($v06ExportToolingNodes) + @($v07ExportToolingNodes) + @($v08ExportToolingNodes))"
    ) in runner
    assert (
        "$toolingV06Xml, $toolingV07Xml, $toolingV08Xml, $toolingOfflineXml"
        in runner
    )
    assert '$env:SPELL_V09_OFFLINE_PROOF = "1"' in runner
    assert '$env:SPELL_V09_OFFLINE_NPM_CACHE_VOLUME = $offlineCacheVolume' in runner
    assert "npm cache verify --cache /npm-cache" in runner
    assert "v0.9 offline package qualification failed" in runner
    assert "$rootExternalToolingNodes = @(" in runner
    assert (
        "scripts/tests/test_validate_release_evidence_v09.py::"
        "test_v09_inherited_v08_binding_includes_external_archive_sidecar_and_tag"
    ) in runner
    assert "@rootExternalToolingNodes -q" in runner
    assert "locked-host accepted-release external tests failed" in runner
    inherited_history_current_root = (
        "scripts/tests/test_accepted_v05_release_v06.py::"
        "test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact",
        "scripts/tests/test_accepted_v05_release_v06.py::"
        "test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/"
        "openbexi-spell-v0.5.0.tar.gz-archive SHA-256 differs]",
        "scripts/tests/test_accepted_v05_release_v06.py::"
        "test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/"
        "openbexi-spell-v0.5.0.tar.gz.sha256-sidecar bytes differ]",
        "scripts/tests/test_accepted_v05_release_v06.py::"
        "test_accepted_v05_tag_claim_rejects_raw_object_mutation",
        "scripts/tests/test_validate_release_evidence_v06.py::"
        "test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag",
        "scripts/tests/test_validate_candidate_evidence_v06.py::"
        "test_candidate_schema_and_runner_are_version_scoped_and_atomic",
        "scripts/tests/test_accepted_v06_release_v07.py::"
        "test_accepted_v06_tag_blobs_archive_and_sidecar_are_exact",
        "scripts/tests/test_validate_release_evidence_v07.py::"
        "test_v07_inherited_v06_binding_includes_external_archive_sidecar_and_tag",
    )
    v05_export = (
        "scripts/tests/test_release_v05.py::"
        "test_current_v05_product_package_fingerprint_is_constructible",
        "scripts/tests/test_validate_release_evidence_v05.py::"
        "test_repository_release_validation_is_positive_or_fails_closed_before_publication",
    )
    for node in inherited_history_current_root + v05_export:
        assert runner.count(f'"{node}"') == 1
    assert "$rootExternalToolingNodes.Count -ne 31" in runner
    assert "$v05ExportToolingNodes = @(" in runner
    assert "@v05ExportToolingNodes -q" in runner
    assert "accepted-v0.5 export tooling tests failed" in runner
    assert '--deselect=scripts/tests"' not in runner
    assert '--deselect=scripts/tests/test_' not in runner
    assert 'Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"' in runner
    assert "refusing an accepted-v0.5 tooling export outside the temporary root" in runner
    assert "git -C $root worktree add --detach $v05Worktree v0.5.0" in runner
    assert 'if ($v05Head -cne "e7b6bb9428833437e0160040541eb840deee7cca")' in runner
    assert runner.count("foreach ($releaseRoot in @($v05Worktree, $v06Worktree, $v07Worktree))") == 2
    assert 'Join-Path $releaseRoot "artifacts/v0.5/$releaseName"' in runner
    assert 'Join-Path $releaseRoot "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"' in runner
    assert "accepted-v0.5 staged release sidecar bytes differ" in runner
    assert "accepted-v0.5 tooling export teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv6-$($runId.Substring(0, 12))"' in runner
    assert "refusing an accepted-v0.6 tooling export outside the temporary root" in runner
    assert "git -C $root worktree add --detach $v06Worktree v0.6.0" in runner
    assert 'if ($v06Head -cne "05ec783a6e54a76e0548bdd536c18538f6bff51b")' in runner
    assert "accepted-v0.6 export tooling tests failed" in runner
    assert "accepted-v0.6 tooling export teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv7-$($runId.Substring(0, 12))"' in runner
    assert "refusing an accepted-v0.7 tooling export outside the temporary root" in runner
    assert "git -C $root worktree add --detach $v07Worktree v0.7.0" in runner
    assert 'if ($v07Head -cne "cf18e9d887ba0476cbcc3d8194e321332a3ae864")' in runner
    assert 'Copy-Item -LiteralPath $stagedManualRoot -Destination $v07ManualDestination -Recurse' in runner
    assert 'assert_accepted_v07_release_v08.ps1") -Root $v07Worktree' in runner
    assert "accepted-v0.7 tracked release binding differs in detached worktree" in runner
    assert "staged release input differs" not in runner
    assert "46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d/regression" in runner
    assert 'Copy-Item -LiteralPath $v07InheritedSource -Destination $v07InheritedDestination -Recurse' in runner
    assert "git -C $root worktree remove --force $v07Worktree" in runner
    assert "accepted-v0.7 export tooling tests failed" in runner
    for node in (
        "scripts/tests/test_qualification_image_v07.py::test_v07_qualification_baseline_inputs_exist_as_regular_files",
        "scripts/tests/test_source_fingerprint_v07.py::test_v07_source_fingerprint_includes_gate_0a_and_contract_inputs",
        "scripts/tests/test_validate_candidate_evidence_v07.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
    ):
        assert runner.count(f'"{node}"') == 1
    assert 'Join-Path $env:TEMP "sv8-$($runId.Substring(0, 12))"' in runner
    assert "refusing an accepted-v0.8 tooling export outside the temporary root" in runner
    assert "git -C $root worktree add --detach $v08Worktree v0.8.0" in runner
    assert 'if ($v08Head -cne "d6e01222de3bf52013279e48a099b6ae7ded121d")' in runner
    assert 'assert_accepted_v08_release_v09.ps1") -Root $v08Worktree' in runner
    assert "accepted-v0.8 export tooling tests failed" in runner
    assert "accepted-v0.8 tooling export teardown failed" in runner
    assert 'SPELL_TEST_DATABASE_URL=$applicationUrl' in runner
    assert 'SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl' in runner
    assert 'POSTGRES_DB=spell_test' in runner
    assert "spell_migration_test" in runner
    assert "Normalize-BrowserJUnit" in runner
    assert 'Assert-JUnitContract $toolingXml $toolingNodes @() "tooling" 36' in runner
    assert '$suite.SetAttribute("tests", [string]$reportedTests)' in runner
    assert "SubtestCount = $reportedTests - $nodes.Count" in runner


def test_v09_final_runner_uses_typed_fail_closed_cleanup_inspection() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    cleanup = runner[
        runner.index("function Invoke-DockerCleanup") :
        runner.index("function Invoke-ComposeCleanup")
    ]

    assert "[OutputType([pscustomobject])]" in cleanup
    assert "[string[]]$lines = @()" in cleanup
    assert "[int]$code = -1" in cleanup
    assert "[pscustomobject]$inspection = Invoke-DockerCleanup" in runner
    assert "@(Invoke-DockerCleanup" not in runner
    assert "$inspection.ExitCode -ne 0" in runner
    assert "$inspection.Lines | Where-Object" in runner


def test_v09_final_runner_captures_exact_nine_suite_contract() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    match = re.search(r"\$finalSuiteIds = @\((.*?)\n\)", runner, re.DOTALL)
    assert match is not None
    suite_ids = re.findall(r'"([a-z_]+)"', match.group(1))

    assert suite_ids == [
        "backend_sqlite",
        "backend_postgresql",
        "backend_docker_host",
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
        "backend-docker-host.xml",
        "driver-host.xml",
        "tooling.xml",
        "frontend-unit.json",
        "frontend-build.json",
        "browser-mocked.xml",
        "browser-real.xml",
    ):
        assert name in runner
    assert 'schema_version = "spell.v09.frontend-build/1"' in runner
    assert 'command = @("npm", "run", "build")' in runner
    assert "Get-TreeDigest" in runner
    assert "subtest_count = [int]$Result.SubtestCount" in runner
    assert "test_count = [int]$vitest.numTotalTests; subtest_count = 0" in runner


def test_v09_final_runner_binds_gate_source_product_and_candidate_evidence() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert 'schema_version = "spell.v09.final-qualification/1"' in runner
    assert "source_fingerprint_sha256 = $sourceFingerprint" in runner
    assert "product_package_sha256 = $productPackageSha256" in runner
    assert "work_package = [ordered]@{" in runner
    assert "gate_0b = [ordered]@{" in runner
    assert "toolchain = $finalToolchain" in runner
    assert "final_qualification_image_id = [string]$script:QualificationImage" in runner
    assert "candidate_qualification_image_id" in runner
    assert "Assert-FinalToolchain $summary.toolchain" in runner
    assert "final qualification toolchain immutable binding differs" in runner
    assert "evidence_sha256 = Get-LowerSha256" in runner
    assert "validator_sha256 = Get-LowerSha256" in runner
    assert "candidate_commit = $candidateCommit" in runner
    assert "Gate 0B success marker differs" in runner
    assert "accepted_exceptions = @()" in runner
    assert "secrets_retained = $false" in runner
    assert "Assert-V08ArtifactsUnchanged $resolvedSource" in runner
    assert '"e2e/operator-workspace.spec.ts"' in runner
    assert '"e2e/data-services.spec.ts"' in runner
    assert '"e2e/development-workspace.spec.ts"' in runner
    assert '"e2e/data-services-real.spec.ts"' in runner
    assert '"e2e/telemetry-observation-real.spec.ts"' in runner
    assert '"e2e/development-workspace-real.spec.ts"' in runner
    assert "--subject v09-final-development-author --role operator" in runner
    assert "--subject v09-final-development-reviewer --role admin" in runner
    assert "$env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken" in runner
    assert "$env:SPELL_E2E_ADMIN_TOKEN = $adminToken" in runner
    assert '$env:SPELL_REAL_BACKEND = "1"' in runner
    assert "real-browser role token output is invalid or not distinct" in runner
    assert "Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN" in runner
    assert "Remove-Item Env:SPELL_E2E_ADMIN_TOKEN" in runner
    assert "$savedBrowser = $null" in runner
    assert "$savedJwtSecret = $null" in runner
    assert runner.count('-f (Join-Path $sourceRoot "compose.yaml")') >= 4
    assert 'python /app/scripts/seed_observation_v07.py' in runner
    assert '--context-id $env:SPELL_TELEMETRY_CONTEXT_ID' in runner
    assert '$env:SPELL_TELEMETRY_CONTEXT_ID = "v09-telemetry-synthetic-context"' in runner
    assert '$env:SPELL_BROWSER_CAPTURE_DIRECTORY' in runner
    assert '$env:SPELL_E2E_ARTIFACT_DIRECTORY = $env:SPELL_BROWSER_CAPTURE_DIRECTORY' in runner
    assert '$env:SPELL_QUALIFICATION_IMAGE_ID = $script:QualificationImage' in runner
    assert "driver-projection-real.spec.ts" not in runner


def test_v09_final_runner_serializes_only_the_stateful_live_browser_suite() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    mocked_run = "& npx playwright test @mockSpecs --reporter=junit --retries=0"
    real_run = (
        "& npx playwright test @realSpecs --reporter=junit --retries=0 --workers=1"
    )

    assert mocked_run in runner
    assert f"{mocked_run} --workers=1" not in runner
    assert real_run in runner
    assert runner.count("--workers=1") == 1


def test_v09_final_runner_only_publishes_final_after_cleanup_and_validation() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    cleanup = runner.index("$qualificationResourcesTornDown = $cleanupFailures.Count -eq 0")
    stage_validation = runner.index("$validatedSummary = Assert-FinalPublication $publicationStage")
    publish = runner.index("Move-Item -LiteralPath $publicationStage -Destination $canonicalFinal")
    published_validation = runner.index("$published = Assert-FinalPublication $canonicalFinal")

    assert cleanup < stage_validation < publish < published_validation
    assert 'Join-Path $artifactRoot ".qualification/final-$runId"' in runner
    assert 'Join-Path $artifactRoot "final"' in runner
    assert 'Join-Path $root "artifacts/v0.9/final"' in runner
    assert "release-qualification.json" not in runner
    assert "validate_release_evidence_v09.py --root" not in runner
    assert '$artifactRoot = Join-Path $root "artifacts/v0.9"' in runner
    assert '$artifactRoot = Join-Path $root "artifacts/v0.4' not in runner
    assert "artifacts/v0.4/browser" not in runner
    assert "Remove-Item -LiteralPath $canonicalFinal -Recurse -Force" in runner
    assert "Move-Item -LiteralPath $publicationBackup -Destination $canonicalFinal" in runner


def test_v09_final_runner_tears_down_only_owned_resources() -> None:
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
