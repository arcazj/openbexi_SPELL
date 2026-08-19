from __future__ import annotations

import ast
import base64
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate_candidate_evidence_v09.py"
SPEC = importlib.util.spec_from_file_location("validate_candidate_evidence_v09", VALIDATOR_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)
PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"


def _junit(path: Path, cases: list[tuple[str, str, str]], *, suite: str = "pytest") -> None:
    skipped = sum(status == "skipped" for _, _, status in cases)
    failures = sum(status == "failure" for _, _, status in cases)
    errors = sum(status == "error" for _, _, status in cases)
    rows = []
    for classname, name, status in cases:
        child = "" if status == "passed" else f"<{status}/>"
        rows.append(f'<testcase classname="{classname}" name="{name}" time="0.01">{child}</testcase>')
    path.write_text(
        f'<testsuites><testsuite name="{suite}" tests="{len(cases)}" skipped="{skipped}" '
        f'failures="{failures}" errors="{errors}">{"".join(rows)}</testsuite></testsuites>',
        encoding="utf-8",
    )


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    )


def _development_png(*, padding: int = 10_050) -> bytes:
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1280, 720, 8, 6, 0, 0, 0)),
            _png_chunk(b"tEXt", b"qualification\x00" + b"x" * padding),
            _png_chunk(b"IDAT", zlib.compress(b"")),
            _png_chunk(b"IEND", b""),
        )
    )


def test_gate_defines_exact_nine_packages_and_45_test_ids() -> None:
    assert validator.PRODUCT_INVENTORY_FROZEN is True
    assert tuple(validator.WORK_PACKAGE_TEST_IDS) == tuple(
        f"V09-DEV-{index:03d}" for index in range(1, 10)
    )
    assert all(len(ids) == 5 for ids in validator.WORK_PACKAGE_TEST_IDS.values())
    assert len(validator.TEST_IDS) == len(set(validator.TEST_IDS)) == 45
    assert validator.FROZEN_SUITE_INVENTORIES == {
        "backend_sqlite": (923, "cb1e76d67e36de5844976c6576999d2322823e3b33318913757ba332db78dd68"),
        "backend_postgresql": (923, "cb1e76d67e36de5844976c6576999d2322823e3b33318913757ba332db78dd68"),
        "backend_docker_host": (3, "b8229fbf14291878413f3b58d304d3138e6e1c4e3d87a8be5285a3c418281567"),
        "backend_v09_soak": (7, "b77a0b1776055356b05eed0d27f70ee2c3bf4657ec34816ff928cc380939a4d0"),
        "driver_host": (82, "a3c0a451d7292c46c2f06fe6924c1b35d9c1b2031940f67a862555d38d534593"),
        "tooling": (1050, "1022465fb4518a89ea3a6ae762bd96db77887215a2c8de9313e1a0cf4e2f7509"),
        "frontend_vitest": (105, "81667150bb1df07891eebfb7bf06a852e007554bdc6ba17ec18437abec495899"),
        "frontend_build": (1, "038b2fb5e8e04bad387c5eb973bba58e1349f6184355526d25f3b64e0d08e53e"),
        "frontend_playwright_mocked": (20, "10ad9cd8182a116b3ce3570cba7cd7d20b654f10c2859c4d1a9c7371a10f1f3b"),
        "frontend_playwright_live": (14, "65995d29961887422abeba749ab726ae884bccebfb84c5896c6610a3a67e8fad"),
    }


@pytest.mark.parametrize(
    "node",
    sorted(validator.TOOLING_ALLOWED_SKIPS),
)
def test_tooling_skip_allowlist_contains_only_exact_platform_nodes(node: str) -> None:
    assert node in validator.TOOLING_ALLOWED_SKIPS


def test_tooling_skip_allowlist_rejects_other_tests_in_an_allowed_module() -> None:
    validator_source = VALIDATOR_PATH.read_text(encoding="utf-8")
    assert len(validator.TOOLING_ALLOWED_SKIPS) == 14
    assert {
        "scripts/tests/test_qualify_release_v05.py::test_v05_final_runner_parses_as_powershell",
        "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell",
        "scripts/tests/test_qualify_release_v09.py::test_v09_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v05.py::test_v05_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_release_v09.py::test_v09_package_publication_fault_rolls_back_executably",
    } <= validator.TOOLING_ALLOWED_SKIPS
    assert (
        "scripts/tests/test_release_v07.py::test_v07_package_rejects_private_key_bytes"
        not in validator.TOOLING_ALLOWED_SKIPS
    )
    assert 'or "release_v06" in node' in validator_source


def test_sqlite_skip_allowlist_is_the_exact_postgresql_and_docker_host_set() -> None:
    assert validator.SQLITE_ALLOWED_SKIPS == {
        "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
        "backend/tests/test_development_postgresql_v09.py::test_v0008_postgresql_schema_and_logical_fingerprint_match_contract",
        "backend/tests/test_development_postgresql_v09.py::test_postgresql_development_idempotency_race_and_catalog_promotion",
        "backend/tests/test_data_catalog_v08.py::test_catalog_dependency_graph_is_verified_on_postgresql",
        "backend/tests/test_data_containers_v08.py::test_two_owners_can_use_the_same_container_id_on_postgresql",
        "backend/tests/test_data_migration_recovery_v08.py::test_postgresql_backup_reconstructs_exact_isolated_manual_target",
        "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
        "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
        "backend/tests/test_driver_isolation.py::test_live_bundle_builders_are_networkless_independent_and_reproducible",
        "backend/tests/test_dictionary_exchange_v08.py::test_two_owners_can_use_the_same_dictionary_id_on_postgresql",
        "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
        "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
        "backend/tests/test_migrations.py::test_v0007_postgresql_preflight_fails_closed_before_ddl",
        "backend/tests/test_data_migration_recovery_v08.py::test_v0007_postgresql_schema_and_fingerprint_match_sqlite_contract",
        "backend/tests/test_shared_data_v08.py::test_two_owners_can_use_the_same_namespace_id_on_postgresql",
        "backend/tests/test_shared_data_v08.py::test_postgresql_latest_revision_reconstruction_uses_parent_row_locks",
    }


def test_candidate_schema_and_runner_are_version_scoped_and_atomic() -> None:
    schema = json.loads(
        (ROOT / "artifacts/v0.9/work-package/schema.json").read_text(encoding="utf-8")
    )
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    validator_source = VALIDATOR_PATH.read_text(encoding="utf-8")
    assert schema["properties"]["schema_version"]["const"] == validator.SCHEMA_VERSION
    assert "spell.v07.candidate-qualification" not in json.dumps(schema)
    assert "[string]$SourceCommit" in runner
    assert "candidate qualification requires a clean explicit source freeze" in runner
    assert "git archive --format=zip --output=$candidateArchive $SourceCommit" in runner
    assert 'Join-Path $artifactRoot ".qualification/candidate-$runId"' in runner
    assert "candidate staging evidence validation failed" in runner
    assert runner.index("candidate staging evidence validation failed") < runner.index(
        "Move-Item -LiteralPath $stageRoot -Destination $canonicalRoot"
    )
    assert "artifacts/v0.7/work-package" not in runner
    assert "qualification-v07.Dockerfile" not in runner
    immutability = schema["properties"]["v0_8_immutability"]
    assert immutability["additionalProperties"] is False
    assert immutability["properties"]["accepted_archive_sha256"]["const"] == (
        "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
    )
    assert immutability["properties"]["accepted_sidecar_sha256"]["const"] == (
        "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
    )
    assert 'Join-Path $env:TEMP "sv7-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.7.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyRoot v0.7.0" in runner
    assert "git -C $root worktree remove --force $legacyRoot" in runner
    assert "v0.7.0 historical checkout teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv6-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.6.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyV06Root v0.6.0" in runner
    assert "git -C $root worktree remove --force $legacyV06Root" in runner
    assert "v0.6.0 historical checkout teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.5.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyV05Root v0.5.0" in runner
    assert "git -C $root worktree remove --force $legacyV05Root" in runner
    assert "v0.5.0 historical checkout teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv8-$($runId.Substring(0, 12))"' in runner
    assert "git -C $root worktree add --detach --quiet $legacyV08Root v0.8.0" in runner
    assert "git -C $root worktree remove --force $legacyV08Root" in runner
    assert "v0.8.0 historical checkout teardown failed" in runner
    assert "accepted_v08_release_v09.py" in runner
    assert '"v0.8.0 is not an ancestor of source"' in validator_source
    assert '"v0.7.0 is not an ancestor of source"' not in validator_source
    assert 'Join-Path $env:TEMP "openbexi-spell-v05-py313-site"' in runner
    assert "openbexi-spell-v07-py313-site" not in runner


def test_v09_candidate_runner_parses_as_powershell() -> None:
    runner = ROOT / "scripts/qualify_candidate_v09.ps1"
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell parser is unavailable")
    escaped = str(runner).replace("'", "''")
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


def test_v09_candidate_runner_isolates_every_locked_host_python_producer() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(
        encoding="utf-8"
    )
    invocations = [
        line.strip()
        for line in runner.splitlines()
        if "& $script:LockedPython " in line
    ]

    assert len(invocations) == 17
    assert all(" -I " in line for line in invocations)
    assert runner.count("Start-Process -FilePath $script:LockedPython") == 1
    assert (
        '-ArgumentList @("-I", $launcher, $script:SitePackages, $candidateRoot)'
        in runner
    )


def test_v09_candidate_tooling_mounts_external_manuals_without_baking_them() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(
        encoding="utf-8"
    )
    ignore = (
        ROOT / "scripts/qualification-v09.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")

    assert "SPELL-DOCUMENTATION" in ignore.splitlines()
    assert (
        'type=bind,source=$stagedManualRoot,'
        'target=/qualification-source/SPELL-DOCUMENTATION,readonly'
        in runner
    )
    assert '$toolingArguments $toolingBaseXml -Mounts @($manualEvidenceMount)' in runner


def test_v09_offline_package_proof_is_containerized_and_runner_bound() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(
        encoding="utf-8"
    )
    proof = (ROOT / "scripts/tests/test_v09_offline_package.py").read_text(
        encoding="utf-8"
    )

    for marker in (
        "sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48",
        "sha256:89924b46ec81c1c0eb0055a7d72790b8067a16a5d0d0512e8117a01aa4a5d7ee",
        "$volumes.Add($offlineCacheVolume)",
        "pinned offline Playwright image is not preinstalled",
        "cannot seed the verified offline npm cache",
        "cp /source/package.json /source/package-lock.json /tmp/work/",
        '$env:SPELL_V09_OFFLINE_PROOF = "1"',
        '$env:SPELL_V09_OFFLINE_SOURCE_ROOT = $candidateRoot',
        '$env:SPELL_V09_OFFLINE_QUALIFICATION_IMAGE = $qualificationImage',
        "$savedOfflineEnvironment = [ordered]@{}",
        "$savedOfflineEnvironment = $null",
    ):
        assert marker in runner
    for marker in (
        '"--network",\n            "none"',
        '"NPM_CONFIG_OFFLINE=true"',
        '"npm",\n                "ci",\n                "--offline",\n                "--ignore-scripts"',
        '_run([*container_base, "npm", "run", "build"])',
        '_run([*container_base, "node", "-e", browser_probe])',
        "_assert_network_none(docker, web_container)",
        "_assert_network_none(docker, api_container)",
        "pathlib.Path('/tmp/spell-backups').mkdir()",
    ):
        assert marker in proof


def test_runner_executes_full_matrix_and_reroutes_only_source_bound_nodes() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    for marker in (
        'Get-CollectedNodes "backend/tests"',
        'Get-CollectedNodes "driver_host/tests"',
        'Get-CollectedNodes "scripts/tests"',
        '"SPELL_TEST_DATABASE_URL=$applicationUrl"',
        '"SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl"',
        '"spell_migration_test"',
        'npm run build',
        'playwright test e2e/operator-workspace.spec.ts',
        'e2e/driver-projection.spec.ts',
        '"e2e/integration.spec.ts"',
        'playwright test e2e/telemetry-observation-real.spec.ts',
        'SPELL_DRIVER_ENABLED = "true"',
        'seed_observation_v07.py',
        '--context-id $env:SPELL_TELEMETRY_CONTEXT_ID',
        'e2e/data-services.spec.ts',
        'e2e/development-workspace.spec.ts',
        'e2e/data-services-real.spec.ts',
        'e2e/development-workspace-real.spec.ts',
        'Get-ComposeImageId "bundle-builder-a"',
        'Get-ComposeImageId "bundle-builder-b"',
        'Assert-ComposeServiceNetworkNone "bundle-builder-a"',
        'Assert-ComposeServiceNetworkNone "bundle-builder-b"',
        'bundle builders do not share the exact backend image',
        '{{.HostConfig.NetworkMode}}',
        '--subject "v09-candidate-development-author" --role operator',
        '--subject "v09-candidate-development-reviewer" --role admin',
        '$env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken',
        '$env:SPELL_E2E_ADMIN_TOKEN = $adminToken',
        '$env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-live-base-output"',
        '$env:SPELL_BROWSER_RUN_ID = $runId',
        '& $npxExe playwright test @realSpecs --reporter=junit --retries=0 --workers=1',
        '"v09-cross-feature-replay-soak"',
        '"DATABASE_URL", "SPELL_DATA_DIR", "SPELL_V0007_BACKUP_DIR"',
        '$env:SPELL_DATA_DIR = $liveDataRoot',
        '$env:SPELL_V0007_BACKUP_DIR = $liveBackupRoot',
        'Write-ProcessDiagnostics $ProcessLabel $LogPaths',
        'Get-Content -LiteralPath $path -Tail 200',
        '-LogPaths @($backendStdout, $backendStderr)',
        'backend/tests/test_development_runtime_race_v09.py::test_sqlite_idempotency_races_and_restart_job_recovery',
        'backend/tests/test_driver_isolation.py::test_live_bundle_builders_are_networkless_independent_and_reproducible',
        '--identity-map',
        '--junit "backend_sqlite=python=',
        '--junit "backend_docker_host=python=',
        '--junit "tooling=python=',
    ):
        assert marker in runner
    from scripts import validate_candidate_evidence_v08 as v08_validator

    inherited = set(v08_validator.REROUTED_TOOLING_TESTS)
    current = {
        "scripts/tests/test_qualification_image_v08.py::test_v08_qualification_baseline_inputs_exist_as_regular_files",
        "scripts/tests/test_source_fingerprint_v08.py::test_v08_source_fingerprint_includes_gate_0a_and_contract_inputs",
        "scripts/tests/test_validate_candidate_evidence_v08.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
        "scripts/tests/test_release_v08.py::test_current_v08_product_package_fingerprint_is_constructible",
        "scripts/tests/test_validate_release_evidence_v08.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication",
        "scripts/tests/test_qualify_release_v08.py::test_v08_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v08.py::test_v08_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_tag_blobs_archive_and_sidecar_are_exact",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz-workspace archive SHA-256 differs]",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256-workspace sidecar bytes differ]",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_raw_tag_mutation",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_tagged_blob_payload_mutation",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_artifact_tree_mutation",
        "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_cli_emits_one_canonical_json_object",
        "scripts/tests/test_accepted_v08_release_v09.py::test_v09_powershell_assertion_is_parseable_and_reuses_canonical_validator",
        "scripts/tests/test_validate_candidate_evidence_v09.py::test_v09_candidate_runner_parses_as_powershell",
        "scripts/tests/test_validate_release_evidence_v09.py::test_v09_inherited_v08_binding_includes_external_archive_sidecar_and_tag",
        "scripts/tests/test_validate_release_evidence_v09.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        validator.OFFLINE_PACKAGE_NODE,
    }
    assert set(validator.REROUTED_TOOLING_TESTS) == inherited | current
    assert sum(
        source == "locked-windows-host-current-root"
        for source in validator.REROUTED_TOOLING_TESTS.values()
        ) == 31
    assert sum(
        source.startswith("locked-windows-host")
        for source in validator.REROUTED_TOOLING_TESTS.values()
    ) == 41
    assert "Invoke-LockedHostPytest $root" in runner
    assert "Invoke-LockedHostPytest $legacyV05Root" in runner
    assert "Invoke-LockedHostPytest $legacyV06Root" in runner
    assert "$toolingOfflineXml = Join-Path $captureRoot \"tooling-offline.xml\"" in runner
    assert "$toolingV08Xml, $toolingHostXml, $toolingOfflineXml" in runner
    assert "$offlineToolingNode = \"locked-windows-offline\"" in runner
    assert '$env:SPELL_V09_OFFLINE_PROOF = "1"' in runner
    assert '$env:SPELL_V09_OFFLINE_NPM_CACHE_VOLUME = $offlineCacheVolume' in runner
    assert "npm cache verify --cache /npm-cache" in runner
    assert "accepted_failures = @()" in runner
    assert "mapped_test_ids_skipped = @()" in runner
    assert "function Merge-JavaScriptJUnit" in runner
    assert "ImportNode($sourceSuite, $true)" in runner
    assert "Merge-JavaScriptJUnit @($liveBaseXml, $developmentXml)" in runner
    assert "Merge-JavaScriptJUnit @($liveBaseXml, $telemetryXml)" not in runner
    assert runner.count("--workers=1") == 3
    assert runner.count("--retries=0") == 4
    assert 'Remove-Item Env:SPELL_REAL_BACKEND' in runner
    assert '$env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-mocked-output"' in runner
    for relative in validator.DEVELOPMENT_SCREENSHOT_PATHS:
        assert f'"{relative}" = Join-Path $captureRoot "{relative}"' in runner
        assert relative in validator.BROWSER_ARTIFACT_PATHS
    assert "$operatorToken = $null" in runner
    assert "$adminToken = $null" in runner
    assert "$savedMockEnvironment = $null" in runner
    assert "$savedLiveEnvironment = $null" in runner
    assert "$savedTelemetryEnvironment = $null" in runner
    assert "Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN" in runner
    assert "Remove-Item Env:SPELL_E2E_ADMIN_TOKEN" in runner
    host_specs_start = runner.index("$realSpecs = @(")
    host_specs_end = runner.index(
        "& $npxExe playwright test @realSpecs", host_specs_start
    )
    assert "e2e/development-workspace-real.spec.ts" not in runner[
        host_specs_start:host_specs_end
    ]
    compose_start = runner.index("up -d --build --wait")
    compose_browser_run = runner.index(
        "playwright test e2e/development-workspace-real.spec.ts", compose_start
    )
    compose_browser = runner[compose_start:compose_browser_run]
    assert "--subject v09-candidate-development-author --role operator" in compose_browser
    assert "--subject v09-candidate-development-reviewer --role admin" in compose_browser
    assert "$env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken" in compose_browser
    assert "$env:SPELL_E2E_ADMIN_TOKEN = $adminToken" in compose_browser
    assert "Merge-JavaScriptJUnit @($liveBaseXml, $developmentXml)" in runner[
        compose_browser_run:
    ]
    assert 'if ($identityLines.Count -ne 1)' in runner
    assert "'^(V09-DEV-00[1-9])-[A-Z0-9-]+$'" in runner
    assert "Substring(0, 11)" not in runner


def test_identity_proofs_are_exact_direct_v09_nodes() -> None:
    assert set(validator.IDENTITY_PROOFS) == set(validator.TEST_IDS)
    allowed_suites = {
        "backend_sqlite",
        "backend_postgresql",
        "backend_docker_host",
        "frontend_vitest",
        "frontend_playwright_mocked",
        "frontend_playwright_live",
        "tooling",
    }
    forbidden_backend_families = (
        "test_data_",
        "test_dictionary_exchange_",
        "test_shared_data_",
        "test_virtual_files_",
    )
    for identity, proofs in validator.IDENTITY_PROOFS.items():
        assert proofs and len(proofs) == len(set(proofs)), identity
        for suite, node in proofs:
            assert suite in allowed_suites
            if node.startswith("backend/tests/"):
                assert not any(value in node for value in forbidden_backend_families), (
                    identity,
                    node,
                )
                assert any(
                    value in node
                    for value in (
                        "/test_development_",
                        "/test_v09_contract_matrices.py::",
                        "/test_driver_isolation.py::",
                    )
                ), (identity, node)
            elif suite == "tooling":
                assert node == validator.OFFLINE_PACKAGE_NODE
            else:
                assert node.startswith(
                    (
                        "src/development/development.test.tsx::",
                        "chromium::development-workspace",
                        "mobile::development-workspace",
                    )
                ), (identity, node)


def test_exact_backend_identity_nodes_exist_except_declared_product_gaps() -> None:
    missing: set[str] = set()
    for proofs in validator.IDENTITY_PROOFS.values():
        for suite, node in proofs:
            if not suite.startswith("backend_"):
                continue
            relative, function = node.split("::", 1)
            function = function.split("[", 1)[0]
            path = ROOT / relative
            if not path.is_file():
                missing.add(node)
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            functions = {
                item.name
                for item in ast.walk(tree)
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if function not in functions:
                missing.add(node)
    mapped = {
        node
        for proofs in validator.IDENTITY_PROOFS.values()
        for suite, node in proofs
        if suite.startswith("backend_")
    }
    assert not missing
    assert validator.UNRESOLVED_IDENTITY_NODES <= mapped
    assert (
        not validator.PRODUCT_INVENTORY_FROZEN
        or not validator.UNRESOLVED_IDENTITY_NODES
    )


def test_runner_stages_ledger_bound_manuals_and_only_the_candidate_schema() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    dockerignore = (
        ROOT / "scripts/qualification-v09.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8").splitlines()

    assert "78c419f898bbc719e9e1134f8e57aa0352a07cd2b4d21644658f3f74237c56ad" in runner
    assert runner.count('2.4.4.pdf" = "') == 6
    assert '"SPELL-GUI-4.0.2-Build-Instructions.pdf" = "' in runner
    assert 'Get-ManualLedgerMap (Join-Path $candidateRoot "SPELL_DOCUMENTATION_REVIEW.md")' in runner
    assert '$manualSource = Join-Path $root "SPELL-DOCUMENTATION"' in runner
    assert '$stagedManualRoot = Join-Path $candidateRoot "SPELL-DOCUMENTATION"' in runner
    assert "external-manual source inventory differs from the committed ledger" in runner
    assert "external-manual source hash differs" in runner
    assert "staged external-manual hash differs" in runner
    assert dockerignore.count("!artifacts/v0.9/work-package/schema.json") == 1
    assert "!artifacts/v0.9/work-package/qualification.json" not in dockerignore
    assert not any(line.startswith("!artifacts/v0.9/work-package/tests") for line in dockerignore)
    assert not any(line.startswith("!artifacts/v0.9/work-package/browser") for line in dockerignore)


def test_runner_cleanup_inspection_preserves_the_originating_failure() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    helper = runner[
        runner.index("function Get-DockerInspectionLines") : runner.index(
            "function Get-RuntimeResources"
        )
    ]

    assert 'if ($results.Count -ne 1)' in helper
    assert '$result.PSObject.Properties["ExitCode"]' in helper
    assert '$result.PSObject.Properties["Lines"]' in helper
    assert 'if ([int]$result.ExitCode -ne 0)' in helper
    assert ")).Lines" not in runner
    assert '$cleanupInspectionFailure = $_' in runner
    assert "candidate qualification failed: $($failure.Exception.Message); cleanup also failed:" in runner
    assert runner.index("if ($failure)") < runner.index("if ($cleanupInspectionFailure)", runner.index("if ($failure)"))


def test_runner_soak_launcher_preserves_encoded_python_and_separate_argv(
    tmp_path: Path,
) -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    nodes_match = re.search(
        r"\$soakNodes = @\(\n(?P<body>.*?)\n  \)", runner, re.DOTALL
    )
    code_match = re.search(r"\$soakCode = @'\n(?P<code>.*?)\n'@", runner, re.DOTALL)
    launcher_match = re.search(r'^  \$soakLauncher = "(?P<code>[^"]+)"$', runner, re.MULTILINE)
    assert nodes_match is not None
    assert sorted(re.findall(r'^\s+"([^"]+)"', nodes_match.group("body"), re.MULTILINE)) == list(
        validator.SOAK_NODES
    )
    assert code_match is not None
    assert launcher_match is not None
    soak_code = code_match.group("code") + "\n"
    launcher = launcher_match.group("code")
    compile(soak_code, "<candidate-soak>", "exec")
    probe_code = (
        "import json,pathlib,sys\n"
        "output=pathlib.Path(sys.argv.pop(1))\n"
        "output.write_text(json.dumps({'argv':sys.argv[1:]},sort_keys=True),encoding='utf-8')\n"
    )
    payload = base64.b64encode(probe_code.encode("utf-8")).decode("ascii")
    output = tmp_path / "soak.json"
    node = (
        "scripts/tests/test_validate_candidate_evidence_v09.py::"
        "test_gate_defines_exact_nine_packages_and_45_test_ids"
    )

    assert "'" not in launcher and '"' not in launcher
    assert "\r" not in launcher and "\n" not in launcher
    assert "base64.b64decode(sys.argv.pop(1))" in launcher
    assert 'subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *nodes, "-q"]' in soak_code
    assert "for iteration in range(1, 6):" in soak_code
    assert '"iterations":5' in soak_code
    assert "nodes = sys.argv[1:]" in soak_code
    assert "$soakPayload, \"/qualification-output/result.json\"" in runner
    assert "foreach ($node in $soakNodes) { $soakArguments += [string]$node }" in runner
    completed = subprocess.run(
        [sys.executable, "-c", launcher, payload, str(output), node],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout.decode() + completed.stderr.decode()
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document == {"argv": [node]}


def test_soak_evidence_requires_the_concurrent_load_and_recovery_inventory(
    tmp_path: Path,
) -> None:
    capture = tmp_path / validator.SUITE_PATHS["backend_v09_soak"]
    capture.parent.mkdir()

    def values(nodes: list[str], iterations: int) -> tuple[dict[str, object], dict[str, object]]:
        document = {
            "profile": "v09-cross-feature-replay-soak",
            "iterations": iterations,
            "nodes": nodes,
            "runs": [
                {"iteration": index, "exit_code": 0, "duration_seconds": 0.1}
                for index in range(1, iterations + 1)
            ],
            "passed": True,
        }
        summary = {
            "kind": "soak",
            "capture": validator.SUITE_PATHS["backend_v09_soak"],
            "collected_nodes": nodes,
            "inventory_sha256": validator.inventory_sha256(nodes),
            "test_count": iterations * len(nodes),
            "subtest_count": 0,
            "passed_count": iterations * len(nodes),
            "skipped_count": 0,
            "failure_count": 0,
            "error_count": 0,
            "duration_seconds": iterations / 10,
            "network_mode": "internal",
        }
        return document, summary

    nodes = list(validator.SOAK_NODES)
    document, summary = values(nodes, validator.SOAK_ITERATIONS)
    capture.write_text(validator.result_json(document) + "\n", encoding="utf-8")
    validator._validate_suite(tmp_path, "backend_v09_soak", summary)

    reduced = [
        node
        for node in nodes
        if "timeout_and_late_worker_leave_no_protocol_or_bundle_output" not in node
    ]
    document, summary = values(reduced, validator.SOAK_ITERATIONS)
    capture.write_text(validator.result_json(document) + "\n", encoding="utf-8")
    with pytest.raises(validator.CandidateEvidenceError, match="frozen test count differs"):
        validator._validate_suite(tmp_path, "backend_v09_soak", summary)


def test_runner_resolves_one_coherent_node_toolchain_for_inline_probe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")

    assert "$nodeCommands = @(Get-Command node -CommandType Application -ErrorAction Stop)" in runner
    assert "$nodeExe = [string]($nodeCommands[0].Source)" in runner
    assert '$nodeBin = Split-Path -Parent $nodeExe' in runner
    assert '$npmExe = Join-Path $nodeBin "npm.cmd"' in runner
    assert '$npxExe = Join-Path $nodeBin "npx.cmd"' in runner
    assert "coherent Node toolchain executable is missing" in runner
    assert "chromium.launch({headless:true})" in runner
    assert "Chromium runtime version is empty" in runner
    assert "$chromiumPath --version" not in runner
    assert "(Get-Command node -CommandType Application -ErrorAction Stop).Source" not in runner
    assert "(Get-Command npm.cmd -CommandType Application -ErrorAction Stop).Source" not in runner
    assert "(Get-Command npx.cmd -CommandType Application -ErrorAction Stop).Source" not in runner


def test_runner_surfaces_staging_validator_failure_detail() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")

    validation_command = "$validation = @(& $script:LockedPython -I $script:Validator"
    block_start = runner.rindex('$savedErrorAction = $ErrorActionPreference', 0, runner.index(validation_command))
    block_end = runner.index('if ($validationExitCode -ne 0)', block_start)
    block = runner[block_start:block_end]
    assert '$ErrorActionPreference = "Continue"' in block
    assert 'finally { $ErrorActionPreference = $savedErrorAction }' in block
    assert "$validationExitCode = $LASTEXITCODE" in runner
    assert "candidate staging evidence validation failed: $($validation -join '; ')" in runner


def test_runner_live_backend_launcher_is_windows_spawn_safe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    match = re.search(r"\$launcherBody = @'\n(?P<code>.*?)\n'@", runner, re.DOTALL)
    assert match is not None
    launcher = match.group("code") + "\n"
    compile(launcher, "<candidate-live-backend>", "exec")
    assert 'if __name__ == "__main__":' in launcher
    assert launcher.index('if __name__ == "__main__":') < launcher.index(
        "uvicorn.run("
    )


def test_runner_sorts_explicit_docker_nodes_before_junit_bijection() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v09.ps1").read_text(encoding="utf-8")
    match = re.search(
        r"\$dockerNodes = (?P<sort>[^\r\n]+) @\((?P<nodes>.*?)\r?\n  \)",
        runner,
        re.DOTALL,
    )
    assert match is not None
    assert match.group("sort") == "Get-OrdinalSortedStrings"
    assert "Assert-ExactInventory $dockerNodes $dockerSummary.collected_nodes" in runner


def test_strict_json_rejects_duplicate_nonfinite_and_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    for payload in (
        b'{"value":1,"value":2}',
        b'{"value":NaN}',
        b'\xff',
    ):
        path.write_bytes(payload)
        with pytest.raises(validator.CandidateEvidenceError):
            validator.read_json(path, "fixture")


def test_python_junit_is_exact_and_counts_subtests(tmp_path: Path) -> None:
    path = tmp_path / "python.xml"
    path.write_text(
        '<testsuites><testsuite name="pytest" tests="3" skipped="1" failures="0" errors="0">'
        '<testcase classname="backend.tests.test_example" name="test_pass" time="0.1"/>'
        '<testcase classname="backend.tests.test_example.TestCase" name="test_skip" time="0.2"><skipped/></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    result = validator.parse_junit(path, "fixture", "python")
    assert result.statuses == {
        "backend/tests/test_example.py::test_pass": "passed",
        "backend/tests/test_example.py::TestCase::test_skip": "skipped",
    }
    assert (result.passed, result.skipped, result.subtests) == (1, 1, 1)


def test_javascript_junit_preserves_project_identity(tmp_path: Path) -> None:
    path = tmp_path / "browser.xml"
    _junit(
        path,
        [("operator-workspace.spec.ts", "operates the dense v0.9 workspace", "passed")],
        suite="mobile",
    )
    result = validator.parse_junit(path, "browser", "javascript")
    assert result.statuses == {
        "mobile::operator-workspace.spec.ts::operates the dense v0.9 workspace": "passed"
    }


@pytest.mark.parametrize(
    "payload, message",
    [
        (
            '<!DOCTYPE testsuite [<!ENTITY x "bad">]><testsuite tests="0" skipped="0" failures="0" errors="0"/>',
            "XML declarations",
        ),
        (
            '<testsuite name="pytest" tests="1" skipped="0" failures="0" errors="0">'
            '<testcase classname="scripts.tests.test_one" name="test_a"/>'
            '<testcase classname="scripts.tests.test_one" name="test_a"/>'
            "</testsuite>",
            "aggregate",
        ),
    ],
)
def test_junit_rejects_unsafe_or_false_structure(
    tmp_path: Path, payload: str, message: str
) -> None:
    path = tmp_path / "bad.xml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(validator.CandidateEvidenceError, match=message):
        validator.parse_junit(path, "fixture", "python")


def _passing_result(nodes: list[str]) -> object:
    return validator.JUnitResult(
        {node: "passed" for node in nodes}, len(nodes), 0, 0, 0, 0, 1.0
    )


@pytest.mark.parametrize(
    ("suite_id", "spec", "names"),
    (
        (
            "frontend_playwright_mocked",
            "development-workspace.spec.ts",
            validator.DEVELOPMENT_MOCKED_TEST_NAMES,
        ),
        (
            "frontend_playwright_live",
            "development-workspace-real.spec.ts",
            validator.DEVELOPMENT_REAL_TEST_NAMES,
        ),
    ),
)
def test_development_browser_workflow_requires_every_desktop_and_mobile_node(
    suite_id: str, spec: str, names: tuple[str, ...]
) -> None:
    nodes = [
        f"{project}::{spec}::{name}"
        for project in ("chromium", "mobile")
        for name in names
    ]
    validator._validate_development_browser_workflow(suite_id, _passing_result(nodes))

    with pytest.raises(validator.CandidateEvidenceError, match="inventory differs"):
        validator._validate_development_browser_workflow(
            suite_id, _passing_result(nodes[:-1])
        )


def _passing_identity_results() -> dict[str, object]:
    nodes_by_suite: dict[str, set[str]] = {}
    for proofs in validator.IDENTITY_PROOFS.values():
        for suite, node in proofs:
            nodes_by_suite.setdefault(suite, set()).add(node)
    return {
        suite: _passing_result(sorted(nodes))
        for suite, nodes in nodes_by_suite.items()
    }


def test_45_id_mapping_expands_only_exact_passing_nodes() -> None:
    packages = validator.expected_work_packages(_passing_identity_results())
    assert tuple(packages) == tuple(validator.WORK_PACKAGE_TEST_IDS)
    assert sum(len(package["test_ids"]) for package in packages.values()) == 45
    for package, identities in validator.WORK_PACKAGE_TEST_IDS.items():
        assert tuple(packages[package]["test_ids"]) == identities
        for identity in identities:
            proof = packages[package]["test_ids"][identity]
            expected = [
                {"suite": suite, "node": node}
                for suite, node in validator.IDENTITY_PROOFS[identity]
            ]
            assert proof == {
                "proofs": expected,
                "passed_count": len(expected),
                "skipped_count": 0,
            }


def test_45_id_mapping_rejects_missing_renamed_and_nonpassing_exact_nodes() -> None:
    results = _passing_identity_results()
    suite, node = validator.IDENTITY_PROOFS["V09-DEV-006-HISTORY"][0]
    statuses = dict(results[suite].statuses)
    statuses[node + "-renamed"] = statuses.pop(node)
    results[suite] = validator.JUnitResult(
        statuses, len(statuses), 0, 0, 0, 0, 1.0
    )
    with pytest.raises(validator.CandidateEvidenceError, match="exact proof node is missing"):
        validator.expected_work_packages(results)

    results = _passing_identity_results()
    statuses = dict(results[suite].statuses)
    statuses[node] = "skipped"
    results[suite] = validator.JUnitResult(
        statuses, len(statuses) - 1, 1, 0, 0, 0, 1.0
    )
    with pytest.raises(validator.CandidateEvidenceError, match="exact proof node did not pass"):
        validator.expected_work_packages(results)


def test_cross_feature_identities_use_their_exact_evidence_suites() -> None:
    suites = {
        identity: {suite for suite, _node in validator.IDENTITY_PROOFS[identity]}
        for identity in (
            "V09-DEV-007-REPRODUCIBILITY",
            "V09-DEV-007-SECURITY",
            "V09-DEV-009-INTEGRATION",
            "V09-DEV-009-BROWSER-MATRIX",
            "V09-DEV-009-OFFLINE-PACKAGE",
            "V09-DEV-009-FAULT-RECOVERY",
        )
    }
    assert suites["V09-DEV-007-REPRODUCIBILITY"] == {"backend_docker_host"}
    assert suites["V09-DEV-007-SECURITY"] == {
        "backend_docker_host",
        "backend_sqlite",
    }
    assert suites["V09-DEV-009-INTEGRATION"] == {"frontend_playwright_live"}
    assert suites["V09-DEV-009-BROWSER-MATRIX"] == {"frontend_playwright_live"}
    assert suites["V09-DEV-009-OFFLINE-PACKAGE"] == {"tooling"}
    assert suites["V09-DEV-009-FAULT-RECOVERY"] == {
        "backend_sqlite",
        "frontend_playwright_live",
    }


def test_secret_scan_allows_only_structured_legacy_canary_names(tmp_path: Path) -> None:
    allowed = tmp_path / "tooling.xml"
    _junit(
        allowed,
        [
            (
                "scripts.tests.test_validate_candidate_evidence_v07",
                f"test_secret_material_scan_rejects_payload[{PRIVATE_KEY_MARKER}]",
                "passed",
            ),
            (
                "backend.tests.test_ir_v06",
                f"test_prompt_secret_material_is_rejected_without_echo[{PRIVATE_KEY_MARKER}\\nredacted]",
                "passed",
            ),
            (
                "backend.tests.test_ir_v06",
                f"test_action_and_startproc_secrets_are_rejected_without_echo[{PRIVATE_KEY_MARKER}\\nredacted]",
                "passed",
            ),
            (
                "backend.tests.test_ir_v06",
                "test_prompt_secret_material_is_rejected_without_echo[https://operator:plaintext@example.invalid/path]",
                "passed",
            ),
            (
                "backend.tests.test_ir_v06",
                "test_action_and_startproc_secrets_are_rejected_without_echo[postgresql://operator:plaintext@example.invalid/app]",
                "passed",
            ),
        ],
    )
    validator._scan_secret(allowed, "allowed")

    rejected = tmp_path / "other.xml"
    _junit(
        rejected,
        [("scripts.tests.test_other", f"test_payload[{PRIVATE_KEY_MARKER}]", "passed")],
    )
    with pytest.raises(validator.CandidateEvidenceError, match="private_key"):
        validator._scan_secret(rejected, "rejected")

    mutated = tmp_path / "mutated.xml"
    _junit(
        mutated,
        [
            (
                "backend.tests.test_ir_v06",
                "test_prompt_secret_material_is_rejected_without_echo[https://operator:stolen-value@example.invalid/path]",
                "passed",
            )
        ],
    )
    with pytest.raises(validator.CandidateEvidenceError, match="credential_url"):
        validator._scan_secret(mutated, "mutated")


def test_real_telemetry_browser_capture_is_exact_and_screenshot_bound(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "browser"
    browser.mkdir()
    stack = {
        name: f"sha256:{str(index) * 64}"
        for index, name in enumerate(
            ("backend", "driver", "pki_init", "postgres", "proxy", "qualification"),
            1,
        )
    }
    for profile, project in (("desktop", "chromium"), ("mobile", "mobile")):
        screenshot_path = browser / f"telemetry-observation-{profile}.png"
        screenshot_path.write_bytes(f"png:{profile}".encode("ascii"))
        capture = {
            "schema_version": "spell.v07.telemetry-browser-observation/1",
            "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
            "run_id": "a" * 32,
            "source_fingerprint_sha256": "b" * 64,
            "project": profile,
            "source_test": "frontend/e2e/telemetry-observation-real.spec.ts",
            "context_id": "v09-telemetry-synthetic-context",
            "runtime": {
                "node_version": "v24.13.0",
                "npm_version": "11.6.2",
                "playwright_version": "1.55.0",
                "browser_name": "chromium",
                "browser_version": "fixture",
                "project": project,
                "stack_image_ids": stack,
            },
            "assertions": {
                "driver_time": True,
                "item_ids": [
                    "TM.POWER.BUS_VOLTAGE",
                    "TM.POWER.SAFE_MODE",
                    "TM.THERMAL.MODE",
                ],
                "quality": "GOOD",
                "validity": "VALID",
                "freshness": "FRESH",
                "alarm": True,
                "cursor_websocket": True,
                "accessibility_blocking_findings": 0,
                "overflow_failures": 0,
                "mutation_control_count": 0,
            },
            "screenshot": {
                "path": f"browser/telemetry-observation-{profile}.png",
                "sha256": validator.sha256_bytes(screenshot_path.read_bytes()),
            },
        }
        (browser / f"telemetry-observation-{profile}.json").write_text(
            validator.result_json(capture) + "\n", encoding="utf-8"
        )

    validator._validate_real_telemetry_browser_artifacts(
        tmp_path,
        source={"source_fingerprint_sha256": "b" * 64},
        toolchain={
            "npm": "11.6.2",
            "qualification_image_id": stack["qualification"],
        },
        teardown={"project": f"spell-v09-candidate-{'a' * 32}"},
    )
    desktop = browser / "telemetry-observation-desktop.json"
    mutated = json.loads(desktop.read_text(encoding="utf-8"))
    mutated["assertions"]["mutation_control_count"] = 1
    desktop.write_text(validator.result_json(mutated) + "\n", encoding="utf-8")
    with pytest.raises(validator.CandidateEvidenceError, match="assertions differ"):
        validator._validate_real_telemetry_browser_artifacts(
            tmp_path,
            source={"source_fingerprint_sha256": "b" * 64},
            toolchain={
                "npm": "11.6.2",
                "qualification_image_id": stack["qualification"],
            },
            teardown={"project": f"spell-v09-candidate-{'a' * 32}"},
        )


def test_development_browser_screenshots_are_real_bounded_pngs(tmp_path: Path) -> None:
    for relative in validator.DEVELOPMENT_SCREENSHOT_PATHS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_development_png())

    validator._validate_development_browser_screenshots(tmp_path)

    chromium = tmp_path / validator.DEVELOPMENT_SCREENSHOT_PATHS[0]
    corrupted = bytearray(chromium.read_bytes())
    corrupted[60] ^= 1
    chromium.write_bytes(corrupted)
    with pytest.raises(validator.CandidateEvidenceError, match="PNG checksum differs"):
        validator._validate_development_browser_screenshots(tmp_path)

    chromium.write_bytes(_development_png(padding=0))
    with pytest.raises(validator.CandidateEvidenceError, match="size is outside bounds"):
        validator._validate_development_browser_screenshots(tmp_path)


def test_inventory_digest_is_sorted_but_duplicate_sensitive() -> None:
    assert validator.inventory_sha256(["b", "a"]) == validator.inventory_sha256(["a", "b"])
    assert validator.inventory_sha256(["a", "a", "b"]) != validator.inventory_sha256(["a", "b"])
