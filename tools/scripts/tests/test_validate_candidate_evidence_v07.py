from __future__ import annotations

import base64
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate_candidate_evidence_v07.py"
SPEC = importlib.util.spec_from_file_location("validate_candidate_evidence_v07", VALIDATOR_PATH)
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


def test_gate_defines_exact_nine_packages_and_45_test_ids() -> None:
    assert tuple(validator.WORK_PACKAGE_TEST_IDS) == tuple(
        f"V07-OBS-{index:03d}" for index in range(1, 10)
    )
    assert all(len(ids) == 5 for ids in validator.WORK_PACKAGE_TEST_IDS.values())
    assert len(validator.TEST_IDS) == len(set(validator.TEST_IDS)) == 45


@pytest.mark.parametrize(
    "node",
    sorted(validator.TOOLING_ALLOWED_SKIPS),
)
def test_tooling_skip_allowlist_contains_only_exact_platform_nodes(node: str) -> None:
    assert node in validator.TOOLING_ALLOWED_SKIPS


def test_tooling_skip_allowlist_rejects_other_tests_in_an_allowed_module() -> None:
    assert len(validator.TOOLING_ALLOWED_SKIPS) == 12
    assert {
        "scripts/tests/test_qualify_release_v05.py::test_v05_final_runner_parses_as_powershell",
        "scripts/tests/test_qualify_release_v07.py::test_v07_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v05.py::test_v05_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_release_v07.py::test_v07_package_publication_fault_rolls_back_executably",
    } <= validator.TOOLING_ALLOWED_SKIPS
    assert (
        "scripts/tests/test_release_v06.py::test_v06_package_rejects_private_key_bytes"
        not in validator.TOOLING_ALLOWED_SKIPS
    )


def test_sqlite_skip_allowlist_is_the_exact_postgresql_and_docker_host_set() -> None:
    assert validator.SQLITE_ALLOWED_SKIPS == {
        "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
        "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
        "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
        "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
        "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
    }


def test_candidate_schema_and_runner_are_version_scoped_and_atomic() -> None:
    schema = json.loads(
        (ROOT / "artifacts/v0.7/work-package/schema.json").read_text(encoding="utf-8")
    )
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
    assert schema["properties"]["schema_version"]["const"] == validator.SCHEMA_VERSION
    assert "spell.v06.candidate-qualification" not in json.dumps(schema)
    assert "[string]$SourceCommit" in runner
    assert "candidate qualification requires a clean explicit source freeze" in runner
    assert "git archive --format=zip --output=$candidateArchive $SourceCommit" in runner
    assert 'Join-Path $artifactRoot ".qualification/candidate-$runId"' in runner
    assert "candidate staging evidence validation failed" in runner
    assert runner.index("candidate staging evidence validation failed") < runner.index(
        "Move-Item -LiteralPath $stageRoot -Destination $canonicalRoot"
    )
    assert "artifacts/v0.6/work-package" not in runner
    assert "qualification-v06.Dockerfile" not in runner
    immutability = schema["properties"]["v0_6_immutability"]
    assert immutability["additionalProperties"] is False
    assert immutability["properties"]["accepted_archive_sha256"]["const"] == (
        "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
    )
    assert immutability["properties"]["accepted_sidecar_sha256"]["const"] == (
        "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
    )
    assert 'Join-Path $env:TEMP "sv6-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.6.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyRoot v0.6.0" in runner
    assert "git -C $root worktree remove --force $legacyRoot" in runner
    assert "v0.6.0 historical checkout teardown failed" in runner
    assert 'Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.5.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyV05Root v0.5.0" in runner
    assert "git -C $root worktree remove --force $legacyV05Root" in runner
    assert "v0.5.0 historical checkout teardown failed" in runner
    assert "accepted_v06_release_v07.py" in runner
    assert 'Join-Path $env:TEMP "openbexi-spell-v05-py313-site"' in runner
    assert "openbexi-spell-v06-py313-site" not in runner


def test_v07_candidate_runner_parses_as_powershell() -> None:
    runner = ROOT / "scripts/qualify_candidate_v07.ps1"
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


def test_runner_executes_full_matrix_and_reroutes_only_source_bound_nodes() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
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
        'playwright test e2e/integration.spec.ts',
        'playwright test e2e/telemetry-observation-real.spec.ts',
        'SPELL_DRIVER_ENABLED = "true"',
        'seed_observation_v07.py',
        '"v07-cross-feature-replay-soak"',
        'backend/tests/test_observation_api.py::test_observation_read_load_is_bounded_authorized_and_nonmutating',
        '--identity-map',
    ):
        assert marker in runner
    assert set(validator.REROUTED_TOOLING_TESTS) == {
        "scripts/tests/test_release_v05.py::test_current_v05_product_package_fingerprint_is_constructible",
        "scripts/tests/test_validate_release_evidence_v05.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication",
        "scripts/tests/test_validate_release_evidence_v05.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact",
        "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz-archive SHA-256 differs]",
        "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256-sidecar bytes differ]",
        "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_tag_claim_rejects_raw_object_mutation",
        "scripts/tests/test_validate_release_evidence_v06.py::test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag",
        "scripts/tests/test_validate_candidate_evidence_v06.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
        "scripts/tests/test_release_v06.py::test_current_v06_product_package_fingerprint_is_constructible",
        "scripts/tests/test_validate_release_evidence_v06.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication",
        "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_tag_blobs_archive_and_sidecar_are_exact",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz-workspace archive SHA-256 differs]",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256-workspace sidecar bytes differ]",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_raw_tag_mutation",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_tagged_blob_payload_mutation",
        "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_cli_emits_one_canonical_json_object",
        "scripts/tests/test_accepted_v06_release_v07.py::test_v07_powershell_assertion_is_parseable_and_reuses_canonical_validator",
        "scripts/tests/test_validate_candidate_evidence_v07.py::test_v07_candidate_runner_parses_as_powershell",
        "scripts/tests/test_validate_release_evidence_v07.py::test_v07_inherited_v06_binding_includes_external_archive_sidecar_and_tag",
        "scripts/tests/test_validate_release_evidence_v07.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
    }
    assert sum(
        source == "locked-windows-host-current-root"
        for source in validator.REROUTED_TOOLING_TESTS.values()
    ) == 14
    assert sum(
        source.startswith("locked-windows-host")
        for source in validator.REROUTED_TOOLING_TESTS.values()
    ) == 18
    assert "Invoke-LockedHostPytest $root" in runner
    assert "Invoke-LockedHostPytest $legacyV05Root" in runner
    assert "Merge-JUnit @($toolingBaseXml, $toolingV05Xml, $toolingLegacyXml, $toolingHostXml)" in runner
    assert "accepted_failures = @()" in runner
    assert "mapped_test_ids_skipped = @()" in runner
    assert "function Merge-JavaScriptJUnit" in runner
    assert "ImportNode($sourceSuite, $true)" in runner
    assert "Merge-JavaScriptJUnit @($liveBaseXml, $telemetryXml)" in runner


def test_high_risk_observation_ids_select_direct_backend_proofs() -> None:
    source = VALIDATOR_PATH.read_text(encoding="utf-8")

    assert '"V07-OBS-008-BACKPRESSURE": ("backend_postgresql", ["observation_websocket_forces_resync_on_client_queue_overflow"])' in source
    assert '"V07-OBS-009-LOAD-SECURITY": ("backend_postgresql", ["observation_read_load_is_bounded_authorized_and_nonmutating"])' in source


def test_runner_stages_ledger_bound_manuals_and_only_the_candidate_schema() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
    dockerignore = (
        ROOT / "scripts/qualification-v07.Dockerfile.dockerignore"
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
    assert dockerignore.count("!artifacts/v0.7/work-package/schema.json") == 1
    assert "!artifacts/v0.7/work-package/qualification.json" not in dockerignore
    assert not any(line.startswith("!artifacts/v0.7/work-package/tests") for line in dockerignore)
    assert not any(line.startswith("!artifacts/v0.7/work-package/browser") for line in dockerignore)


def test_runner_cleanup_inspection_preserves_the_originating_failure() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
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
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
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
        "scripts/tests/test_validate_candidate_evidence_v07.py::"
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
    capture = tmp_path / validator.SUITE_PATHS["backend_v07_soak"]
    capture.parent.mkdir()

    def values(nodes: list[str], iterations: int) -> tuple[dict[str, object], dict[str, object]]:
        document = {
            "profile": "v07-cross-feature-replay-soak",
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
            "capture": validator.SUITE_PATHS["backend_v07_soak"],
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
    validator._validate_suite(tmp_path, "backend_v07_soak", summary)

    reduced = [
        node
        for node in nodes
        if "observation_read_load_is_bounded_authorized_and_nonmutating" not in node
    ]
    document, summary = values(reduced, validator.SOAK_ITERATIONS)
    capture.write_text(validator.result_json(document) + "\n", encoding="utf-8")
    with pytest.raises(validator.CandidateEvidenceError, match="soak inventory differs"):
        validator._validate_suite(tmp_path, "backend_v07_soak", summary)


def test_runner_resolves_one_coherent_node_toolchain_for_inline_probe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")

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
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")

    validation_command = "$validation = @(& $script:LockedPython -I $script:Validator"
    block_start = runner.rindex('$savedErrorAction = $ErrorActionPreference', 0, runner.index(validation_command))
    block_end = runner.index('if ($validationExitCode -ne 0)', block_start)
    block = runner[block_start:block_end]
    assert '$ErrorActionPreference = "Continue"' in block
    assert 'finally { $ErrorActionPreference = $savedErrorAction }' in block
    assert "$validationExitCode = $LASTEXITCODE" in runner
    assert "candidate staging evidence validation failed: $($validation -join '; ')" in runner


def test_runner_live_backend_launcher_is_windows_spawn_safe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
    match = re.search(r"\$launcherBody = @'\n(?P<code>.*?)\n'@", runner, re.DOTALL)
    assert match is not None
    launcher = match.group("code") + "\n"
    compile(launcher, "<candidate-live-backend>", "exec")
    assert 'if __name__ == "__main__":' in launcher
    assert launcher.index('if __name__ == "__main__":') < launcher.index(
        "uvicorn.run("
    )


def test_runner_sorts_explicit_docker_nodes_before_junit_bijection() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v07.ps1").read_text(encoding="utf-8")
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
        [("operator-workspace.spec.ts", "operates the dense v0.7 workspace", "passed")],
        suite="mobile",
    )
    result = validator.parse_junit(path, "browser", "javascript")
    assert result.statuses == {
        "mobile::operator-workspace.spec.ts::operates the dense v0.7 workspace": "passed"
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


def test_45_id_mapping_expands_only_to_passing_concrete_nodes() -> None:
    backend = [
        "backend/tests/test_v07_contract_matrices.py::test_time_and_sample_contract_is_typed_atomic_and_lifecycle_compatible",
        "backend/tests/test_driver_gateway.py::test_poll_task_survives_storage_outage_and_resumes_observation_without_restart",
        "backend/tests/test_observation_repository.py::test_collector_uses_current_then_restart_cursor_next_without_duplicates",
        "backend/tests/test_observation_domain.py::test_scalar_values_have_exact_types_and_canonical_json_encodings",
        "backend/tests/test_observation_domain.py::test_sample_identity_and_driver_authored_objects_are_strict",
        "backend/tests/test_driver_client_observation.py::test_client_maps_time_and_atomic_sample_without_protobuf_leakage",
        "backend/tests/test_condition_runtime_v07.py::test_repository_get_tm_current_preserves_uint64_and_atomic_evidence",
        "backend/tests/test_observation_repository.py::test_atomic_sample_gap_resynchronization_alarm_and_idempotency",
        "backend/tests/test_observation_repository.py::test_uint64_source_sequence_round_trips_without_sqlite_precision_loss",
        "backend/tests/test_condition_runtime_v07.py::test_repository_get_tm_next_replay_uses_the_persisted_deadline",
        "backend/tests/test_condition_runtime_v07.py::test_repository_get_tm_next_deadline_wins_when_replay_returns_at_deadline",
        "backend/tests/test_condition_runtime_v07.py::test_repository_get_tm_next_stops_when_execution_is_cancelled",
        "backend/tests/test_condition_runtime_v07.py::test_repository_get_tm_next_cancellation_wins_when_replay_returns_a_sample",
        "backend/tests/test_observation_repository.py::test_time_and_freshness_transitions_are_durable",
        "backend/tests/test_condition_engine_v07.py::test_sample_acceptability_matrix_is_indeterminate[quality]",
        "backend/tests/test_driver_client_observation.py::test_client_fails_closed_on_scalar_oneof_or_identity_mismatch",
        "backend/tests/test_observation_repository.py::test_bundled_catalog_mismatch_is_rejected_before_projection",
        "backend/tests/test_condition_engine_v07.py::test_typed_scalar_wire_round_trip_is_canonical_and_rejects_ambiguity",
        "backend/tests/test_condition_engine_v07.py::test_plan_round_trip_binds_identity_tree_and_typed_operands",
        "backend/tests/test_condition_service_v07.py::test_condition_evidence_cursors_are_lossless_json_decimal_strings",
        "backend/tests/test_condition_engine_v07.py::test_numeric_tolerance_and_tm_to_tm_use_one_atomic_snapshot",
        "backend/tests/test_condition_service_v07.py::test_verify_zero_retry_delay_timeout_and_cancel_are_durable",
        "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
        "backend/tests/test_condition_service_v07.py::test_late_true_snapshot_cannot_satisfy_verify_wait_or_schedule",
        "backend/tests/test_condition_service_v07.py::test_verify_may_settle_a_complete_predeadline_snapshot_after_evaluation_delay",
        "backend/tests/test_condition_service_v07.py::test_evaluation_settlement_drives_retry_settlement_and_claim_times",
        "backend/tests/test_condition_service_v07.py::test_verify_is_idempotent_retries_and_commits_leaf_sample_evidence",
        "backend/tests/test_supervisor_v07_runtime.py::test_supervisor_commits_result_before_delivery_and_replays_exact_bytes",
        "backend/tests/test_condition_engine_v07.py::test_plan_validation_is_closed_world_typed_and_bounded",
        "backend/tests/test_v07_contract_matrices.py::test_condition_engine_is_bounded_atomic_and_cannot_dispatch_effects",
        "backend/tests/test_v07_contract_matrices.py::test_waitfor_and_schedule_preserve_deadlines_evidence_and_one_outcome",
        "backend/tests/test_condition_runtime_v07.py::test_procedure_runtime_drives_verify_and_wait_to_canonical_terminal_results",
        "backend/tests/test_worker_v07.py::test_waitfor_remains_paused_while_a_result_arrives_and_resumes_once",
        "backend/tests/test_condition_service_v07.py::test_relative_and_absolute_waits_settle_from_database_targets",
        "backend/tests/test_condition_service_v07.py::test_database_clock_regression_fails_closed_without_moving_deadline",
        "backend/tests/test_condition_service_v07.py::test_same_epoch_restart_uses_persisted_monotonic_deadline",
        "backend/tests/test_condition_service_v07.py::test_epoch_change_rebases_from_immutable_utc_deadline",
        "backend/tests/test_condition_runtime_v07.py::test_execution_interrupt_accepts_a_concurrent_cas_winner",
        "backend/tests/test_condition_service_v07.py::test_wait_interrupt_resume_preserves_original_deadline_and_cancel_is_idempotent",
        "backend/tests/test_condition_service_v07.py::test_telemetry_wait_restart_reuses_cursor_policy_deadline_and_evidence",
        "backend/tests/test_condition_service_v07.py::test_telemetry_schedule_pins_true_evidence_and_fires_one_occurrence",
        "backend/tests/test_v07_telemetry_schedule_routes.py::test_telemetry_schedule_create_list_get_cancel_is_controller_bound",
        "backend/tests/test_condition_service_v07.py::test_telemetry_schedule_cursors_are_lossless_json_decimal_strings",
        "backend/tests/test_condition_service_v07.py::test_schedule_cancel_deadline_and_argument_security_are_fail_closed",
        "backend/tests/test_condition_runtime_v07.py::test_recovery_loop_and_occurrence_bound_starter_are_narrow_and_idempotent",
        "backend/tests/test_condition_service_v07.py::test_claimed_schedule_recovers_with_the_same_occurrence_bound_callback",
        "backend/tests/test_condition_service_v07.py::test_persisted_terminal_states_are_not_rewritten_by_recovery",
        "backend/tests/test_observation_catalog_v07.py::test_catalog_digest_and_result_order_are_deterministic",
        "backend/tests/test_observation_read_service_v07.py::test_catalog_identity_exposes_only_finite_read_only_counts",
        "backend/tests/test_observation_read_service_v07.py::test_exact_resource_memory_and_tmtc_reads_are_digest_pinned",
        "backend/tests/test_observation_api.py::test_observation_catalog_reads_preserve_safe_outcomes_and_authentication",
        "backend/tests/test_observation_catalog_v07.py::test_memory_reads_are_exact_checked_and_cannot_cross_regions",
        "backend/tests/test_observation_catalog_v07.py::test_tmtc_lookup_has_no_wildcard_filter_or_direction_fallback",
        "backend/tests/test_bundled_observation_catalog_v07.py::test_bundled_catalog_is_deterministic_and_uses_the_driver_telemetry_digest",
        "backend/tests/test_observation_catalog_v07.py::test_resource_read_is_exact_digest_pinned_and_authorization_scoped",
        "backend/tests/test_bundled_observation_catalog_v07.py::test_bundled_reads_are_exact_bounded_and_read_only",
        "backend/tests/test_observation_catalog_v07.py::test_limit_contract_requires_canonical_bands_types_and_order",
        "backend/tests/test_observation_catalog_v07.py::test_is_alarmed_returns_deterministic_read_only_band_state[critical]",
        "backend/tests/test_observation_repository.py::test_no_sample_alarm_is_indeterminate_and_read_only",
        "backend/tests/test_observation_catalog_v07.py::test_alarm_quality_freshness_and_gap_matrix_is_indeterminate[quality]",
        "backend/tests/test_observation_catalog_v07.py::test_no_sample_disabled_limits_and_unit_mismatch_never_clear_an_alarm",
        "backend/tests/test_bundled_observation_catalog_v07.py::test_real_driver_sample_can_be_evaluated_against_bundled_limits",
        "backend/tests/test_observation_catalog_v07.py::test_alarm_uses_the_limit_telemetry_digest_not_the_read_catalog_digest",
        "backend/tests/test_v07_contract_matrices.py::test_cursor_stream_is_separate_durable_bounded_and_resynchronizable",
        "backend/tests/test_observation_repository.py::test_projection_cursor_uses_bigint_and_crosses_int32_boundary",
        "backend/tests/test_observation_api.py::test_observation_websocket_replays_strings_and_requires_epoch_resync",
        "backend/tests/test_observation_api.py::test_observation_websocket_forces_resync_on_client_queue_overflow",
        "backend/tests/test_v07_contract_matrices.py::test_manifest_has_exact_nine_packages_and_45_planned_test_ids",
        "backend/tests/test_ir_v07.py::test_parser_selects_v07_and_canonicalizes_all_observation_steps",
        "backend/tests/test_supervisor_v07_runtime.py::test_restart_between_next_request_and_result_reuses_the_durable_anchor",
        "backend/tests/test_condition_runtime_v07.py::test_durable_execution_cancellation_probe_tracks_terminal_state",
        "backend/tests/test_observation_api.py::test_observation_read_load_is_bounded_authorized_and_nonmutating",
    ]
    driver = [
        "driver_host/tests/test_observation.py::test_clock_sources_provenance_regression_and_uncertainty_are_typed",
        "driver_host/tests/test_observation.py::test_service_time_current_next_gap_deadline_and_stale_fencing",
        "driver_host/tests/test_wire.py::test_observation_rpc_uses_the_same_strict_raw_wire_boundary",
    ]
    vitest = [
        "useTelemetryObservationStream.test.tsx::refreshes ordered projection events and ignores keepalives",
        "useTelemetryObservationStream.test.tsx::resynchronizes a sequence gap from the committed snapshot cursor",
        "useTelemetryObservationStream.test.tsx::invalidates authentication on 4401 without reconnecting",
    ]
    mocked = [
        "chromium::driver-projection.spec.ts::distinguishes every bounded driver fault state without a mutation route",
        "mobile::driver-projection.spec.ts::distinguishes every bounded driver fault state without a mutation route",
    ]
    live = [
        "chromium::telemetry-observation-real.spec.ts::renders real telemetry observations and cursor stream without mutation controls",
        "mobile::telemetry-observation-real.spec.ts::renders real telemetry observations and cursor stream without mutation controls",
    ]
    packages = validator.expected_work_packages(
        {
            "backend_postgresql": _passing_result(backend),
            "driver_host": _passing_result(driver),
            "frontend_vitest": _passing_result(vitest),
            "frontend_playwright_mocked": _passing_result(mocked),
            "frontend_playwright_live": _passing_result(live),
        }
    )
    identities = [
        (identity, proof)
        for package in packages.values()
        for identity, proof in package["test_ids"].items()
    ]
    assert len(identities) == 45
    assert all(proof["passed_count"] == len(proof["proofs"]) > 0 for _, proof in identities)
    assert all(proof["skipped_count"] == 0 for _, proof in identities)
    for identity in validator.REAL_TELEMETRY_TEST_IDS:
        package = identity[:11]
        suites = {
            item["suite"]
            for item in packages[package]["test_ids"][identity]["proofs"]
        }
        assert "frontend_playwright_live" in suites

    serialized = validator.result_json(packages, preserve_order=True)
    round_trip = json.loads(serialized)
    for package_id, planned_ids in validator.WORK_PACKAGE_TEST_IDS.items():
        assert tuple(round_trip[package_id]["test_ids"]) == planned_ids
    assert validator.result_json({"z": 1, "a": 2}) == '{"a":2,"z":1}'


def test_secret_scan_allows_only_structured_legacy_canary_names(tmp_path: Path) -> None:
    allowed = tmp_path / "tooling.xml"
    _junit(
        allowed,
        [
            (
                "scripts.tests.test_validate_candidate_evidence_v06",
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
            "scope_profile": validator.SCOPE_PROFILE,
            "run_id": "a" * 32,
            "source_fingerprint_sha256": "b" * 64,
            "project": profile,
            "source_test": "frontend/e2e/telemetry-observation-real.spec.ts",
            "context_id": "v07-telemetry-synthetic-context",
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
        teardown={"project": f"spell-v07-candidate-{'a' * 32}"},
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
            teardown={"project": f"spell-v07-candidate-{'a' * 32}"},
        )


def test_inventory_digest_is_sorted_but_duplicate_sensitive() -> None:
    assert validator.inventory_sha256(["b", "a"]) == validator.inventory_sha256(["a", "b"])
    assert validator.inventory_sha256(["a", "a", "b"]) != validator.inventory_sha256(["a", "b"])
