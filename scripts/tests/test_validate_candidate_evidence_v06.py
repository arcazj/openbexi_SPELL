from __future__ import annotations

import base64
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate_candidate_evidence_v06.py"
SPEC = importlib.util.spec_from_file_location("validate_candidate_evidence_v06", VALIDATOR_PATH)
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
        f"V06-OP-{index:03d}" for index in range(1, 10)
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
    assert (
        "scripts/tests/test_release_v05.py::test_v05_package_rejects_private_key_bytes"
        not in validator.TOOLING_ALLOWED_SKIPS
    )


def test_candidate_schema_and_runner_are_version_scoped_and_atomic() -> None:
    schema = json.loads(
        (ROOT / "artifacts/v0.6/work-package/schema.json").read_text(encoding="utf-8")
    )
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    assert schema["properties"]["schema_version"]["const"] == validator.SCHEMA_VERSION
    assert "spell.v05.candidate-qualification" not in json.dumps(schema)
    assert "[string]$SourceCommit" in runner
    assert "candidate qualification requires a clean explicit source freeze" in runner
    assert "git archive --format=zip --output=$candidateArchive $SourceCommit" in runner
    assert 'Join-Path $artifactRoot ".qualification/candidate-$runId"' in runner
    assert "candidate staging evidence validation failed" in runner
    assert runner.index("candidate staging evidence validation failed") < runner.index(
        "Move-Item -LiteralPath $stageRoot -Destination $canonicalRoot"
    )
    assert "artifacts/v0.5/work-package" not in runner
    assert "qualification-v05.Dockerfile" not in runner
    immutability = schema["properties"]["v0_5_immutability"]
    assert immutability["additionalProperties"] is False
    assert immutability["properties"]["accepted_archive_sha256"]["const"] == (
        "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
    )
    assert immutability["properties"]["accepted_sidecar_sha256"]["const"] == (
        "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
    )
    assert 'Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"' in runner
    assert "refusing a v0.5.0 historical checkout outside the temporary root" in runner
    assert "git -C $root worktree add --detach --quiet $legacyRoot v0.5.0" in runner
    assert "git -C $root worktree remove --force $legacyRoot" in runner
    assert "v0.5.0 historical checkout teardown failed" in runner
    assert "accepted_v05_release_v06.py" in runner


def test_runner_executes_full_matrix_and_reroutes_only_source_bound_nodes() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    for marker in (
        'Get-CollectedNodes "backend/tests"',
        'Get-CollectedNodes "driver_host/tests"',
        'Get-CollectedNodes "scripts/tests"',
        '"SPELL_TEST_DATABASE_URL=$applicationUrl"',
        '"SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl"',
        '"spell_migration_test"',
        'npm run build',
        'playwright test e2e/operator-workspace.spec.ts',
        'playwright test e2e/integration.spec.ts',
        '"v06-cross-feature-replay-soak"',
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
        "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably",
    }
    assert sum(
        source == "locked-windows-host-current-root"
        for source in validator.REROUTED_TOOLING_TESTS.values()
    ) == 5
    assert sum(
        source.startswith("locked-windows-host")
        for source in validator.REROUTED_TOOLING_TESTS.values()
    ) == 9
    assert "Invoke-LockedHostPytest $root" in runner
    assert "accepted_failures = @()" in runner
    assert "mapped_test_ids_skipped = @()" in runner


def test_runner_stages_ledger_bound_manuals_and_only_the_candidate_schema() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    dockerignore = (
        ROOT / "scripts/qualification-v06.Dockerfile.dockerignore"
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
    assert dockerignore.count("!artifacts/v0.6/work-package/schema.json") == 1
    assert "!artifacts/v0.6/work-package/qualification.json" not in dockerignore
    assert not any(line.startswith("!artifacts/v0.6/work-package/tests") for line in dockerignore)
    assert not any(line.startswith("!artifacts/v0.6/work-package/browser") for line in dockerignore)


def test_runner_cleanup_inspection_preserves_the_originating_failure() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
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
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    code_match = re.search(r"\$soakCode = @'\n(?P<code>.*?)\n'@", runner, re.DOTALL)
    launcher_match = re.search(r'^  \$soakLauncher = "(?P<code>[^"]+)"$', runner, re.MULTILINE)
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
        "scripts/tests/test_validate_candidate_evidence_v06.py::"
        "test_gate_defines_exact_nine_packages_and_45_test_ids"
    )

    assert "'" not in launcher and '"' not in launcher
    assert "\r" not in launcher and "\n" not in launcher
    assert "base64.b64decode(sys.argv.pop(1))" in launcher
    assert 'subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *nodes, "-q"]' in soak_code
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


def test_runner_resolves_one_coherent_node_toolchain_for_inline_probe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")

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
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")

    validation_command = "$validation = @(& $script:LockedPython -I $script:Validator"
    block_start = runner.rindex('$savedErrorAction = $ErrorActionPreference', 0, runner.index(validation_command))
    block_end = runner.index('if ($validationExitCode -ne 0)', block_start)
    block = runner[block_start:block_end]
    assert '$ErrorActionPreference = "Continue"' in block
    assert 'finally { $ErrorActionPreference = $savedErrorAction }' in block
    assert "$validationExitCode = $LASTEXITCODE" in runner
    assert "candidate staging evidence validation failed: $($validation -join '; ')" in runner


def test_runner_live_backend_launcher_is_windows_spawn_safe() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
    match = re.search(r"\$launcherBody = @'\n(?P<code>.*?)\n'@", runner, re.DOTALL)
    assert match is not None
    launcher = match.group("code") + "\n"
    compile(launcher, "<candidate-live-backend>", "exec")
    assert 'if __name__ == "__main__":' in launcher
    assert launcher.index('if __name__ == "__main__":') < launcher.index(
        "uvicorn.run("
    )


def test_runner_sorts_explicit_docker_nodes_before_junit_bijection() -> None:
    runner = (ROOT / "scripts/qualify_candidate_v06.ps1").read_text(encoding="utf-8")
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
        [("operator-workspace.spec.ts", "operates the dense v0.6 workspace", "passed")],
        suite="mobile",
    )
    result = validator.parse_junit(path, "browser", "javascript")
    assert result.statuses == {
        "mobile::operator-workspace.spec.ts::operates the dense v0.6 workspace": "passed"
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
        "backend/tests/test_v06_contract_matrices.py::test_manifest_has_exact_accepted_gate_contract_inventory",
        "backend/tests/test_procedure_parser.py::test_catalog_identity",
        "backend/tests/test_v06_operator_workspace.py::test_startproc_admitting_restart",
        "backend/tests/test_v06_operator_workspace.py::test_viewer_mutation_and_strict_json",
        "backend/tests/test_v06_contract_matrices.py::test_lease_modes_make_monitor_structurally_read_only",
        "backend/tests/test_v06_operator_workspace.py::test_handover_expiry_commits",
        "backend/tests/test_v06_operator_workspace.py::test_monitor_reconnect_count",
        "backend/tests/test_worker_v06.py::test_control_loss_replays",
        "backend/tests/test_v06_operator_workspace.py::test_control_proof_privacy",
        "backend/tests/test_v06_operator_workspace.py::test_command_admission_is_schema_exact",
        "backend/tests/test_v06_contract_matrices.py::test_command_matrix_is_total_and_rejects_kill",
        "backend/tests/test_supervisor_v06_runtime.py::test_concurrent_command_delivery",
        "backend/tests/test_supervisor_v06_runtime.py::test_restart_replays_applying_worker_command",
        "backend/tests/test_worker_v06.py::test_worker_rejects_kill",
        "backend/tests/test_v06_operator_workspace.py::test_prompt_canonical_defaults",
        "backend/tests/test_v06_operator_workspace.py::test_snapshot_projects_the_durable_typed_prompt",
        "backend/tests/test_v06_operator_workspace.py::test_prompt_controller_loss_grace",
        "backend/tests/test_worker_v06.py::test_prompt_settlement_replays",
        "backend/tests/test_v06_contract_matrices.py::test_schedule_contract_is_one_shot",
        "backend/tests/test_v06_operator_workspace.py::test_schedule_identity_misfire_restart",
        "backend/tests/test_v06_contract_matrices.py::test_inspection_actions_and_startproc_forbid_code_execution",
        "backend/tests/test_v06_operator_workspace.py::test_inspection_edit_is_pending",
        "backend/tests/test_worker_v06.py::test_inspection_edit_replays",
        "backend/tests/test_v06_operator_workspace.py::test_nested_redaction_workspace",
        "backend/tests/test_ir_v06.py::test_user_actions_require_pinned_handlers",
        "backend/tests/test_v06_operator_workspace.py::test_action_bundle_registration_and_atomic_effect",
        "backend/tests/test_v06_operator_workspace.py::test_action_and_inspection_application_reject_stale",
        "backend/tests/test_worker_v06.py::test_user_action_replay",
        "backend/tests/test_ir_v06.py::test_parser_rejects_unbounded_or_unpinned_user_actions",
        "backend/tests/test_ir_v06.py::test_startproc_resolution_pins_unique",
        "backend/tests/test_supervisor_v06_runtime.py::test_startproc_terminal",
        "backend/tests/test_ir_v06.py::test_startproc_rejects_ambiguity_cycles_depth",
        "backend/tests/test_worker_v06.py::test_startproc_terminal_delivery_replays",
        "backend/tests/test_procedure_parser.py::test_catalog_rejects_symlinks",
        "backend/tests/test_api_execution.py::test_recovery",
    ]
    mocked = [
        "chromium::operator-workspace.spec.ts::operates the dense v0.6 workspace",
        "mobile::operator-workspace.spec.ts::operates the dense v0.6 workspace",
    ]
    live = [
        "chromium::integration.spec.ts::controls a durable prompt workflow",
        "mobile::integration.spec.ts::controls a durable prompt workflow",
    ]
    packages = validator.expected_work_packages(
        {
            "backend_postgresql": _passing_result(backend),
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
                "scripts.tests.test_validate_candidate_evidence_v05",
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


def test_inventory_digest_is_sorted_but_duplicate_sensitive() -> None:
    assert validator.inventory_sha256(["b", "a"]) == validator.inventory_sha256(["a", "b"])
    assert validator.inventory_sha256(["a", "a", "b"]) != validator.inventory_sha256(["a", "b"])
