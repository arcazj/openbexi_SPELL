from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath


ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "scripts" / "collect_fault_runtime_v04.ps1"
TEXT = PRODUCER.read_text(encoding="utf-8")

RUNTIME_IDS = {
    "V04-SCOPE-002",
    "V04-MIG-004",
    "V04-SEC-002",
    "V04-SEC-004",
    "V04-BOUND-002",
    "V04-ISO-003",
    "V04-ISO-004",
    "V04-REC-005",
}


def _function_body(name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)} \{{(.*?)(?=^function |^if \(\$PSCmdlet)",
        TEXT,
    )
    assert match is not None, name
    return match.group(1)


def test_all_embedded_python_programs_compile() -> None:
    programs = re.findall(r"(?ms)= @'\r?\n(.*?)\r?\n'@", TEXT)
    assert len(programs) == 11
    for index, program in enumerate(programs, start=1):
        compile(program, f"{PRODUCER.name}:embedded-python-{index}", "exec")


def test_runtime_producer_declares_and_dispatches_the_exact_live_set() -> None:
    validate_set = re.search(
        r'(?s)ParameterSetName = "Probe".*?\[ValidateSet\((.*?)\)\]\s*\[string\]\$RuntimeProbe',
        TEXT,
    )
    assert validate_set is not None
    assert set(re.findall(r'"(V04-[A-Z]+-\d{3})"', validate_set.group(1))) == RUNTIME_IDS

    expected_functions = {
        "V04-SCOPE-002": "Invoke-ProbeScope002",
        "V04-MIG-004": "Invoke-ProbeMig004",
        "V04-SEC-002": "Invoke-ProbeSec002",
        "V04-SEC-004": "Invoke-ProbeSec004",
        "V04-BOUND-002": "Invoke-ProbeBound002",
        "V04-ISO-003": "Invoke-ProbeIso003",
        "V04-ISO-004": "Invoke-ProbeIso004",
        "V04-REC-005": "Invoke-ProbeRec005",
    }
    for test_id, function in expected_functions.items():
        assert f'"{test_id}" {{ {function}; break }}' in TEXT
        assert f"function {function} {{" in TEXT
    assert "pytest" not in TEXT.casefold()


def test_nested_command_capture_is_byte_exact_canonical_and_environment_bounded() -> None:
    body = _function_body("Invoke-RuntimeProbeCommand")
    assert "Invoke-ExactProcessCapture" in body
    assert "$startedAt" in body and "$finishedAt" in body
    assert "started_at = $startedAt" in body
    assert "finished_at = $finishedAt" in body
    assert "Get-LowerSha256 $stdoutCapture" in body
    assert "Get-LowerSha256 $canonicalCheck" in body
    assert "if ($stderrBytes.Length -ne 0)" in body
    assert "[byte[]]$stderrBytes = [byte[]]::new(0)" in body
    assert "$stderrBytes = [IO.File]::ReadAllBytes($stderrCapture)" in body
    assert "else { [byte[]]@() }" not in body
    assert "WriteAllBytes((Join-Path $script:stagingRoot $stdoutRelative), $stdoutBytes)" in body
    assert "WriteAllBytes((Join-Path $script:stagingRoot $evidenceRelative), $stdoutBytes)" in body

    expected_environment = {
        "V04-SCOPE-002": [
            "DATABASE_URL",
            "SPELL_RUNTIME_CONTEXT_FILE",
            "SPELL_RUNTIME_OPERATOR_TOKEN",
        ],
        "V04-MIG-004": ["DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE"],
        "V04-SEC-002": [
            "DATABASE_URL",
            "SPELL_RUNTIME_CONTEXT_FILE",
            "SPELL_RUNTIME_OPERATOR_TOKEN",
        ],
        "V04-SEC-004": [
            "SPELL_RUNTIME_CONTEXT_FILE",
            "SPELL_RUNTIME_JWT_SECRET",
            "SPELL_RUNTIME_OPERATOR_TOKEN",
        ],
        "V04-BOUND-002": ["SPELL_RUNTIME_CONTEXT_FILE"],
        "V04-ISO-003": [
            "SPELL_RUNTIME_CONTEXT_FILE",
            "SPELL_RUNTIME_OPERATOR_TOKEN",
        ],
        "V04-ISO-004": ["SPELL_RUNTIME_CONTEXT_FILE"],
        "V04-REC-005": ["DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE"],
    }
    for test_id, environment_keys in expected_environment.items():
        entry = re.search(rf'"{test_id}"\s*=\s*@\((.*?)\)', body, re.DOTALL)
        assert entry is not None, test_id
        assert re.findall(r'"([A-Z][A-Z0-9_]+)"', entry.group(1)) == environment_keys
    assert "SPELL_FAULT_RUNTIME_CONTEXT" not in TEXT

    process = _function_body("Invoke-ExactProcessCapture")
    assert "$hostEnvironmentAllowlist" in process
    assert "$start.EnvironmentVariables.Remove" in process
    for forbidden in ("DATABASE_URL", "PYTHONPATH", "PYTHONHOME", "HTTP_PROXY", "HTTPS_PROXY"):
        assert forbidden not in process
    assert 'if (([string]$name).ToUpperInvariant() -notin $hostEnvironmentAllowlist)' in process


def test_container_python_payloads_use_quote_stable_base64_execution() -> None:
    helper = _function_body("ConvertTo-PythonExecCode")
    assert "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Code))" in helper
    assert "__import__('builtins').exec(__import__('base64').b64decode('$encoded'))" in helper
    invocations = re.findall(r'"python", "-c", ([^\r\n]+)', TEXT)
    assert len(invocations) == 10
    assert all("ConvertTo-PythonExecCode" in invocation for invocation in invocations)
    assert re.search(r'"python", "-c", \$[A-Za-z]', TEXT) is None
    assert "-I -c (ConvertTo-PythonExecCode $code) $inputPath $Path" in TEXT
    assert "-I -c $code $inputPath $Path" not in TEXT


def test_every_result_binds_all_actual_host_tools_with_canonical_artifacts() -> None:
    body = _function_body("Invoke-RuntimeProbeCommand")
    for suffix in ("host-powershell", "host-python", "host-docker", "host-compose"):
        assert suffix in body
    for metric in (
        "host_powershell_sha256",
        "host_powershell_version",
        "host_python_sha256",
        "host_python_version",
        "host_docker_sha256",
        "host_docker_version",
        "host_compose_sha256",
        "host_compose_version",
    ):
        assert metric in TEXT
    assert "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1" in TEXT
    assert '$script:PythonVersion -cne "3.13.14"' in TEXT
    assert "$script:DockerExe.Equals($lockedDockerPath" in TEXT
    assert "$script:ComposeExe.Equals($lockedComposePath" in TEXT


def test_collect_uses_exact_images_fresh_staging_and_cleanup_before_one_publish() -> None:
    assert '"artifacts/v0.4/.qualification/runtime-captures"' in TEXT
    assert "strict descendant of the canonical runtime-captures directory" in TEXT
    assert '$stagingRoot = Join-Path $outputParent ".fault-stage-$runId"' in TEXT
    assert '$stagingRoot = Join-Path $outputParent ".$outputLeaf.staging-$runId"' not in TEXT
    assert '$workspaceRuntimeRoot = Join-Path $outputParent ".fault-work-$runId"' in TEXT
    assert '$hostConfigurationPath = Join-Path $workspaceRuntimeRoot "host-profile.json"' in TEXT
    assert 'Join-Path $temporaryRoot "host-profile.json"' not in TEXT
    assert 'Join-Path $script:workspaceRuntimeRoot "rec005-coordination"' in TEXT
    assert 'Join-Path $script:temporaryRoot "rec005-coordination"' not in TEXT
    assert 'schema_version = "spell.v04.fault-runtime-input/1"' in TEXT
    assert '"up", "--detach", "--no-build", "--pull", "never", "--wait"' in TEXT
    assert "pull_policy: never" in TEXT
    assert re.search(r'(?i)\bdocker\s+build\b', TEXT) is None
    assert 'Invoke-Compose @("down", "--volumes", "--remove-orphans"' in TEXT
    assert 'Remove-ProjectLabeledResources "containers"' in TEXT
    assert 'Remove-ProjectLabeledResources $kind' in TEXT
    assert "Assert-NoProjectResources" in TEXT
    assert TEXT.count("Move-Item -LiteralPath $stagingRoot -Destination $outputPath") == 1
    cleanup = TEXT.split("catch { $script:failure = $_ }\nfinally {", 1)[1].split(
        "\n}\n\nif (-not $script:failure", 1
    )[0]
    container_cleanup = cleanup.index('Remove-ProjectLabeledResources "containers"')
    compose_down = cleanup.index('Invoke-Compose @("down", "--volumes", "--remove-orphans"')
    workspace_delete = cleanup.index(
        "Remove-Item -LiteralPath $workspaceRuntimeRoot -Recurse -Force"
    )
    final_assertion = cleanup.rindex("Assert-NoProjectResources")
    assert container_cleanup < compose_down < workspace_delete < final_assertion
    assert TEXT.index("Assert-NoProjectResources", TEXT.index(cleanup)) < TEXT.index(
        "Move-Item -LiteralPath $stagingRoot -Destination $outputPath"
    )


def test_all_docker_bind_sources_reside_in_the_validated_workspace() -> None:
    bind_sources = re.findall(r'type=bind,source=([^,"\s]+),target=', TEXT)
    assert len(bind_sources) == TEXT.count("type=bind,source=")
    assert set(bind_sources) == {"$coordinationRoot", "$script:stagingRoot"}
    assert r"$hostMount = $script:hostConfigurationPath.Replace('\', '/')" in TEXT
    assert '$hostConfigurationPath = Join-Path $workspaceRuntimeRoot "host-profile.json"' in TEXT
    assert '$coordinationRoot = Join-Path $script:workspaceRuntimeRoot "rec005-coordination"' in TEXT
    assert "type=bind,source=$script:temporaryRoot" not in TEXT
    assert '$detailSource = Join-Path $script:workspaceRuntimeRoot "rec005-coordination/result.json"' in TEXT
    probe_context = _function_body("Import-ProbeContext")
    assert ".fault-work-$($script:runId)" in probe_context
    assert "$expectedWorkspaceParent" in probe_context
    assert "fault-runtime probe workspace path differs" in probe_context


def test_rec005_sidecar_uses_the_one_use_runtime_credential_bootstrap() -> None:
    probe = _function_body("Invoke-ProbeRec005")
    assert 'CONTEXT_SCHEMA_VERSION = "context-schema-1"' in probe
    assert 'schema_version="spell.driver.context-profile/1"' not in probe
    assert 'configuration_schema_version="spell.driver.context-profile/1"' not in probe
    assert 'target=/run/spell-driver-client-source,readonly"' in probe
    assert "target=/run/spell-driver-client,readonly" not in probe
    assert (
        '"--tmpfs", "/run/spell-driver-client:rw,noexec,nosuid,nodev,'
        'size=64k,mode=0700,uid=0,gid=0"' in probe
    )
    for helper in (
        "clear_credentials",
        "install_runtime_credentials",
        "read_source_credentials",
    ):
        assert helper in probe
    assert 'Path("/run/spell-driver-client-source")' in probe
    assert 'Path("/run/spell-driver-client")' in probe
    assert "runtime_uid=0" in probe
    assert "runtime_gid=0" in probe
    assert 'Path("/run/spell-driver-client/client.key").exists()' in probe
    assert "REC005 sidecar gateway retained its private key" in probe


def test_rec005_releases_each_context_before_the_next_outage_case() -> None:
    probe = _function_body("Invoke-ProbeRec005")
    assert "CloseContextCommand" in probe
    assert "async def close_context" in probe
    make_command = probe.index("def make_command")
    create_context = probe.index("repository.create_context_generation", make_command)
    return_open = probe.index("return OpenContextCommand", create_context)
    make_close = probe.index("def make_close_command", return_open)
    assert make_command < create_context < return_open < make_close
    assert "commands = [make_command(gateway, base, 1)]" in probe
    assert "commands = [make_command(gateway, base, index)" not in probe
    for number in (1, 2, 3):
        assert f"await close_context(gateway, commands[{number - 1}], {number})" in probe
    assert probe.count("commands.append(make_command(gateway, base,") == 2
    assert 'result["stage"] != "SETTLED"' in probe
    assert 'result["disposition"] != "OK"' in probe


def test_rec005_discards_stale_pool_connections_at_each_outage_boundary() -> None:
    probe = _function_body("Invoke-ProbeRec005")
    assert "def __init__(self, delegate, engine):" in probe
    assert "coordinated = CoordinatedRepository(base, engine)" in probe
    assert probe.count("self.engine.dispose()") == 2
    assert (
        "commands = [make_command(gateway, base, 1)]\n"
        "    engine.dispose()\n"
        '    marker("sidecar_ready")' in probe
    )
    assert "async def wait_database(factory, timeout=30):" in probe
    assert "session.scalar(select(1)) == 1" in probe
    assert probe.count("await wait_database(factory)") == 3
    assert 'socket.gethostbyname("postgres")' in probe
    assert "database_address.version != 4" in probe
    assert "not database_address.is_private" in probe
    assert "database_url.set(host=str(database_address))" in probe
    assert "create_database(pinned_database_url)" in probe
    assert "database_url=pinned_database_url" in probe


def test_rec005_owns_internal_routes_independent_of_backend_liveness() -> None:
    probe = _function_body("Invoke-ProbeRec005")
    assert '$databaseNetwork = "$($script:project)_spell-internal"' in probe
    assert '$driverNetwork = "$($script:project)_spell-driver-internal"' in probe
    assert "REC005 network is not an exact project-owned internal route" in probe
    assert '"--network", $databaseNetwork' in probe
    assert '"--network", "container:$($script:containerIds.backend)"' not in probe
    assert (
        'Invoke-Docker @("network", "connect", $driverNetwork, $probeContainer)'
        in probe
    )


def test_mig004_uses_the_execution_api_accepted_status_contract() -> None:
    probe = _function_body("Invoke-ProbeMig004")
    assert "execution_count = int(response.status_code == 202)" in probe
    assert "response.status_code in {200, 201}" not in probe


def test_sec002_health_probe_consumes_only_an_ephemeral_runtime_key() -> None:
    probe = _function_body("Invoke-ProbeSec002")
    assert "read_source_credentials" in probe
    assert "install_runtime_credentials" in probe
    assert "clear_credentials" in probe
    assert 'Path("/run/spell-driver-client-source")' in probe
    assert 'Path("/run/spell-driver-client")' in probe
    assert "runtime_uid=0" in probe
    assert "runtime_gid=0" in probe
    assert "SEC002 health probe retained its private key" in probe
    assert (
        "/run/spell-driver-client:rw,noexec,nosuid,nodev,size=64k,"
        "mode=0700,uid=0,gid=0" in probe
    )
    assert "target=/run/spell-driver-client-source,readonly" in probe


def test_runtime_capture_paths_fit_the_pinned_windows_path_budget() -> None:
    root = PureWindowsPath(r"C:\projects\openbexi_spell")
    fingerprint = "f" * 64
    orchestration_run_id = "a" * 32
    collector_run_id = "b" * 32
    parent = (
        root
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / fingerprint
    )
    longest_artifact = (
        PureWindowsPath("artifacts")
        / "runtime-v04-scope-002.host-powershell.json"
    )
    staging = parent / f".fault-stage-{collector_run_id}" / longest_artifact
    published = parent / f"fault-runtime-{orchestration_run_id}" / longest_artifact
    assert len(str(staging)) == 237
    assert len(str(published)) == 238
    assert len(str(staging)) <= len(str(published)) < 260


def test_native_wrappers_do_not_treat_docker_progress_on_stderr_as_failure() -> None:
    for name in ("Invoke-Docker", "Invoke-Compose"):
        body = _function_body(name)
        assert "$savedPreference = $ErrorActionPreference" in body
        assert '$ErrorActionPreference = "Continue"' in body
        assert "$ErrorActionPreference = $savedPreference" in body
        assert "2>&1" in body
        assert "$exitCode = $LASTEXITCODE" in body
        assert "if ($exitCode -ne 0)" in body


def test_manifest_inventory_is_self_contained_secret_scanned_and_read_only() -> None:
    assert '"runtime-fault-evidence.json"' in TEXT
    assert '"artifacts/$stdoutId.json"' in TEXT
    assert "Assert-ExactArtifactInventory" in TEXT
    inventory = _function_body("Assert-ExactArtifactInventory")
    assert '($rootFiles -join "`0") -cne "runtime-fault-evidence.json"' in inventory
    assert '($rootDirectories -join "`0") -cne "artifacts"' in inventory
    assert "Assert-NoSecretMaterial" in TEXT
    assert "Set-EvidenceReadOnly" in TEXT
    assert "find /runtime-input -type f -exec chmod 0444" in TEXT
    assert "Move-Item -LiteralPath $temporary -Destination $script:contextPath" in TEXT
    assert "[IO.File]::Replace($temporary, $script:contextPath, $backup)" in TEXT
    assert "Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue" in TEXT
    assert "[IO.File]::Replace($temporary, $script:contextPath, $null)" not in TEXT


def test_migration_probe_is_live_postgres_backup_restore_and_both_dialects() -> None:
    body = _function_body("Invoke-ProbeMig004")
    for token in (
        '"pg_dump", "--format", "custom"',
        '"pg_restore", "--no-owner"',
        "_seed_operation_truth_table",
        "UnsafeDriverRollbackError",
        "rollback_driver_foundation",
        "seed_populated_v03_schema",
        "sqlite3.connect",
        "v03_simulator_execution_count",
        "postgres_snapshot_mismatch_count",
        "unsafe_rollback_evidence_loss_count",
    ):
        assert token in body
    assert '"postgres-dump"' in _function_body("Invoke-RuntimeProbeCommand")


def test_recovery_probe_coordinates_three_real_postgres_outage_boundaries() -> None:
    body = _function_body("Invoke-ProbeRec005")
    for marker in (
        "case1_go",
        "case2_dispatched",
        "case3_effect_observed",
        "before_acceptance",
        "during_dispatch",
        "after_effect_before_project_commit",
    ):
        assert marker in body
    assert body.count('"stop", "--time", "1", $script:containerIds.postgres') == 3
    assert "repository.create_context_generation(" in body
    assert body.index("commands = [make_command") < body.index('marker("sidecar_ready")')
    for metric in (
        "phase_count",
        "operation_case_count",
        "duplicate_effect_count",
        "resend_count",
        "unreconstructable_count",
        "audit_outbox_mismatch_count",
        "commit_publish_violation_count",
        "final_disposition_count",
    ):
        assert metric in body
    wrapper = _function_body("Invoke-RuntimeProbeCommand")
    assert "recovery-details" in wrapper
    assert "sidecar-log" in wrapper


def test_security_boundary_and_isolation_metric_names_match_semantic_contract() -> None:
    sec = _function_body("Invoke-ProbeSec004")
    assert re.search(r"\$unsafe = @\(\s+@\(.*?\) \| Where-Object .*?\s+\)", sec, re.DOTALL)
    for key in (
        "direct_administration_status",
        "proxy_route_http_status",
        "unauthorized_metadata_status",
        "safe_audit_reason_count",
        "unsafe_echo_count",
    ):
        assert key in sec
    bound = _function_body("Invoke-ProbeBound002")
    for key in (
        "nominal_captured_frame_count",
        "fault_captured_frame_count",
        "nominal_endpoint_tuple_count",
        "fault_endpoint_tuple_count",
        "nominal_unapproved_endpoint_count",
        "fault_unapproved_endpoint_count",
        "connection_log_unapproved_endpoint_count",
    ):
        assert key in bound
    iso = _function_body("Invoke-ProbeIso004")
    assert '"inspect", "--format", "{{json .}}"' in iso
    assert '"network", "inspect", "--format", "{{json .}}"' in iso


def test_rotation_readiness_comes_from_live_health_and_authenticated_projection() -> None:
    body = _function_body("Invoke-ProbeSec002")
    assert "await client.handshake()" in body
    assert "await client.health()" in body
    assert "Wait-ForDriverProjection" in body
    assert 'Authorization = "Bearer $env:SPELL_RUNTIME_OPERATOR_TOKEN"' in body
    for metric in (
        "prior_trust_fingerprint_count",
        "new_trust_fingerprint_count",
        "retained_prior_trust_fingerprint_count",
        "unexpected_new_trust_fingerprint_count",
        "old_credential_rejection_count",
        "post_rotation_ready_observation_count",
        "post_rotation_stale_observation_count",
        "ready_credential_epoch",
    ):
        assert metric in body
    assert "x509.load_pem_x509_certificate" in _function_body("Get-CredentialHashes")
    assert "prior_trust_fingerprint_count = $priorTrustFingerprintCount" in body
    assert "new_trust_fingerprint_count = $newTrustFingerprintCount" in body
    assert "prior_trust_fingerprint_count = 1" not in body
    assert "new_trust_fingerprint_count = 1" not in body
    assert "$priorTrustFingerprints | Where-Object" in body
    assert "enabled::text" not in body
