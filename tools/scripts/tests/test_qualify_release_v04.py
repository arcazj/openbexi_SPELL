from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import collect_performance_v04, qualify_browser_v04, qualify_faults_v04
from scripts import qualify_v04
from scripts.supply_provenance_v04 import SUPPORTED_TEST_IDS


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "qualify_release_v04.ps1"
PLAN_LOCK = ROOT / "scripts" / "qualification-plan-v04.lock.json"


def _powershell_executable() -> str:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    return powershell


def _run_powershell_harness(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            _powershell_executable(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            source,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _plan_entries() -> list[tuple[str, str, str]]:
    plan = qualify_v04._plan()
    return [
        (gate_id, entry["test_id"], entry["mode"])
        for gate_id, gate in plan["gates"].items()
        for entry in gate
    ]


def test_live_plan_has_one_exact_collector_owner_per_test_id() -> None:
    entries = _plan_entries()
    builtin = {test_id for _, test_id, mode in entries if mode == "builtin"}
    collector = {test_id for _, test_id, mode in entries if mode == "collector"}
    fault = set(qualify_faults_v04.ASSIGNED_IDS)
    browser = set(qualify_browser_v04.TEST_IDS)
    performance = set(collect_performance_v04.TEST_IDS)
    supply = {
        test_id
        for gate, test_id, mode in entries
        if gate == "V04-GATE-5" and mode == "collector"
    }
    regression = collector - fault - browser - performance - supply
    owners = (fault, browser, performance, supply, regression)

    assert len(entries) == 74
    assert len({test_id for _, test_id, _ in entries}) == 74
    assert len(builtin) == 41
    assert len(collector) == 33
    assert tuple(map(len, owners)) == (18, 4, 4, 6, 1)
    assert supply == {f"V04-SC-{index:03d}" for index in range(1, 7)}
    assert set(SUPPORTED_TEST_IDS) < supply
    assert set().union(*owners) == collector
    assert sum(map(len, owners)) == len(set().union(*owners))


def test_tracked_plan_lock_matches_live_plan_and_documents_iso_override() -> None:
    plan = qualify_v04._plan()
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    lock = json.loads(PLAN_LOCK.read_text(encoding="utf-8"))

    assert lock == {
        "schema_version": "spell.v04.qualification-plan-lock/1",
        "product_version": "0.4.0",
        "plan_schema_version": "spell.v04.qualification-plan/1",
        "canonical_plan_sha256": hashlib.sha256(canonical).hexdigest(),
        "test_count": 74,
        "planned_builtin_count": 41,
        "planned_collector_count": 33,
        "actual_builtin_count": 40,
        "actual_collector_count": 34,
        "builtin_collector_overrides": ["V04-ISO-001"],
    }
    entries = {test_id: mode for _, test_id, mode in _plan_entries()}
    assert entries["V04-ISO-001"] == "builtin"


def test_runner_pins_one_qualification_image_and_orders_publication() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    toolchain = runner.index("assert_release_toolchain_v04.ps1")
    qualification_build = runner.index('"scripts/qualification.Dockerfile"')
    isolation = runner.index("collect_isolation_v04.ps1")
    browser = runner.index("qualify_browser_real_v04.ps1")
    performance = runner.index("qualify_performance_v04.py")
    regression = runner.index("qualify_regression_v04.ps1")
    supply = runner.index("audit_supply_chain_v04.ps1")
    sec003_build = runner.index('"scripts/stage_sec003_prepublish_v04.py"), "build"')
    sec003_validate = runner.index(
        '"scripts/stage_sec003_prepublish_v04.py"), "validate"'
    )
    faults = runner.index("collect_fault_gate_v04.ps1")
    status = runner.index('"scripts/qualify_v04.py"), "--root", $root, "status"')
    publish = runner.index('"publish", "--replace"', status)
    package = runner.index("package_release_v04.ps1", publish)

    assert runner.count('"scripts/qualification.Dockerfile"') == 1
    assert toolchain < qualification_build < isolation < browser < performance < regression
    assert regression < supply < sec003_build < sec003_validate < faults < status < publish
    assert publish < package
    assert runner.count('"-QualificationImageId", $qualificationImage') >= 3
    assert '"-ExpectedSourceFingerprint", $source' in runner
    assert '"-DriverImageId", $images.driver' in runner
    assert '"-PkiImageId", $images.pki_init' in runner
    assert '"-DockerExecutable", $DockerExe' in runner
    assert "created-runtime-isolation-covered-by-exact-fault-runtime-composition" not in runner
    assert "collect-composed-builtin.ps1" not in runner
    assert "refusing to pull an unpinned image reference" in runner
    assert 'postgres = Build-RunImage "postgres" "driver_host/postgres.Dockerfile"' in runner
    assert "return Get-ImageId $tag" in runner
    assert 'if ($Mode -ceq "Preliminary")' in runner
    assert 'if ($Mode -ceq "Final")' in runner
    assert "Invoke-QualifierCollect" in runner


def test_runner_cleanup_is_exact_and_never_kills_by_executable_name() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    cleanup = runner.index("finally {")

    assert 'spell.v04.qualification.run=$runId' in runner
    assert 'openbexi-spell-v04-qualification:$runId' in runner
    assert cleanup < runner.index("$runContainers | Select-Object -Unique", cleanup)
    assert cleanup < runner.index("$runNetworks | Select-Object -Unique", cleanup)
    assert cleanup < runner.index("$runVolumes | Select-Object -Unique", cleanup)
    assert cleanup < runner.index("$runTags | Select-Object -Unique", cleanup)
    assert '"container", "inspect", $name' in runner
    assert '"network", "inspect", $name' in runner
    assert '"volume", "inspect", $name' in runner
    assert '"image", "inspect", $tag' in runner
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in runner
    assert "AssignProcessToJobObject" in runner
    assert "Get-QualificationJobActiveProcessCount" in runner
    assert "$activeJobProcesses -ne 1" in runner
    assert "StartedUtcTicks" in runner
    assert "CreationDate.ToUniversalTime().Ticks" in runner
    assert "$cimTicks -lt ($ParentStartedUtcTicks - 10000)" in runner
    assert "Add-ExactDescendants $childId $startedTicks" in runner
    assert "Assert-NativeProcessesExited" in runner
    assert "native process timed out after" in runner

    forbidden = (
        "Stop-Process -Name",
        "Get-Process git",
        "Get-Process docker",
        "taskkill",
        '"container", "prune"',
        '"image", "prune"',
        '"system", "prune"',
    )
    assert not any(value.casefold() in runner.casefold() for value in forbidden)


def test_cleanup_inspection_distinguishes_absence_from_transport_failure() -> None:
    runner = str(RUNNER).replace("'", "''")
    completed = _run_powershell_harness(
        rf"""
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  '{runner}', [ref]$tokens, [ref]$errors
)
$definition = $ast.Find(
  {{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -ceq "Get-CleanupDockerInspectionDisposition"
  }},
  $true
)
if ($null -eq $definition -or $errors.Count -ne 0) {{
  throw "cannot load cleanup inspection classifier"
}}
Invoke-Expression $definition.Extent.Text
$assertDefinition = $ast.Find(
  {{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -ceq "Assert-CleanupDockerObjectAbsent"
  }},
  $true
)
if ($null -eq $assertDefinition) {{
  throw "cannot load cleanup inspection assertion"
}}
Invoke-Expression $assertDefinition.Extent.Text

$reference = "spell-v04-exact-resource"
$transport = [pscustomobject]@{{
  ExitCode = $null
  Lines = [string[]]@()
  Stderr = "native process timed out"
  InvocationFailed = $true
}}
$daemon = [pscustomobject]@{{
  ExitCode = 1
  Lines = [string[]]@()
  Stderr = "error during connect: the Docker daemon is unavailable"
  InvocationFailed = $false
}}
$present = [pscustomobject]@{{
  ExitCode = 0
  Lines = [string[]]@('{{"Id":"present"}}')
  Stderr = ""
  InvocationFailed = $false
}}
$missing = @(
  [pscustomobject]@{{
    Kind = "container"
    Stderr = "Error: No such container: $reference"
  }},
  [pscustomobject]@{{
    Kind = "network"
    Stderr = "Error response from daemon: network $reference not found"
  }},
  [pscustomobject]@{{
    Kind = "volume"
    Stderr = "Error response from daemon: get ${{reference}}: no such volume"
  }},
  [pscustomobject]@{{
    Kind = "image"
    Stderr = "Error: No such image: $reference"
  }}
)
$observed = [Collections.Generic.List[string]]::new()
$observed.Add((Get-CleanupDockerInspectionDisposition `
  -Kind "container" -Reference $reference -Inspection $transport))
$observed.Add((Get-CleanupDockerInspectionDisposition `
  -Kind "container" -Reference $reference -Inspection $daemon))
$observed.Add((Get-CleanupDockerInspectionDisposition `
  -Kind "container" -Reference $reference -Inspection $present))
foreach ($case in $missing) {{
  $inspection = [pscustomobject]@{{
    ExitCode = 1
    Lines = [string[]]@("[]")
    Stderr = $case.Stderr
    InvocationFailed = $false
  }}
  $observed.Add((Get-CleanupDockerInspectionDisposition `
    -Kind $case.Kind -Reference $reference -Inspection $inspection))
}}
$script:cleanupFailures = [Collections.Generic.List[string]]::new()
Assert-CleanupDockerObjectAbsent `
  -Kind "container" -Reference $reference -Inspection $daemon
Assert-CleanupDockerObjectAbsent `
  -Kind "image" -Reference $reference -Inspection $inspection
[pscustomobject]@{{
  Dispositions = [string[]]$observed
  CleanupFailures = [string[]]$script:cleanupFailures
}} | ConvertTo-Json -Compress
"""
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip())
    assert result["Dispositions"] == [
        "unverified",
        "unverified",
        "present",
        "absent",
        "absent",
        "absent",
        "absent",
    ]
    assert len(result["CleanupFailures"]) == 1
    assert result["CleanupFailures"][0].startswith(
        "cannot verify container cleanup: spell-v04-exact-resource:"
    )


def _run_stop_exact_tree_harness(*, root_snapshot_matches: bool) -> list[int]:
    if os.name != "nt":
        pytest.skip("Windows process identity test")
    runner = str(RUNNER).replace("'", "''")
    snapshot_time = (
        "$rootStart"
        if root_snapshot_matches
        else "$rootStart.AddSeconds(5)"
    )
    completed = _run_powershell_harness(
        rf"""
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  '{runner}', [ref]$tokens, [ref]$errors
)
$definition = $ast.Find(
  {{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -ceq "Stop-ExactNativeProcessTree"
  }},
  $true
)
if ($null -eq $definition -or $errors.Count -ne 0) {{
  throw "cannot load exact process-tree cleanup"
}}
Invoke-Expression $definition.Extent.Text

$hostExecutable = (Microsoft.PowerShell.Management\Get-Process -Id $PID).Path
$rootProcess = Start-Process -FilePath $hostExecutable -ArgumentList @(
  "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"
) -PassThru -WindowStyle Hidden
try {{
  $rootProcess.Refresh()
  $rootStart = $rootProcess.StartTime
  $script:rootProcessId = [int]$rootProcess.Id
  $script:fakeChildId = 2147483000
  $script:fakeChildStart = ({snapshot_time}).AddMilliseconds(1)
  $script:snapshot = @(
    [pscustomobject]@{{
      ProcessId = $script:rootProcessId
      ParentProcessId = 0
      CreationDate = {snapshot_time}
    }},
    [pscustomobject]@{{
      ProcessId = $script:fakeChildId
      ParentProcessId = $script:rootProcessId
      CreationDate = $script:fakeChildStart
    }}
  )
  $script:stopped = [Collections.Generic.List[int]]::new()

  function Get-CimInstance {{
    [CmdletBinding()]
    param([Parameter(Position = 0)]$ClassName)
    return $script:snapshot
  }}
  function Get-Process {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Id)
    if ($Id -eq $script:fakeChildId) {{
      return [pscustomobject]@{{ StartTime = $script:fakeChildStart }}
    }}
    return Microsoft.PowerShell.Management\Get-Process `
      -Id $Id -ErrorAction SilentlyContinue
  }}
  function Stop-Process {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Id, [switch]$Force)
    $script:stopped.Add($Id)
    if ($Id -eq $script:rootProcessId) {{
      Microsoft.PowerShell.Management\Stop-Process `
        -Id $Id -Force -ErrorAction SilentlyContinue
    }}
  }}

  Stop-ExactNativeProcessTree -Process $rootProcess
  $script:stopped | ConvertTo-Json -Compress
}}
finally {{
  if (-not $rootProcess.HasExited) {{
    Microsoft.PowerShell.Management\Stop-Process `
      -Id $rootProcess.Id -Force -ErrorAction SilentlyContinue
    [void]$rootProcess.WaitForExit(10000)
  }}
  $rootProcess.Dispose()
}}
"""
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    parsed = json.loads(completed.stdout.strip())
    return parsed if isinstance(parsed, list) else [parsed]


def test_stop_exact_tree_rejects_children_of_a_reused_root_pid() -> None:
    stopped = _run_stop_exact_tree_harness(root_snapshot_matches=False)

    assert len(stopped) == 1
    assert stopped[0] != 2147483000


def test_stop_exact_tree_preserves_descendant_first_cleanup() -> None:
    stopped = _run_stop_exact_tree_harness(root_snapshot_matches=True)

    assert len(stopped) == 2
    assert stopped[0] == 2147483000
    assert stopped[1] != 2147483000


def test_runner_executes_builtins_detached_and_polls_the_exit_state() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert '"run", "--detach", "--name", $builtinRunner' in runner
    assert '"run", "--rm", "--name", $builtinRunner' not in runner
    assert '"volume", "create", "--label", $runLabel, $builtinOutputVolume' in runner
    assert (
        '"type=volume,source=$builtinOutputVolume,'
        'target=/qualification-source/artifacts/v0.4/.qualification"'
    ) in runner
    assert '"type=bind,source=$root,target=/qualification-source"' not in runner
    assert "Invoke-DetachedContainerChecked -ContainerName $builtinRunner" in runner
    assert '"container", "inspect", $ContainerName, "--format", "{{json .State}}"' in runner
    assert '-Arguments @("logs", $ContainerName) -TimeoutSeconds 120' in runner
    assert '"$ContainerName is still running ($elapsedSeconds seconds)"' in runner
    assert (
        '"cp", "${builtinRunner}:/qualification-source/artifacts/v0.4/.qualification/.",'
        in runner
    )


def test_runner_uses_only_the_tracked_plan_lock_and_reports_actual_execution() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert "scripts/qualification-plan-v04.lock.json" in runner
    assert "artifacts/v04-plan.json" not in runner
    assert "canonical_plan_sha256" in runner
    assert "$actualBuiltinCount = $plannedBuiltinCount - $builtinCollectorOverrides.Count" in runner
    assert "$actualCollectorCount = $plannedCollectorCount + $builtinCollectorOverrides.Count" in runner
    assert 'Assert-ExactSet -Expected @("V04-ISO-001")' in runner
    assert "planned_builtin_count = $plannedBuiltinCount" in runner
    assert "actual_collector_count = $actualCollectorCount" in runner


def test_runner_keeps_preliminary_fault_evidence_nonfinal() -> None:
    runner = RUNNER.read_text(encoding="utf-8")

    assert 'if ($Mode -ceq "Preliminary") { $faultCaptureArguments += "-Preliminary" }' in runner
    assert 'else { $faultCaptureArguments += "-ReplaceProvenance" }' in runner
    assert 'if ($Mode -ceq "Preliminary") { $faultExtractArguments += "-Preliminary" }' in runner
    assert '"-CaptureRawReport",\n      "-ReplaceProvenance"' not in runner


def test_runner_uses_the_postgresql_18_data_mount_layout() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    fault_collector = (ROOT / "scripts/collect_fault_gate_v04.ps1").read_text(
        encoding="utf-8"
    )

    for source in (runner, fault_collector):
        assert (
            "/var/lib/postgresql:rw,noexec,nosuid,size=512m,"
            "uid=70,gid=70,mode=1777"
        ) in source
        assert (
            "/var/run/postgresql:rw,noexec,nosuid,size=16m,"
            "uid=70,gid=70,mode=3775"
        ) in source
        assert (
            "/tmp:rw,noexec,nosuid,size=32m,uid=70,gid=70,mode=1777"
        ) in source
        assert "/var/lib/postgresql/data:" not in source


def test_hardened_postgres_entrypoint_creates_the_configured_database() -> None:
    entrypoint = (ROOT / "driver_host/postgres_entrypoint.sh").read_text(
        encoding="utf-8"
    )

    assert 'if [ "$POSTGRES_DB" != "postgres" ]; then' in entrypoint
    assert 'createdb --username "$POSTGRES_USER" "$POSTGRES_DB"' in entrypoint
    assert 'if [ "$POSTGRES_DB" != "$POSTGRES_USER" ]; then' not in entrypoint


def test_shared_image_wrappers_only_remove_images_they_build() -> None:
    for relative in (
        "scripts/qualify_browser_real_v04.ps1",
        "scripts/qualify_regression_v04.ps1",
    ):
        wrapper = (ROOT / relative).read_text(encoding="utf-8")
        assert "[string]$QualificationImageId" in wrapper
        assert "$qualificationImageOwned = $false" in wrapper
        assert "$qualificationImageOwned = $true" in wrapper
        assert "if ($qualificationImageOwned)" in wrapper
        assert "^sha256:[0-9a-f]{64}$" in wrapper


def test_plan_only_executes_without_starting_the_release_gate() -> None:
    powershell = _powershell_executable()
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(RUNNER),
            "-PlanOnly",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    assert lines, completed.stdout
    result = json.loads(lines[-1])
    assert result == {
        "schema_version": "spell.v04.qualification-orchestration/1",
        "run_id": result["run_id"],
        "mode": "Preliminary",
        "planned": True,
        "planned_builtin_count": 41,
        "planned_collector_count": 33,
        "actual_builtin_count": 40,
        "actual_collector_count": 34,
        "builtin_collector_overrides": ["V04-ISO-001"],
        "published": False,
        "package_published": False,
        "cleanup_complete": True,
        "cleanup_failures": [],
        "succeeded": True,
    }
    assert re.fullmatch(r"[0-9a-f]{32}", result["run_id"])
