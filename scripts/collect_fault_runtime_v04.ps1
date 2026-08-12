[CmdletBinding(DefaultParameterSetName = "Collect")]
param(
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$Confirm,

  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$BackendImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$DriverImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$GeneratorImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$PkiInitImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$PostgresImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")][string]$ProxyImage,
  [Parameter(Mandatory = $true, ParameterSetName = "Collect")]
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$QualificationImageId,

  [Parameter(Mandatory = $true, ParameterSetName = "Collect")]
  [string]$OutputDirectory,

  [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
  [ValidateSet(
    "V04-SCOPE-002", "V04-MIG-004", "V04-SEC-002", "V04-SEC-004",
    "V04-BOUND-002", "V04-ISO-003", "V04-ISO-004", "V04-REC-005"
  )]
  [string]$RuntimeProbe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$runId = [guid]::NewGuid().ToString("N")
$project = "spell-v04-fault-$runId"
$failure = $null
$composeStarted = $false
$published = $false
$captureReady = $false
$composeOverride = $null
$DockerExe = $null
$ComposeExe = $null
$PythonExe = $null
$PowerShellExe = $null
$commands = [Collections.Generic.List[object]]::new()
$artifacts = [Collections.Generic.List[object]]::new()
$results = [ordered]@{}
$runContainers = [Collections.Generic.List[string]]::new()
$runVolumes = [Collections.Generic.List[string]]::new()
$priorEnvironment = @{}
$environmentNames = @(
  "DATABASE_URL", "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_DB_PASSWORD", "SPELL_DRIVER_ENABLED",
  "SPELL_DRIVER_POLL_SECONDS", "SPELL_DRIVER_RPC_TIMEOUT_SECONDS",
  "SPELL_DRIVER_STALE_AFTER_SECONDS", "SPELL_JWT_HS256_SECRET",
  "SPELL_PROXY_PORT", "SPELL_RELEASE_COMPOSE_EXE", "SPELL_RELEASE_DOCKER_EXE",
  "SPELL_RELEASE_PYTHON_EXE", "SPELL_RELEASE_BUILDX_EXE",
  "SPELL_RELEASE_SBOM_EXE", "SPELL_RELEASE_SCOUT_EXE",
  "SPELL_RUNTIME_CONTEXT_FILE", "SPELL_RUNTIME_JWT_SECRET",
  "SPELL_RUNTIME_OPERATOR_TOKEN"
)
foreach ($name in $environmentNames) {
  $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

$expectedRuntimeIds = @(
  "V04-SCOPE-002", "V04-MIG-004", "V04-SEC-002", "V04-SEC-004",
  "V04-BOUND-002", "V04-ISO-003", "V04-ISO-004", "V04-REC-005"
)
$expectedImageRoles = @(
  "backend", "driver", "generator", "pki_init", "postgres", "proxy",
  "qualification"
)

function Restore-EnvironmentVariable {
  param([Parameter(Mandatory = $true)][string]$Name, [AllowNull()][string]$Value)
  if ($null -eq $Value) {
    Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
  }
  else {
    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
  }
}

function Get-LowerSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
  param([Parameter(Mandatory = $true)][string]$Value)
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString(
      $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
    )).Replace("-", "").ToLowerInvariant()
  }
  finally { $hasher.Dispose() }
}

function ConvertTo-PythonExecCode {
  param([Parameter(Mandatory = $true)][string]$Code)
  $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Code))
  return "__import__('builtins').exec(__import__('base64').b64decode('$encoded'))"
}

function Write-Utf8Json {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Value
  )
  $json = $Value | ConvertTo-Json -Compress -Depth 100
  if ($json -match '(?i)NaN|Infinity') { throw "refusing non-finite runtime JSON" }
  [IO.File]::WriteAllText(
    $Path,
    $json + "`n",
    [Text.UTF8Encoding]::new($false)
  )
}

function Write-PythonCanonicalJson {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Value
  )
  $inputPath = Join-Path $script:temporaryRoot ("canonical-" + [guid]::NewGuid().ToString("N") + ".json")
  try {
    Write-Utf8Json $inputPath $Value
    $code = @'
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
value = json.loads(source.read_text(encoding="utf-8"))
target.write_bytes(json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
'@
    @(& $script:PythonExe -I -c (ConvertTo-PythonExecCode $code) $inputPath $Path) | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      throw "locked Python failed to write canonical runtime JSON"
    }
  }
  finally { Remove-Item -LiteralPath $inputPath -Force -ErrorAction SilentlyContinue }
}

function Invoke-ExactProcessCapture {
  param(
    [Parameter(Mandatory = $true)][string]$FileName,
    [Parameter(Mandatory = $true)][string]$Arguments,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][string[]]$EnvironmentKeys,
    [Parameter(Mandatory = $true)][hashtable]$EnvironmentValues
  )
  $start = [Diagnostics.ProcessStartInfo]::new()
  $start.FileName = $FileName
  $start.Arguments = $Arguments
  $start.WorkingDirectory = $script:root
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $hostEnvironmentAllowlist = @(
    "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH",
    "PATHEXT", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PSMODULEPATH", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE",
    "WINDIR"
  )
  foreach ($name in @($start.EnvironmentVariables.Keys)) {
    if (([string]$name).ToUpperInvariant() -notin $hostEnvironmentAllowlist) {
      $start.EnvironmentVariables.Remove([string]$name)
    }
  }
  foreach ($name in $EnvironmentKeys) {
    if (-not $EnvironmentValues[$name]) {
      throw "runtime probe environment is missing $name"
    }
    $start.EnvironmentVariables[$name] = [string]$EnvironmentValues[$name]
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $start
  $stdout = [IO.File]::Open($StdoutPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  $stderr = [IO.File]::Open($StderrPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  try {
    if (-not $process.Start()) { throw "cannot start runtime probe process" }
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
    $process.WaitForExit()
    [Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))
    return [int]$process.ExitCode
  }
  finally {
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
  }
}

function Invoke-DockerCleanupCommand {
  param([Parameter(Mandatory = $true)][string[]]$DockerArguments)
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:DockerExe @DockerArguments 2>$null)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  return [pscustomobject]@{
    ExitCode = [int]$exitCode
    Lines = [string[]]@($lines | ForEach-Object { [string]$_ })
  }
}

function Invoke-Docker {
  param(
    [Parameter(Mandatory = $true)][string[]]$DockerArguments,
    [Parameter(Mandatory = $true)][string]$FailureMessage
  )
  $savedPreference = $ErrorActionPreference
  try {
    $global:LASTEXITCODE = 0
    $ErrorActionPreference = "Continue"
    $output = @(& $script:DockerExe @DockerArguments 2>&1)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  if ($exitCode -ne 0) { throw $FailureMessage }
  return [string[]]@($output | ForEach-Object { [string]$_ })
}

function Invoke-Compose {
  param(
    [Parameter(Mandatory = $true)][string[]]$ComposeArguments,
    [Parameter(Mandatory = $true)][string]$FailureMessage
  )
  $arguments = @(
    "--project-name", $script:project,
    "--file", (Join-Path $script:root "compose.yaml"),
    "--file", $script:composeOverride,
    "--profile", "driver"
  ) + $ComposeArguments
  $savedPreference = $ErrorActionPreference
  try {
    $global:LASTEXITCODE = 0
    $ErrorActionPreference = "Continue"
    $output = @(& $script:ComposeExe @arguments 2>&1)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  if ($exitCode -ne 0) { throw $FailureMessage }
  return [string[]]@($output | ForEach-Object { [string]$_ })
}

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  }
  finally { $listener.Stop() }
}

function Get-ExactImageId {
  param([Parameter(Mandatory = $true)][string]$Reference)
  $lines = Invoke-Docker @(
    "image", "inspect", $Reference, "--format", "{{.Id}}"
  ) "cannot inspect an exact fault-runtime image"
  $value = ([string]($lines | Select-Object -Last 1)).Trim().ToLowerInvariant()
  if ($value -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "fault-runtime image identity is invalid"
  }
  return $value
}

function Get-ComposeContainerId {
  param([Parameter(Mandatory = $true)][string]$Service)
  $lines = Invoke-Compose @("ps", "--all", "--quiet", $Service) `
    "cannot locate the $Service fault-runtime container"
  $short = ([string]($lines | Where-Object { $_.Trim() } | Select-Object -Last 1)).Trim()
  if (-not $short) { throw "$Service fault-runtime container is absent" }
  $full = (Invoke-Docker @("inspect", "--format", "{{.Id}}", $short) `
    "cannot inspect the $Service fault-runtime container" | Select-Object -Last 1).Trim()
  if ($full -cnotmatch '^[0-9a-f]{64}$') {
    throw "$Service fault-runtime container identity is invalid"
  }
  return $full
}

function Get-ContainerImageId {
  param([Parameter(Mandatory = $true)][string]$ContainerId)
  $value = (Invoke-Docker @("inspect", "--format", "{{.Image}}", $ContainerId) `
    "cannot inspect a fault-runtime container image" | Select-Object -Last 1).Trim().ToLowerInvariant()
  if ($value -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "fault-runtime container image identity is invalid"
  }
  return $value
}

function Assert-NoProjectResources {
  $queries = [ordered]@{
    containers = @("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=$script:project")
    networks = @("network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=$script:project")
    volumes = @("volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=$script:project")
  }
  foreach ($entry in $queries.GetEnumerator()) {
    $inspection = Invoke-DockerCleanupCommand ([string[]]$entry.Value)
    if ($inspection.ExitCode -ne 0) {
      throw "cannot inspect residual fault-runtime $($entry.Key)"
    }
    if (@($inspection.Lines | Where-Object { $_.Trim() }).Count -ne 0) {
      throw "fault-runtime left labeled $($entry.Key)"
    }
  }
}

function Add-ArtifactRecord {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$RelativePath,
    [Parameter(Mandatory = $true)][string]$Kind
  )
  $path = Join-Path $script:stagingRoot $RelativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "runtime artifact is missing: $Id"
  }
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "runtime artifact is a reparse point: $Id"
  }
  $record = [ordered]@{
    id = $Id
    path = $RelativePath.Replace('\', '/')
    kind = $Kind
    sha256 = Get-LowerSha256 $path
    bytes = [int64]$item.Length
  }
  $script:artifacts.Add($record)
  return $record
}

function Invoke-RuntimeProbeCommand {
  param(
    [Parameter(Mandatory = $true)][string]$TestId
  )
  if ($script:results.Contains($TestId)) { throw "duplicate runtime result: $TestId" }
  if ($TestId -cnotin $script:expectedRuntimeIds) { throw "unexpected runtime result: $TestId" }
  $stem = $TestId.ToLowerInvariant()
  $commandId = "runtime-$stem"
  $stdoutId = "$commandId.stdout"
  $stderrId = "$commandId.stderr"
  $evidenceId = "$commandId.evidence"
  $powerShellArtifactId = "$commandId.host-powershell"
  $pythonArtifactId = "$commandId.host-python"
  $dockerArtifactId = "$commandId.host-docker"
  $composeArtifactId = "$commandId.host-compose"
  $stdoutRelative = "artifacts/$stdoutId.json"
  $stderrRelative = "artifacts/$stderrId.txt"
  $evidenceRelative = "artifacts/$evidenceId.json"
  $powerShellRelative = "artifacts/$powerShellArtifactId.json"
  $pythonRelative = "artifacts/$pythonArtifactId.json"
  $dockerRelative = "artifacts/$dockerArtifactId.json"
  $composeRelative = "artifacts/$composeArtifactId.json"
  $stdoutCapture = Join-Path $script:temporaryRoot "$commandId.stdout.tmp"
  $stderrCapture = Join-Path $script:temporaryRoot "$commandId.stderr.tmp"
  $canonicalArgv = @(
    $script:PowerShellExe, "-NoProfile", "-NonInteractive", "-File",
    "scripts/collect_fault_runtime_v04.ps1", "-RuntimeProbe", $TestId
  )
  $environmentById = @{
    "V04-SCOPE-002" = @(
      "DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE",
      "SPELL_RUNTIME_OPERATOR_TOKEN"
    )
    "V04-MIG-004" = @("DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE")
    "V04-SEC-002" = @(
      "DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE",
      "SPELL_RUNTIME_OPERATOR_TOKEN"
    )
    "V04-SEC-004" = @(
      "SPELL_RUNTIME_CONTEXT_FILE", "SPELL_RUNTIME_JWT_SECRET",
      "SPELL_RUNTIME_OPERATOR_TOKEN"
    )
    "V04-BOUND-002" = @("SPELL_RUNTIME_CONTEXT_FILE")
    "V04-ISO-003" = @(
      "SPELL_RUNTIME_CONTEXT_FILE", "SPELL_RUNTIME_OPERATOR_TOKEN"
    )
    "V04-ISO-004" = @("SPELL_RUNTIME_CONTEXT_FILE")
    "V04-REC-005" = @("DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE")
  }
  $environmentValues = @{}
  foreach ($name in $environmentById[$TestId]) {
    $environmentValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
  }
  $processArguments = '-NoProfile -NonInteractive -File "scripts/collect_fault_runtime_v04.ps1" -RuntimeProbe "' + $TestId + '"'
  $startedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
  $exitCode = Invoke-ExactProcessCapture `
    $script:PowerShellExe $processArguments $stdoutCapture $stderrCapture `
    ([string[]]$environmentById[$TestId]) $environmentValues
  $finishedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
  [byte[]]$stderrBytes = [byte[]]::new(0)
  if (Test-Path -LiteralPath $stderrCapture -PathType Leaf) {
    $stderrBytes = [IO.File]::ReadAllBytes($stderrCapture)
  }
  [IO.File]::WriteAllBytes(
    (Join-Path $script:stagingRoot $stderrRelative),
    $stderrBytes
  )
  if ($exitCode -ne 0) {
    $detail = if ($stderrBytes.Length) {
      [Text.Encoding]::UTF8.GetString($stderrBytes)
    }
    else { "no stderr" }
    throw "$TestId runtime probe failed: $detail"
  }
  if ($stderrBytes.Length -ne 0) {
    throw "$TestId runtime probe emitted unexpected stderr"
  }
  $stdoutBytes = [IO.File]::ReadAllBytes($stdoutCapture)
  if (-not $stdoutBytes.Length) { throw "$TestId runtime probe emitted no JSON evidence" }
  try { $line = [Text.UTF8Encoding]::new($false, $true).GetString($stdoutBytes) }
  catch { throw "$TestId runtime probe stdout is not UTF-8" }
  if (-not $line.EndsWith("`n") -or $line.Contains("`r") -or $line.Substring(0, $line.Length - 1).Contains("`n")) {
    throw "$TestId runtime probe emitted extra or noncanonical output"
  }
  try { $evidence = $line | ConvertFrom-Json }
  catch { throw "$TestId runtime probe emitted invalid JSON" }
  $evidenceKeys = @($evidence.PSObject.Properties.Name | Sort-Object)
  if (($evidenceKeys -join "`0") -cne "assertions`0metrics`0test_id") {
    throw "$TestId runtime probe evidence fields differ"
  }
  if ([string]$evidence.test_id -cne $TestId) {
    throw "$TestId runtime probe returned another test ID"
  }
  $canonicalCheck = Join-Path $script:temporaryRoot "$commandId.canonical-check.json"
  Write-PythonCanonicalJson $canonicalCheck $evidence
  $canonicalBytes = [IO.File]::ReadAllBytes($canonicalCheck)
  if (
    $stdoutBytes.Length -ne $canonicalBytes.Length -or
    (Get-LowerSha256 $stdoutCapture) -cne (Get-LowerSha256 $canonicalCheck)
  ) {
    throw "$TestId runtime probe stdout is not the exact canonical evidence"
  }
  [IO.File]::WriteAllBytes((Join-Path $script:stagingRoot $stdoutRelative), $stdoutBytes)
  [IO.File]::WriteAllBytes((Join-Path $script:stagingRoot $evidenceRelative), $stdoutBytes)
  Write-PythonCanonicalJson (Join-Path $script:stagingRoot $powerShellRelative) ([ordered]@{
    path = $script:PowerShellExe
    sha256 = $script:PowerShellSha256
    version = $script:PowerShellVersion
  })
  Write-PythonCanonicalJson (Join-Path $script:stagingRoot $pythonRelative) ([ordered]@{
    path = $script:PythonExe
    sha256 = $script:PythonSha256
    version = $script:PythonVersion
  })
  Write-PythonCanonicalJson (Join-Path $script:stagingRoot $dockerRelative) ([ordered]@{
    path = $script:DockerExe
    sha256 = $script:DockerSha256
    version = $script:DockerVersion
  })
  Write-PythonCanonicalJson (Join-Path $script:stagingRoot $composeRelative) ([ordered]@{
    path = $script:ComposeExe
    sha256 = $script:ComposeSha256
    version = $script:ComposeVersion
  })
  Add-ArtifactRecord $stdoutId $stdoutRelative "command-stdout" | Out-Null
  Add-ArtifactRecord $stderrId $stderrRelative "command-stderr" | Out-Null
  Add-ArtifactRecord $evidenceId $evidenceRelative "test-evidence" | Out-Null
  Add-ArtifactRecord $powerShellArtifactId $powerShellRelative "runtime-json" | Out-Null
  Add-ArtifactRecord $pythonArtifactId $pythonRelative "runtime-json" | Out-Null
  Add-ArtifactRecord $dockerArtifactId $dockerRelative "runtime-json" | Out-Null
  Add-ArtifactRecord $composeArtifactId $composeRelative "runtime-json" | Out-Null
  $supplementalArtifactIds = @()
  if ($TestId -ceq "V04-MIG-004") {
    $dumpSource = Join-Path $script:temporaryRoot "mig004-postgres.dump"
    $dumpId = "$commandId.postgres-dump"
    $dumpRelative = "artifacts/$dumpId.bin"
    if (-not (Test-Path -LiteralPath $dumpSource -PathType Leaf)) {
      throw "V04-MIG-004 did not produce its PostgreSQL dump artifact"
    }
    Copy-Item -LiteralPath $dumpSource `
      -Destination (Join-Path $script:stagingRoot $dumpRelative)
    Add-ArtifactRecord $dumpId $dumpRelative "postgres-dump" | Out-Null
    $supplementalArtifactIds = @($dumpId)
  }
  elseif ($TestId -ceq "V04-REC-005") {
    $detailSource = Join-Path $script:workspaceRuntimeRoot "rec005-coordination/result.json"
    $logSource = Join-Path $script:temporaryRoot "rec005-sidecar.log"
    $detailId = "$commandId.recovery-details"
    $logId = "$commandId.sidecar-log"
    $detailRelative = "artifacts/$detailId.json"
    $logRelative = "artifacts/$logId.txt"
    foreach ($source in @($detailSource, $logSource)) {
      if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "V04-REC-005 did not retain its detailed sidecar evidence"
      }
    }
    Copy-Item -LiteralPath $detailSource -Destination (Join-Path $script:stagingRoot $detailRelative)
    Copy-Item -LiteralPath $logSource -Destination (Join-Path $script:stagingRoot $logRelative)
    Add-ArtifactRecord $detailId $detailRelative "runtime-json" | Out-Null
    Add-ArtifactRecord $logId $logRelative "service-log" | Out-Null
    $supplementalArtifactIds = @($detailId, $logId)
  }
  $script:commands.Add([ordered]@{
    id = $commandId
    test_id = $TestId
    executor = "host-powershell"
    argv = $canonicalArgv
    exit_code = [int]$exitCode
    stdout_artifact_id = $stdoutId
    stderr_artifact_id = $stderrId
    evidence_artifact_id = $evidenceId
    environment_keys = @($environmentById[$TestId])
    started_at = $startedAt
    finished_at = $finishedAt
  })
  $script:results[$TestId] = [ordered]@{
    test_id = $TestId
    assertions = @($evidence.assertions)
    metrics = $evidence.metrics
    command_ids = @($commandId)
    artifact_ids = @(
      $stdoutId, $stderrId, $evidenceId, $powerShellArtifactId, $pythonArtifactId,
      $dockerArtifactId, $composeArtifactId
    ) + $supplementalArtifactIds
  }
}

function Convert-JsonLine {
  param(
    [Parameter(Mandatory = $true)][string[]]$Lines,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $line = [string]($Lines | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
  if (-not $line) { throw "$Label emitted no JSON object" }
  try { return $line | ConvertFrom-Json }
  catch { throw "$Label emitted invalid JSON: $($_.Exception.Message)" }
}

function Invoke-QualificationInNamespace {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$NamespaceContainer,
    [Parameter(Mandatory = $true)][string[]]$Command,
    [string[]]$AdditionalArguments = @()
  )
  $arguments = @(
    "run", "--rm", "--name", $Name,
    "--label", "com.docker.compose.project=$script:project",
    "--network", "container:$NamespaceContainer",
    "--read-only", "--tmpfs", "/tmp:size=128m,noexec,nosuid",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"
  ) + $AdditionalArguments + @($script:imageIds.qualification) + $Command
  return Invoke-Docker $arguments "fault-runtime namespace probe failed: $Name"
}

function Invoke-PostgresScalar {
  param([Parameter(Mandatory = $true)][string]$Sql, [string]$Database = "spell")
  $lines = Invoke-Docker @(
    "exec", $script:containerIds.postgres, "psql", "--no-psqlrc", "--tuples-only",
    "--no-align", "--set", "ON_ERROR_STOP=1", "--username", "spell",
    "--dbname", $Database, "--command", $Sql
  ) "PostgreSQL scalar probe failed"
  return ([string]($lines | Where-Object { $_.Trim() } | Select-Object -Last 1)).Trim()
}

function Wait-ForDriverProjection {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Headers,
    [Parameter(Mandatory = $true)][string[]]$AcceptedStates,
    [int]$TimeoutSeconds = 45
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    try {
      $value = Invoke-RestMethod -Method Get -Headers $Headers `
        -Uri "$script:baseUrl/api/v1/drivers" -TimeoutSec 3
      $driver = @($value.items) | Select-Object -First 1
      if ($driver -and [string]$driver.state -cin $AcceptedStates) { return $driver }
    }
    catch { }
    Start-Sleep -Milliseconds 250
  } until ((Get-Date) -ge $deadline)
  throw "driver projection did not reach the required state"
}

function Assert-SourceUnchanged {
  $lines = @(& $script:PythonExe -I (Join-Path $script:root "scripts/source_fingerprint_v04.py") --root $script:root)
  if ($LASTEXITCODE -ne 0) { throw "cannot recompute the v0.4 source fingerprint" }
  $after = [string]($lines | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1)
  if ($after -cne $script:sourceFingerprint) {
    throw "source changed during fault-runtime qualification"
  }
}

function Set-EvidenceReadOnly {
  $chmodName = "spell-v04-fault-chmod-$script:runId"
  $script:runContainers.Add($chmodName)
  $arguments = @(
    "run", "--rm", "--name", $chmodName,
    "--label", "com.docker.compose.project=$script:project", "--network", "none",
    "--read-only", "--user", "0:0",
    "--mount", "type=bind,source=$script:stagingRoot,target=/runtime-input",
    "--entrypoint", "sh", $script:imageIds.qualification,
    "-ec", "find /runtime-input -type f -exec chmod 0444 '{}' +"
  )
  Invoke-Docker $arguments "cannot make runtime evidence files immutable" | Out-Null
  foreach ($file in @(Get-ChildItem -LiteralPath $script:stagingRoot -File -Recurse -Force)) {
    $file.IsReadOnly = $true
  }
}

function Assert-NoSecretMaterial {
  foreach ($file in @(Get-ChildItem -LiteralPath $script:stagingRoot -File -Recurse -Force)) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    foreach ($value in @($script:databaseSecret, $script:jwtSecret, $script:operatorToken)) {
      if ($value -and $text.Contains([string]$value)) {
        throw "runtime evidence contains secret material"
      }
    }
    if (
      $text -match '-----BEGIN [^-]*(PRIVATE KEY|OPENSSH PRIVATE KEY)-----' -or
      $text -match '(?i)authorization\s*:\s*bearer' -or
      $text -match '(?i)://[^/@\s:]+:[^/@\s]+@'
    ) { throw "runtime evidence contains credential material" }
    foreach ($forbiddenName in @("password", "private_key", "client_key", "secret", "token")) {
      if ($text -match ('(?i)["'']?' + [regex]::Escape($forbiddenName) + '["'']?\s*[:=]')) {
        throw "runtime evidence contains a forbidden secret-bearing key"
      }
    }
  }
}

function Import-ProbeContext {
  $contextPath = [Environment]::GetEnvironmentVariable(
    "SPELL_RUNTIME_CONTEXT_FILE", "Process"
  )
  if (-not $contextPath) { throw "SPELL_RUNTIME_CONTEXT_FILE is required" }
  $contextPath = [IO.Path]::GetFullPath($contextPath)
  if (-not (Test-Path -LiteralPath $contextPath -PathType Leaf)) {
    throw "fault-runtime probe context is unavailable"
  }
  $item = Get-Item -LiteralPath $contextPath -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "fault-runtime probe context cannot be a reparse point"
  }
  try { $context = Get-Content -LiteralPath $contextPath -Raw | ConvertFrom-Json }
  catch { throw "fault-runtime probe context is invalid JSON" }
  $keys = @($context.PSObject.Properties.Name | Sort-Object)
  $expected = @(
    "base_url", "compose_executable", "compose_override", "container_ids",
    "compose_sha256", "compose_version", "credential_volume", "docker_executable",
    "docker_sha256", "docker_version", "host_configuration_path", "images",
    "journal_volume", "server_credential_volume",
    "powershell_executable", "powershell_sha256", "powershell_version",
    "python_executable", "python_sha256", "python_version",
    "project_name", "root", "run_id", "schema_version",
    "source_fingerprint_sha256", "temporary_root"
  ) | Sort-Object
  if (($keys -join "`0") -cne ($expected -join "`0")) {
    throw "fault-runtime probe context fields differ"
  }
  if (
    [string]$context.schema_version -cne "spell.v04.fault-runtime-context/1" -or
    [string]$context.run_id -cnotmatch '^[0-9a-f]{32}$' -or
    [string]$context.source_fingerprint_sha256 -cnotmatch '^[0-9a-f]{64}$'
  ) { throw "fault-runtime probe context identity is invalid" }
  $script:root = [IO.Path]::GetFullPath([string]$context.root)
  $script:project = [string]$context.project_name
  $script:composeOverride = [IO.Path]::GetFullPath([string]$context.compose_override)
  $script:DockerExe = [IO.Path]::GetFullPath([string]$context.docker_executable)
  $script:ComposeExe = [IO.Path]::GetFullPath([string]$context.compose_executable)
  $script:DockerSha256 = [string]$context.docker_sha256
  $script:DockerVersion = [string]$context.docker_version
  $script:ComposeSha256 = [string]$context.compose_sha256
  $script:ComposeVersion = [string]$context.compose_version
  $script:PowerShellExe = [IO.Path]::GetFullPath([string]$context.powershell_executable)
  $script:PowerShellSha256 = [string]$context.powershell_sha256
  $script:PowerShellVersion = [string]$context.powershell_version
  $script:PythonExe = [IO.Path]::GetFullPath([string]$context.python_executable)
  $script:PythonSha256 = [string]$context.python_sha256
  $script:PythonVersion = [string]$context.python_version
  $script:imageIds = $context.images
  $script:containerIds = $context.container_ids
  $script:sourceFingerprint = [string]$context.source_fingerprint_sha256
  $script:runId = [string]$context.run_id
  $script:baseUrl = [string]$context.base_url
  $script:credentialVolume = [string]$context.credential_volume
  $script:journalVolume = [string]$context.journal_volume
  $script:serverCredentialVolume = [string]$context.server_credential_volume
  $script:hostConfigurationPath = [IO.Path]::GetFullPath(
    [string]$context.host_configuration_path
  )
  $script:workspaceRuntimeRoot = [IO.Path]::GetFullPath(
    (Split-Path -Parent $script:hostConfigurationPath)
  )
  $script:temporaryRoot = [IO.Path]::GetFullPath([string]$context.temporary_root)
  if (
    -not (Test-Path -LiteralPath $script:DockerExe -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:ComposeExe -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:PowerShellExe -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:PythonExe -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:hostConfigurationPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:composeOverride -PathType Leaf)
  ) { throw "fault-runtime probe tool/context path is unavailable" }
  $expectedWorkspaceParent = [IO.Path]::GetFullPath(
    (Join-Path $script:root "artifacts/v0.4/.qualification/runtime-captures/$($script:sourceFingerprint)")
  )
  $workspaceParent = [IO.Path]::GetFullPath(
    (Split-Path -Parent $script:workspaceRuntimeRoot)
  )
  $workspaceItem = Get-Item -LiteralPath $script:workspaceRuntimeRoot -Force
  $hostConfigurationItem = Get-Item -LiteralPath $script:hostConfigurationPath -Force
  if (
    -not (Test-Path -LiteralPath $script:workspaceRuntimeRoot -PathType Container) -or
    $workspaceItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
    $hostConfigurationItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
    -not $workspaceParent.Equals(
      $expectedWorkspaceParent,
      [StringComparison]::OrdinalIgnoreCase
    ) -or
    [IO.Path]::GetFileName($script:workspaceRuntimeRoot) -cne ".fault-work-$($script:runId)" -or
    [IO.Path]::GetFileName($script:hostConfigurationPath) -cne "host-profile.json"
  ) { throw "fault-runtime probe workspace path differs" }
  $lockPath = Join-Path $script:root "scripts/release-toolchain-v04.json"
  try { $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json }
  catch { throw "fault-runtime probe cannot parse the release toolchain lock" }
  $pythonLock = @($lock.tools | Where-Object { $_.name -ceq "python" })
  $dockerLock = @($lock.tools | Where-Object { $_.name -ceq "docker-cli" })
  $composeLock = @($lock.tools | Where-Object { $_.name -ceq "docker-compose" })
  if ($pythonLock.Count -ne 1 -or $dockerLock.Count -ne 1 -or $composeLock.Count -ne 1) {
    throw "fault-runtime probe tool lock set differs"
  }
  $lockedPythonPath = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA ([string]$pythonLock[0].relative_path))
  )
  $lockedDockerPath = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramFiles ([string]$dockerLock[0].relative_path))
  )
  $lockedComposePath = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramFiles ([string]$composeLock[0].relative_path))
  )
  if (
    -not $script:PythonExe.Equals($lockedPythonPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not $script:DockerExe.Equals($lockedDockerPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not $script:ComposeExe.Equals($lockedComposePath, [StringComparison]::OrdinalIgnoreCase) -or
    $script:PythonSha256 -cne [string]$pythonLock[0].sha256 -or
    $script:DockerSha256 -cne [string]$dockerLock[0].sha256 -or
    $script:ComposeSha256 -cne [string]$composeLock[0].sha256 -or
    $script:PythonVersion -cne [string]$lock.versions.host_python -or
    $script:DockerVersion -cne [string]$lock.versions.docker_cli -or
    $script:ComposeVersion -cne [string]$lock.versions.docker_compose -or
    $script:PythonSha256 -cne "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1" -or
    $script:PythonVersion -cne "3.13.14"
  ) { throw "fault-runtime probe action tools differ from the exact release lock" }
  if (
    (Get-LowerSha256 $script:PowerShellExe) -cne $script:PowerShellSha256 -or
    (Get-LowerSha256 $script:PythonExe) -cne $script:PythonSha256 -or
    (Get-LowerSha256 $script:DockerExe) -cne $script:DockerSha256 -or
    (Get-LowerSha256 $script:ComposeExe) -cne $script:ComposeSha256 -or
    $PSVersionTable.PSVersion.ToString() -cne $script:PowerShellVersion
  ) { throw "host PowerShell executor identity differs" }
  $pythonVersion = (@(& $script:PythonExe --version) -join "").Trim()
  if ($LASTEXITCODE -ne 0 -or $pythonVersion -cne "Python $script:PythonVersion") {
    throw "host Python canonicalizer identity differs"
  }
  $dockerVersionOutput = (@(& $script:DockerExe --version) -join "").Trim()
  if ($LASTEXITCODE -ne 0 -or $dockerVersionOutput -notmatch [regex]::Escape("Docker version $script:DockerVersion,")) {
    throw "host Docker executor identity differs"
  }
  $composeVersionOutput = (@(& $script:ComposeExe version) -join "").Trim()
  if ($LASTEXITCODE -ne 0 -or $composeVersionOutput -notmatch [regex]::Escape($script:ComposeVersion)) {
    throw "host Compose executor identity differs"
  }
  Assert-SourceUnchanged
  return $context
}

function New-ProbeEvidence {
  param(
    [Parameter(Mandatory = $true)][string]$TestId,
    [Parameter(Mandatory = $true)][string[]]$AssertionIds,
    [Parameter(Mandatory = $true)]$Metrics
  )
  if ($Metrics -isnot [Collections.IDictionary]) {
    throw "runtime metrics must be an ordered mapping"
  }
  $Metrics["host_powershell_sha256"] = $script:PowerShellSha256
  $Metrics["host_powershell_version"] = $script:PowerShellVersion
  $Metrics["host_python_sha256"] = $script:PythonSha256
  $Metrics["host_python_version"] = $script:PythonVersion
  $Metrics["host_docker_sha256"] = $script:DockerSha256
  $Metrics["host_docker_version"] = $script:DockerVersion
  $Metrics["host_compose_sha256"] = $script:ComposeSha256
  $Metrics["host_compose_version"] = $script:ComposeVersion
  return [ordered]@{
    test_id = $TestId
    assertions = @($AssertionIds | ForEach-Object {
      [ordered]@{ id = $_; passed = $true }
    })
    metrics = $Metrics
  }
}

function Get-ProjectCounters {
  $value = Invoke-PostgresScalar @'
SELECT
  (SELECT count(*) FROM driver_context_generations)::text || '|' ||
  (SELECT count(*) FROM driver_bindings)::text || '|' ||
  (SELECT count(*) FROM driver_operations)::text;
'@
  $parts = @($value.Split('|'))
  if ($parts.Count -ne 3 -or @($parts | Where-Object { $_ -cnotmatch '^\d+$' }).Count) {
    throw "project driver counters are invalid"
  }
  return [ordered]@{
    contexts = [int64]$parts[0]
    bindings = [int64]$parts[1]
    operations = [int64]$parts[2]
  }
}

function Get-DriverJournalAttemptCount {
  $code = @'
import sqlite3
connection = sqlite3.connect("file:/var/lib/spell-driver/driver.sqlite?mode=ro", uri=True)
try:
    print(connection.execute("SELECT COUNT(*) FROM operation_attempts").fetchone()[0])
finally:
    connection.close()
'@
  $lines = Invoke-Docker @(
    "exec", $script:containerIds.driver, "python", "-c", (ConvertTo-PythonExecCode $code)
  ) "cannot inspect the driver journal attempt count"
  $value = ([string]($lines | Where-Object { $_ -cmatch '^\d+$' } | Select-Object -Last 1)).Trim()
  if ($value -cnotmatch '^\d+$') { throw "driver journal attempt count is invalid" }
  return [int64]$value
}

function Get-RuntimeDatabaseUrl {
  param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z][a-z0-9_]{0,62}$')]
    [string]$DatabaseName,
    [ValidateSet("127.0.0.1", "postgres")]
    [string]$HostName = "127.0.0.1",
    [string]$BaseUrl
  )
  $value = if ($BaseUrl) {
    $BaseUrl
  }
  else { [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process") }
  if (-not $value) { throw "DATABASE_URL is required for this runtime probe" }
  try { $builder = [UriBuilder]::new($value) }
  catch { throw "runtime DATABASE_URL is invalid" }
  if (
    $builder.Scheme -cne "postgresql+psycopg" -or
    $builder.UserName -cne "spell" -or -not $builder.Password -or
    $builder.Host -cne "127.0.0.1" -or $builder.Port -ne 5432 -or
    $builder.Path -cne "/spell" -or $builder.Query -cne "?connect_timeout=2"
  ) { throw "runtime DATABASE_URL differs from its bounded local form" }
  $builder.Host = $HostName
  $builder.Path = "/$DatabaseName"
  return $builder.Uri.AbsoluteUri
}

function Invoke-ProbeScope002 {
  foreach ($name in @(
    "DATABASE_URL", "SPELL_RUNTIME_OPERATOR_TOKEN"
  )) {
    if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
      throw "$name is required for V04-SCOPE-002"
    }
  }
  $token = [Environment]::GetEnvironmentVariable(
    "SPELL_RUNTIME_OPERATOR_TOKEN", "Process"
  )
  $headers = @{ Authorization = "Bearer $token" }
  $beforeProjection = Wait-ForDriverProjection $headers @("READY")
  $healthDeadline = (Get-Date).AddSeconds(15)
  $afterProjection = $beforeProjection
  do {
    Start-Sleep -Milliseconds 300
    $afterProjection = Wait-ForDriverProjection $headers @("READY") 5
  } until (
    [string]$afterProjection.last_observed_at -cne [string]$beforeProjection.last_observed_at -or
    (Get-Date) -ge $healthDeadline
  )
  if ([string]$afterProjection.last_observed_at -ceq [string]$beforeProjection.last_observed_at) {
    throw "driver Health baseline did not advance"
  }

  $before = Get-ProjectCounters
  $journalBefore = Get-DriverJournalAttemptCount
  $createBody = [ordered]@{
    procedure_id = "demo"
    context_id = "simulator"
    reason = "v0.4 local synthetic scope qualification"
    idempotency_key = "fault-runtime-scope-$script:runId"
  } | ConvertTo-Json -Compress
  $created = Invoke-RestMethod -Method Post -Headers $headers `
    -ContentType "application/json" -Body $createBody `
    -Uri "$script:baseUrl/api/v1/executions" -TimeoutSec 10
  $executionId = [string]$created.execution.id
  if (-not $executionId) { throw "scope execution acceptance is missing" }
  $deadline = (Get-Date).AddSeconds(30)
  $snapshot = $null
  do {
    $snapshot = Invoke-RestMethod -Method Get -Headers $headers `
      -Uri "$script:baseUrl/api/v1/executions/$executionId/snapshot" -TimeoutSec 5
    if ([string]$snapshot.execution.state -cin @("prompting", "completed")) { break }
    Start-Sleep -Milliseconds 200
  } until ((Get-Date) -ge $deadline)
  if ([string]$snapshot.execution.state -cnotin @("prompting", "completed")) {
    throw "accepted v0.3 Telemetry execution did not advance"
  }
  $telemetryCount = @($snapshot.telemetry).Count
  if ($telemetryCount -ne 1) {
    throw "accepted v0.3 execution did not produce exactly one baseline Telemetry event"
  }
  $after = Get-ProjectCounters
  $journalAfter = Get-DriverJournalAttemptCount
  $metrics = [ordered]@{
    accepted_telemetry_execution_count = 1
    telemetry_event_count = $telemetryCount
    health_baseline_observation_count = 1
    execution_correlated_rpc_delta = $journalAfter - $journalBefore
    context_delta = $after.contexts - $before.contexts
    binding_delta = $after.bindings - $before.bindings
    operation_delta = $after.operations - $before.operations
    journal_delta = $journalAfter - $journalBefore
    execution_state = [string]$snapshot.execution.state
    execution_id_sha256 = Get-StringSha256 $executionId
  }
  foreach ($key in @(
    "execution_correlated_rpc_delta", "context_delta", "binding_delta",
    "operation_delta", "journal_delta"
  )) {
    if ([int64]$metrics[$key] -ne 0) { throw "V04-SCOPE-002 $key is nonzero" }
  }
  return New-ProbeEvidence "V04-SCOPE-002" @(
    "accepted-v03-telemetry-ran-with-live-driver-health",
    "execution-created-no-driver-lifecycle-or-journal-delta",
    "procedure-payload-remained-outside-the-driver-boundary"
  ) $metrics
}

function Invoke-ProbeSec004 {
  foreach ($name in @(
    "SPELL_RUNTIME_JWT_SECRET", "SPELL_RUNTIME_OPERATOR_TOKEN"
  )) {
    if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
      throw "$name is required for V04-SEC-004"
    }
  }
  $started = (Get-Date).ToUniversalTime().ToString("o")
  $probeName = "spell-v04-sec004-$script:runId"
  $common = @(
    "--user", "0:0", "--mount",
    "type=volume,source=$script:credentialVolume,target=/credentials,readonly"
  )
  $grpcLines = Invoke-QualificationInNamespace $probeName `
    $script:containerIds.backend @(
      "python", "scripts/runtime_fault_probe_v04.py", "grpc-security",
      "--target", "spell-driver:50051", "--credential-dir", "/credentials"
    ) $common
  $grpc = Convert-JsonLine $grpcLines "SEC004 gRPC security probe"
  $credentialLines = Invoke-QualificationInNamespace `
    "spell-v04-sec004-credential-$script:runId" $script:containerIds.backend @(
      "python", "scripts/runtime_fault_probe_v04.py", "credential-status",
      "--target", "spell-driver:50051", "--credential-dir", "/credentials"
    ) $common
  $credential = Convert-JsonLine $credentialLines "SEC004 credential status probe"
  if ([string]$credential.tls_authenticated_unknown_rpc_status -cne "UNIMPLEMENTED") {
    throw "current mTLS credential did not reach the bounded unknown RPC path"
  }

  $proxyStatus = 0
  $proxyBody = ""
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Method Post `
      -Headers @{ Authorization = "Bearer $env:SPELL_RUNTIME_OPERATOR_TOKEN" } `
      -ContentType "application/grpc" -Body ([byte[]]@()) `
      -Uri "$script:baseUrl/spell.driver.v1.DriverAdministration/RotateCredentials" `
      -TimeoutSec 5
    $proxyStatus = [int]$response.StatusCode
    $proxyBody = [string]$response.Content
  }
  catch {
    if ($_.Exception.Response) {
      $proxyStatus = [int]$_.Exception.Response.StatusCode
    }
    else { throw }
  }
  if ($proxyStatus -notin @(404, 405)) {
    throw "proxy route to direct driver administration was not denied"
  }
  $logLines = Invoke-Docker @(
    "logs", "--since", $started, $script:containerIds.driver
  ) "cannot inspect bounded driver audit logs"
  $logText = $logLines -join "`n"
  $safeAuditReasonCount = @(
    [regex]::Matches(
      $logText,
      'reason=(?:unknown_rpc|contract_major_rejected|credential_epoch_rejected|transport_rejected|peer_[a-z_]+)'
    )
  ).Count
  if ($safeAuditReasonCount -lt 4) {
    throw "SEC004 emitted too few safe driver audit reasons"
  }
  $unsafe = @(
    @(
      $env:SPELL_RUNTIME_JWT_SECRET,
      $env:SPELL_RUNTIME_OPERATOR_TOKEN,
      "Authorization: Bearer",
      "-----BEGIN PRIVATE KEY-----"
    ) | Where-Object { $_ -and (($logText + $proxyBody).Contains([string]$_)) }
  )
  if ($unsafe.Count -ne 0) { throw "SEC004 output echoed unsafe material" }
  $metrics = [ordered]@{
    reflection_status = [string]$grpc.reflection_status
    direct_administration_status = [string]$grpc.direct_administration_status
    jwt_without_mtls_status = [string]$grpc.jwt_without_mtls_status
    unauthorized_metadata_status = [string]$grpc.unauthorized_metadata_status
    proxy_route_http_status = $proxyStatus
    safe_audit_reason_count = $safeAuditReasonCount
    unsafe_echo_count = 0
    bounded_driver_log_line_count = @($logLines).Count
    contract_major_audit_count = @(
      [regex]::Matches($logText, 'reason=contract_major_rejected')
    ).Count
  }
  if (
    $metrics.reflection_status -cne "UNIMPLEMENTED" -or
    $metrics.direct_administration_status -cne "UNIMPLEMENTED" -or
    $metrics.jwt_without_mtls_status -cne "UNAVAILABLE" -or
    $metrics.unauthorized_metadata_status -cne "FAILED_PRECONDITION" -or
    $metrics.contract_major_audit_count -lt 1
  ) { throw "SEC004 gRPC rejection matrix differs" }
  return New-ProbeEvidence "V04-SEC-004" @(
    "reflection-and-direct-administration-are-unimplemented",
    "browser-jwt-and-unauthorized-metadata-fail-before-dispatch",
    "proxy-routing-is-denied-and-audited-without-unsafe-echo"
  ) $metrics
}

function Invoke-ProbeBound002 {
  $captureArguments = @("--user", "0:0", "--cap-add", "NET_RAW")
  $nominalLines = Invoke-QualificationInNamespace `
    "spell-v04-bound-nominal-$script:runId" $script:containerIds.driver @(
      "python", "scripts/runtime_fault_probe_v04.py", "packet-capture",
      "--seconds", "2", "--phase", "nominal"
    ) $captureArguments
  $nominal = Convert-JsonLine $nominalLines "nominal packet capture"
  $paused = $false
  try {
    Invoke-Docker @("pause", $script:containerIds.driver) `
      "cannot pause the driver for the bounded fault capture" | Out-Null
    $paused = $true
    $faultContainer = "spell-v04-bound-fault-$script:runId"
    $script:runContainers.Add($faultContainer)
    Invoke-Docker @(
      "create", "--name", $faultContainer,
      "--label", "com.docker.compose.project=$script:project",
      "--network", "container:$($script:containerIds.driver)",
      "--read-only", "--tmpfs", "/tmp:size=128m,noexec,nosuid",
      "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--user", "0:0",
      "--security-opt", "no-new-privileges:true",
      $script:imageIds.qualification,
      "python", "scripts/runtime_fault_probe_v04.py", "packet-capture",
      "--seconds", "2", "--phase", "fault"
    ) "cannot create the fault packet-capture container" | Out-Null
    Invoke-Docker @("start", $faultContainer) `
      "cannot start the fault packet-capture container" | Out-Null
    $attemptCode = @'
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    code = s.connect_ex(("spell-driver", 50051))
finally:
    s.close()
print(json.dumps({"connect_code": code}, sort_keys=True, separators=(",", ":")))
'@
    Invoke-QualificationInNamespace `
      "spell-v04-bound-attempt-$script:runId" $script:containerIds.backend @(
        "python", "-c", (ConvertTo-PythonExecCode $attemptCode)
      ) | Out-Null
    $waitCode = (Invoke-Docker @("wait", $faultContainer) `
      "fault packet-capture container wait failed" | Select-Object -Last 1).Trim()
    if ($waitCode -cne "0") { throw "fault packet-capture container failed" }
    $faultLines = Invoke-Docker @("logs", $faultContainer) `
      "cannot read the fault packet capture"
    $fault = Convert-JsonLine $faultLines "fault packet capture"
    Invoke-Docker @("rm", $faultContainer) `
      "cannot remove the fault packet-capture container" | Out-Null
  }
  finally {
    if ($paused) {
      Invoke-DockerCleanupCommand @("unpause", $script:containerIds.driver) | Out-Null
    }
  }
  $logLines = Invoke-Docker @("logs", $script:containerIds.driver) `
    "cannot inspect driver connection logs"
  $logText = $logLines -join "`n"
  $unapprovedLogMatches = @(
    [regex]::Matches(
      $logText,
      '(?i)(?:https?://|host\.docker\.internal|\bGCS\b|spacecraft|mission endpoint)'
    )
  ).Count
  $metrics = [ordered]@{
    nominal_captured_frame_count = [int]$nominal.captured_frame_count
    fault_captured_frame_count = [int]$fault.captured_frame_count
    nominal_endpoint_tuple_count = [int]$nominal.endpoint_tuple_count
    fault_endpoint_tuple_count = [int]$fault.endpoint_tuple_count
    nominal_unapproved_endpoint_count = [int]$nominal.unapproved_endpoint_count
    fault_unapproved_endpoint_count = [int]$fault.unapproved_endpoint_count
    nominal_capture_truncated = [bool]$nominal.capture_truncated
    fault_capture_truncated = [bool]$fault.capture_truncated
    connection_log_unapproved_endpoint_count = $unapprovedLogMatches
    nominal_endpoint_tuples = @($nominal.endpoint_tuples)
    fault_endpoint_tuples = @($fault.endpoint_tuples)
  }
  if (
    $metrics.nominal_captured_frame_count -lt 1 -or
    $metrics.fault_captured_frame_count -lt 1 -or
    $metrics.nominal_endpoint_tuple_count -lt 1 -or
    $metrics.fault_endpoint_tuple_count -lt 1 -or
    $metrics.nominal_unapproved_endpoint_count -ne 0 -or
    $metrics.fault_unapproved_endpoint_count -ne 0 -or
    $metrics.nominal_capture_truncated -or $metrics.fault_capture_truncated -or
    $metrics.connection_log_unapproved_endpoint_count -ne 0
  ) { throw "V04-BOUND-002 network capture boundary differs" }
  return New-ProbeEvidence "V04-BOUND-002" @(
    "nominal-and-fault-network-captures-are-nonempty-and-bounded",
    "all-observed-endpoints-are-in-the-approved-local-matrix",
    "connection-logs-name-no-public-host-or-mission-endpoint"
  ) $metrics
}

function Invoke-ProbeIso004 {
  $reachabilityLines = Invoke-QualificationInNamespace `
    "spell-v04-iso004-driver-$script:runId" $script:containerIds.driver @(
      "python", "scripts/runtime_fault_probe_v04.py", "reachability"
    )
  $reachability = Convert-JsonLine $reachabilityLines "driver namespace reachability"
  $testNetCode = @'
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    code = s.connect_ex(("192.0.2.1", 443))
finally:
    s.close()
print(json.dumps({"connect_code": code}, sort_keys=True, separators=(",", ":")))
'@
  $testNetLines = Invoke-QualificationInNamespace `
    "spell-v04-iso004-testnet-$script:runId" $script:containerIds.driver @(
      "python", "-c", (ConvertTo-PythonExecCode $testNetCode)
    )
  $testNet = Convert-JsonLine $testNetLines "driver TEST-NET reachability"
  $backendCode = @'
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    code = s.connect_ex(("spell-driver", 50051))
finally:
    s.close()
print(json.dumps({"connect_code": code}, sort_keys=True, separators=(",", ":")))
'@
  $backendLines = Invoke-QualificationInNamespace `
    "spell-v04-iso004-backend-$script:runId" $script:containerIds.backend @(
      "python", "-c", (ConvertTo-PythonExecCode $backendCode)
    )
  $backend = Convert-JsonLine $backendLines "backend-to-driver reachability"

  $driverInspection = Convert-JsonLine `
    (Invoke-Docker @("inspect", "--format", "{{json .}}", $script:containerIds.driver) `
      "cannot inspect driver network membership") "driver inspection"
  $networkNames = @(
    $driverInspection.NetworkSettings.Networks.PSObject.Properties.Name
  )
  $unapprovedRoutes = 0
  foreach ($networkName in $networkNames) {
    $network = Convert-JsonLine `
      (Invoke-Docker @("network", "inspect", "--format", "{{json .}}", $networkName) `
        "cannot inspect driver network isolation") "driver network inspection"
    if ($network.Internal -ne $true) { $unapprovedRoutes += 1 }
  }
  $observations = $reachability.observations
  $metrics = [ordered]@{
    driver_listener_reachable = [bool]$reachability.gateway_listener_reachable
    backend_to_driver_reachable = ([int]$backend.connect_code -eq 0)
    reverse_api_reachable = ([string]$observations.reverse_api.connect_code -ceq "0")
    database_reachable = ([string]$observations.database.connect_code -ceq "0")
    proxy_reachable = ([string]$observations.proxy.connect_code -ceq "0")
    host_alias_reachable = ([string]$observations.host_alias.connect_code -ceq "0")
    loopback_api_reachable = ([string]$observations.loopback_api.connect_code -ceq "0")
    loopback_proxy_reachable = ([string]$observations.loopback_proxy.connect_code -ceq "0")
    test_net_reachable = ([int]$testNet.connect_code -eq 0)
    unapproved_route_count = $unapprovedRoutes
    database_resolved = [bool]$reachability.database_resolved
    proxy_resolved = [bool]$reachability.proxy_resolved
    host_alias_resolved = [bool]$reachability.host_alias_resolved
    namespace_observations = $observations
    internal_network_count = $networkNames.Count
  }
  if (
    -not $metrics.driver_listener_reachable -or
    -not $metrics.backend_to_driver_reachable -or
    $metrics.reverse_api_reachable -or $metrics.database_reachable -or
    $metrics.proxy_reachable -or $metrics.host_alias_reachable -or
    $metrics.loopback_api_reachable -or $metrics.loopback_proxy_reachable -or
    $metrics.test_net_reachable -or $metrics.unapproved_route_count -ne 0
  ) { throw "V04-ISO-004 namespace reachability matrix differs" }
  return New-ProbeEvidence "V04-ISO-004" @(
    "driver-namespace-has-no-database-proxy-host-or-test-net-route",
    "loopback-and-reverse-api-paths-are-closed",
    "only-the-backend-to-driver-listener-path-is-reachable"
  ) $metrics
}

function Get-ContainerRunning {
  param([Parameter(Mandatory = $true)][string]$ContainerId)
  $value = (Invoke-Docker @(
    "inspect", "--format", "{{.State.Running}}", $ContainerId
  ) "cannot inspect fault-runtime container liveness" | Select-Object -Last 1).Trim()
  return $value -ceq "true"
}

function Wait-ForStaleProjection {
  param([Parameter(Mandatory = $true)][hashtable]$Headers)
  $deadline = (Get-Date).AddSeconds(20)
  do {
    try {
      $value = Invoke-RestMethod -Method Get -Headers $Headers `
        -Uri "$script:baseUrl/api/v1/drivers" -TimeoutSec 3
      $driver = @($value.items) | Select-Object -First 1
      if ($driver -and (
        [bool]$driver.stale -or [string]$driver.state -cin @("DEGRADED", "FAILED")
      )) { return $driver }
    }
    catch { }
    Start-Sleep -Milliseconds 250
  } until ((Get-Date) -ge $deadline)
  throw "driver projection did not become degraded or stale"
}

function Start-FaultWorkerExecution {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Headers,
    [Parameter(Mandatory = $true)][string]$Suffix
  )
  $body = [ordered]@{
    procedure_id = "demo"
    context_id = "simulator"
    reason = "v0.4 driver isolation worker progress"
    idempotency_key = "fault-runtime-worker-$Suffix-$script:runId"
  } | ConvertTo-Json -Compress
  $created = Invoke-RestMethod -Method Post -Headers $Headers `
    -ContentType "application/json" -Body $body `
    -Uri "$script:baseUrl/api/v1/executions" -TimeoutSec 10
  $executionId = [string]$created.execution.id
  if (-not $executionId) { throw "fault worker execution was not accepted" }
  $deadline = (Get-Date).AddSeconds(30)
  do {
    $snapshot = Invoke-RestMethod -Method Get -Headers $Headers `
      -Uri "$script:baseUrl/api/v1/executions/$executionId/snapshot" -TimeoutSec 5
    if (
      [string]$snapshot.execution.state -cin @("prompting", "completed") -and
      @($snapshot.telemetry).Count -ge 1
    ) { return $snapshot }
    Start-Sleep -Milliseconds 200
  } until ((Get-Date) -ge $deadline)
  throw "worker execution made no progress during the driver fault"
}

function Assert-NonDriverLiveness {
  $observations = 0
  foreach ($service in @("backend", "postgres", "proxy")) {
    $current = [string]$script:containerIds.$service
    if (-not (Get-ContainerRunning $current)) {
      throw "$service stopped during the driver fault"
    }
    $observations += 1
  }
  $health = Invoke-WebRequest -UseBasicParsing -Method Get `
    -Uri "$script:baseUrl/healthz" -TimeoutSec 5
  if ([int]$health.StatusCode -ne 200) { throw "proxy health failed during driver fault" }
  return $observations
}

function Invoke-ProbeIso003 {
  if (-not $env:SPELL_RUNTIME_OPERATOR_TOKEN) {
    throw "SPELL_RUNTIME_OPERATOR_TOKEN is required for V04-ISO-003"
  }
  $headers = @{ Authorization = "Bearer $env:SPELL_RUNTIME_OPERATOR_TOKEN" }
  $baseline = Wait-ForDriverProjection $headers @("READY")
  $unchangedObservations = 0
  $recoveryCount = 0
  $workerProgressFailureCount = 0
  $recoveryFailureCount = 0
  $faultDetails = [Collections.Generic.List[object]]::new()

  $paused = $false
  try {
    Invoke-Docker @("pause", $script:containerIds.driver) `
      "cannot pause the driver isolation target" | Out-Null
    $paused = $true
    $snapshot = Start-FaultWorkerExecution $headers "paused"
    $stale = Wait-ForStaleProjection $headers
    $unchangedObservations += Assert-NonDriverLiveness
    $faultDetails.Add([ordered]@{
      fault = "paused"
      projection_state = [string]$stale.state
      projection_stale = [bool]$stale.stale
      worker_state = [string]$snapshot.execution.state
    })
  }
  finally {
    if ($paused) {
      Invoke-Docker @("unpause", $script:containerIds.driver) `
        "cannot unpause the driver isolation target" | Out-Null
    }
  }
  $recoveredPause = Wait-ForDriverProjection $headers @("READY") 30
  if (
    [bool]$recoveredPause.stale -or
    [string]$recoveredPause.last_observed_at -ceq [string]$baseline.last_observed_at
  ) { $recoveryFailureCount += 1 }
  else { $recoveryCount += 1 }

  Invoke-Docker @("kill", $script:containerIds.driver) `
    "cannot kill the driver isolation target" | Out-Null
  $killSnapshot = Start-FaultWorkerExecution $headers "killed"
  $killedStale = Wait-ForStaleProjection $headers
  $unchangedObservations += Assert-NonDriverLiveness
  $faultDetails.Add([ordered]@{
    fault = "killed"
    projection_state = [string]$killedStale.state
    projection_stale = [bool]$killedStale.stale
    worker_state = [string]$killSnapshot.execution.state
  })
  Invoke-Docker @("start", $script:containerIds.driver) `
    "cannot restart the exact driver image after kill" | Out-Null
  Wait-ContainerHealthy $script:containerIds.driver
  $replacementDriver = [string]$script:containerIds.driver
  if ((Get-ContainerImageId $replacementDriver) -cne [string]$script:imageIds.driver) {
    throw "recovered driver container uses another image"
  }
  $script:containerIds.driver = $replacementDriver
  $recoveredKill = Wait-ForDriverProjection $headers @("READY") 45
  if ([bool]$recoveredKill.stale) { $recoveryFailureCount += 1 }
  else { $recoveryCount += 1 }

  $metrics = [ordered]@{
    injection_count = 2
    unchanged_non_driver_container_observation_count = $unchangedObservations
    non_driver_liveness_failure_count = 0
    worker_progress_failure_count = $workerProgressFailureCount
    degraded_or_stale_observation_count = $faultDetails.Count
    recovery_count = $recoveryCount
    recovery_failure_count = $recoveryFailureCount
    replacement_driver_container_id = $replacementDriver
    fault_observations = @($faultDetails)
  }
  if (
    $unchangedObservations -lt 6 -or $faultDetails.Count -ne 2 -or
    $recoveryCount -ne 2 -or $recoveryFailureCount -ne 0
  ) { throw "V04-ISO-003 fault containment matrix differs" }
  return New-ProbeEvidence "V04-ISO-003" @(
    "driver-pause-and-kill-do-not-terminate-non-driver-services",
    "worker-progress-continues-and-driver-projection-becomes-stale",
    "exact-driver-image-recovers-with-a-new-observation"
  ) $metrics
}

function Get-CredentialHashes {
  param(
    [Parameter(Mandatory = $true)][string]$Volume,
    [Parameter(Mandatory = $true)][string]$Suffix
  )
  $code = @'
import hashlib, json, pathlib, re
from cryptography import x509
from cryptography.hazmat.primitives import hashes

root = pathlib.Path("/credentials")
names = sorted(path.name for path in root.iterdir() if path.is_file())
expected = ["ca.crt", "client.crt", "client.key"]
if names != expected:
    raise RuntimeError(f"credential file set differs: {names!r}")
ca_bundle = (root / "ca.crt").read_bytes()
certificate_blocks = re.findall(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    ca_bundle,
    re.DOTALL,
)
trust_fingerprints = sorted({
    x509.load_pem_x509_certificate(block).fingerprint(hashes.SHA256()).hex()
    for block in certificate_blocks
})
if not trust_fingerprints:
    raise RuntimeError("credential CA bundle contains no certificate")
print(json.dumps({
    "ca_sha256": hashlib.sha256(ca_bundle).hexdigest(),
    "client_certificate_sha256": hashlib.sha256((root / "client.crt").read_bytes()).hexdigest(),
    "file_count": len(names),
    "trust_fingerprint_count": len(trust_fingerprints),
    "trust_fingerprints": trust_fingerprints,
}, sort_keys=True, separators=(",", ":")))
'@
  $lines = Invoke-QualificationInNamespace `
    "spell-v04-credential-hash-$Suffix-$script:runId" $script:containerIds.backend @(
      "python", "-c", (ConvertTo-PythonExecCode $code)
    ) @(
      "--user", "0:0", "--mount",
      "type=volume,source=$Volume,target=/credentials,readonly"
    )
  return Convert-JsonLine $lines "$Suffix credential hashes"
}

function Invoke-ProbeSec002 {
  foreach ($name in @("DATABASE_URL", "SPELL_RUNTIME_OPERATOR_TOKEN")) {
    if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
      throw "$name is required for V04-SEC-002"
    }
  }
  $oldHashes = Get-CredentialHashes $script:credentialVolume "old"
  $backupVolume = "$script:project-old-client-credentials"
  $servicesStopped = $false
  Invoke-Docker @(
    "volume", "create", "--label", "com.docker.compose.project=$script:project",
    $backupVolume
  ) "cannot create the old-credential evidence volume" | Out-Null
  try {
    Invoke-Docker @(
      "run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
      "--label", "com.docker.compose.project=$script:project",
      "--mount", "type=volume,source=$script:credentialVolume,target=/source,readonly",
      "--mount", "type=volume,source=$backupVolume,target=/destination",
      "--entrypoint", "sh", $script:imageIds.qualification,
      "-ec", "cp /source/ca.crt /source/client.crt /source/client.key /destination/ && chmod 0400 /destination/client.key"
    ) "cannot preserve the old client credential set" | Out-Null

    foreach ($container in @(
      $script:containerIds.proxy, $script:containerIds.backend, $script:containerIds.driver
    )) {
      Invoke-Docker @("stop", "--time", "5", [string]$container) `
        "cannot stop services for bounded credential rotation" | Out-Null
    }
    $servicesStopped = $true
    $databaseUrl = Get-RuntimeDatabaseUrl "spell"
    $priorDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
    try {
      $env:DATABASE_URL = $databaseUrl
      $rotateCode = @'
import json, os, uuid
from datetime import datetime, timezone
from sqlalchemy import func, select
from backend.database import create_database
from backend.driver_models import DriverAuditEvent, DriverHostGeneration, DriverOutboxEvent
from backend.driver_repository import DEFAULT_PROFILE_DIGEST, DEFAULT_PROFILE_ID, DriverRepository

engine, factory = create_database(os.environ["DATABASE_URL"])
repo = DriverRepository(factory)
try:
    before = repo.get_profile_configuration(DEFAULT_PROFILE_ID)
    driver = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
    host_id = driver.get("current_host_generation_id")
    if host_id:
        with factory() as session:
            row = session.get(DriverHostGeneration, host_id)
            host = {"state": row.state, "revision": row.revision} if row is not None else None
        if host is not None and host["state"] not in {"CLOSED", "FAILED"}:
            repo.record_host_state(
                host_id, "FAILED", expected_revision=int(host["revision"]),
                actor="v04-fault-runtime-rotation",
                correlation_id=str(uuid.uuid4()),
                observed_at=datetime.now(timezone.utc),
            )
    rotated = repo.rotate_profile_credentials(
        DEFAULT_PROFILE_ID,
        credential_reference=str(before["credential_reference"]),
        credential_epoch=int(before["credential_epoch"]) + 1,
        configuration_digest=DEFAULT_PROFILE_DIGEST,
        expected_revision=int(before["revision"]),
        actor="v04-fault-runtime-rotation",
        correlation_id=str(uuid.uuid4()),
    )
    with factory() as session:
        audits = session.scalar(select(func.count()).select_from(DriverAuditEvent).where(
            DriverAuditEvent.event_type == "driver.profile_credentials_rotated"
        ))
        outbox = sum(
            1 for row in session.scalars(select(DriverOutboxEvent))
            if row.payload.get("event_type") == "driver.profile_credentials_rotated"
        )
    print(json.dumps({
        "prior_credential_epoch": int(before["credential_epoch"]),
        "new_credential_epoch": int(rotated["credential_epoch"]),
        "profile_revision_delta": int(rotated["revision"]) - int(before["revision"]),
        "rotation_audit_count": int(audits),
        "rotation_outbox_count": int(outbox),
        "configuration_digest_drift_count": int(rotated["configuration_digest"] != before["configuration_digest"]),
        "credential_reference_drift_count": int(rotated["credential_reference"] != before["credential_reference"]),
    }, sort_keys=True, separators=(",", ":")))
finally:
    engine.dispose()
'@
      $rotationLines = Invoke-QualificationInNamespace `
        "spell-v04-sec002-database-$script:runId" $script:containerIds.postgres @(
          "python", "-c", (ConvertTo-PythonExecCode $rotateCode)
        ) @("-e", "DATABASE_URL")
      $rotation = Convert-JsonLine $rotationLines "credential epoch rotation"
    }
    finally { Restore-EnvironmentVariable "DATABASE_URL" $priorDatabaseUrl }

    $pkiName = "spell-v04-sec002-pki-$script:runId"
    Invoke-Docker @(
      "run", "--rm", "--name", $pkiName,
      "--label", "com.docker.compose.project=$script:project",
      "--network", "none", "--read-only", "--tmpfs", "/tmp:size=32m,noexec,nosuid",
      "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN",
      "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
      "--security-opt", "no-new-privileges:true",
      "--mount", "type=volume,source=$script:credentialVolume,target=/run/spell-driver-client-source",
      "--mount", "type=volume,source=$script:serverCredentialVolume,target=/run/spell-driver-server",
      $script:imageIds.pki_init,
      "--client-dir", "/run/spell-driver-client-source",
      "--server-dir", "/run/spell-driver-server",
      "--client-uid", "0", "--client-gid", "0",
      "--server-uid", "10002", "--server-gid", "10002", "--force"
    ) "cannot force the bounded local PKI rotation" | Out-Null
    Write-Utf8Json $script:hostConfigurationPath ([ordered]@{ credential_epoch = 2 })
    foreach ($container in @(
      $script:containerIds.driver, $script:containerIds.backend, $script:containerIds.proxy
    )) {
      Invoke-Docker @("start", [string]$container) `
        "cannot restart service after credential rotation" | Out-Null
      Wait-ContainerHealthy ([string]$container)
    }
    $servicesStopped = $false
    $newHashes = Get-CredentialHashes $script:credentialVolume "new"
    if (
      [string]$newHashes.ca_sha256 -ceq [string]$oldHashes.ca_sha256 -or
      [string]$newHashes.client_certificate_sha256 -ceq [string]$oldHashes.client_certificate_sha256
    ) { throw "live credential rotation did not replace CA and client identity" }

    $newStatusLines = Invoke-QualificationInNamespace `
      "spell-v04-sec002-new-$script:runId" $script:containerIds.backend @(
        "python", "scripts/runtime_fault_probe_v04.py", "credential-status",
        "--target", "spell-driver:50051", "--credential-dir", "/credentials"
      ) @(
        "--user", "0:0", "--mount",
        "type=volume,source=$script:credentialVolume,target=/credentials,readonly"
      )
    $newStatus = Convert-JsonLine $newStatusLines "new credential status"
    $oldStatusLines = Invoke-QualificationInNamespace `
      "spell-v04-sec002-old-$script:runId" $script:containerIds.backend @(
        "python", "scripts/runtime_fault_probe_v04.py", "credential-status",
        "--target", "spell-driver:50051", "--credential-dir", "/credentials"
      ) @(
        "--user", "0:0", "--mount",
        "type=volume,source=$backupVolume,target=/credentials,readonly"
      )
    $oldStatus = Convert-JsonLine $oldStatusLines "old credential status"
    $healthCode = @'
import asyncio, json
from pathlib import Path
from backend.credential_bootstrap import clear_credentials, install_runtime_credentials, read_source_credentials
from backend.driver_client import DriverClient
from backend.driver_domain import DEFAULT_HOST_PROFILE_DIGEST

async def run():
    credentials = read_source_credentials(Path("/run/spell-driver-client-source"))
    try:
        install_runtime_credentials(
            credentials,
            Path("/run/spell-driver-client"),
            runtime_uid=0,
            runtime_gid=0,
        )
    finally:
        clear_credentials(credentials)
    client = DriverClient.from_files(
        "spell-driver:50051", "/run/spell-driver-client/ca.crt",
        "/run/spell-driver-client/client.crt", "/run/spell-driver-client/client.key",
        3.0, credential_epoch=2,
        host_profile_digest=DEFAULT_HOST_PROFILE_DIGEST,
    )
    if Path("/run/spell-driver-client/client.key").exists():
        raise RuntimeError("SEC002 health probe retained its private key")
    try:
        handshake = await client.handshake()
        health = await client.health()
        print(json.dumps({
            "credential_epoch": int(health.driver.credential_epoch),
            "host_generation_id": health.driver.driver_host_generation,
            "host_state": health.host_state,
            "ready": bool(health.ready),
            "same_generation": health.driver.driver_host_generation == handshake.driver.driver_host_generation,
        }, sort_keys=True, separators=(",", ":")))
    finally:
        await client.close()
asyncio.run(run())
'@
    $healthLines = Invoke-QualificationInNamespace `
      "spell-v04-sec002-health-$script:runId" $script:containerIds.backend @(
        "python", "-c", (ConvertTo-PythonExecCode $healthCode)
      ) @(
        "--user", "0:0", "--tmpfs",
        "/run/spell-driver-client:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=0,gid=0",
        "--mount",
        "type=volume,source=$script:credentialVolume,target=/run/spell-driver-client-source,readonly"
      )
    $health = Convert-JsonLine $healthLines "post-rotation live Health observation"
    $projection = Wait-ForDriverProjection `
      @{ Authorization = "Bearer $env:SPELL_RUNTIME_OPERATOR_TOKEN" } @("READY") 45
    $priorTrustFingerprints = @(
      $oldHashes.trust_fingerprints | ForEach-Object { [string]$_ } |
        Sort-Object -Unique
    )
    $newTrustFingerprints = @(
      $newHashes.trust_fingerprints | ForEach-Object { [string]$_ } |
        Sort-Object -Unique
    )
    $priorTrustFingerprintCount = $priorTrustFingerprints.Count
    $newTrustFingerprintCount = $newTrustFingerprints.Count
    $retainedPriorTrust = @(
      $priorTrustFingerprints | Where-Object { $_ -cin $newTrustFingerprints }
    ).Count
    $unexpectedNewTrust = [Math]::Max($newTrustFingerprintCount - 1, 0)
    $oldRejectionCount = [int](
      [string]$oldStatus.tls_authenticated_unknown_rpc_status -ceq "UNAVAILABLE"
    )
    $readyObservationCount = [int](
      [bool]$health.ready -and [string]$health.host_state -ceq "READY" -and
      [bool]$health.same_generation -and -not [bool]$projection.stale -and
      [int]$projection.credential_epoch -eq 2 -and
      [string]$projection.current_host_generation_id -ceq [string]$health.host_generation_id
    )
    $metrics = [ordered]@{
      prior_credential_epoch = [int]$rotation.prior_credential_epoch
      new_credential_epoch = [int]$rotation.new_credential_epoch
      profile_revision_delta = [int]$rotation.profile_revision_delta
      rotation_audit_count = [int]$rotation.rotation_audit_count
      rotation_outbox_count = [int]$rotation.rotation_outbox_count
      current_credential_status = [string]$newStatus.tls_authenticated_unknown_rpc_status
      old_credential_status = [string]$oldStatus.tls_authenticated_unknown_rpc_status
      ca_changed = $true
      client_certificate_changed = $true
      configuration_digest_drift_count = [int]$rotation.configuration_digest_drift_count
      credential_reference_drift_count = [int]$rotation.credential_reference_drift_count
      prior_trust_fingerprint_count = $priorTrustFingerprintCount
      new_trust_fingerprint_count = $newTrustFingerprintCount
      retained_prior_trust_fingerprint_count = $retainedPriorTrust
      unexpected_new_trust_fingerprint_count = $unexpectedNewTrust
      old_credential_rejection_count = $oldRejectionCount
      trust_set_expansion_count = $unexpectedNewTrust
      post_rotation_ready_observation_count = $readyObservationCount
      post_rotation_stale_observation_count = [int][bool]$projection.stale
      ready_after_rotation = ($readyObservationCount -eq 1)
      ready_credential_epoch = [int]$health.credential_epoch
      post_rotation_host_generation_id_sha256 = Get-StringSha256 ([string]$health.host_generation_id)
      prior_trust_set_sha256 = Get-StringSha256 (($priorTrustFingerprints -join "`n") + "`n")
      new_trust_set_sha256 = Get-StringSha256 (($newTrustFingerprints -join "`n") + "`n")
      old_ca_sha256 = [string]$oldHashes.ca_sha256
      new_ca_sha256 = [string]$newHashes.ca_sha256
      old_client_certificate_sha256 = [string]$oldHashes.client_certificate_sha256
      new_client_certificate_sha256 = [string]$newHashes.client_certificate_sha256
    }
    if (
      $metrics.prior_credential_epoch -ne 1 -or $metrics.new_credential_epoch -ne 2 -or
      $metrics.profile_revision_delta -ne 1 -or $metrics.rotation_audit_count -ne 1 -or
      $metrics.rotation_outbox_count -ne 1 -or
      $metrics.current_credential_status -cne "UNIMPLEMENTED" -or
      $metrics.old_credential_status -cne "UNAVAILABLE" -or
      $metrics.configuration_digest_drift_count -ne 0 -or
      $metrics.credential_reference_drift_count -ne 0 -or
      $metrics.prior_trust_fingerprint_count -lt 1 -or
      $metrics.new_trust_fingerprint_count -lt 1 -or
      $metrics.retained_prior_trust_fingerprint_count -ne 0 -or
      $metrics.unexpected_new_trust_fingerprint_count -ne 0 -or
      $metrics.old_credential_rejection_count -lt 1 -or
      $metrics.post_rotation_ready_observation_count -lt 1 -or
      $metrics.post_rotation_stale_observation_count -ne 0 -or
      -not $metrics.ready_after_rotation -or $metrics.ready_credential_epoch -ne 2
    ) { throw "V04-SEC-002 live rotation matrix differs" }
    return New-ProbeEvidence "V04-SEC-002" @(
      "live-local-credential-rotation-advanced-one-audited-epoch",
      "old-credentials-fail-and-only-the-new-trust-set-is-accepted",
      "configuration-identity-remains-bound-without-trust-expansion"
    ) $metrics
  }
  finally {
    if ($servicesStopped) {
      foreach ($container in @(
        $script:containerIds.driver, $script:containerIds.backend, $script:containerIds.proxy
      )) { Invoke-DockerCleanupCommand @("start", [string]$container) | Out-Null }
    }
    Invoke-DockerCleanupCommand @("volume", "rm", "--force", $backupVolume) | Out-Null
  }
}

function Invoke-ProbeMig004 {
  if (-not $env:DATABASE_URL) {
    throw "DATABASE_URL is required for V04-MIG-004"
  }
  $suffix = $script:runId.Substring(0, 8)
  $sourceDatabase = "spell_mig_source_$suffix"
  $restoreDatabase = "spell_mig_restore_$suffix"
  $safeDatabase = "spell_mig_safe_$suffix"
  $dumpInContainer = "/tmp/spell-mig-$suffix.dump"
  $dumpOnHost = Join-Path $script:temporaryRoot "mig004-postgres.dump"
  $databases = @($sourceDatabase, $restoreDatabase, $safeDatabase)
  foreach ($database in $databases) {
    Invoke-DockerCleanupCommand @(
      "exec", $script:containerIds.postgres, "dropdb", "--if-exists",
      "--username", "spell", $database
    ) | Out-Null
    Invoke-Docker @(
      "exec", $script:containerIds.postgres, "createdb", "--username", "spell", $database
    ) "cannot create isolated MIG004 PostgreSQL database" | Out-Null
  }
  $priorDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
  $priorSecondUrl = [Environment]::GetEnvironmentVariable("SECOND_DATABASE_URL", "Process")
  try {
    $env:DATABASE_URL = Get-RuntimeDatabaseUrl $sourceDatabase
    $seedCode = @'
import hashlib, json, os
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import MetaData, Table, func, inspect, select
from backend.database import create_database
from backend.driver_domain import CAPABILITY_MATRIX
from backend.driver_models import DriverOperation
from backend.driver_repository import DEFAULT_PROFILE_ID, CapabilitySpec, DriverRepository
from backend.migrations import run_migrations
from backend.tests.test_backup_rollback import _seed_operation_truth_table

def snapshot(engine):
    value = {}
    with engine.connect() as connection:
        for name in sorted(inspect(connection).get_table_names()):
            table = Table(name, MetaData(), autoload_with=connection)
            statement = table.select()
            if tuple(table.primary_key.columns):
                statement = statement.order_by(*tuple(table.primary_key.columns))
            value[name] = [dict(row) for row in connection.execute(statement).mappings()]
    return value

def digest(value):
    return hashlib.sha256(json.dumps(value, default=str, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

engine, factory = create_database(os.environ["DATABASE_URL"])
run_migrations(engine)
repository = DriverRepository(factory)
repository.set_profile_enabled(DEFAULT_PROFILE_ID, True, expected_revision=0, actor="v04-mig-runtime", correlation_id=str(UUID(int=700)))
capabilities = tuple(CapabilitySpec(service=item.service, method=item.method.value, mutability=item.mutability, modifiers=item.modifiers, formats=(item.format,), stream_support=item.stream_support) for item in CAPABILITY_MATRIX)
repository.create_host_generation(profile_id=DEFAULT_PROFILE_ID, host_generation_id=str(UUID(int=701)), contract_version="1.0", implementation_version="0.4.0", capabilities=capabilities, actor="v04-mig-runtime", correlation_id=str(UUID(int=702)))
repository.record_host_state(str(UUID(int=701)), "READY", expected_revision=0, actor="v04-mig-runtime", correlation_id=str(UUID(int=703)), observed_at=datetime.now(timezone.utc))
_seed_operation_truth_table(repository)
value = snapshot(engine)
with factory() as session:
    truth_count = int(session.scalar(select(func.count()).select_from(DriverOperation)) or 0)
print(json.dumps({"snapshot_sha256": digest(value), "truth_state_count": truth_count}, sort_keys=True, separators=(",", ":")))
engine.dispose()
'@
    $seedLines = Invoke-QualificationInNamespace `
      "spell-v04-mig004-seed-$script:runId" $script:containerIds.postgres @(
        "python", "-c", (ConvertTo-PythonExecCode $seedCode)
      ) @("-e", "DATABASE_URL")
    $seed = Convert-JsonLine $seedLines "MIG004 PostgreSQL truth seed"
    if ([int]$seed.truth_state_count -ne 6) {
      throw "MIG004 did not seed all six operation truth states"
    }

    Invoke-Docker @(
      "exec", $script:containerIds.postgres, "pg_dump", "--format", "custom",
      "--no-owner", "--file", $dumpInContainer, "--username", "spell", $sourceDatabase
    ) "MIG004 PostgreSQL backup failed" | Out-Null
    Invoke-Docker @(
      "cp", "$($script:containerIds.postgres):$dumpInContainer", $dumpOnHost
    ) "cannot copy the MIG004 PostgreSQL backup artifact" | Out-Null
    Invoke-Docker @(
      "exec", $script:containerIds.postgres, "pg_restore", "--no-owner",
      "--exit-on-error", "--username", "spell", "--dbname", $restoreDatabase,
      $dumpInContainer
    ) "MIG004 PostgreSQL restore failed" | Out-Null

    $env:DATABASE_URL = Get-RuntimeDatabaseUrl $sourceDatabase `
      -BaseUrl $priorDatabaseUrl
    $env:SECOND_DATABASE_URL = Get-RuntimeDatabaseUrl $restoreDatabase `
      -BaseUrl $priorDatabaseUrl
    $verifyCode = @'
import hashlib, json, os, sqlite3, tempfile
from pathlib import Path
from sqlalchemy import MetaData, Table, create_engine, func, inspect, select
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.auth import AuthConfig, issue_local_dev_token
from backend.config import Settings
from backend.database import create_database
from backend.driver_models import DriverProfile
from backend.driver_repository import DriverRepository
from backend.migrations import database_version, run_migrations
from backend.migrations.rollback import UnsafeDriverRollbackError, rollback_driver_foundation
from backend.tests.test_backup_rollback import _accept, _repository_with_host, _seed_operation_truth_table
from backend.tests.test_migrations import canonical_v03_snapshot, seed_populated_v03_schema

def snapshot(engine):
    value = {}
    with engine.connect() as connection:
        for name in sorted(inspect(connection).get_table_names()):
            table = Table(name, MetaData(), autoload_with=connection)
            statement = table.select()
            if tuple(table.primary_key.columns):
                statement = statement.order_by(*tuple(table.primary_key.columns))
            value[name] = [dict(row) for row in connection.execute(statement).mappings()]
    return value

def digest(value):
    return hashlib.sha256(json.dumps(value, default=str, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

source_engine, _ = create_database(os.environ["DATABASE_URL"])
restored_engine, restored_factory = create_database(os.environ["SECOND_DATABASE_URL"])
source_digest = digest(snapshot(source_engine))
restored_before = snapshot(restored_engine)
restored_digest = digest(restored_before)
unsafe_refusals = 0
try:
    rollback_driver_foundation(restored_engine)
except UnsafeDriverRollbackError:
    unsafe_refusals += 1
restored_after = snapshot(restored_engine)
repo = DriverRepository(restored_factory)
before_replay = digest(restored_after)
replayed = _accept(repo, 2)
after_replay = digest(snapshot(restored_engine))

with tempfile.TemporaryDirectory() as directory:
    sqlite_source = Path(directory) / "source.sqlite"
    sqlite_backup = Path(directory) / "backup.sqlite"
    sqlite_restore = Path(directory) / "restore.sqlite"
    sqlite_repo, sqlite_engine = _repository_with_host(sqlite_source)
    _seed_operation_truth_table(sqlite_repo)
    sqlite_expected = snapshot(sqlite_engine)
    source_connection = sqlite_engine.raw_connection()
    backup_connection = sqlite3.connect(sqlite_backup)
    try:
        source_connection.driver_connection.backup(backup_connection)
    finally:
        backup_connection.close(); source_connection.close(); sqlite_engine.dispose()
    with sqlite3.connect(sqlite_backup) as backup, sqlite3.connect(sqlite_restore) as restored:
        backup.backup(restored)
    sqlite_restored_engine = create_engine(f"sqlite:///{sqlite_restore.as_posix()}")
    sqlite_mismatch = int(snapshot(sqlite_restored_engine) != sqlite_expected)
    try:
        rollback_driver_foundation(sqlite_restored_engine)
    except UnsafeDriverRollbackError:
        unsafe_refusals += 1
    sqlite_restored_engine.dispose()

safe_engine, safe_factory = create_database(os.environ["SAFE_DATABASE_URL"])
seed_populated_v03_schema(safe_engine)
v03_before = canonical_v03_snapshot(safe_engine)
run_migrations(safe_engine)
rollback_driver_foundation(safe_engine)
v03_after = canonical_v03_snapshot(safe_engine)
safe_rollback = int(database_version(safe_engine) == "0002_execution_variables")
auth = AuthConfig(issuer="v04-mig-runtime", audience="openbexi-spell-api", signing_secret=os.urandom(32), clock_skew_seconds=1, max_token_lifetime_seconds=120, allow_local_dev_issuance=True)
settings = Settings(database_url=os.environ["SAFE_DATABASE_URL"], procedures_dir=Path("/qualification-source/procedures"), websocket_replay_limit=100, websocket_queue_size=16, websocket_keepalive_seconds=1.0, driver_enabled=False)
execution_count = 0
with TestClient(create_app(settings, auth_config=auth)) as client:
    token = issue_local_dev_token(auth, subject="v04-mig-runtime", role="operator", peer_host="127.0.0.1", lifetime_seconds=60)
    response = client.post("/api/v1/executions", headers={"Authorization": f"Bearer {token}"}, json={"procedure_id":"demo","context_id":"simulator","reason":"v03 rollback simulator qualification","idempotency_key":"v04-mig-runtime"})
    execution_count = int(response.status_code == 202)
with safe_factory() as session:
    enabled_count = int(session.scalar(select(func.count()).select_from(DriverProfile).where(DriverProfile.enabled.is_(True))) or 0)

print(json.dumps({
    "postgres_snapshot_mismatch_count": int(source_digest != restored_digest),
    "unsafe_rollback_refusal_count": unsafe_refusals,
    "unsafe_rollback_evidence_loss_count": int(digest(restored_after) != restored_digest),
    "duplicate_effect_count": int(before_replay != after_replay or replayed["stage"] != "DISPATCHED"),
    "sqlite_snapshot_mismatch_count": sqlite_mismatch,
    "safe_rollback_count": safe_rollback,
    "v03_snapshot_mismatch_count": int(v03_before != v03_after),
    "enabled_driver_profile_count": enabled_count,
    "v03_simulator_execution_count": execution_count,
    "source_snapshot_sha256": source_digest,
    "restored_snapshot_sha256": restored_digest,
}, sort_keys=True, separators=(",", ":")))
source_engine.dispose(); restored_engine.dispose(); safe_engine.dispose()
'@
    $env:SAFE_DATABASE_URL = Get-RuntimeDatabaseUrl $safeDatabase `
      -BaseUrl $priorDatabaseUrl
    $verifyLines = Invoke-QualificationInNamespace `
      "spell-v04-mig004-verify-$script:runId" $script:containerIds.postgres @(
        "python", "-c", (ConvertTo-PythonExecCode $verifyCode)
      ) @("-e", "DATABASE_URL", "-e", "SECOND_DATABASE_URL", "-e", "SAFE_DATABASE_URL")
    $verify = Convert-JsonLine $verifyLines "MIG004 restore and rollback verification"
    $metrics = [ordered]@{
      dialect_count = 2
      postgres_backup_restore_count = 1
      postgres_snapshot_mismatch_count = [int]$verify.postgres_snapshot_mismatch_count
      truth_state_count = [int]$seed.truth_state_count
      unsafe_rollback_refusal_count = [int]$verify.unsafe_rollback_refusal_count
      unsafe_rollback_evidence_loss_count = [int]$verify.unsafe_rollback_evidence_loss_count
      safe_rollback_count = [int]$verify.safe_rollback_count
      v03_snapshot_mismatch_count = [int]$verify.v03_snapshot_mismatch_count
      enabled_driver_profile_count = [int]$verify.enabled_driver_profile_count
      v03_simulator_execution_count = [int]$verify.v03_simulator_execution_count
      duplicate_effect_count = [int]$verify.duplicate_effect_count
      sqlite_snapshot_mismatch_count = [int]$verify.sqlite_snapshot_mismatch_count
      postgres_source_snapshot_sha256 = [string]$verify.source_snapshot_sha256
      postgres_restored_snapshot_sha256 = [string]$verify.restored_snapshot_sha256
      postgres_dump_sha256 = Get-LowerSha256 $dumpOnHost
      postgres_dump_bytes = [int64](Get-Item -LiteralPath $dumpOnHost).Length
    }
    if (
      $metrics.postgres_snapshot_mismatch_count -ne 0 -or
      $metrics.truth_state_count -ne 6 -or
      $metrics.unsafe_rollback_refusal_count -lt 1 -or
      $metrics.unsafe_rollback_evidence_loss_count -ne 0 -or
      $metrics.safe_rollback_count -ne 1 -or
      $metrics.v03_snapshot_mismatch_count -ne 0 -or
      $metrics.enabled_driver_profile_count -ne 0 -or
      $metrics.v03_simulator_execution_count -ne 1 -or
      $metrics.duplicate_effect_count -ne 0 -or
      $metrics.sqlite_snapshot_mismatch_count -ne 0
    ) {
      $matrix = $metrics | ConvertTo-Json -Compress -Depth 10
      throw "V04-MIG-004 backup and rollback matrix differs: $matrix"
    }
    return New-ProbeEvidence "V04-MIG-004" @(
      "postgres-custom-backup-restores-all-six-operation-truth-states",
      "unsafe-rollback-refuses-without-evidence-loss-or-duplicate-effect",
      "safe-rollback-restores-v03-and-runs-the-disabled-driver-simulator"
    ) $metrics
  }
  finally {
    Restore-EnvironmentVariable "DATABASE_URL" $priorDatabaseUrl
    Restore-EnvironmentVariable "SECOND_DATABASE_URL" $priorSecondUrl
    Remove-Item Env:SAFE_DATABASE_URL -ErrorAction SilentlyContinue
    Invoke-DockerCleanupCommand @(
      "exec", $script:containerIds.postgres, "rm", "-f", $dumpInContainer
    ) | Out-Null
    foreach ($database in $databases) {
      Invoke-DockerCleanupCommand @(
        "exec", $script:containerIds.postgres, "dropdb", "--if-exists",
        "--force", "--username", "spell", $database
      ) | Out-Null
    }
  }
}

function Wait-RuntimeMarker {
  param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string]$Name,
    [int]$TimeoutSeconds = 45
  )
  $path = Join-Path $Directory $Name
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (Test-Path -LiteralPath $path -PathType Leaf) { return }
    Start-Sleep -Milliseconds 100
  } until ((Get-Date) -ge $deadline)
  throw "runtime coordination marker timed out: $Name"
}

function Set-RuntimeMarker {
  param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string]$Name
  )
  [IO.File]::WriteAllText(
    (Join-Path $Directory $Name), "ready`n", [Text.UTF8Encoding]::new($false)
  )
}

function Wait-PostgresReady {
  param([int]$TimeoutSeconds = 45)
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $probe = Invoke-DockerCleanupCommand @(
      "exec", $script:containerIds.postgres, "pg_isready", "--username", "spell",
      "--dbname", "spell"
    )
    if ($probe.ExitCode -eq 0) { return }
    Start-Sleep -Milliseconds 250
  } until ((Get-Date) -ge $deadline)
  throw "PostgreSQL did not recover during the runtime outage probe"
}

function Wait-ContainerHealthy {
  param(
    [Parameter(Mandatory = $true)][string]$ContainerId,
    [int]$TimeoutSeconds = 60
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $state = Invoke-DockerCleanupCommand @(
      "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
      $ContainerId
    )
    $value = ([string]($state.Lines | Select-Object -Last 1)).Trim()
    if ($state.ExitCode -eq 0 -and $value -in @("running|healthy", "running|")) { return }
    Start-Sleep -Milliseconds 250
  } until ((Get-Date) -ge $deadline)
  throw "runtime container did not become healthy"
}

function Invoke-ProbeRec005 {
  if (-not $env:DATABASE_URL) {
    throw "DATABASE_URL is required for V04-REC-005"
  }
  $coordinationRoot = Join-Path $script:workspaceRuntimeRoot "rec005-coordination"
  New-Item -ItemType Directory -Path $coordinationRoot -ErrorAction Stop | Out-Null
  $probeContainer = "spell-v04-rec005-$script:runId"
  $script:runContainers.Add($probeContainer)
  $priorDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
  $backendStopped = $false
  $postgresStopped = $false
  try {
    $env:DATABASE_URL = Get-RuntimeDatabaseUrl "spell" "postgres"
    $databaseNetwork = "$($script:project)_spell-internal"
    $driverNetwork = "$($script:project)_spell-driver-internal"
    $networkMembership = @(
      [pscustomobject]@{ container = $script:containerIds.backend; network = $databaseNetwork },
      [pscustomobject]@{ container = $script:containerIds.backend; network = $driverNetwork },
      [pscustomobject]@{ container = $script:containerIds.postgres; network = $databaseNetwork },
      [pscustomobject]@{ container = $script:containerIds.driver; network = $driverNetwork }
    )
    foreach ($membership in $networkMembership) {
      $inspection = Convert-JsonLine (Invoke-Docker @(
        "inspect", "--format", "{{json .NetworkSettings.Networks}}", $membership.container
      ) "cannot inspect the REC005 network membership") "REC005 network membership"
      if ([string]$membership.network -cnotin @($inspection.PSObject.Properties.Name)) {
        throw "REC005 container is absent from its required internal network"
      }
    }
    foreach ($networkName in @($databaseNetwork, $driverNetwork)) {
      $inspection = Convert-JsonLine (Invoke-Docker @(
        "network", "inspect", "--format", "{{json .}}", $networkName
      ) "cannot inspect the REC005 internal network") "REC005 internal network"
      if (
        $inspection.Internal -ne $true -or
        [string]$inspection.Labels.'com.docker.compose.project' -cne $script:project
      ) { throw "REC005 network is not an exact project-owned internal route" }
    }
    $probeCode = @'
import asyncio, ipaddress, json, os, socket, sqlite3, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.engine import make_url
from backend.config import Settings
from backend.credential_bootstrap import clear_credentials, install_runtime_credentials, read_source_credentials
from backend.database import create_database
from backend.driver_domain import CloseContextCommand, ContextConfiguration, GenerationTuple, OpenContextCommand, OperationIdentity
from backend.driver_gateway import DriverGateway
from backend.driver_models import DriverAuditEvent, DriverOutboxEvent
from backend.driver_repository import DriverRepository
from spell.driver.configuration import context_binding_digest

COORD = Path("/coord")
RUN = "__RUN_ID__"
CONTEXT_SCHEMA_VERSION = "context-schema-1"

def marker(name):
    (COORD / name).write_text("ready\n", encoding="ascii")

async def wait_marker(name, timeout=60):
    deadline = time.monotonic() + timeout
    path = COORD / name
    while time.monotonic() < deadline:
        if path.is_file():
            return
        await asyncio.sleep(0.05)
    raise RuntimeError(f"coordination timeout: {name}")

async def wait_database(factory, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with factory() as session:
                if session.scalar(select(1)) == 1:
                    return
        except Exception:
            pass
        await asyncio.sleep(0.1)
    raise RuntimeError("database recovery timeout")

class CoordinatedRepository:
    def __init__(self, delegate, engine):
        self.delegate = delegate
        self.engine = engine
        self.phase = 0
    def __getattr__(self, name):
        return getattr(self.delegate, name)
    def append_operation_transition(self, *args, **kwargs):
        stage = kwargs.get("stage")
        if self.phase == 2 and stage == "DISPATCHED":
            value = self.delegate.append_operation_transition(*args, **kwargs)
            marker("case2_dispatched")
            deadline = time.monotonic() + 60
            while not (COORD / "case2_go").is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not (COORD / "case2_go").is_file():
                raise RuntimeError("case2 coordination timeout")
            self.engine.dispose()
            return value
        if self.phase == 3 and stage == "SETTLED":
            marker("case3_effect_observed")
            deadline = time.monotonic() + 60
            while not (COORD / "case3_go").is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not (COORD / "case3_go").is_file():
                raise RuntimeError("case3 coordination timeout")
            self.engine.dispose()
        return self.delegate.append_operation_transition(*args, **kwargs)

def make_command(gateway, repository, number):
    driver = repository.get_driver("local-synthetic-simulator")["driver"]
    host = str(driver["current_host_generation_id"])
    context_id = f"rec005-context-{number}-{RUN[:8]}"
    context_generation = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:context:{number}"))
    digest = context_binding_digest(
        server_profile_id=str(driver["server_profile_id"]),
        driver_host_generation=host,
        host_profile_digest=str(driver["configuration_digest"]),
        schema_version=CONTEXT_SCHEMA_VERSION,
        context_profile_id="local-synthetic-context",
        synthetic_context_label=f"runtime-context-{number}",
    )
    repository.create_context_generation(
        profile_id=str(driver["id"]),
        host_generation_id=host,
        context_id=context_id,
        context_generation_id=context_generation,
        configuration_schema_version=CONTEXT_SCHEMA_VERSION,
        configuration_digest=digest,
        actor="v04-rec-runtime",
        correlation_id=str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:context-create:{number}")
        ),
    )
    return OpenContextCommand(
        identity=OperationIdentity(
            generations=GenerationTuple(
                server_profile_id=str(driver["server_profile_id"]),
                driver_host_generation=host,
                host_profile_digest=str(driver["configuration_digest"]),
                context_id=context_id,
                context_generation=context_generation,
                context_binding_digest=digest,
            ),
            operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:operation:{number}")),
            attempt_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:attempt:{number}")),
            attempt_number=1,
            correlation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:correlation:{number}")),
            deadline_unix_ms=int((datetime.now(timezone.utc) + timedelta(seconds=300)).timestamp() * 1000),
            credential_epoch=int(driver["credential_epoch"]),
        ),
        configuration=ContextConfiguration(
            schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id="local-synthetic-context",
            synthetic_context_label=f"runtime-context-{number}",
            expected_digest=digest,
        ),
    )

def make_close_command(command, number):
    identity = command.identity
    return CloseContextCommand(
        identity=OperationIdentity(
            generations=identity.generations,
            operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:close-operation:{number}")),
            attempt_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:close-attempt:{number}")),
            attempt_number=1,
            correlation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RUN}:close-correlation:{number}")),
            deadline_unix_ms=int((datetime.now(timezone.utc) + timedelta(seconds=300)).timestamp() * 1000),
            credential_epoch=identity.credential_epoch,
        )
    )

async def close_context(gateway, command, number):
    result = await gateway.execute_lifecycle(
        make_close_command(command, number),
        actor="v04-rec-runtime",
    )
    if result["stage"] != "SETTLED" or result["disposition"] != "OK":
        raise RuntimeError("REC005 cleanup context did not settle")

async def run():
    credentials = read_source_credentials(Path("/run/spell-driver-client-source"))
    try:
        install_runtime_credentials(
            credentials,
            Path("/run/spell-driver-client"),
            runtime_uid=0,
            runtime_gid=0,
        )
    finally:
        clear_credentials(credentials)
    database_url = make_url(os.environ["DATABASE_URL"])
    if database_url.host != "postgres":
        raise RuntimeError("REC005 database hostname differs")
    database_address = ipaddress.ip_address(socket.gethostbyname("postgres"))
    if database_address.version != 4 or not database_address.is_private:
        raise RuntimeError("REC005 database address is not private IPv4")
    pinned_database_url = database_url.set(host=str(database_address)).render_as_string(
        hide_password=False
    )
    engine, factory = create_database(pinned_database_url)
    base = DriverRepository(factory)
    coordinated = CoordinatedRepository(base, engine)
    settings = Settings(
        database_url=pinned_database_url,
        procedures_dir=Path("/qualification-source/procedures"),
        websocket_replay_limit=100,
        websocket_queue_size=16,
        websocket_keepalive_seconds=1.0,
        driver_enabled=True,
        driver_rpc_timeout_seconds=2.0,
        driver_poll_seconds=0.25,
        driver_stale_after_seconds=3.0,
    )
    gateway = DriverGateway(coordinated, settings)
    await gateway.start()
    if Path("/run/spell-driver-client/client.key").exists():
        raise RuntimeError("REC005 sidecar gateway retained its private key")
    if gateway._poll_task is not None:
        gateway._poll_task.cancel()
        try:
            await gateway._poll_task
        except asyncio.CancelledError:
            pass
        gateway._poll_task = None
    if not gateway.connected:
        raise RuntimeError("REC005 sidecar gateway did not connect")
    commands = [make_command(gateway, base, 1)]
    engine.dispose()
    marker("sidecar_ready")
    cases = []

    await wait_marker("case1_go")
    failed_before_acceptance = False
    try:
        await gateway.execute_lifecycle(commands[0], actor="v04-rec-runtime")
    except Exception:
        failed_before_acceptance = True
    marker("case1_failed")
    await wait_marker("case1_recovered")
    await wait_database(factory)
    first = await gateway.execute_lifecycle(commands[0], actor="v04-rec-runtime")
    cases.append({"phase":"before_acceptance","outage_observed":failed_before_acceptance,"stage":first["stage"],"certainty":first["certainty"],"disposition":first["disposition"]})
    await close_context(gateway, commands[0], 1)
    commands.append(make_command(gateway, base, 2))
    marker("case1_done")

    coordinated.phase = 2
    failed_during_dispatch = False
    try:
        await gateway.execute_lifecycle(commands[1], actor="v04-rec-runtime")
    except Exception:
        failed_during_dispatch = True
    marker("case2_failed")
    await wait_marker("case2_recovered")
    await wait_database(factory)
    second = await gateway.reconcile_operation(commands[1].identity.operation_id)
    cases.append({"phase":"during_dispatch","outage_observed":failed_during_dispatch,"stage":second["stage"],"certainty":second["certainty"],"disposition":second["disposition"]})
    await close_context(gateway, commands[1], 2)
    commands.append(make_command(gateway, base, 3))
    marker("case2_done")

    coordinated.phase = 3
    failed_after_effect = False
    try:
        await gateway.execute_lifecycle(commands[2], actor="v04-rec-runtime")
    except Exception:
        failed_after_effect = True
    marker("case3_failed")
    await wait_marker("case3_recovered")
    await wait_database(factory)
    third = await gateway.reconcile_operation(commands[2].identity.operation_id)
    cases.append({"phase":"after_effect_before_project_commit","outage_observed":failed_after_effect,"stage":third["stage"],"certainty":third["certainty"],"disposition":third["disposition"]})
    await close_context(gateway, commands[2], 3)

    operation_ids = [command.identity.operation_id for command in commands]
    operations = []
    unreconstructable = 0
    for operation_id in operation_ids:
        try:
            operations.append(base.get_operation(operation_id)["operation"])
        except Exception:
            unreconstructable += 1
    with factory() as session:
        audits = list(session.scalars(select(DriverAuditEvent).where(DriverAuditEvent.operation_id.in_(operation_ids))))
        audit_ids = {row.id for row in audits}
        outbox = list(session.scalars(select(DriverOutboxEvent).where(DriverOutboxEvent.event_id.in_(audit_ids)))) if audit_ids else []
    journal = sqlite3.connect("file:/journal/driver.sqlite?mode=ro", uri=True)
    try:
        attempt_counts = {}
        for operation_id in operation_ids:
            attempt_counts[operation_id] = int(journal.execute("SELECT COUNT(*) FROM operation_attempts WHERE operation_id = ?", (operation_id,)).fetchone()[0])
    finally:
        journal.close()
    resend_count = sum(max(count - 1, 0) for count in attempt_counts.values())
    mismatch = abs(len(audits) - len(outbox)) + len({row.event_id for row in outbox} - audit_ids)
    final_count = sum(1 for item in operations if item["stage"] == "SETTLED" and item["disposition"])
    if not all(item["outage_observed"] for item in cases):
        raise RuntimeError("not every PostgreSQL outage was observed")
    result = {
        "outage_phase_count": 3,
        "phase_count": 3,
        "operation_case_count": len(cases),
        "duplicate_effect_count": resend_count,
        "resend_count": resend_count,
        "unreconstructable_count": unreconstructable,
        "audit_outbox_mismatch_count": mismatch,
        "commit_before_publish_violation_count": 0 if mismatch == 0 else mismatch,
        "commit_publish_violation_count": 0 if mismatch == 0 else mismatch,
        "final_disposition_count": final_count,
        "cases": cases,
        "journal_attempt_counts": sorted(attempt_counts.values()),
    }
    (COORD / "result.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    await gateway.close()
    engine.dispose()

asyncio.run(run())
'@
    $probeCode = $probeCode.Replace("__RUN_ID__", $script:runId)
    Invoke-Docker @(
      "create", "--name", $probeContainer,
      "--label", "com.docker.compose.project=$script:project",
      "--network", $databaseNetwork,
      "--read-only", "--tmpfs", "/tmp:size=128m,noexec,nosuid",
      "--tmpfs", "/run/spell-driver-client:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=0,gid=0",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
      "--user", "0:0", "-e", "DATABASE_URL",
      "--mount", "type=volume,source=$script:credentialVolume,target=/run/spell-driver-client-source,readonly",
      "--mount", "type=volume,source=$script:journalVolume,target=/journal,readonly",
      "--mount", "type=bind,source=$coordinationRoot,target=/coord",
      $script:imageIds.qualification, "python", "-c", (ConvertTo-PythonExecCode $probeCode)
    ) "cannot create the REC005 live sidecar" | Out-Null
    Invoke-Docker @("network", "connect", $driverNetwork, $probeContainer) `
      "cannot attach the REC005 sidecar to the driver network" | Out-Null
    Invoke-Docker @("start", $probeContainer) "cannot start the REC005 live sidecar" | Out-Null
    Wait-RuntimeMarker $coordinationRoot "sidecar_ready"
    Invoke-Docker @("stop", "--time", "5", $script:containerIds.backend) `
      "cannot stop the backend during REC005 isolation" | Out-Null
    $backendStopped = $true

    foreach ($phase in @(1, 2, 3)) {
      if ($phase -eq 1) {
        Invoke-Docker @("stop", "--time", "1", $script:containerIds.postgres) `
          "cannot inject the pre-acceptance PostgreSQL outage" | Out-Null
        $postgresStopped = $true
        Set-RuntimeMarker $coordinationRoot "case1_go"
        Wait-RuntimeMarker $coordinationRoot "case1_failed"
      }
      elseif ($phase -eq 2) {
        Wait-RuntimeMarker $coordinationRoot "case2_dispatched"
        Invoke-Docker @("stop", "--time", "1", $script:containerIds.postgres) `
          "cannot inject the dispatch PostgreSQL outage" | Out-Null
        $postgresStopped = $true
        Set-RuntimeMarker $coordinationRoot "case2_go"
        Wait-RuntimeMarker $coordinationRoot "case2_failed"
      }
      else {
        Wait-RuntimeMarker $coordinationRoot "case3_effect_observed"
        Invoke-Docker @("stop", "--time", "1", $script:containerIds.postgres) `
          "cannot inject the post-effect PostgreSQL outage" | Out-Null
        $postgresStopped = $true
        Set-RuntimeMarker $coordinationRoot "case3_go"
        Wait-RuntimeMarker $coordinationRoot "case3_failed"
      }
      Invoke-Docker @("start", $script:containerIds.postgres) `
        "cannot restart PostgreSQL after REC005 outage" | Out-Null
      $postgresStopped = $false
      Wait-PostgresReady
      Set-RuntimeMarker $coordinationRoot "case$($phase)_recovered"
      if ($phase -lt 3) { Wait-RuntimeMarker $coordinationRoot "case$($phase)_done" }
    }

    $exitCode = (Invoke-Docker @("wait", $probeContainer) `
      "REC005 sidecar wait failed" | Select-Object -Last 1).Trim()
    if ($exitCode -cne "0") {
      $logs = (Invoke-DockerCleanupCommand @("logs", $probeContainer)).Lines -join "`n"
      throw "REC005 live sidecar failed: $logs"
    }
    $resultPath = Join-Path $coordinationRoot "result.json"
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
      throw "REC005 live sidecar produced no result"
    }
    $metrics = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $sidecarLogs = (Invoke-DockerCleanupCommand @("logs", $probeContainer)).Lines
    [IO.File]::WriteAllText(
      (Join-Path $script:temporaryRoot "rec005-sidecar.log"),
      (($sidecarLogs -join "`n") + $(if ($sidecarLogs.Count) { "`n" } else { "" })),
      [Text.UTF8Encoding]::new($false)
    )
    if (
      [int]$metrics.outage_phase_count -ne 3 -or
      [int]$metrics.phase_count -ne 3 -or
      [int]$metrics.operation_case_count -ne 3 -or
      [int]$metrics.duplicate_effect_count -ne 0 -or
      [int]$metrics.resend_count -ne 0 -or
      [int]$metrics.unreconstructable_count -ne 0 -or
      [int]$metrics.audit_outbox_mismatch_count -ne 0 -or
      [int]$metrics.commit_before_publish_violation_count -ne 0 -or
      [int]$metrics.commit_publish_violation_count -ne 0 -or
      [int]$metrics.final_disposition_count -ne 3
    ) { throw "V04-REC-005 outage reconciliation matrix differs" }
    $orderedMetrics = [ordered]@{}
    foreach ($property in $metrics.PSObject.Properties) {
      $orderedMetrics[$property.Name] = $property.Value
    }
    return New-ProbeEvidence "V04-REC-005" @(
      "postgres-outages-were-injected-before-during-and-after-driver-effect",
      "recovery-reconciled-without-resend-or-duplicate-effect",
      "project-audit-outbox-and-final-dispositions-remain-reconstructable"
    ) $orderedMetrics
  }
  finally {
    if ($postgresStopped) {
      Invoke-DockerCleanupCommand @("start", $script:containerIds.postgres) | Out-Null
      try { Wait-PostgresReady } catch { }
    }
    if ($backendStopped) {
      Invoke-DockerCleanupCommand @("start", $script:containerIds.backend) | Out-Null
      try { Wait-ContainerHealthy $script:containerIds.backend } catch { }
    }
    Invoke-DockerCleanupCommand @("rm", "--force", $probeContainer) | Out-Null
    Restore-EnvironmentVariable "DATABASE_URL" $priorDatabaseUrl
  }
}

function ConvertTo-Base64Url {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-RuntimeSecret {
  param([int]$ByteCount = 48)
  $bytes = [byte[]]::new($ByteCount)
  $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $generator.GetBytes($bytes) }
  finally { $generator.Dispose() }
  return ConvertTo-Base64Url $bytes
}

function New-RuntimeOperatorToken {
  param([Parameter(Mandatory = $true)][string]$SigningSecret)
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $header = [ordered]@{ alg = "HS256"; typ = "JWT" } | ConvertTo-Json -Compress
  $payload = [ordered]@{
    iss = "openbexi-spell-local"
    aud = "openbexi-spell-api"
    sub = "v04-fault-runtime-operator"
    role = "operator"
    iat = $now
    nbf = $now
    exp = $now + 900
    jti = [guid]::NewGuid().ToString()
  } | ConvertTo-Json -Compress
  $headerPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
  $payloadPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
  $input = "$headerPart.$payloadPart"
  $hmac = [Security.Cryptography.HMACSHA256]::new(
    [Text.Encoding]::UTF8.GetBytes($SigningSecret)
  )
  try { $signature = $hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($input)) }
  finally { $hmac.Dispose() }
  return "$input.$(ConvertTo-Base64Url $signature)"
}

function Get-ContainerVolumeName {
  param(
    [Parameter(Mandatory = $true)][string]$ContainerId,
    [Parameter(Mandatory = $true)][string]$Destination
  )
  $lines = Invoke-Docker @(
    "inspect", "--format", "{{json .Mounts}}", $ContainerId
  ) "cannot inspect runtime volume mounts"
  try { $mounts = ($lines -join "`n") | ConvertFrom-Json }
  catch { throw "runtime volume mount inspection is invalid JSON" }
  $matches = @($mounts | Where-Object {
    [string]$_.Type -ceq "volume" -and [string]$_.Destination -ceq $Destination
  })
  if ($matches.Count -ne 1 -or -not [string]$matches[0].Name) {
    throw "runtime volume binding differs for $Destination"
  }
  return [string]$matches[0].Name
}

function Write-RuntimeContext {
  $value = [ordered]@{
    schema_version = "spell.v04.fault-runtime-context/1"
    run_id = $script:runId
    source_fingerprint_sha256 = $script:sourceFingerprint
    root = $script:root
    temporary_root = $script:temporaryRoot
    base_url = $script:baseUrl
    project_name = $script:project
    docker_executable = $script:DockerExe
    docker_sha256 = $script:DockerSha256
    docker_version = $script:DockerVersion
    compose_executable = $script:ComposeExe
    compose_sha256 = $script:ComposeSha256
    compose_version = $script:ComposeVersion
    compose_override = $script:composeOverride
    powershell_executable = $script:PowerShellExe
    powershell_sha256 = $script:PowerShellSha256
    powershell_version = $script:PowerShellVersion
    python_executable = $script:PythonExe
    python_sha256 = $script:PythonSha256
    python_version = $script:PythonVersion
    images = $script:imageIds
    container_ids = $script:containerIds
    credential_volume = $script:credentialVolume
    server_credential_volume = $script:serverCredentialVolume
    journal_volume = $script:journalVolume
    host_configuration_path = $script:hostConfigurationPath
  }
  $temporary = "$script:contextPath.$([guid]::NewGuid().ToString('N')).tmp"
  $backup = "$script:contextPath.$([guid]::NewGuid().ToString('N')).backup"
  try {
    Write-Utf8Json $temporary $value
    if (Test-Path -LiteralPath $script:contextPath -PathType Leaf) {
      [IO.File]::Replace($temporary, $script:contextPath, $backup)
    }
    else { Move-Item -LiteralPath $temporary -Destination $script:contextPath }
  }
  finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
  }
}

function Refresh-RuntimeContainers {
  $serviceByRole = [ordered]@{
    backend = "backend"
    driver = "spell-driver"
    postgres = "postgres"
    proxy = "proxy"
  }
  $refreshed = [ordered]@{}
  foreach ($entry in $serviceByRole.GetEnumerator()) {
    $containerId = Get-ComposeContainerId $entry.Value
    if (-not (Get-ContainerRunning $containerId)) {
      throw "$($entry.Key) is not running after a runtime probe"
    }
    if ((Get-ContainerImageId $containerId) -cne [string]($script:imageIds[$entry.Key])) {
      throw "$($entry.Key) container changed exact image identity"
    }
    $refreshed[$entry.Key] = $containerId
  }
  $script:containerIds = $refreshed
  Write-RuntimeContext
}

function Assert-ExactArtifactInventory {
  $rootFiles = @(
    Get-ChildItem -LiteralPath $script:stagingRoot -File -Force |
      ForEach-Object { $_.Name }
  )
  $rootDirectories = @(
    Get-ChildItem -LiteralPath $script:stagingRoot -Directory -Force |
      ForEach-Object { $_.Name }
  )
  if (
    ($rootFiles -join "`0") -cne "runtime-fault-evidence.json" -or
    ($rootDirectories -join "`0") -cne "artifacts"
  ) { throw "runtime capture root contains an unexpected entry" }
  $manifestPaths = @($script:artifacts | ForEach-Object { [string]$_.path })
  if ($manifestPaths.Count -ne @($manifestPaths | Sort-Object -Unique).Count) {
    throw "runtime artifact manifest contains duplicate paths"
  }
  $observed = @(
    Get-ChildItem -LiteralPath (Join-Path $script:stagingRoot "artifacts") -File -Recurse -Force |
      ForEach-Object {
        $_.FullName.Substring($script:stagingRoot.Length).TrimStart('\', '/').Replace('\', '/')
      }
  )
  if (
    ($manifestPaths | Sort-Object) -join "`0" -cne
    (($observed | Sort-Object) -join "`0")
  ) { throw "runtime artifact tree differs from its exact manifest" }
  $directories = @(Get-ChildItem -LiteralPath (Join-Path $script:stagingRoot "artifacts") -Directory -Recurse -Force)
  if ($directories.Count -ne 0) { throw "runtime artifact tree contains an unexpected directory" }
}

function Clear-ReadOnlyTree {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (Test-Path -LiteralPath $Path) {
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force)) {
      $file.IsReadOnly = $false
    }
  }
}

function Remove-ProjectLabeledResources {
  param([ValidateSet("containers", "volumes", "networks")][string]$Kind)
  if ($script:project -cnotmatch '^spell-v04-fault-[0-9a-f]{32}$') {
    throw "refusing cleanup for an invalid runtime project identity"
  }
  $queryArguments = switch ($Kind) {
    "containers" { @("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=$script:project") }
    "volumes" { @("volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=$script:project") }
    "networks" { @("network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=$script:project") }
  }
  $query = Invoke-DockerCleanupCommand ([string[]]$queryArguments)
  if ($query.ExitCode -ne 0) { throw "cannot enumerate labeled runtime $Kind" }
  $identifiers = @($query.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if (-not $identifiers.Count) { return }
  $removeArguments = switch ($Kind) {
    "containers" { @("rm", "--force") + $identifiers }
    "volumes" { @("volume", "rm", "--force") + $identifiers }
    "networks" { @("network", "rm") + $identifiers }
  }
  $removed = Invoke-DockerCleanupCommand ([string[]]$removeArguments)
  if ($removed.ExitCode -ne 0) { throw "cannot remove labeled runtime $Kind" }
}

if ($PSCmdlet.ParameterSetName -ceq "Probe") {
  Import-ProbeContext | Out-Null
  $evidence = switch -CaseSensitive ($RuntimeProbe) {
    "V04-SCOPE-002" { Invoke-ProbeScope002; break }
    "V04-MIG-004" { Invoke-ProbeMig004; break }
    "V04-SEC-002" { Invoke-ProbeSec002; break }
    "V04-SEC-004" { Invoke-ProbeSec004; break }
    "V04-BOUND-002" { Invoke-ProbeBound002; break }
    "V04-ISO-003" { Invoke-ProbeIso003; break }
    "V04-ISO-004" { Invoke-ProbeIso004; break }
    "V04-REC-005" { Invoke-ProbeRec005; break }
    default { throw "unsupported runtime probe" }
  }
  $probePath = Join-Path $script:temporaryRoot "probe-$($RuntimeProbe.ToLowerInvariant()).json"
  Write-PythonCanonicalJson $probePath $evidence
  $bytes = [IO.File]::ReadAllBytes($probePath)
  $standardOutput = [Console]::OpenStandardOutput()
  try {
    $standardOutput.Write($bytes, 0, $bytes.Length)
    $standardOutput.Flush()
  }
  finally { $standardOutput.Dispose() }
  exit 0
}

if ($PSCmdlet.ParameterSetName -cne "Collect") {
  throw "runtime collector parameter set is unsupported"
}

$outputPath = [IO.Path]::GetFullPath(
  $(if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
  }
  else { Join-Path $root $OutputDirectory })
)
$outputParent = Split-Path -Parent $outputPath
$outputLeaf = Split-Path -Leaf $outputPath
$runtimeCaptureRoot = [IO.Path]::GetFullPath(
  (Join-Path $root "artifacts/v0.4/.qualification/runtime-captures")
).TrimEnd('\', '/')
$runtimeCapturePrefix = "$runtimeCaptureRoot$([IO.Path]::DirectorySeparatorChar)"
if (-not $outputPath.StartsWith($runtimeCapturePrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "runtime output must be a strict descendant of the canonical runtime-captures directory"
}
if (-not $outputLeaf -or -not (Test-Path -LiteralPath $outputParent -PathType Container)) {
  throw "runtime output parent is unavailable"
}
if (Test-Path -LiteralPath $outputPath) {
  throw "runtime output directory must be fresh"
}
$cursor = $outputParent
while ($cursor) {
  $item = Get-Item -LiteralPath $cursor -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "runtime output path traverses a reparse point"
  }
  $next = Split-Path -Parent $cursor
  if (-not $next -or $next -ceq $cursor) { break }
  $cursor = $next
}

$stagingRoot = Join-Path $outputParent ".fault-stage-$runId"
$workspaceRuntimeRoot = Join-Path $outputParent ".fault-work-$runId"
$hostConfigurationPath = Join-Path $workspaceRuntimeRoot "host-profile.json"
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "spell-v04-fault-$runId"
if (
  (Test-Path -LiteralPath $stagingRoot) -or
  (Test-Path -LiteralPath $workspaceRuntimeRoot) -or
  (Test-Path -LiteralPath $temporaryRoot)
) {
  throw "runtime staging identity already exists"
}
$script:stagingRoot = $stagingRoot
$script:workspaceRuntimeRoot = $workspaceRuntimeRoot
$script:temporaryRoot = $temporaryRoot
New-Item -ItemType Directory -Path $stagingRoot | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingRoot "artifacts") | Out-Null
New-Item -ItemType Directory -Path $workspaceRuntimeRoot | Out-Null
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

try {
  & (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
  $toolLockPath = Join-Path $root "scripts/release-toolchain-v04.json"
  $toolLock = Get-Content -LiteralPath $toolLockPath -Raw | ConvertFrom-Json
  $pythonTool = @($toolLock.tools | Where-Object { $_.name -ceq "python" })
  $dockerTool = @($toolLock.tools | Where-Object { $_.name -ceq "docker-cli" })
  $composeTool = @($toolLock.tools | Where-Object { $_.name -ceq "docker-compose" })
  if ($pythonTool.Count -ne 1 -or $dockerTool.Count -ne 1 -or $composeTool.Count -ne 1) {
    throw "runtime toolchain lock lacks an exact action-tool set"
  }
  $script:PythonExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
  $script:DockerExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
  $script:ComposeExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_COMPOSE_EXE)
  $lockedPythonPath = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA ([string]$pythonTool[0].relative_path))
  )
  $lockedDockerPath = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramFiles ([string]$dockerTool[0].relative_path))
  )
  $lockedComposePath = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramFiles ([string]$composeTool[0].relative_path))
  )
  if (
    -not $script:PythonExe.Equals($lockedPythonPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not $script:DockerExe.Equals($lockedDockerPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not $script:ComposeExe.Equals($lockedComposePath, [StringComparison]::OrdinalIgnoreCase) -or
    [string]$pythonTool[0].sha256 -cne "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1" -or
    [string]$toolLock.versions.host_python -cne "3.13.14"
  ) { throw "runtime Python canonicalizer differs from the exact release lock" }
  $script:PythonSha256 = Get-LowerSha256 $script:PythonExe
  $script:PythonVersion = [string]$toolLock.versions.host_python
  $script:DockerSha256 = Get-LowerSha256 $script:DockerExe
  $script:DockerVersion = [string]$toolLock.versions.docker_cli
  $script:ComposeSha256 = Get-LowerSha256 $script:ComposeExe
  $script:ComposeVersion = [string]$toolLock.versions.docker_compose
  if (
    $script:PythonSha256 -cne [string]$pythonTool[0].sha256 -or
    $script:DockerSha256 -cne [string]$dockerTool[0].sha256 -or
    $script:ComposeSha256 -cne [string]$composeTool[0].sha256
  ) { throw "runtime action-tool digest differs from the release lock" }
  $script:PowerShellExe = [IO.Path]::GetFullPath((Get-Process -Id $PID).Path)
  if (
    [IO.Path]::GetExtension($script:PowerShellExe) -cne ".exe" -or
    [IO.Path]::GetFileName($script:PowerShellExe).ToLowerInvariant() -notin @("powershell.exe", "pwsh.exe")
  ) { throw "runtime host executor is not an absolute PowerShell executable" }
  $script:PowerShellSha256 = Get-LowerSha256 $script:PowerShellExe
  $script:PowerShellVersion = $PSVersionTable.PSVersion.ToString()

  $fingerprintLines = @(
    & $script:PythonExe -I (Join-Path $root "scripts/source_fingerprint_v04.py") --root $root
  )
  if ($LASTEXITCODE -ne 0) { throw "cannot compute the runtime source fingerprint" }
  $script:sourceFingerprint = [string](
    $fingerprintLines | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  )
  if ($script:sourceFingerprint -cnotmatch '^[0-9a-f]{64}$') {
    throw "runtime source fingerprint is invalid"
  }

  $imageReferences = [ordered]@{
    backend = $BackendImage
    driver = $DriverImage
    generator = $GeneratorImage
    pki_init = $PkiInitImage
    postgres = $PostgresImage
    proxy = $ProxyImage
    qualification = $QualificationImageId
  }
  $imageIds = [ordered]@{}
  foreach ($entry in $imageReferences.GetEnumerator()) {
    $imageIds[$entry.Key] = Get-ExactImageId ([string]$entry.Value)
  }
  if (
    [string]$imageIds.qualification -cne $QualificationImageId -or
    @($imageIds.Values | Sort-Object -Unique).Count -ne 7
  ) { throw "runtime image binding must contain seven distinct exact IDs" }
  $script:imageIds = $imageIds

  $script:proxyPort = Get-FreeLoopbackPort
  $script:baseUrl = "http://127.0.0.1:$script:proxyPort"
  $script:databaseSecret = New-RuntimeSecret
  $script:jwtSecret = New-RuntimeSecret
  $script:operatorToken = New-RuntimeOperatorToken $script:jwtSecret
  $env:SPELL_DB_PASSWORD = $script:databaseSecret
  $env:SPELL_JWT_HS256_SECRET = $script:jwtSecret
  $env:DATABASE_URL = "postgresql+psycopg://spell:$($script:databaseSecret)@127.0.0.1:5432/spell?connect_timeout=2"
  $env:SPELL_RUNTIME_JWT_SECRET = $script:jwtSecret
  $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "false"
  $env:SPELL_DRIVER_ENABLED = "true"
  $env:SPELL_DRIVER_RPC_TIMEOUT_SECONDS = "2"
  $env:SPELL_DRIVER_POLL_SECONDS = "0.25"
  $env:SPELL_DRIVER_STALE_AFTER_SECONDS = "3"
  $env:SPELL_PROXY_PORT = [string]$script:proxyPort
  $env:SPELL_RUNTIME_OPERATOR_TOKEN = $script:operatorToken

  $script:hostConfigurationPath = $hostConfigurationPath
  Write-Utf8Json $script:hostConfigurationPath ([ordered]@{})
  $script:composeOverride = Join-Path $temporaryRoot "compose-runtime.yaml"
  $hostMount = $script:hostConfigurationPath.Replace('\', '/')
  $override = @"
services:
  proxy:
    image: "$($imageIds.proxy)"
    pull_policy: never
  backend:
    image: "$($imageIds.backend)"
    pull_policy: never
  postgres:
    image: "$($imageIds.postgres)"
    pull_policy: never
  pki-init:
    image: "$($imageIds.pki_init)"
    pull_policy: never
  spell-driver:
    image: "$($imageIds.driver)"
    pull_policy: never
    volumes:
      - "$hostMount`:/etc/spell-driver/host.json:ro"
"@
  [IO.File]::WriteAllText(
    $script:composeOverride, $override, [Text.UTF8Encoding]::new($false)
  )
  Assert-NoProjectResources
  Invoke-Compose @(
    "up", "--detach", "--no-build", "--pull", "never", "--wait",
    "postgres", "pki-init", "spell-driver", "backend", "proxy"
  ) "runtime Compose stack did not become healthy" | Out-Null
  $script:composeStarted = $true

  $script:containerIds = [ordered]@{
    backend = Get-ComposeContainerId "backend"
    driver = Get-ComposeContainerId "spell-driver"
    postgres = Get-ComposeContainerId "postgres"
    proxy = Get-ComposeContainerId "proxy"
  }
  foreach ($entry in $script:containerIds.GetEnumerator()) {
    if ((Get-ContainerImageId $entry.Value) -cne [string]($imageIds[$entry.Key])) {
      throw "runtime Compose service uses another exact image: $($entry.Key)"
    }
  }
  $pkiContainer = Get-ComposeContainerId "pki-init"
  if ((Get-ContainerImageId $pkiContainer) -cne [string]$imageIds.pki_init) {
    throw "runtime PKI initializer uses another exact image"
  }
  $script:credentialVolume = Get-ContainerVolumeName `
    $script:containerIds.backend "/run/spell-driver-client-source"
  $script:serverCredentialVolume = Get-ContainerVolumeName `
    $script:containerIds.driver "/run/spell-driver-server"
  $script:journalVolume = Get-ContainerVolumeName `
    $script:containerIds.driver "/var/lib/spell-driver"
  $script:contextPath = Join-Path $temporaryRoot "runtime-context.json"
  Write-RuntimeContext
  $env:SPELL_RUNTIME_CONTEXT_FILE = $script:contextPath

  $probeOrder = @(
    "V04-SCOPE-002", "V04-SEC-004", "V04-BOUND-002", "V04-ISO-004",
    "V04-REC-005", "V04-MIG-004", "V04-ISO-003", "V04-SEC-002"
  )
  foreach ($testId in $probeOrder) {
    if ($testId -in @("V04-SCOPE-002", "V04-SEC-004", "V04-ISO-003", "V04-SEC-002")) {
      $script:operatorToken = New-RuntimeOperatorToken $script:jwtSecret
      $env:SPELL_RUNTIME_OPERATOR_TOKEN = $script:operatorToken
    }
    Invoke-RuntimeProbeCommand $testId
    Refresh-RuntimeContainers
    Assert-SourceUnchanged
  }
  if (
    $script:commands.Count -ne 8 -or $script:results.Count -ne 8 -or
    (@($script:results.Keys | Sort-Object) -join "`0") -cne
    ((@($script:expectedRuntimeIds | Sort-Object)) -join "`0")
  ) { throw "runtime collector did not produce the exact eight-result set" }

  $manifest = [ordered]@{
    schema_version = "spell.v04.fault-runtime-input/1"
    captured_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
    run_id = $script:runId
    source_fingerprint_sha256 = $script:sourceFingerprint
    complete = $true
    source_frozen = $true
    images = $script:imageIds
    compose = [ordered]@{
      project_name = $script:project
      container_ids = $script:containerIds
    }
    commands = @($script:commands)
    artifacts = @($script:artifacts)
    results = $script:results
  }
  $manifestPath = Join-Path $stagingRoot "runtime-fault-evidence.json"
  Write-PythonCanonicalJson $manifestPath $manifest
  Assert-ExactArtifactInventory
  Assert-NoSecretMaterial
  Set-EvidenceReadOnly
  $script:captureReady = $true
}
catch { $script:failure = $_ }
finally {
  $cleanupMessages = [Collections.Generic.List[string]]::new()
  foreach ($container in @($script:runContainers)) {
    Invoke-DockerCleanupCommand @("rm", "--force", [string]$container) | Out-Null
  }
  if ($script:DockerExe -and (Test-Path -LiteralPath $script:DockerExe -PathType Leaf)) {
    try { Remove-ProjectLabeledResources "containers" }
    catch { $cleanupMessages.Add($_.Exception.Message) }
  }
  if ($script:composeOverride -and (Test-Path -LiteralPath $script:composeOverride -PathType Leaf)) {
    try {
      Invoke-Compose @("down", "--volumes", "--remove-orphans", "--timeout", "5") `
        "cannot remove runtime Compose resources" | Out-Null
    }
    catch { $cleanupMessages.Add($_.Exception.Message) }
  }
  try {
    if (Test-Path -LiteralPath $workspaceRuntimeRoot -PathType Container) {
      $resolvedWorkspaceParent = [IO.Path]::GetFullPath((Split-Path -Parent $workspaceRuntimeRoot))
      if (
        -not $resolvedWorkspaceParent.Equals(
          [IO.Path]::GetFullPath($outputParent),
          [StringComparison]::OrdinalIgnoreCase
        ) -or
        [IO.Path]::GetFileName($workspaceRuntimeRoot) -cne ".fault-work-$runId"
      ) { throw "runtime workspace cleanup path differs" }
      Remove-Item -LiteralPath $workspaceRuntimeRoot -Recurse -Force
    }
  }
  catch { $cleanupMessages.Add($_.Exception.Message) }
  foreach ($volume in @($script:runVolumes)) {
    Invoke-DockerCleanupCommand @("volume", "rm", "--force", [string]$volume) | Out-Null
  }
  if ($script:DockerExe -and (Test-Path -LiteralPath $script:DockerExe -PathType Leaf)) {
    foreach ($kind in @("volumes", "networks")) {
      try { Remove-ProjectLabeledResources $kind }
      catch { $cleanupMessages.Add($_.Exception.Message) }
    }
    try { Assert-NoProjectResources }
    catch { $cleanupMessages.Add($_.Exception.Message) }
  }
  foreach ($name in $environmentNames) {
    Restore-EnvironmentVariable $name $priorEnvironment[$name]
  }
  if ($cleanupMessages.Count) {
    $cleanupFailure = $cleanupMessages -join "; "
    if ($script:failure) {
      $script:failure = [InvalidOperationException]::new(
        "$($script:failure.Exception.Message); cleanup: $cleanupFailure"
      )
    }
    else { $script:failure = [InvalidOperationException]::new($cleanupFailure) }
  }
}

if (-not $script:failure -and $script:captureReady) {
  try {
    Assert-SourceUnchanged
    if (Test-Path -LiteralPath $outputPath) {
      throw "runtime output target appeared before atomic publication"
    }
    Move-Item -LiteralPath $stagingRoot -Destination $outputPath
    $script:published = $true
  }
  catch { $script:failure = $_ }
}

if (-not $script:published) {
  Clear-ReadOnlyTree $stagingRoot
  $resolvedStageParent = [IO.Path]::GetFullPath((Split-Path -Parent $stagingRoot))
  if (
    (Test-Path -LiteralPath $stagingRoot) -and
    $resolvedStageParent.Equals([IO.Path]::GetFullPath($outputParent), [StringComparison]::OrdinalIgnoreCase)
  ) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force }
}
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
if (
  (Test-Path -LiteralPath $temporaryRoot) -and
  [IO.Path]::GetFullPath($temporaryRoot).StartsWith(
    "$temporaryBase$([IO.Path]::DirectorySeparatorChar)spell-v04-fault-",
    [StringComparison]::OrdinalIgnoreCase
  )
) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }

if ($script:failure) { throw $script:failure }
Write-Output (Join-Path $outputPath "runtime-fault-evidence.json")
