[CmdletBinding(DefaultParameterSetName = "Extract")]
param(
  [Parameter(Mandatory = $true, ParameterSetName = "Extract")]
  [ValidateSet(
    "V04-SCOPE-002", "V04-CON-001", "V04-CON-002", "V04-CON-003",
    "V04-MIG-002", "V04-MIG-004", "V04-SEC-004", "V04-BOUND-002",
    "V04-ISO-003", "V04-ISO-004", "V04-SEC-002", "V04-SEC-003",
    "V04-DEAD-004", "V04-JRN-001", "V04-REC-003", "V04-REC-005",
    "V04-API-002", "V04-API-003"
  )]
  [string]$TestId,

  [Parameter(Mandatory = $true, ParameterSetName = "Validate")]
  [switch]$ValidateRawReport,

  [Parameter(Mandatory = $true, ParameterSetName = "Capture")]
  [switch]$CaptureRawReport,

  [Parameter(ParameterSetName = "Capture")]
  [switch]$ReplaceProvenance,

  [switch]$Preliminary,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$BackendImage,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$DriverImage,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$GeneratorImage,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$PkiInitImage,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$PostgresImage,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$ProxyImage,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^sha256:[0-9a-f]{64}$")]
  [string]$QualificationImageId,

  [Parameter(Mandatory = $true, ParameterSetName = "Capture")]
  [string]$PrepublishRoot,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$RuntimeInput,

  [string]$RawReport = "artifacts/v0.4/.qualification/runtime-captures/fault-gate-run/fault-gate-raw.json"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if ($Preliminary -and $ReplaceProvenance) {
  throw "preliminary fault capture must not replace canonical provenance"
}

function Assert-NoReparseTraversal {
  param([Parameter(Mandatory = $true)][string]$Path)
  $cursor = [System.IO.Path]::GetFullPath($Path)
  while (-not (Test-Path -LiteralPath $cursor)) {
    $parent = Split-Path -Parent $cursor
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
    $cursor = $parent
  }
  while (-not [string]::IsNullOrWhiteSpace($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "release path traverses a reparse point: $cursor"
    }
    $parent = Split-Path -Parent $cursor
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
    $cursor = $parent
  }
}

function Test-PathOverlap {
  param(
    [Parameter(Mandatory = $true)][string]$Left,
    [Parameter(Mandatory = $true)][string]$Right
  )
  $separator = [System.IO.Path]::DirectorySeparatorChar
  $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd($separator)
  $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd($separator)
  return (
    $leftPath.Equals($rightPath, [System.StringComparison]::OrdinalIgnoreCase) -or
    $leftPath.StartsWith("$rightPath$separator", [System.StringComparison]::OrdinalIgnoreCase) -or
    $rightPath.StartsWith("$leftPath$separator", [System.StringComparison]::OrdinalIgnoreCase)
  )
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE

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
  $resolved = (& $DockerExe image inspect $entry.Value --format "{{.Id}}" 2>$null).Trim().ToLowerInvariant()
  if ($LASTEXITCODE -ne 0 -or $resolved -notmatch "^sha256:[0-9a-f]{64}$") {
    throw "exact $($entry.Key) image is unavailable: $($entry.Value)"
  }
  $imageIds[$entry.Key] = $resolved
}
if ($imageIds.qualification -ne $QualificationImageId) {
  throw "qualification image reference differs from its exact image ID"
}
if (@($imageIds.Values | Sort-Object -Unique).Count -ne $imageIds.Count) {
  throw "fault-gate image roles must resolve to seven distinct image IDs"
}

$observedImageArguments = @()
foreach ($entry in $imageIds.GetEnumerator()) {
  $observedImageArguments += @("--observed-image", "$($entry.Key)=$($entry.Value)")
}

if ([System.IO.Path]::IsPathRooted($RawReport)) {
  $rawPath = [System.IO.Path]::GetFullPath($RawReport)
}
else {
  $rawPath = [System.IO.Path]::GetFullPath((Join-Path $root $RawReport))
}
$captureDirectory = Split-Path -Parent $rawPath
Assert-NoReparseTraversal -Path $captureDirectory
if ($PSCmdlet.ParameterSetName -eq "Capture") {
  if (Test-Path -LiteralPath $captureDirectory) {
    throw "fresh fault-gate run directory already exists: $captureDirectory"
  }
  $captureParent = Split-Path -Parent $captureDirectory
  if (-not (Test-Path -LiteralPath $captureParent -PathType Container)) {
    throw "fault-gate run-directory parent is unavailable: $captureParent"
  }
}
elseif (-not (Test-Path -LiteralPath $captureDirectory -PathType Container)) {
  throw "fault-gate capture directory is unavailable: $captureDirectory"
}
$rawName = [System.IO.Path]::GetFileName($rawPath)
$containerRawPath = "/evidence/runtime-captures/$rawName"
$readOnlyCaptureMount = "type=bind,src=$captureDirectory,dst=/evidence/runtime-captures,readonly"

if ([System.IO.Path]::IsPathRooted($RuntimeInput)) {
  $runtimeInputPath = [System.IO.Path]::GetFullPath($RuntimeInput)
}
else {
  $runtimeInputPath = [System.IO.Path]::GetFullPath((Join-Path $root $RuntimeInput))
}
if (-not (Test-Path -LiteralPath $runtimeInputPath -PathType Leaf)) {
  throw "runtime fault input is unavailable: $runtimeInputPath"
}
Assert-NoReparseTraversal -Path $runtimeInputPath
if ([System.IO.Path]::GetFileName($runtimeInputPath) -ne "runtime-fault-evidence.json") {
  throw "runtime fault input must use the canonical filename"
}
$runtimeInputRoot = Split-Path -Parent $runtimeInputPath
$runtimeInputMount = "type=bind,src=$runtimeInputRoot,dst=/runtime-input,readonly"

function Get-RawReadArguments {
  param([string]$Mode, [string]$SelectedTestId)
  $arguments = @(
    "run", "--rm", "--network", "none", "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "--mount", $readOnlyCaptureMount,
    "--mount", $runtimeInputMount,
    $imageIds.qualification,
    "python", "scripts/qualify_faults_v04.py",
    "--root", "/qualification-source",
    "--qualification-image-id", $imageIds.qualification,
    "--artifact-directory", "/evidence/runtime-captures",
    "--runtime-input", "/runtime-input/runtime-fault-evidence.json"
  )
  $arguments += $observedImageArguments
  if ($Mode -eq "Validate") {
    $arguments += @("--validate-raw-report", $containerRawPath)
  }
  else {
    $arguments += @($SelectedTestId, "--raw-report", $containerRawPath)
  }
  if ($Preliminary) { $arguments += "--preliminary" }
  return $arguments
}

if ($PSCmdlet.ParameterSetName -eq "Capture") {
  if (Test-Path -LiteralPath $rawPath) {
    throw "fault-gate raw report already exists: $rawPath"
  }
  if ([System.IO.Path]::IsPathRooted($PrepublishRoot)) {
    $prepublishPath = [System.IO.Path]::GetFullPath($PrepublishRoot)
  }
  else {
    $prepublishPath = [System.IO.Path]::GetFullPath((Join-Path $root $PrepublishRoot))
  }
  if (-not (Test-Path -LiteralPath $prepublishPath -PathType Container)) {
    throw "SEC003 prepublish root is unavailable: $prepublishPath"
  }
  Assert-NoReparseTraversal -Path $prepublishPath
  $expectedRuntimeInputRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $prepublishPath "runtime_captures")
  )
  if (-not $runtimeInputRoot.Equals(
      $expectedRuntimeInputRoot,
      [System.StringComparison]::OrdinalIgnoreCase
    )) {
    throw "runtime fault input must be the exact SEC003 runtime_captures corpus"
  }
  if (
    (Test-PathOverlap -Left $captureDirectory -Right $prepublishPath) -or
    (Test-PathOverlap -Left $captureDirectory -Right $runtimeInputRoot)
  ) {
    throw "fault-gate output must be disjoint from prepublish and runtime inputs"
  }
  $faultProvenancePath = [System.IO.Path]::GetFullPath(
    (Join-Path $root "artifacts/v0.4/provenance/fault-gate")
  )
  if (-not $Preliminary) {
    Assert-NoReparseTraversal -Path $faultProvenancePath
    if ((Test-Path -LiteralPath $faultProvenancePath) -and -not $ReplaceProvenance) {
      throw "canonical fault provenance already exists; pass -ReplaceProvenance to replace"
    }
  }
  $null = New-Item -ItemType Directory -Path $captureDirectory
  Assert-NoReparseTraversal -Path $captureDirectory
  $runToken = [Guid]::NewGuid().ToString("N")
  $migrationNetwork = "spell-v04-fault-$runToken"
  $migrationContainer = "spell-v04-migration-$runToken"
  $priorMigrationUrl = $env:SPELL_MIGRATION_TEST_DATABASE_URL
  $captureFailure = $null
  $cleanupFailures = [System.Collections.Generic.List[string]]::new()
  try {
    $networkId = (& $DockerExe network create --internal $migrationNetwork 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($networkId)) {
      throw "dedicated fault-gate migration network creation failed"
    }
    $databaseId = (& $DockerExe run --detach --name $migrationContainer `
      --network $migrationNetwork --network-alias spell-migration-postgres `
      --read-only `
      --tmpfs "/var/lib/postgresql:rw,noexec,nosuid,size=512m,uid=70,gid=70,mode=1777" `
      --tmpfs "/var/run/postgresql:rw,noexec,nosuid,size=16m,uid=70,gid=70,mode=3775" `
      --tmpfs "/tmp:rw,noexec,nosuid,size=32m,uid=70,gid=70,mode=1777" `
      --env "POSTGRES_DB=spell_migration_test" `
      --env "POSTGRES_USER=spell" `
      --env "POSTGRES_HOST_AUTH_METHOD=trust" `
      $imageIds.postgres 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $databaseId -notmatch "^[0-9a-f]{64}$") {
      throw "dedicated fault-gate migration database did not start"
    }
    $databaseReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
      & $DockerExe exec $migrationContainer pg_isready -U spell -d spell_migration_test *> $null
      if ($LASTEXITCODE -eq 0) {
        $databaseReady = $true
        break
      }
      Start-Sleep -Seconds 1
    }
    if (-not $databaseReady) {
      throw "dedicated fault-gate migration database did not become ready"
    }

    $env:SPELL_MIGRATION_TEST_DATABASE_URL = (
      "postgresql+psycopg://spell@spell-migration-postgres:5432/spell_migration_test"
    )
    $writeMount = "type=bind,src=$captureDirectory,dst=/evidence/runtime-captures"
    $prepublishMount = "type=bind,src=$prepublishPath,dst=/prepublish,readonly"
    $captureArguments = @(
      "run", "--rm", "--network", $migrationNetwork, "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
      "--mount", $writeMount,
      "--mount", $prepublishMount,
      "--mount", $runtimeInputMount,
      "--env", "SPELL_MIGRATION_TEST_DATABASE_URL",
      $imageIds.qualification,
      "python", "scripts/qualify_faults_v04.py",
      "--root", "/qualification-source",
      "--qualification-image-id", $imageIds.qualification,
      "--capture-raw-report", $containerRawPath,
      "--prepublish-root", "/prepublish",
      "--runtime-input", "/runtime-input/runtime-fault-evidence.json"
    )
    if ($Preliminary) {
      $captureArguments += "--preliminary"
    }
    else {
      $captureArguments += "--final"
    }
    $captureArguments += $observedImageArguments
    $null = & $DockerExe @captureArguments
    if ($LASTEXITCODE -ne 0) {
      throw "all-ID fault-gate raw report capture failed"
    }
    $validateArguments = Get-RawReadArguments -Mode "Validate" -SelectedTestId ""
    & $DockerExe @validateArguments
    if ($LASTEXITCODE -ne 0) {
      throw "new all-ID fault-gate raw report failed immediate validation"
    }
  }
  catch {
    $captureFailure = $_
  }
  finally {
    if ($null -eq $priorMigrationUrl) {
      Remove-Item Env:SPELL_MIGRATION_TEST_DATABASE_URL -ErrorAction SilentlyContinue
    }
    else {
      $env:SPELL_MIGRATION_TEST_DATABASE_URL = $priorMigrationUrl
    }
    & $DockerExe rm --force $migrationContainer *> $null
    $remainingContainers = @(
      & $DockerExe container ls --all --filter "name=^/$migrationContainer$" --format "{{.Names}}" 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
      $cleanupFailures.Add("could not verify dedicated migration container absence")
    }
    elseif (@($remainingContainers | Where-Object { $_.Trim() -eq $migrationContainer }).Count -ne 0) {
      $cleanupFailures.Add("dedicated migration container remains: $migrationContainer")
    }
    & $DockerExe network rm $migrationNetwork *> $null
    $remainingNetworks = @(
      & $DockerExe network ls --filter "name=^$migrationNetwork$" --format "{{.Name}}" 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
      $cleanupFailures.Add("could not verify dedicated migration network absence")
    }
    elseif (@($remainingNetworks | Where-Object { $_.Trim() -eq $migrationNetwork }).Count -ne 0) {
      $cleanupFailures.Add("dedicated migration network remains: $migrationNetwork")
    }
  }
  if ($cleanupFailures.Count -ne 0) {
    $cleanupMessage = $cleanupFailures -join "; "
    if ($null -ne $captureFailure) {
      throw [System.InvalidOperationException]::new(
        "$($captureFailure.Exception.Message); cleanup verification failed: $cleanupMessage",
        $captureFailure.Exception
      )
    }
    throw "fault-gate cleanup verification failed: $cleanupMessage"
  }
  if ($null -ne $captureFailure) {
    throw $captureFailure
  }
  if ($Preliminary) {
    return
  }
  $publisherArguments = @(
    "-I", (Join-Path $PSScriptRoot "publish_fault_provenance_v04.py"),
    "--raw-source", $captureDirectory,
    "--runtime-source", $runtimeInputRoot,
    "--destination", $faultProvenancePath
  )
  if ($ReplaceProvenance) { $publisherArguments += "--replace" }
  & $env:SPELL_RELEASE_PYTHON_EXE @publisherArguments
  if ($LASTEXITCODE -ne 0) {
    throw "atomic canonical fault provenance publication failed"
  }
  return
}

if (-not (Test-Path -LiteralPath $rawPath -PathType Leaf)) {
  throw "complete fault-gate raw report is unavailable: $rawPath"
}
if ($PSCmdlet.ParameterSetName -eq "Validate") {
  $arguments = Get-RawReadArguments -Mode "Validate" -SelectedTestId ""
}
else {
  $arguments = Get-RawReadArguments -Mode "Extract" -SelectedTestId $TestId
}
& $DockerExe @arguments
if ($LASTEXITCODE -ne 0) {
  if ($PSCmdlet.ParameterSetName -eq "Validate") {
    throw "all-ID fault-gate raw report validation failed"
  }
  throw "$TestId raw-report extraction failed"
}
