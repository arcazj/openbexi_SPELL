[CmdletBinding()]
param(
  [ValidatePattern('^V04-ISO-001$')]
  [string]$TestId = "V04-ISO-001",

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-f]{64}$')]
  [string]$ExpectedSourceFingerprint,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$QualificationImageId,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$DriverImageId,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$PkiImageId,

  [string]$DockerExecutable = $env:SPELL_RELEASE_DOCKER_EXE,

  [string]$Root,

  [ValidateRange(30, 1800)]
  [int]$CommandTimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($Root)) {
  $Root = Split-Path -Parent $PSScriptRoot
}
$rootFull = [IO.Path]::GetFullPath($Root)
$composePath = Join-Path $rootFull "compose.yaml"
if (-not (Test-Path -LiteralPath $composePath -PathType Leaf)) {
  throw "compose.yaml is missing from the v0.4 source root"
}
if ([string]::IsNullOrWhiteSpace($DockerExecutable)) {
  $dockerCommand = Get-Command docker -CommandType Application -ErrorAction Stop
  $DockerExecutable = $dockerCommand.Source
}
$dockerFull = [IO.Path]::GetFullPath($DockerExecutable)
if (-not (Test-Path -LiteralPath $dockerFull -PathType Leaf)) {
  throw "the Docker executable is unavailable"
}

$runId = [guid]::NewGuid().ToString("N")
$project = "spell-v04-iso-$($runId.Substring(0, 20))"
$resourceLabelName = "spell.v04.isolation.run"
$resourceLabel = "$resourceLabelName=$runId"
$staticContainer = "spell-v04-iso-static-$($runId.Substring(0, 20))"
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "spell-v04-iso-$runId"
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$temporaryFull = [IO.Path]::GetFullPath($temporaryRoot)
if (-not $temporaryFull.StartsWith(
    "$temporaryBase$([IO.Path]::DirectorySeparatorChar)spell-v04-iso-",
    [StringComparison]::OrdinalIgnoreCase
  )) {
  throw "refusing an unsafe isolation collector temporary path"
}
$overridePath = Join-Path $temporaryFull "compose.isolation.override.yaml"

$nativeProcesses = [Collections.Generic.List[object]]::new()
$cleanupFailures = [Collections.Generic.List[string]]::new()
$assertions = [Collections.Generic.List[object]]::new()
$metrics = [ordered]@{}
$failure = $null
$cleanupComplete = $false

function ConvertTo-NativeArgument {
  param([AllowEmptyString()][Parameter(Mandatory = $true)][string]$Value)

  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') {
      $slashes += 1
      continue
    }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) {
      [void]$builder.Append(('\' * $slashes))
      $slashes = 0
    }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) {
    [void]$builder.Append(('\' * ($slashes * 2)))
  }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Stop-ExactProcessTree {
  param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

  if ($Process.HasExited) { return }
  $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
  $children = @{}
  $cimByProcessId = @{}
  foreach ($entry in $all) {
    $cimByProcessId[[int]$entry.ProcessId] = $entry
    $parent = [int]$entry.ParentProcessId
    if (-not $children.ContainsKey($parent)) {
      $children[$parent] = [Collections.Generic.List[int]]::new()
    }
    $children[$parent].Add([int]$entry.ProcessId)
  }
  $ordered = [Collections.Generic.List[object]]::new()
  function Add-Descendants([int]$ParentId) {
    if (-not $children.ContainsKey($ParentId)) { return }
    foreach ($childId in $children[$ParentId]) {
      Add-Descendants $childId
      $candidate = Get-Process -Id $childId -ErrorAction SilentlyContinue
      if ($null -eq $candidate -or -not $cimByProcessId.ContainsKey($childId)) {
        continue
      }
      $startedTicks = [int64]$candidate.StartTime.ToUniversalTime().Ticks
      $cimTicks = [int64]$cimByProcessId[$childId].CreationDate.ToUniversalTime().Ticks
      if ([Math]::Abs($startedTicks - $cimTicks) -gt 10000) { continue }
      $ordered.Add([pscustomobject]@{
          ProcessId = $childId
          StartedUtcTicks = $startedTicks
        })
    }
  }
  Add-Descendants $Process.Id
  $ordered.Add([pscustomobject]@{
      ProcessId = [int]$Process.Id
      StartedUtcTicks = [int64]$Process.StartTime.ToUniversalTime().Ticks
    })
  foreach ($identity in $ordered) {
    $candidate = Get-Process -Id $identity.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { continue }
    try { $startedTicks = [int64]$candidate.StartTime.ToUniversalTime().Ticks }
    catch { continue }
    if ($startedTicks -ne $identity.StartedUtcTicks) { continue }
    Stop-Process -Id $identity.ProcessId -Force -ErrorAction SilentlyContinue
  }
  [void]$Process.WaitForExit(10000)
}

function Invoke-NativeProcess {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [int]$TimeoutSeconds = $script:CommandTimeoutSeconds,
    [switch]$AllowFailure
  )

  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Executable
  $startInfo.Arguments = (@($Arguments | ForEach-Object {
        ConvertTo-NativeArgument ([string]$_)
      }) -join ' ')
  $startInfo.WorkingDirectory = $script:rootFull
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true

  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $started = $false
  try {
    if (-not $process.Start()) {
      throw "cannot start native process: $Executable"
    }
    $started = $true
    $identity = [pscustomobject]@{
      ProcessId = [int]$process.Id
      StartedUtcTicks = [int64]$process.StartTime.ToUniversalTime().Ticks
    }
    $script:nativeProcesses.Add($identity)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      Stop-ExactProcessTree -Process $process
      throw "native process timed out after $TimeoutSeconds seconds: $Executable"
    }
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $result = [pscustomobject]@{
      ExitCode = [int]$process.ExitCode
      Stdout = [string]$stdout
      Stderr = [string]$stderr
    }
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
      $detail = $result.Stderr.Trim()
      if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $result.Stdout.Trim() }
      if ($detail.Length -gt 1000) { $detail = $detail.Substring(0, 1000) }
      throw "native process failed with exit $($result.ExitCode): $detail"
    }
    return $result
  }
  finally {
    if ($started -and -not $process.HasExited) {
      Stop-ExactProcessTree -Process $process
    }
    $process.Dispose()
  }
}

function Invoke-Docker {
  param(
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [int]$TimeoutSeconds = $script:CommandTimeoutSeconds,
    [switch]$AllowFailure
  )
  return Invoke-NativeProcess -Executable $script:dockerFull -Arguments $Arguments `
    -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Assert-Condition {
  param(
    [Parameter(Mandatory = $true)][bool]$Condition,
    [Parameter(Mandatory = $true)][string]$Message
  )
  if (-not $Condition) { throw $Message }
}

function Assert-ExactStrings {
  param(
    [AllowNull()][AllowEmptyCollection()][Parameter(Mandatory = $true)]
    [object[]]$Observed,
    [AllowNull()][AllowEmptyCollection()][Parameter(Mandatory = $true)]
    [string[]]$Expected,
    [Parameter(Mandatory = $true)][string]$Message
  )
  $left = @($Observed | ForEach-Object { [string]$_ } | Sort-Object) -join "`0"
  $right = @($Expected | Sort-Object) -join "`0"
  Assert-Condition ($left -ceq $right) $Message
}

function Add-PassedAssertion {
  param([Parameter(Mandatory = $true)][string]$Id)
  $script:assertions.Add([ordered]@{ id = $Id; passed = $true })
}

function Get-JsonObject {
  param(
    [Parameter(Mandatory = $true)][string]$Json,
    [Parameter(Mandatory = $true)][string]$Label
  )
  try { $value = $Json | ConvertFrom-Json }
  catch { throw "$Label is not valid JSON: $($_.Exception.Message)" }
  if ($null -eq $value) { throw "$Label is empty" }
  return $value
}

function Get-OptionalProperty {
  param(
    [Parameter(Mandatory = $true)][object]$Object,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) { return $null }
  return $property.Value
}

function Test-NullOrEmptyJsonObject {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return $true }
  return @($Value.PSObject.Properties).Count -eq 0
}

function Get-ImageIdentity {
  param([Parameter(Mandatory = $true)][string]$ImageId)
  $result = Invoke-Docker @("image", "inspect", $ImageId, "--format", "{{.Id}}") 60
  $observed = $result.Stdout.Trim().ToLowerInvariant()
  Assert-Condition ($observed -ceq $ImageId) "Docker image identity differs: $ImageId"
  return $observed
}

function Get-MatchingIds {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("container", "network", "volume")]
    [string]$Resource,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $arguments = @($Resource, "ls")
  if ($Resource -ceq "container") { $arguments += "--all" }
  $arguments += @("--quiet", "--filter", "label=$Label")
  $result = Invoke-Docker $arguments 60
  return [string[]]@(
    $result.Stdout -split "`r?`n" |
      ForEach-Object { $_.Trim() } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  )
}

function Invoke-ExactCleanup {
  $composePrefix = @(
    "compose", "--project-directory", $script:rootFull,
    "--file", $script:composePath, "--file", $script:overridePath,
    "--project-name", $script:project, "--profile", "driver"
  )
  if (Test-Path -LiteralPath $script:overridePath -PathType Leaf) {
    $down = Invoke-Docker ($composePrefix + @(
        "down", "--volumes", "--remove-orphans", "--timeout", "10"
      )) 120 -AllowFailure
    if ($down.ExitCode -ne 0) {
      $script:cleanupFailures.Add("Compose down failed for exact project $($script:project)")
    }
  }

  foreach ($resource in @("container", "network", "volume")) {
    try {
      $ids = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
      )
      foreach ($label in @(
          $script:resourceLabel,
          "com.docker.compose.project=$($script:project)"
        )) {
        foreach ($id in @(Get-MatchingIds $resource $label)) { [void]$ids.Add($id) }
      }
      if ($ids.Count -gt 0) {
        $verb = if ($resource -ceq "container") { "rm" } else { "rm" }
        $removeArguments = @($resource, $verb)
        if ($resource -in @("container", "volume")) { $removeArguments += "--force" }
        $removeArguments += [string[]]@($ids)
        $removed = Invoke-Docker $removeArguments 120 -AllowFailure
        if ($removed.ExitCode -ne 0) {
          $script:cleanupFailures.Add("exact $resource cleanup failed")
        }
      }
    }
    catch { $script:cleanupFailures.Add("exact $resource cleanup failed: $($_.Exception.Message)") }
  }

  foreach ($resource in @("container", "network", "volume")) {
    try {
      foreach ($label in @(
          $script:resourceLabel,
          "com.docker.compose.project=$($script:project)"
        )) {
        if (@(Get-MatchingIds $resource $label).Count -ne 0) {
          $script:cleanupFailures.Add("labelled $resource resources remain: $label")
        }
      }
    }
    catch { $script:cleanupFailures.Add("cannot verify $resource cleanup: $($_.Exception.Message)") }
  }
}

function Assert-NativeProcessesExited {
  foreach ($identity in $script:nativeProcesses) {
    $candidate = Get-Process -Id $identity.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { continue }
    try { $ticks = [int64]$candidate.StartTime.ToUniversalTime().Ticks }
    catch { continue }
    if ($ticks -eq $identity.StartedUtcTicks) {
      $script:cleanupFailures.Add(
        "collector-started process remains: PID $($identity.ProcessId)"
      )
    }
  }
}

$environmentNames = @(
  "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_DB_PASSWORD", "SPELL_DRIVER_ENABLED",
  "SPELL_JWT_HS256_SECRET"
)
$priorEnvironment = @{}
foreach ($name in $environmentNames) {
  $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
  New-Item -ItemType Directory -Path $temporaryFull | Out-Null
  $override = @"
services:
  pki-init:
    build: null
    image: "$PkiImageId"
    labels:
      ${resourceLabelName}: "$runId"
  spell-driver:
    build: null
    image: "$DriverImageId"
    labels:
      ${resourceLabelName}: "$runId"
volumes:
  spell-driver-client-credentials:
    labels:
      ${resourceLabelName}: "$runId"
  spell-driver-server-credentials:
    labels:
      ${resourceLabelName}: "$runId"
  spell-driver-journal:
    labels:
      ${resourceLabelName}: "$runId"
networks:
  spell-driver-internal:
    internal: true
    labels:
      ${resourceLabelName}: "$runId"
"@
  [IO.File]::WriteAllText(
    $overridePath, $override, [Text.UTF8Encoding]::new($false)
  )

  [Environment]::SetEnvironmentVariable(
    "SPELL_ALLOW_LOCAL_DEV_TOKEN", "true", "Process"
  )
  [Environment]::SetEnvironmentVariable(
    "SPELL_DB_PASSWORD", "v04-isolation-local-synthetic", "Process"
  )
  [Environment]::SetEnvironmentVariable("SPELL_DRIVER_ENABLED", "true", "Process")
  [Environment]::SetEnvironmentVariable(
    "SPELL_JWT_HS256_SECRET",
    "v04-isolation-local-synthetic-secret-32-bytes",
    "Process"
  )

  $qualificationIdentity = Get-ImageIdentity $QualificationImageId
  $driverIdentity = Get-ImageIdentity $DriverImageId
  $pkiIdentity = Get-ImageIdentity $PkiImageId
  Assert-Condition (
    @($qualificationIdentity, $driverIdentity, $pkiIdentity | Sort-Object -Unique).Count -eq 3
  ) "isolation collector images must have distinct exact identities"

  $staticRunPrefix = @(
    "run", "--rm", "--pull", "never", "--name", $staticContainer,
    "--label", $resourceLabel, "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
    "--mount", "type=bind,source=$rootFull,target=/qualification-source,readonly",
    "--workdir", "/qualification-source", "--env", "PYTHONDONTWRITEBYTECODE=1",
    $QualificationImageId
  )
  $fingerprintBefore = Invoke-Docker ($staticRunPrefix + @(
      "python", "-I", "scripts/source_fingerprint_v04.py", "--root",
      "/qualification-source"
    )) 180
  $containerSourceBefore = $fingerprintBefore.Stdout.Trim().ToLowerInvariant()
  Assert-Condition (
    $containerSourceBefore -ceq $ExpectedSourceFingerprint
  ) "qualification-image source mount fingerprint differs before isolation checks"

  $staticTest = Invoke-Docker ($staticRunPrefix + @(
      "python", "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider",
      "backend/tests/test_driver_isolation.py::test_compose_statically_isolates_and_hardens_the_driver"
    )) 600
  Assert-Condition (
    $staticTest.Stdout -cmatch '(?m)^1 passed(?: in [0-9.]+s)?\s*$'
  ) "static isolation pytest accounting differs"
  Assert-Condition (
    $staticTest.Stdout -cnotmatch '(?i)skipped|failed|error'
  ) "static isolation pytest did not pass without skips"
  Add-PassedAssertion "source-bound-static-runner"
  Add-PassedAssertion "static-compose-isolation-contract-passed"

  $composePrefix = @(
    "compose", "--project-directory", $rootFull,
    "--file", $composePath, "--file", $overridePath,
    "--project-name", $project, "--profile", "driver"
  )
  $effectiveConfig = Invoke-Docker ($composePrefix + @("config", "--quiet")) 120
  Assert-Condition ($effectiveConfig.ExitCode -eq 0) "effective Compose model is invalid"
  [void](Invoke-Docker ($composePrefix + @(
        "create", "--no-build", "--pull", "never", "pki-init", "spell-driver"
      )) 600)
  [void](Invoke-Docker ($composePrefix + @(
        "up", "--detach", "--no-build", "--pull", "never", "--wait",
        "--wait-timeout", "60", "pki-init", "spell-driver"
      )) 180)

  $driverPs = Invoke-Docker ($composePrefix + @(
      "ps", "--all", "--quiet", "spell-driver"
    )) 60
  $driverContainers = @(
    $driverPs.Stdout -split "`r?`n" | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' }
  )
  Assert-Condition ($driverContainers.Count -eq 1) "Compose created driver identity differs"
  $driverContainerId = [string]$driverContainers[0]
  $driverInspectResult = Invoke-Docker @("container", "inspect", $driverContainerId) 60
  $driverInspectArray = @(Get-JsonObject $driverInspectResult.Stdout "driver inspect")
  Assert-Condition ($driverInspectArray.Count -eq 1) "driver inspect count differs"
  $driver = $driverInspectArray[0]
  $hostConfig = $driver.HostConfig

  $pkiPs = Invoke-Docker ($composePrefix + @("ps", "--all", "--quiet", "pki-init")) 60
  $pkiContainers = @(
    $pkiPs.Stdout -split "`r?`n" | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' }
  )
  Assert-Condition ($pkiContainers.Count -eq 1) "Compose created PKI identity differs"
  $pkiInspectResult = Invoke-Docker @("container", "inspect", $pkiContainers[0]) 60
  $pkiInspectArray = @(Get-JsonObject $pkiInspectResult.Stdout "PKI inspect")
  Assert-Condition ($pkiInspectArray.Count -eq 1) "PKI inspect count differs"
  $pki = $pkiInspectArray[0]

  Assert-Condition ([string]$driver.Image -ceq $DriverImageId) "runtime driver image differs"
  Assert-Condition ([string]$pki.Image -ceq $PkiImageId) "runtime PKI image differs"
  Assert-Condition (
    [string]$driver.Config.Labels.'com.docker.compose.project' -ceq $project
  ) "driver Compose project label differs"
  Assert-Condition (
    [string]$driver.Config.Labels.$resourceLabelName -ceq $runId
  ) "driver isolation-run label differs"
  Assert-Condition (
    [string]$driver.Config.Labels.'com.docker.compose.service' -ceq "spell-driver"
  ) "driver Compose service label differs"
  Assert-Condition ([bool]$driver.State.Running) "created driver is not running"
  Assert-Condition (
    [string]$driver.State.Health.Status -ceq "healthy"
  ) "created driver is not healthy"
  Assert-Condition ([string]$pki.State.Status -ceq "exited") "PKI initializer did not exit"
  Assert-Condition ([int]$pki.State.ExitCode -eq 0) "PKI initializer failed"
  Add-PassedAssertion "runtime-created-from-exact-prebuilt-images"

  Assert-Condition ([string]$driver.Config.User -ceq "10002:10002") "driver user differs"
  Assert-Condition ([string]$driver.Config.StopSignal -ceq "SIGINT") "stop signal differs"
  Assert-Condition (Test-NullOrEmptyJsonObject (
      Get-OptionalProperty $driver.Config "ExposedPorts"
    )) "driver exposes a port"
  Assert-Condition (Test-NullOrEmptyJsonObject (
      Get-OptionalProperty $hostConfig "PortBindings"
    )) "driver publishes a port"
  Assert-Condition (-not [bool]$hostConfig.PublishAllPorts) "driver publishes all ports"
  Add-PassedAssertion "runtime-healthy-unprivileged-without-ports"

  Assert-Condition ([bool]$hostConfig.ReadonlyRootfs) "driver root filesystem is writable"
  Assert-ExactStrings @($hostConfig.CapDrop) @("ALL") "driver dropped capabilities differ"
  Assert-ExactStrings @(
    Get-OptionalProperty $hostConfig "CapAdd"
  ) @() "driver added a capability"
  Assert-ExactStrings @($hostConfig.SecurityOpt) @(
    "no-new-privileges:true"
  ) "driver security options differ"
  Assert-Condition (
    [string](Get-OptionalProperty $hostConfig "PidMode") -ceq ""
  ) "driver shares a PID namespace"
  Add-PassedAssertion "runtime-rootfs-capability-and-privilege-controls"

  Assert-Condition ([int64]$hostConfig.PidsLimit -eq 64) "driver PID limit differs"
  Assert-Condition (
    [int64]$hostConfig.Memory -eq (256 * 1024 * 1024)
  ) "driver memory limit differs"
  Assert-Condition (
    [int64]$hostConfig.NanoCpus -eq 1000000000
  ) "driver CPU limit differs"
  Assert-Condition ([int]$driver.Config.StopTimeout -eq 2) "driver stop timeout differs"
  $tmpfsProperty = $hostConfig.Tmpfs.PSObject.Properties['/tmp']
  Assert-Condition ($null -ne $tmpfsProperty) "driver /tmp tmpfs is absent"
  $tmpfsOptions = [string]$tmpfsProperty.Value
  Assert-Condition ($tmpfsOptions -cmatch '(^|,)noexec(,|$)') "driver tmpfs permits exec"
  Assert-Condition ($tmpfsOptions -cmatch '(^|,)nosuid(,|$)') "driver tmpfs permits suid"
  Assert-Condition (
    $tmpfsOptions -cmatch '(^|,)size=(33554432|32m)(,|$)'
  ) "driver tmpfs size differs"
  Add-PassedAssertion "runtime-resource-stop-and-tmpfs-controls"

  $volumeMounts = @($driver.Mounts | Where-Object { $_.Type -ceq "volume" })
  Assert-Condition ($volumeMounts.Count -eq 2) "driver named-volume count differs"
  $mountByDestination = @{}
  foreach ($mount in $volumeMounts) {
    $mountByDestination[[string]$mount.Destination] = $mount
  }
  Assert-ExactStrings @($mountByDestination.Keys) @(
    "/run/spell-driver-server", "/var/lib/spell-driver"
  ) "driver named-volume destinations differ"
  Assert-Condition (
    -not [bool]$mountByDestination['/run/spell-driver-server'].RW
  ) "server credential mount is writable"
  Assert-Condition (
    [bool]$mountByDestination['/var/lib/spell-driver'].RW
  ) "driver journal mount is read-only"
  foreach ($mount in $volumeMounts) {
    Assert-Condition (
      [string]$mount.Name -clike "$project`_*"
    ) "driver volume is not owned by the exact Compose project"
    $volumeInspectResult = Invoke-Docker @("volume", "inspect", [string]$mount.Name) 60
    $volumeInspect = @(Get-JsonObject $volumeInspectResult.Stdout "volume inspect")[0]
    Assert-Condition (
      [string]$volumeInspect.Labels.'com.docker.compose.project' -ceq $project
    ) "driver volume project label differs"
    Assert-Condition (
      [string]$volumeInspect.Labels.$resourceLabelName -ceq $runId
    ) "driver volume isolation-run label differs"
  }
  Assert-Condition (
    @($driver.Config.Env | Where-Object { $_ -cmatch '^DATABASE_URL=' }).Count -eq 0
  ) "driver received a product database URL"
  Add-PassedAssertion "runtime-filesystem-and-database-boundaries"

  $networkNames = @($driver.NetworkSettings.Networks.PSObject.Properties.Name)
  Assert-Condition ($networkNames.Count -eq 1) "driver network attachment count differs"
  Assert-Condition (
    [string]$hostConfig.NetworkMode -ceq [string]$networkNames[0]
  ) "driver network mode differs from its only attachment"
  $networkInspectResult = Invoke-Docker @("network", "inspect", $networkNames[0]) 60
  $networkInspect = @(Get-JsonObject $networkInspectResult.Stdout "network inspect")[0]
  Assert-Condition ([bool]$networkInspect.Internal) "driver network is not internal"
  Assert-Condition (
    [string]$networkInspect.Labels.'com.docker.compose.project' -ceq $project
  ) "driver network project label differs"
  Assert-Condition (
    [string]$networkInspect.Labels.$resourceLabelName -ceq $runId
  ) "driver network isolation-run label differs"
  Assert-Condition (
    @($networkInspect.Containers.PSObject.Properties.Name).Count -eq 1
  ) "driver internal network contains an unexpected container"
  Add-PassedAssertion "runtime-single-internal-network-boundary"

  $fingerprintAfter = Invoke-Docker ($staticRunPrefix + @(
      "python", "-I", "scripts/source_fingerprint_v04.py", "--root",
      "/qualification-source"
    )) 180
  $containerSourceAfter = $fingerprintAfter.Stdout.Trim().ToLowerInvariant()
  Assert-Condition (
    $containerSourceAfter -ceq $ExpectedSourceFingerprint
  ) "qualification-image source mount fingerprint differs after isolation checks"
  Add-PassedAssertion "source-fingerprint-stable-through-runtime-inspection"

  $metrics = [ordered]@{
    qualification_image_id = $qualificationIdentity
    driver_image_id = $driverIdentity
    pki_image_id = $pkiIdentity
    exact_image_count = 3
    static_pytest_passed = 1
    runtime_driver_running = $true
    runtime_driver_healthy = $true
    runtime_user = [string]$driver.Config.User
    runtime_read_only_rootfs = [bool]$hostConfig.ReadonlyRootfs
    runtime_pids_limit = [int64]$hostConfig.PidsLimit
    runtime_memory_bytes = [int64]$hostConfig.Memory
    runtime_nano_cpus = [int64]$hostConfig.NanoCpus
    runtime_stop_timeout_seconds = [int]$driver.Config.StopTimeout
    runtime_named_volume_count = $volumeMounts.Count
    runtime_network_count = $networkNames.Count
    runtime_network_internal = [bool]$networkInspect.Internal
  }
}
catch { $failure = $_ }
finally {
  try { Invoke-ExactCleanup }
  catch { $cleanupFailures.Add("exact Docker cleanup failed: $($_.Exception.Message)") }
  foreach ($name in $environmentNames) {
    if ($null -eq $priorEnvironment[$name]) {
      [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    else {
      [Environment]::SetEnvironmentVariable(
        $name, [string]$priorEnvironment[$name], "Process"
      )
    }
  }
  if (Test-Path -LiteralPath $temporaryFull) {
    try { Remove-Item -LiteralPath $temporaryFull -Recurse -Force }
    catch { $cleanupFailures.Add("temporary directory cleanup failed") }
  }
  Assert-NativeProcessesExited
  $cleanupComplete = ($cleanupFailures.Count -eq 0)
}

if ($null -ne $failure) {
  if (-not $cleanupComplete) {
    throw "V04-ISO-001 failed and cleanup also failed: $($failure.Exception.Message); $($cleanupFailures -join '; ')"
  }
  throw $failure
}
if (-not $cleanupComplete) {
  throw "V04-ISO-001 cleanup verification failed: $($cleanupFailures -join '; ')"
}

Add-PassedAssertion "exact-labelled-resource-and-process-cleanup-verified"
$result = [ordered]@{
  test_id = $TestId
  source_fingerprint_sha256 = $ExpectedSourceFingerprint
  assertions = @($assertions)
  metrics = $metrics
}
$result | ConvertTo-Json -Compress -Depth 12
