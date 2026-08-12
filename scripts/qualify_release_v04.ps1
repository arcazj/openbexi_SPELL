[CmdletBinding()]
param(
  [ValidateSet("Preliminary", "Final")]
  [string]$Mode = "Preliminary",

  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$Confirm = "LOCAL_SYNTHETIC_NON_CUI_ONLY",

  [ValidateRange(60, 86400)]
  [int]$CollectorTimeoutSeconds = 14400,

  [switch]$PlanOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not ("SpellV04QualificationJobNative" -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SpellV04QualificationJobNative {
  public const UInt32 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
  public const Int32 JobObjectBasicAccountingInformation = 1;
  public const Int32 JobObjectExtendedLimitInformation = 9;

  [StructLayout(LayoutKind.Sequential)]
  public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    public Int64 PerProcessUserTimeLimit;
    public Int64 PerJobUserTimeLimit;
    public UInt32 LimitFlags;
    public UIntPtr MinimumWorkingSetSize;
    public UIntPtr MaximumWorkingSetSize;
    public UInt32 ActiveProcessLimit;
    public UIntPtr Affinity;
    public UInt32 PriorityClass;
    public UInt32 SchedulingClass;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct IO_COUNTERS {
    public UInt64 ReadOperationCount;
    public UInt64 WriteOperationCount;
    public UInt64 OtherOperationCount;
    public UInt64 ReadTransferCount;
    public UInt64 WriteTransferCount;
    public UInt64 OtherTransferCount;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit;
    public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed;
    public UIntPtr PeakJobMemoryUsed;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    public Int64 TotalUserTime;
    public Int64 TotalKernelTime;
    public Int64 ThisPeriodTotalUserTime;
    public Int64 ThisPeriodTotalKernelTime;
    public UInt32 TotalPageFaultCount;
    public UInt32 TotalProcesses;
    public UInt32 ActiveProcesses;
    public UInt32 TotalTerminatedProcesses;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool SetInformationJobObject(
    IntPtr job,
    Int32 informationClass,
    ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
    UInt32 informationLength
  );

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool QueryInformationJobObject(
    IntPtr job,
    Int32 informationClass,
    out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
    UInt32 informationLength,
    IntPtr returnLength
  );
}
'@
}

function New-QualificationProcessJob {
  $handle = [SpellV04QualificationJobNative]::CreateJobObject([IntPtr]::Zero, $null)
  if ($handle -eq [IntPtr]::Zero) {
    throw "cannot create the v0.4 qualification process Job Object: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  $limits = New-Object SpellV04QualificationJobNative+JOBOBJECT_EXTENDED_LIMIT_INFORMATION
  $limits.BasicLimitInformation.LimitFlags = [SpellV04QualificationJobNative]::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
  $limitSize = [Runtime.InteropServices.Marshal]::SizeOf($limits)
  if (-not [SpellV04QualificationJobNative]::SetInformationJobObject(
      $handle,
      [SpellV04QualificationJobNative]::JobObjectExtendedLimitInformation,
      [ref]$limits,
      [uint32]$limitSize
    )) {
    throw "cannot configure the v0.4 qualification process Job Object: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
  if (-not [SpellV04QualificationJobNative]::AssignProcessToJobObject(
      $handle, $currentProcess.Handle
    )) {
    throw "cannot contain the v0.4 qualification runner process: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  return $handle
}

function Get-QualificationJobActiveProcessCount {
  $accounting = New-Object SpellV04QualificationJobNative+JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
  $accountingSize = [Runtime.InteropServices.Marshal]::SizeOf($accounting)
  if (-not [SpellV04QualificationJobNative]::QueryInformationJobObject(
      $script:qualificationProcessJob,
      [SpellV04QualificationJobNative]::JobObjectBasicAccountingInformation,
      [ref]$accounting,
      [uint32]$accountingSize,
      [IntPtr]::Zero
    )) {
    throw "cannot inspect the v0.4 qualification process Job Object: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  return [int]$accounting.ActiveProcesses
}

$qualificationProcessJob = New-QualificationProcessJob

$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$runId = [guid]::NewGuid().ToString("N")
$runLabel = "spell.v04.qualification.run=$runId"
$qualificationTag = "openbexi-spell-v04-qualification:$runId"
$runTags = [Collections.Generic.List[string]]::new()
$runContainers = [Collections.Generic.List[string]]::new()
$runNetworks = [Collections.Generic.List[string]]::new()
$runVolumes = [Collections.Generic.List[string]]::new()
$cleanupFailures = [Collections.Generic.List[string]]::new()
$failure = $null
$summary = $null
$published = $false
$packagePublished = $false
$source = $null
$qualificationImage = $null
$plannedBuiltinCount = 0
$plannedCollectorCount = 0
$actualBuiltinCount = 0
$actualCollectorCount = 0
$builtinCollectorOverrides = [string[]]@()
$runNativeProcesses = [Collections.Generic.List[object]]::new()
$PowerShellExe = [IO.Path]::GetFullPath((Get-Process -Id $PID).Path)
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "spell-v04-release-$runId"
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$temporaryFull = [IO.Path]::GetFullPath($temporaryRoot)
if (-not $temporaryFull.StartsWith(
    "$temporaryBase$([IO.Path]::DirectorySeparatorChar)spell-v04-release-",
    [StringComparison]::OrdinalIgnoreCase
  )) { throw "refusing an unsafe v0.4 release temporary path" }

$releaseEnvironmentNames = @(
  "SPELL_RELEASE_DOCKER_EXE", "SPELL_RELEASE_BUILDX_EXE",
  "SPELL_RELEASE_COMPOSE_EXE", "SPELL_RELEASE_SBOM_EXE",
  "SPELL_RELEASE_SCOUT_EXE", "SPELL_RELEASE_PYTHON_EXE",
  "SPELL_V04_QUALIFICATION_RUN_ID"
)
$priorEnvironment = @{}
foreach ($name in $releaseEnvironmentNames) {
  $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$env:SPELL_V04_QUALIFICATION_RUN_ID = $runId

function ConvertTo-NativeArgument {
  param([AllowEmptyString()][Parameter(Mandatory = $true)][string]$Value)
  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') { $slashes += 1; continue }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Stop-ExactNativeProcessTree {
  param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)
  if ($Process.HasExited) { return }
  $processStartedTicks = [int64]$Process.StartTime.ToUniversalTime().Ticks
  $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
  $children = @{}
  $cimByProcessId = @{}
  foreach ($entry in $all) {
    $cimByProcessId[[int]$entry.ProcessId] = $entry
    $parent = [int]$entry.ParentProcessId
    if (-not $children.ContainsKey($parent)) {
      $children[$parent] = [Collections.Generic.List[object]]::new()
    }
    $children[$parent].Add($entry)
  }
  $ordered = [Collections.Generic.List[object]]::new()
  $visited = [Collections.Generic.HashSet[int]]::new()
  function Add-ExactDescendants([int]$ParentId, [int64]$ParentStartedUtcTicks) {
    if (-not $children.ContainsKey($ParentId)) { return }
    foreach ($child in $children[$ParentId]) {
      $childId = [int]$child.ProcessId
      if (-not $visited.Add($childId)) { continue }
      try { $cimTicks = [int64]$child.CreationDate.ToUniversalTime().Ticks }
      catch { continue }
      if ($cimTicks -lt ($ParentStartedUtcTicks - 10000)) { continue }
      $candidate = Get-Process -Id $childId -ErrorAction SilentlyContinue
      if ($null -eq $candidate) { continue }
      try { $startedTicks = [int64]$candidate.StartTime.ToUniversalTime().Ticks }
      catch { continue }
      if ([Math]::Abs($startedTicks - $cimTicks) -gt 10000) { continue }
      Add-ExactDescendants $childId $startedTicks
      $ordered.Add([pscustomobject]@{
          ProcessId = $childId
          StartedUtcTicks = $startedTicks
      })
    }
  }
  $rootSnapshotMatches = $false
  if ($cimByProcessId.ContainsKey([int]$Process.Id)) {
    try {
      $rootCimTicks = [int64]$cimByProcessId[[int]$Process.Id].CreationDate.ToUniversalTime().Ticks
      $rootSnapshotMatches = (
        [Math]::Abs($rootCimTicks - $processStartedTicks) -le 10000
      )
    }
    catch { $rootSnapshotMatches = $false }
  }
  if ($rootSnapshotMatches) {
    Add-ExactDescendants $Process.Id $processStartedTicks
  }
  $ordered.Add([pscustomobject]@{
      ProcessId = [int]$Process.Id
      StartedUtcTicks = $processStartedTicks
    })
  foreach ($identity in $ordered) {
    $candidate = Get-Process -Id $identity.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { continue }
    try { $startedTicks = [int64]$candidate.StartTime.ToUniversalTime().Ticks }
    catch { continue }
    if ($startedTicks -ne $identity.StartedUtcTicks) { continue }
    Stop-Process -Id $identity.ProcessId -Force -ErrorAction SilentlyContinue
  }
  try { [void]$Process.WaitForExit(10000) }
  catch { }
}

function Invoke-NativeProcess {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = $script:CollectorTimeoutSeconds,
    [switch]$AllowFailure
  )
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Executable
  $startInfo.Arguments = (@($Arguments | ForEach-Object {
        ConvertTo-NativeArgument ([string]$_)
      }) -join ' ')
  $startInfo.WorkingDirectory = $script:root
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $started = $false
  try {
    if (-not $process.Start()) { throw "cannot start native process: $Executable" }
    $started = $true
    $script:runNativeProcesses.Add([pscustomobject]@{
        ProcessId = [int]$process.Id
        StartedUtcTicks = [int64]$process.StartTime.ToUniversalTime().Ticks
      })
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      Stop-ExactNativeProcessTree -Process $process
      throw "native process timed out after $TimeoutSeconds seconds: $Executable"
    }
    $process.WaitForExit()
    $result = [pscustomobject]@{
      ExitCode = [int]$process.ExitCode
      Stdout = [string]$stdoutTask.GetAwaiter().GetResult()
      Stderr = [string]$stderrTask.GetAwaiter().GetResult()
    }
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
      throw "native process failed with exit $($result.ExitCode): $Executable"
    }
    return $result
  }
  finally {
    if ($started -and -not $process.HasExited) {
      Stop-ExactNativeProcessTree -Process $process
    }
    $process.Dispose()
  }
}

function Write-NativeText {
  param([AllowEmptyString()][string]$Value)
  if (-not [string]::IsNullOrEmpty($Value)) {
    Write-Host $Value.TrimEnd([char[]]"`r`n")
  }
}

function Invoke-NativeChecked {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$FailureMessage,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = $script:CollectorTimeoutSeconds,
    [switch]$Capture
  )
  $result = Invoke-NativeProcess -Executable $Executable -Arguments $Arguments `
    -TimeoutSeconds $TimeoutSeconds -AllowFailure
  Write-NativeText $result.Stderr
  if ($result.ExitCode -ne 0) { throw "$FailureMessage (exit $($result.ExitCode))" }
  if ($Capture) {
    return [string[]]@(
      $result.Stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrEmpty($_) }
    )
  }
  Write-NativeText $result.Stdout
}

function Invoke-CleanupDocker {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  try {
    $result = Invoke-NativeProcess -Executable $script:DockerExe -Arguments $Arguments `
      -TimeoutSeconds 120 -AllowFailure
    return [pscustomobject]@{
      ExitCode = [int]$result.ExitCode
      Lines = [string[]]@(
        $result.Stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrEmpty($_) }
      )
      Stderr = [string]$result.Stderr
      InvocationFailed = $false
    }
  }
  catch {
    return [pscustomobject]@{
      ExitCode = $null
      Lines = [string[]]@()
      Stderr = [string]$_.Exception.Message
      InvocationFailed = $true
    }
  }
}

function Get-CleanupDockerInspectionDisposition {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("container", "network", "volume", "image")]
    [string]$Kind,
    [Parameter(Mandatory = $true)][string]$Reference,
    [Parameter(Mandatory = $true)]$Inspection
  )
  if ($Inspection.InvocationFailed -or $null -eq $Inspection.ExitCode) {
    return "unverified"
  }
  if ([int]$Inspection.ExitCode -eq 0) { return "present" }
  if ([int]$Inspection.ExitCode -ne 1) { return "unverified" }

  $stdout = (@($Inspection.Lines) -join "`n").Trim()
  $stderr = ([string]$Inspection.Stderr).Trim()
  $mentionsReference = (
    $stderr.IndexOf($Reference, [StringComparison]::OrdinalIgnoreCase) -ge 0
  )
  if (
    $stdout -ceq "[]" -and $mentionsReference -and
    $stderr -match '(?i)\b(?:no such|not found)\b'
  ) {
    return "absent"
  }
  return "unverified"
}

function Assert-CleanupDockerObjectAbsent {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("container", "network", "volume", "image")]
    [string]$Kind,
    [Parameter(Mandatory = $true)][string]$Reference,
    [Parameter(Mandatory = $true)]$Inspection
  )
  $disposition = Get-CleanupDockerInspectionDisposition `
    -Kind $Kind -Reference $Reference -Inspection $Inspection
  if ($disposition -ceq "present") {
    $script:cleanupFailures.Add("$Kind remains: $Reference")
  }
  elseif ($disposition -ceq "unverified") {
    $detail = ([string]$Inspection.Stderr).Trim()
    if ([string]::IsNullOrEmpty($detail)) { $detail = "no diagnostic detail" }
    $script:cleanupFailures.Add(
      "cannot verify $Kind cleanup: $Reference`: $detail"
    )
  }
}

function Assert-NativeProcessesExited {
  foreach ($identity in $script:runNativeProcesses) {
    $candidate = Get-Process -Id $identity.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $candidate) { continue }
    try { $ticks = [int64]$candidate.StartTime.ToUniversalTime().Ticks }
    catch { continue }
    if ($ticks -eq $identity.StartedUtcTicks) {
      $script:cleanupFailures.Add(
        "runner-started native process remains: PID $($identity.ProcessId)"
      )
    }
  }
}

function Get-LastJsonObject {
  param([Parameter(Mandatory = $true)][string[]]$Lines, [string]$Label = "command")
  $line = $Lines | Where-Object { $_ -cmatch '^\{.*\}$' } | Select-Object -Last 1
  if (-not $line) { throw "$Label emitted no compact JSON object" }
  try { return $line | ConvertFrom-Json }
  catch { throw "$Label emitted invalid JSON: $($_.Exception.Message)" }
}

function Invoke-DetachedContainerChecked {
  param(
    [Parameter(Mandatory = $true)][string]$ContainerName,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$FailureMessage,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = $script:CollectorTimeoutSeconds
  )
  $startResult = Invoke-NativeProcess -Executable $script:DockerExe -Arguments $Arguments `
    -TimeoutSeconds 120 -AllowFailure
  Write-NativeText $startResult.Stderr
  if ($startResult.ExitCode -ne 0) {
    throw "$FailureMessage could not start (exit $($startResult.ExitCode))"
  }
  $containerId = @(
    $startResult.Stdout -split "`r?`n" |
      Where-Object { $_ -cmatch '^[0-9a-f]{64}$' }
  ) | Select-Object -Last 1
  if (-not $containerId) {
    throw "$FailureMessage emitted no container identity"
  }
  Write-Host "started $ContainerName ($containerId)"

  $startedUtc = [DateTime]::UtcNow
  $deadlineUtc = $startedUtc.AddSeconds($TimeoutSeconds)
  $nextProgressUtc = $startedUtc.AddSeconds(30)
  while ([DateTime]::UtcNow -lt $deadlineUtc) {
    $stateResult = Invoke-NativeProcess -Executable $script:DockerExe -Arguments @(
      "container", "inspect", $ContainerName, "--format", "{{json .State}}"
    ) -TimeoutSeconds 30 -AllowFailure
    if ($stateResult.ExitCode -ne 0) {
      Write-NativeText $stateResult.Stderr
      throw "$FailureMessage container disappeared before reporting an exit status"
    }
    $stateLines = [string[]]@(
      $stateResult.Stdout -split "`r?`n" |
        Where-Object { -not [string]::IsNullOrEmpty($_) }
    )
    $state = Get-LastJsonObject $stateLines "$FailureMessage container state"
    if ($state.Running -ne $true) {
      $logsResult = Invoke-NativeProcess -Executable $script:DockerExe `
        -Arguments @("logs", $ContainerName) -TimeoutSeconds 120 -AllowFailure
      Write-NativeText $logsResult.Stderr
      Write-NativeText $logsResult.Stdout
      if ($logsResult.ExitCode -ne 0) {
        throw "$FailureMessage logs could not be read (exit $($logsResult.ExitCode))"
      }
      if ([int]$state.ExitCode -ne 0) {
        throw "$FailureMessage (exit $([int]$state.ExitCode))"
      }
      return
    }
    if ([DateTime]::UtcNow -ge $nextProgressUtc) {
      $elapsedSeconds = [int]([DateTime]::UtcNow - $startedUtc).TotalSeconds
      Write-Host "$ContainerName is still running ($elapsedSeconds seconds)"
      $nextProgressUtc = [DateTime]::UtcNow.AddSeconds(30)
    }
    Start-Sleep -Seconds 2
  }
  throw "$FailureMessage timed out after $TimeoutSeconds seconds"
}

function Get-PlanEntries {
  param([Parameter(Mandatory = $true)]$Plan)
  return @(
    foreach ($gate in $Plan.gates.PSObject.Properties) {
      foreach ($entry in @($gate.Value)) {
        [pscustomobject]@{ Gate = $gate.Name; TestId = [string]$entry.test_id; Mode = [string]$entry.mode; Entry = $entry }
      }
    }
  )
}

function Assert-ExactSet {
  param(
    [Parameter(Mandatory = $true)][string[]]$Expected,
    [Parameter(Mandatory = $true)][string[]]$Observed,
    [Parameter(Mandatory = $true)][string]$Label
  )
  if ((@($Expected | Sort-Object) -join "`0") -cne (@($Observed | Sort-Object) -join "`0")) {
    throw "$Label differs"
  }
}

function Get-ImageId {
  param(
    [Parameter(Mandatory = $true)][string]$Reference,
    [switch]$PullIfMissing
  )
  $inspectArguments = @("image", "inspect", $Reference, "--format", "{{.Id}}")
  $result = Invoke-NativeProcess -Executable $script:DockerExe `
    -Arguments $inspectArguments -TimeoutSeconds $script:CollectorTimeoutSeconds `
    -AllowFailure
  if ($result.ExitCode -ne 0 -and $PullIfMissing) {
    if ($Reference -cnotmatch '@sha256:[0-9a-f]{64}$') {
      throw "refusing to pull an unpinned image reference: $Reference"
    }
    Invoke-NativeChecked -Executable $script:DockerExe -Arguments @("pull", $Reference) `
      -FailureMessage "cannot pull pinned image $Reference"
    $result = Invoke-NativeProcess -Executable $script:DockerExe `
      -Arguments $inspectArguments -TimeoutSeconds $script:CollectorTimeoutSeconds `
      -AllowFailure
  }
  if ($result.ExitCode -ne 0) {
    Write-NativeText $result.Stderr
    throw "cannot inspect image $Reference (exit $($result.ExitCode))"
  }
  $lines = [string[]]@(
    $result.Stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrEmpty($_) }
  )
  $value = ([string]$lines[-1]).Trim().ToLowerInvariant()
  if ($value -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "image identity is invalid: $Reference"
  }
  return $value
}

function Build-RunImage {
  param(
    [Parameter(Mandatory = $true)][string]$Role,
    [Parameter(Mandatory = $true)][string]$Dockerfile
  )
  $tag = "openbexi-spell-v04-$Role`:$runId"
  $script:runTags.Add($tag)
  Invoke-NativeChecked -Executable $script:DockerExe -Arguments @(
    "build", "--pull=false", "--provenance=false", "--label", $script:runLabel,
    "-f", $Dockerfile, "-t", $tag, "."
  ) -FailureMessage "v0.4 $Role image build failed" | Out-Host
  return Get-ImageId $tag
}

function Invoke-QualifierCollect {
  param(
    [Parameter(Mandatory = $true)][string]$TestId,
    [Parameter(Mandatory = $true)][string]$CollectorExecutable,
    [Parameter(Mandatory = $true)][string[]]$CollectorArguments
  )
  $arguments = @(
    "-I", (Join-Path $script:root "scripts/qualify_v04.py"),
    "--root", $script:root, "collect", "--test-id", $TestId,
    "--timeout-seconds", [string]$script:CollectorTimeoutSeconds,
    "--replace", "--", $CollectorExecutable
  ) + $CollectorArguments
  Invoke-NativeChecked -Executable $script:PythonExe -Arguments $arguments `
    -FailureMessage "$TestId collector staging failed"
}

function Restore-ReleaseEnvironment {
  foreach ($name in $script:releaseEnvironmentNames) {
    if ($null -eq $script:priorEnvironment[$name]) {
      Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    else {
      [Environment]::SetEnvironmentVariable(
        $name, [string]$script:priorEnvironment[$name], "Process"
      )
    }
  }
}

New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
Push-Location $root
try {
  & (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
  $DockerExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
  $ComposeExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_COMPOSE_EXE)
  $PythonExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)

  $planLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
    "-I", (Join-Path $root "scripts/qualify_v04.py"), "--root", $root, "plan"
  ) -FailureMessage "cannot load the live v0.4 qualification plan" -Capture
  $plan = Get-LastJsonObject $planLines "v0.4 qualification plan"
  $entries = @(Get-PlanEntries $plan)
  $builtinIds = @($entries | Where-Object Mode -CEQ "builtin" | ForEach-Object TestId)
  $collectorIds = @($entries | Where-Object Mode -CEQ "collector" | ForEach-Object TestId)
  if (
    $plan.schema_version -cne "spell.v04.qualification-plan/1" -or
    [int]$plan.test_count -ne 74 -or [int]$plan.collector_required_count -ne 33 -or
    $entries.Count -ne 74 -or @($entries.TestId | Sort-Object -Unique).Count -ne 74 -or
    $builtinIds.Count -ne 41 -or $collectorIds.Count -ne 33
  ) { throw "live v0.4 qualification plan count or identity contract differs" }

  $planLock = Get-Content -LiteralPath (Join-Path $root "scripts/qualification-plan-v04.lock.json") -Raw |
    ConvertFrom-Json
  if (
    $planLock.schema_version -cne "spell.v04.qualification-plan-lock/1" -or
    $planLock.product_version -cne "0.4.0" -or
    $planLock.plan_schema_version -cne $plan.schema_version -or
    [string]$planLock.canonical_plan_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [int]$planLock.test_count -ne 74 -or
    [int]$planLock.planned_builtin_count -ne 41 -or
    [int]$planLock.planned_collector_count -ne 33 -or
    [int]$planLock.actual_builtin_count -ne 40 -or
    [int]$planLock.actual_collector_count -ne 34
  ) { throw "tracked v0.4 qualification plan lock differs" }

  $contractCode = @'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from scripts.qualify_v04 import _plan
from scripts.qualify_faults_v04 import ASSIGNED_IDS
from scripts.qualify_browser_v04 import TEST_IDS as BROWSER_IDS
from scripts.collect_performance_v04 import TEST_IDS as PERFORMANCE_IDS
plan = _plan()
canonical_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(json.dumps({"fault": sorted(ASSIGNED_IDS), "browser": sorted(BROWSER_IDS), "performance": sorted(PERFORMANCE_IDS), "canonical_plan_sha256": hashlib.sha256(canonical_plan).hexdigest()}, sort_keys=True, separators=(",", ":")))
'@
  $contractProbe = Join-Path $temporaryRoot "collector-contracts.py"
  [IO.File]::WriteAllText(
    $contractProbe, $contractCode, [Text.UTF8Encoding]::new($false)
  )
  $contractLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
    "-I", $contractProbe, $root
  ) -FailureMessage "cannot load v0.4 collector ownership contracts" -Capture
  $contracts = Get-LastJsonObject $contractLines "collector ownership contract"
  if ([string]$contracts.canonical_plan_sha256 -cne [string]$planLock.canonical_plan_sha256) {
    throw "live v0.4 qualification plan differs from the tracked lock"
  }
  $faultIds = [string[]]@($contracts.fault)
  $browserIds = [string[]]@($contracts.browser)
  $performanceIds = [string[]]@($contracts.performance)
  $supplyIds = [string[]]@(
    $entries | Where-Object { $_.Gate -ceq "V04-GATE-5" -and $_.Mode -ceq "collector" } |
      ForEach-Object TestId
  )
  $knownCollectorIds = @($faultIds + $browserIds + $performanceIds + $supplyIds)
  $regressionIds = [string[]]@($collectorIds | Where-Object { $_ -cnotin $knownCollectorIds })
  if (
    $faultIds.Count -ne 18 -or $browserIds.Count -ne 4 -or
    $performanceIds.Count -ne 4 -or $supplyIds.Count -ne 6 -or
    $regressionIds.Count -ne 1
  ) { throw "v0.4 collector ownership count differs" }
  Assert-ExactSet -Expected $collectorIds `
    -Observed @($knownCollectorIds + $regressionIds) `
    -Label "v0.4 collector ownership allocation"
  $plannedBuiltinCount = $builtinIds.Count
  $plannedCollectorCount = $collectorIds.Count
  $builtinCollectorOverrides = [string[]]@($planLock.builtin_collector_overrides)
  Assert-ExactSet -Expected @("V04-ISO-001") -Observed $builtinCollectorOverrides `
    -Label "v0.4 builtin collector override allocation"
  if ($builtinCollectorOverrides[0] -cnotin $builtinIds) {
    throw "v0.4 builtin collector override is not a planned builtin"
  }
  $actualBuiltinCount = $plannedBuiltinCount - $builtinCollectorOverrides.Count
  $actualCollectorCount = $plannedCollectorCount + $builtinCollectorOverrides.Count
  if (
    $actualBuiltinCount -ne [int]$planLock.actual_builtin_count -or
    $actualCollectorCount -ne [int]$planLock.actual_collector_count
  ) { throw "v0.4 actual execution allocation differs from the tracked lock" }

  if ($PlanOnly) {
    $summary = [ordered]@{
      schema_version = "spell.v04.qualification-orchestration/1"
      run_id = $runId
      mode = $Mode
      planned = $true
      planned_builtin_count = $plannedBuiltinCount
      planned_collector_count = $plannedCollectorCount
      actual_builtin_count = $actualBuiltinCount
      actual_collector_count = $actualCollectorCount
      builtin_collector_overrides = $builtinCollectorOverrides
      published = $false
      package_published = $false
    }
  }
  else {
    $runTags.Add($qualificationTag)
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "build", "--pull=false", "--provenance=false", "--label", $runLabel,
      "-f", "scripts/qualification.Dockerfile", "-t", $qualificationTag, "."
    ) -FailureMessage "run-scoped v0.4 qualification image build failed"
    $qualificationImage = Get-ImageId $qualificationTag

    $images = [ordered]@{
      backend = Build-RunImage "backend" "backend/Dockerfile"
      driver = Build-RunImage "driver" "driver_host/Dockerfile"
      generator = Build-RunImage "generator" "scripts/generator-v04.Dockerfile"
      pki_init = Build-RunImage "pki" "driver_host/pki.Dockerfile"
      postgres = Build-RunImage "postgres" "driver_host/postgres.Dockerfile"
      proxy = Build-RunImage "proxy" "proxy/Dockerfile"
      qualification = $qualificationImage
    }
    if (@($images.Values | Sort-Object -Unique).Count -ne 7) {
      throw "v0.4 runtime image roles are not seven distinct exact IDs"
    }

    $sourceLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
      "-I", (Join-Path $root "scripts/source_fingerprint_v04.py"), "--root", $root
    ) -FailureMessage "cannot compute the v0.4 source fingerprint" -Capture
    $source = $sourceLines | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
    if (-not $source) { throw "v0.4 source fingerprint output is invalid" }

    $runtimeBase = Join-Path $root "artifacts/v0.4/.qualification/runtime-captures/$source"
    New-Item -ItemType Directory -Force -Path $runtimeBase | Out-Null

    # Built-ins execute from the one qualification image. A dedicated internal
    # PostgreSQL instance satisfies the only network-bound built-in recipe.
    $builtinNetwork = "spell-v04-qual-builtin-$runId"
    $builtinPostgres = "spell-v04-qual-postgres-$runId"
    $builtinRunner = "spell-v04-qual-builtins-$runId"
    $builtinOutputInit = "spell-v04-qual-output-init-$runId"
    $builtinOutputVolume = "spell-v04-qual-output-$runId"
    $runNetworks.Add($builtinNetwork)
    $runContainers.Add($builtinPostgres)
    $runContainers.Add($builtinRunner)
    $runContainers.Add($builtinOutputInit)
    $runVolumes.Add($builtinOutputVolume)
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "network", "create", "--internal", "--label", $runLabel, $builtinNetwork
    ) -FailureMessage "cannot create the builtin qualification network"
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "volume", "create", "--label", $runLabel, $builtinOutputVolume
    ) -FailureMessage "cannot create the builtin qualification output volume"
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "run", "--rm", "--name", $builtinOutputInit, "--label", $runLabel,
      "--network", "none", "--read-only", "--user", "0",
      "--mount", "type=volume,source=$builtinOutputVolume,target=/qualification-output",
      $qualificationImage, "chown", "spell:spell", "/qualification-output"
    ) -FailureMessage "cannot initialize the builtin qualification output volume"
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "run", "--detach", "--name", $builtinPostgres, "--label", $runLabel,
      "--network", $builtinNetwork, "--network-alias", "spell-migration-postgres",
      "--read-only", "--tmpfs", "/var/lib/postgresql:rw,noexec,nosuid,size=512m,uid=70,gid=70,mode=1777",
      "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=16m,uid=70,gid=70,mode=3775",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,uid=70,gid=70,mode=1777",
      "--env", "POSTGRES_DB=spell_migration_test", "--env", "POSTGRES_USER=spell",
      "--env", "POSTGRES_HOST_AUTH_METHOD=trust", $images.postgres
    ) -FailureMessage "cannot start the builtin qualification database"
    $databaseReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
      $readyResult = Invoke-NativeProcess -Executable $DockerExe -Arguments @(
        "exec", $builtinPostgres, "pg_isready", "-U", "spell", "-d", "spell_migration_test"
      ) -TimeoutSeconds 15 -AllowFailure
      if ($readyResult.ExitCode -eq 0) { $databaseReady = $true; break }
      Start-Sleep -Seconds 1
    }
    if (-not $databaseReady) { throw "builtin qualification database did not become ready" }

    $isoEntries = @(
      $entries | Where-Object {
        $_.Mode -ceq "builtin" -and
        ((@($_.Entry.commands | ForEach-Object { @($_) }) -join " ") -match
          'test_created_compose_driver_has_runtime_isolation_controls')
      }
    )
    if ($isoEntries.Count -ne 1) { throw "composed builtin allocation differs" }
    $containerBuiltinIds = @($builtinIds | Where-Object { $_ -cne $isoEntries[0].TestId })
    $builtinArguments = @(
      "run", "--detach", "--name", $builtinRunner, "--label", $runLabel,
      "--network", $builtinNetwork, "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
      "--mount", "type=volume,source=$builtinOutputVolume,target=/qualification-source/artifacts/v0.4/.qualification",
      "--env", "SPELL_MIGRATION_TEST_DATABASE_URL=postgresql+psycopg://spell@spell-migration-postgres:5432/spell_migration_test",
      $qualificationImage, "python", "scripts/qualify_v04.py", "--root",
      "/qualification-source", "run", "--replace"
    )
    foreach ($testId in $containerBuiltinIds) {
      $builtinArguments += @("--test-id", $testId)
    }
    Invoke-DetachedContainerChecked -ContainerName $builtinRunner `
      -Arguments $builtinArguments -FailureMessage "v0.4 builtin qualification failed"
    $hostStagingRoot = Join-Path $root "artifacts/v0.4/.qualification"
    New-Item -ItemType Directory -Force -Path $hostStagingRoot | Out-Null
    Invoke-NativeChecked -Executable $DockerExe -Arguments @(
      "cp", "${builtinRunner}:/qualification-source/artifacts/v0.4/.qualification/.",
      $hostStagingRoot
    ) -FailureMessage "cannot copy builtin qualification evidence to the host"

    # Docker inspection runs on the host while the static test runs in the
    # exact qualification image. The collector creates an isolated Compose
    # project from the exact prebuilt driver and PKI image identities.
    Invoke-QualifierCollect -TestId $isoEntries[0].TestId -CollectorExecutable $PowerShellExe `
      -CollectorArguments @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $root "scripts/collect_isolation_v04.ps1"),
        "-TestId", $isoEntries[0].TestId,
        "-ExpectedSourceFingerprint", $source,
        "-QualificationImageId", $qualificationImage,
        "-DriverImageId", $images.driver, "-PkiImageId", $images.pki_init,
        "-DockerExecutable", $DockerExe, "-Root", $root
      )

    Invoke-NativeChecked -Executable $PowerShellExe -Arguments @(
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      (Join-Path $root "scripts/qualify_browser_real_v04.ps1"),
      "-Confirm", $Confirm, "-PythonExecutable", $PythonExe,
      "-QualificationImageId", $qualificationImage
    ) -FailureMessage "real browser v0.4 qualification failed"
    foreach ($testId in $browserIds) {
      Invoke-QualifierCollect -TestId $testId -CollectorExecutable $PythonExe `
        -CollectorArguments @(
          "-I", (Join-Path $root "scripts/qualify_browser_v04.py"),
          "--root", $root, "--test-id", $testId
        )
    }

    $performanceRoot = Join-Path $runtimeBase "performance-$runId"
    New-Item -ItemType Directory -Path $performanceRoot | Out-Null
    foreach ($profile in @("quick", "soak")) {
      $container = "spell-v04-qual-performance-$profile-$runId"
      $runContainers.Add($container)
      Invoke-NativeChecked -Executable $DockerExe -Arguments @(
        "run", "--rm", "--name", $container, "--label", $runLabel,
        "--network", "none", "--read-only", "--tmpfs", "/tmp:size=1g,noexec,nosuid",
        "--mount", "type=bind,source=$root,target=/qualification-source,readonly",
        "--mount", "type=bind,source=$performanceRoot,target=/qualification-output",
        "--env", "SPELL_QUALIFICATION_IMAGE_ID=$qualificationImage",
        $qualificationImage, "python", "scripts/qualify_performance_v04.py",
        "--$profile", "--run-id", $runId, "--output", "/qualification-output/$profile.json"
      ) -FailureMessage "v0.4 $profile performance qualification failed"
    }
    foreach ($testId in $performanceIds) {
      $reportName = if ($testId -ceq ($performanceIds | Sort-Object | Select-Object -Last 1)) {
        "soak.json"
      } else { "quick.json" }
      Invoke-QualifierCollect -TestId $testId -CollectorExecutable $PythonExe `
        -CollectorArguments @(
          "-I", (Join-Path $root "scripts/collect_performance_v04.py"),
          "--root", $root, "--report", (Join-Path $performanceRoot $reportName),
          "--test-id", $testId
        )
    }

    $regressionId = $regressionIds[0]
    Invoke-QualifierCollect -TestId $regressionId -CollectorExecutable $PowerShellExe `
      -CollectorArguments @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $root "scripts/qualify_regression_v04.ps1"),
        "-LocalConfirmation", $Confirm, "-Replace",
        "-QualificationImageId", $qualificationImage
      )

    foreach ($testId in @($supplyIds | Sort-Object)) {
      $collector = switch -CaseSensitive ($testId) {
        "V04-SC-001" { "audit_supply_chain_v04.ps1"; break }
        "V04-SC-002" { "generate_sbom_v04.ps1"; break }
        "V04-SC-003" { "inspect_release_v04.ps1"; break }
        default { "collect_supply_chain_v04.ps1" }
      }
      $arguments = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $root "scripts/$collector")
      )
      if ($collector -ceq "collect_supply_chain_v04.ps1") {
        $arguments += @("-TestId", $testId)
      }
      Invoke-QualifierCollect -TestId $testId -CollectorExecutable $PowerShellExe `
        -CollectorArguments $arguments
    }

    $runtimeCapturePath = Join-Path $runtimeBase "fault-runtime-$runId"
    Invoke-NativeChecked -Executable $PowerShellExe -Arguments @(
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      (Join-Path $root "scripts/collect_fault_runtime_v04.ps1"),
      "-Confirm", $Confirm, "-BackendImage", $images.backend,
      "-DriverImage", $images.driver, "-GeneratorImage", $images.generator,
      "-PkiInitImage", $images.pki_init, "-PostgresImage", $images.postgres,
      "-ProxyImage", $images.proxy, "-QualificationImageId", $qualificationImage,
      "-OutputDirectory", $runtimeCapturePath
    ) -FailureMessage "v0.4 runtime fault capture failed"

    $prepublishRoot = Join-Path $runtimeBase "sec003-prepublish-$runId"
    $prepublishLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
      "-I", (Join-Path $root "scripts/stage_sec003_prepublish_v04.py"), "build",
      "--root", $root, "--destination", $prepublishRoot,
      "--source-fingerprint", $source,
      "--frontend-bundle", (Join-Path $runtimeBase "regression/frontend-dist"),
      "--browser-provenance", (Join-Path $root "artifacts/v0.4/provenance/browser"),
      "--browser-storage", (Join-Path $root "artifacts/v0.4/browser-storage.json"),
      "--desktop-screenshot", (Join-Path $root "artifacts/v0.4/driver-projection-desktop.png"),
      "--mobile-screenshot", (Join-Path $root "artifacts/v0.4/driver-projection-mobile.png"),
      "--sbom-directory", (Join-Path $root "artifacts/v0.4/sbom"),
      "--runtime-captures", $runtimeCapturePath
    ) -FailureMessage "SEC003 prepublish corpus assembly failed" -Capture
    $prepublish = Get-LastJsonObject $prepublishLines "SEC003 prepublish corpus"
    if (
      $prepublish.schema_version -cne "spell.v04.sec003-prepublish/1" -or
      $prepublish.source_fingerprint_sha256 -cne $source -or
      [int]$prepublish.category_count -ne 5
    ) { throw "SEC003 prepublish corpus binding differs" }
    $prepublishValidationLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
      "-I", (Join-Path $root "scripts/stage_sec003_prepublish_v04.py"), "validate",
      "--root", $root, "--destination", $prepublishRoot,
      "--source-fingerprint", $source,
      "--frontend-bundle", (Join-Path $runtimeBase "regression/frontend-dist"),
      "--browser-provenance", (Join-Path $root "artifacts/v0.4/provenance/browser"),
      "--browser-storage", (Join-Path $root "artifacts/v0.4/browser-storage.json"),
      "--desktop-screenshot", (Join-Path $root "artifacts/v0.4/driver-projection-desktop.png"),
      "--mobile-screenshot", (Join-Path $root "artifacts/v0.4/driver-projection-mobile.png"),
      "--sbom-directory", (Join-Path $root "artifacts/v0.4/sbom"),
      "--runtime-captures", $runtimeCapturePath
    ) -FailureMessage "SEC003 prepublish corpus validation failed" -Capture
    $prepublishValidation = Get-LastJsonObject `
      $prepublishValidationLines "SEC003 prepublish corpus validation"
    if ($prepublishValidation.corpus_sha256 -cne $prepublish.corpus_sha256) {
      throw "SEC003 prepublish corpus changed between build and validation"
    }

    $faultRawDirectory = Join-Path $runtimeBase "fault-gate-$runId"
    $faultRawReport = Join-Path $faultRawDirectory "fault-gate-raw.json"
    $faultCaptureArguments = @(
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      (Join-Path $root "scripts/collect_fault_gate_v04.ps1"), "-CaptureRawReport",
      "-BackendImage", $images.backend, "-DriverImage", $images.driver,
      "-GeneratorImage", $images.generator,
      "-PkiInitImage", $images.pki_init, "-PostgresImage", $images.postgres,
      "-ProxyImage", $images.proxy, "-QualificationImageId", $qualificationImage,
      "-PrepublishRoot", $prepublishRoot,
      "-RuntimeInput", (Join-Path $prepublishRoot "runtime_captures/runtime-fault-evidence.json"),
      "-RawReport", $faultRawReport
    )
    if ($Mode -ceq "Preliminary") { $faultCaptureArguments += "-Preliminary" }
    else { $faultCaptureArguments += "-ReplaceProvenance" }
    Invoke-NativeChecked -Executable $PowerShellExe -Arguments $faultCaptureArguments `
      -FailureMessage "v0.4 all-ID fault-gate capture failed"
    foreach ($testId in $faultIds) {
      $faultExtractArguments = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $root "scripts/collect_fault_gate_v04.ps1"), "-TestId", $testId,
        "-BackendImage", $images.backend, "-DriverImage", $images.driver,
        "-GeneratorImage", $images.generator, "-PkiInitImage", $images.pki_init,
        "-PostgresImage", $images.postgres, "-ProxyImage", $images.proxy,
        "-QualificationImageId", $qualificationImage,
        "-RuntimeInput", (Join-Path $prepublishRoot "runtime_captures/runtime-fault-evidence.json"),
        "-RawReport", $faultRawReport
      )
      if ($Mode -ceq "Preliminary") { $faultExtractArguments += "-Preliminary" }
      Invoke-QualifierCollect -TestId $testId -CollectorExecutable $PowerShellExe `
        -CollectorArguments $faultExtractArguments
    }

    $statusLines = Invoke-NativeChecked -Executable $PythonExe -Arguments @(
      "-I", (Join-Path $root "scripts/qualify_v04.py"), "--root", $root, "status"
    ) -FailureMessage "v0.4 staged qualification is not publish-ready" -Capture
    $status = Get-LastJsonObject $statusLines "v0.4 qualification status"
    if (
      $status.publish_ready -ne $true -or [int]$status.valid_count -ne 74 -or
      [int]$status.invalid_count -ne 0 -or [int]$status.missing_count -ne 0
    ) { throw "v0.4 staged qualification status differs" }

    $publishArguments = @(
      "-I", (Join-Path $root "scripts/qualify_v04.py"), "--root", $root,
      "publish", "--replace"
    )
    if ($Mode -ceq "Preliminary") { $publishArguments += "--preliminary" }
    Invoke-NativeChecked -Executable $PythonExe -Arguments $publishArguments `
      -FailureMessage "v0.4 qualification publication failed"
    $published = $true

    if ($Mode -ceq "Final") {
      Invoke-NativeChecked -Executable $PowerShellExe -Arguments @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $root "scripts/package_release_v04.ps1")
      ) -FailureMessage "final v0.4 release package publication failed"
      $packagePublished = $true
    }

    $summary = [ordered]@{
      schema_version = "spell.v04.qualification-orchestration/1"
      run_id = $runId
      mode = $Mode
      planned = $false
      source_fingerprint_sha256 = $source
      qualification_image_id = $qualificationImage
      planned_builtin_count = $plannedBuiltinCount
      planned_collector_count = $plannedCollectorCount
      actual_builtin_count = $actualBuiltinCount
      actual_collector_count = $actualCollectorCount
      builtin_collector_overrides = $builtinCollectorOverrides
      staged_valid_count = [int]$status.valid_count
      published = $published
      package_published = $packagePublished
    }
  }
}
catch { $failure = $_ }
finally {
  if (Get-Variable DockerExe -ErrorAction SilentlyContinue) {
    foreach ($name in @($runContainers | Select-Object -Unique)) {
      Invoke-CleanupDocker @("container", "rm", "--force", $name) | Out-Null
      $inspection = Invoke-CleanupDocker @("container", "inspect", $name)
      Assert-CleanupDockerObjectAbsent `
        -Kind "container" -Reference $name -Inspection $inspection
    }
    foreach ($name in @($runNetworks | Select-Object -Unique)) {
      Invoke-CleanupDocker @("network", "rm", $name) | Out-Null
      $inspection = Invoke-CleanupDocker @("network", "inspect", $name)
      Assert-CleanupDockerObjectAbsent `
        -Kind "network" -Reference $name -Inspection $inspection
    }
    foreach ($name in @($runVolumes | Select-Object -Unique)) {
      Invoke-CleanupDocker @("volume", "rm", "--force", $name) | Out-Null
      $inspection = Invoke-CleanupDocker @("volume", "inspect", $name)
      Assert-CleanupDockerObjectAbsent `
        -Kind "volume" -Reference $name -Inspection $inspection
    }
    foreach ($tag in @($runTags | Select-Object -Unique)) {
      Invoke-CleanupDocker @("image", "rm", $tag) | Out-Null
      $inspection = Invoke-CleanupDocker @("image", "inspect", $tag)
      Assert-CleanupDockerObjectAbsent `
        -Kind "image" -Reference $tag -Inspection $inspection
    }
  }
  try {
    if (
      (Test-Path -LiteralPath $temporaryRoot) -and
      [IO.Path]::GetFullPath($temporaryRoot).StartsWith(
        "$temporaryBase$([IO.Path]::DirectorySeparatorChar)spell-v04-release-",
        [StringComparison]::OrdinalIgnoreCase
      )
    ) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
  }
  catch { $cleanupFailures.Add("temporary path cleanup failed: $($_.Exception.Message)") }
  try { Restore-ReleaseEnvironment }
  catch { $cleanupFailures.Add("release environment restoration failed: $($_.Exception.Message)") }
  try { Pop-Location }
  catch { $cleanupFailures.Add("working-directory restoration failed: $($_.Exception.Message)") }
  Assert-NativeProcessesExited
  try {
    $activeJobProcesses = Get-QualificationJobActiveProcessCount
    if ($activeJobProcesses -ne 1) {
      $cleanupFailures.Add(
        "qualification Job Object contains $activeJobProcesses active processes; expected only runner PID $PID"
      )
    }
  }
  catch { $cleanupFailures.Add("process-tree cleanup verification failed: $($_.Exception.Message)") }
}

$cleanupComplete = $cleanupFailures.Count -eq 0
if ($null -eq $summary) {
  $summary = [ordered]@{
    schema_version = "spell.v04.qualification-orchestration/1"
    run_id = $runId
    mode = $Mode
    planned = [bool]$PlanOnly
    source_fingerprint_sha256 = $source
    qualification_image_id = $qualificationImage
    planned_builtin_count = $plannedBuiltinCount
    planned_collector_count = $plannedCollectorCount
    actual_builtin_count = $actualBuiltinCount
    actual_collector_count = $actualCollectorCount
    builtin_collector_overrides = $builtinCollectorOverrides
    published = $published
    package_published = $packagePublished
  }
}
$summary.cleanup_complete = $cleanupComplete
$summary.cleanup_failures = @($cleanupFailures)
$summary.succeeded = ($null -eq $failure -and $cleanupComplete)
$summary | ConvertTo-Json -Compress -Depth 10 | Write-Output

if ($null -ne $failure) {
  if (-not $cleanupComplete) {
    throw [InvalidOperationException]::new(
      "$($failure.Exception.Message); cleanup failed: $($cleanupFailures -join '; ')",
      $failure.Exception
    )
  }
  throw $failure
}
if (-not $cleanupComplete) {
  throw "v0.4 qualification cleanup verification failed: $($cleanupFailures -join '; ')"
}
