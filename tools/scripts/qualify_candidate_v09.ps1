param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-f]{40}$')]
  [string]$SourceCommit,
  [Parameter(Mandatory = $true)]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$LocalConfirmation,
  [switch]$Replace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$manualLedgerSha256 = "78c419f898bbc719e9e1134f8e57aa0352a07cd2b4d21644658f3f74237c56ad"
$expectedManuals = [ordered]@{
  "SPELL - Build Manual - 2.4.4.pdf" = "6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6"
  "SPELL - Development Environment Manual - 2.4.4.pdf" = "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81"
  "SPELL - Driver Development Manual - 2.4.4.pdf" = "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5"
  "SPELL - GUI User Manual - 2.4.4.pdf" = "1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6"
  "SPELL - Language Reference - 2.4.4.pdf" = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
  "SPELL - Server Manual - 2.4.4.pdf" = "ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9"
  "SPELL-GUI-4.0.2-Build-Instructions.pdf" = "5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6"
}
$runId = [guid]::NewGuid().ToString("N")
$project = "spell-v09-candidate-$runId"
$browserProject = "$project-browser"
$qualificationTag = "openbexi-spell-v09-candidate-qualification:$runId"
$postgresTag = "openbexi-spell-v09-candidate-postgres:$runId"
$network = "$project-internal"
$postgresContainer = "$project-postgres"
$postgresVolume = "$project-postgres-data"
$offlinePlaywrightImage = (
  "mcr.microsoft.com/playwright:v1.61.1-noble@" +
  "sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48"
)
$offlinePlaywrightImageId = "sha256:89924b46ec81c1c0eb0055a7d72790b8067a16a5d0d0512e8117a01aa4a5d7ee"
$offlineCacheVolume = "sv09-offline-cache-$($runId.Substring(0, 12))"
$offlineToolingNode = (
  "scripts/tests/test_v09_offline_package.py::" +
  "test_v09_offline_package_build_install_and_network_none_health"
)
$artifactRoot = Join-Path $root "artifacts/v0.9"
$scratchRoot = Join-Path $artifactRoot ".qualification/candidate-$runId"
$candidateRoot = Join-Path $scratchRoot "source"
$legacyV08Root = Join-Path $env:TEMP "sv8-$($runId.Substring(0, 12))"
$legacyRoot = Join-Path $env:TEMP "sv7-$($runId.Substring(0, 12))"
$legacyV06Root = Join-Path $env:TEMP "sv6-$($runId.Substring(0, 12))"
$legacyV05Root = Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"
$legacyV08RootFull = [IO.Path]::GetFullPath($legacyV08Root)
$legacyRootFull = [IO.Path]::GetFullPath($legacyRoot)
$legacyV06RootFull = [IO.Path]::GetFullPath($legacyV06Root)
$legacyV05RootFull = [IO.Path]::GetFullPath($legacyV05Root)
$tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $legacyV08RootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a v0.8.0 historical checkout outside the temporary root"
}
if (-not $legacyRootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a v0.7.0 historical checkout outside the temporary root"
}
if (-not $legacyV06RootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a v0.6.0 historical checkout outside the temporary root"
}
if (-not $legacyV05RootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a v0.5.0 historical checkout outside the temporary root"
}
$captureRoot = Join-Path $scratchRoot "captures"
$stageRoot = Join-Path $artifactRoot ".qualification/publication-$runId"
$backupRoot = Join-Path $artifactRoot ".qualification/backup-$runId"
$canonicalRoot = Join-Path $artifactRoot "work-package"
$containers = [Collections.Generic.List[string]]::new()
$volumes = [Collections.Generic.List[string]]::new()
$imageTags = [Collections.Generic.List[string]]::new()
$imageTags.Add($qualificationTag)
$imageTags.Add($postgresTag)
$failure = $null
$qualificationImage = $null
$postgresImage = $null
$backendProcess = $null
$frontendProcess = $null
$resourcesTornDown = $false
$runtimeResourcesTornDown = $false
$runtimeProcessesStopped = $false
$imageTagsRemoved = $false
$runtimeBaseline = $null
$legacyV08RootOwned = $false
$legacyV08CleanupFailed = $false
$legacyRootOwned = $false
$legacyCleanupFailed = $false
$legacyV06RootOwned = $false
$legacyV06CleanupFailed = $false
$legacyV05RootOwned = $false
$legacyV05CleanupFailed = $false
$browserComposeTouched = $false
$browserCleanupFailed = $false
$cleanupInspectionFailure = $null

if ($LocalConfirmation -cne "LOCAL_SYNTHETIC_NON_CUI_ONLY") {
  throw "v0.9 candidate qualification requires the exact local synthetic non-CUI confirmation"
}
$validatorSource = [IO.File]::ReadAllText(
  (Join-Path $root "scripts/validate_candidate_evidence_v09.py"),
  [Text.Encoding]::UTF8
)
if ($validatorSource -cnotmatch '(?m)^PRODUCT_INVENTORY_FROZEN = True$') {
  throw "v0.9 product qualification inventory is not frozen"
}

function Assert-NativeSuccess([string]$Message) {
  if ($LASTEXITCODE -ne 0) { throw $Message }
}

function Get-LowerSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  }
  finally { $listener.Stop() }
}

function Get-ManualLedgerMap([string]$Path) {
  if ((Get-LowerSha256 $Path) -cne $manualLedgerSha256) {
    throw "committed external-manual ledger hash differs"
  }
  $raw = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
  $pattern = '(?m)^\|\s*`(?<name>[^`\r\n]+\.pdf)`\s*\|[^|\r\n]*\|[^|\r\n]*\|\s*`(?<sha>[0-9a-f]{64})`\s*\|'
  $observed = [ordered]@{}
  foreach ($match in [regex]::Matches($raw, $pattern)) {
    $name = $match.Groups["name"].Value
    $sha = $match.Groups["sha"].Value
    if ($observed.Contains($name)) { throw "external-manual ledger contains a duplicate PDF" }
    $observed[$name] = $sha
  }
  if ($observed.Count -ne $expectedManuals.Count) {
    throw "external-manual ledger PDF inventory differs"
  }
  foreach ($entry in $expectedManuals.GetEnumerator()) {
    if (-not $observed.Contains($entry.Key) -or $observed[$entry.Key] -cne $entry.Value) {
      throw "external-manual ledger binding differs: $($entry.Key)"
    }
  }
  return $observed
}

function Get-OrdinalSortedStrings([object[]]$Values) {
  [string[]]$items = @($Values | ForEach-Object { [string]$_ })
  [Array]::Sort($items, [StringComparer]::Ordinal)
  return $items
}

function Get-InventoryDigest([string[]]$Nodes) {
  $payload = [Text.Encoding]::UTF8.GetBytes(($Nodes -join "`n") + "`n")
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace("-", "").ToLowerInvariant() }
  finally { $hasher.Dispose() }
}

function Invoke-DockerCleanup([string[]]$Arguments) {
  $saved = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:DockerExe @Arguments 2>$null)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $saved }
  return [pscustomobject]@{ ExitCode = [int]$code; Lines = [string[]]$lines }
}

function Invoke-ComposeCleanup([string[]]$Arguments) {
  $saved = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:ComposeExe @Arguments 2>$null)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $saved }
  return [pscustomobject]@{ ExitCode = [int]$code; Lines = [string[]]$lines }
}

function Get-ComposeImageId([string]$Service) {
  $container = @(
    & $script:ComposeExe -p $browserProject --profile driver `
      -f (Join-Path $candidateRoot "compose.yaml") ps -a -q $Service
  ) | Where-Object { $_.Trim() } | Select-Object -Last 1
  Assert-NativeSuccess "cannot resolve the $Service telemetry browser container"
  if (-not $container) { throw "the $Service telemetry browser container is missing" }
  $image = (& $script:DockerExe inspect --format "{{.Image}}" $container).Trim()
  Assert-NativeSuccess "cannot resolve the $Service telemetry browser image"
  if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "the $Service telemetry browser image identity is invalid"
  }
  return $image
}

function Assert-ComposeServiceNetworkNone([string]$Service) {
  [string[]]$containers = @(
    & $script:ComposeExe -p $browserProject --profile driver `
      -f (Join-Path $candidateRoot "compose.yaml") ps -a -q $Service
  ) | Where-Object { $_.Trim() }
  Assert-NativeSuccess "cannot resolve the $Service telemetry browser container"
  if ($containers.Count -ne 1) {
    throw "the $Service telemetry browser container inventory differs"
  }
  $networkMode = @(
    & $script:DockerExe inspect --format "{{.HostConfig.NetworkMode}}" $containers[0]
  ) -join "`n"
  Assert-NativeSuccess "cannot inspect the $Service telemetry browser network mode"
  if ($networkMode.Trim() -cne "none") {
    throw "the $Service telemetry browser network mode is not none"
  }
}

function Get-DockerInspectionLines([string[]]$Arguments, [string]$Label) {
  [object[]]$results = @(Invoke-DockerCleanup $Arguments)
  if ($results.Count -ne 1) { throw "$Label inspection result cardinality differs" }
  $result = $results[0]
  if (
    $null -eq $result -or
    $null -eq $result.PSObject.Properties["ExitCode"] -or
    $null -eq $result.PSObject.Properties["Lines"]
  ) { throw "$Label inspection result shape differs" }
  if ([int]$result.ExitCode -ne 0) { throw "$Label inspection failed" }
  return [string[]]@($result.Lines)
}

function Get-RuntimeResources {
  return [ordered]@{
    containers = @(& $script:DockerExe ps -a --format "{{.Names}}" | Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
    networks = @(& $script:DockerExe network ls --format "{{.Name}}" | Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
    volumes = @(& $script:DockerExe volume ls --format "{{.Name}}" | Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
    images = @(& $script:DockerExe image ls --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
  }
}

function Remove-NewRuntimeResources([Collections.IDictionary]$Before) {
  $current = Get-RuntimeResources
  foreach ($name in @($current.containers | Where-Object { $_ -notin $Before.containers })) { Invoke-DockerCleanup @("rm", "-f", [string]$name) | Out-Null }
  foreach ($name in @($current.networks | Where-Object { $_ -notin $Before.networks })) { Invoke-DockerCleanup @("network", "rm", [string]$name) | Out-Null }
  foreach ($name in @($current.volumes | Where-Object { $_ -notin $Before.volumes })) { Invoke-DockerCleanup @("volume", "rm", "-f", [string]$name) | Out-Null }
  foreach ($name in @($current.images | Where-Object { $_ -notin $Before.images })) { Invoke-DockerCleanup @("image", "rm", [string]$name) | Out-Null }
  $after = Get-RuntimeResources
  return (
    @($after.containers | Where-Object { $_ -notin $Before.containers }).Count -eq 0 -and
    @($after.networks | Where-Object { $_ -notin $Before.networks }).Count -eq 0 -and
    @($after.volumes | Where-Object { $_ -notin $Before.volumes }).Count -eq 0 -and
    @($after.images | Where-Object { $_ -notin $Before.images }).Count -eq 0
  )
}

function Stop-OwnedProcess([Diagnostics.Process]$Process) {
  if ($null -eq $Process) { return }
  $existing = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
  if ($null -eq $existing) { return }
  & "$env:SystemRoot/System32/taskkill.exe" /PID $Process.Id /T /F 2>$null | Out-Null
  $existing.WaitForExit(10000) | Out-Null
}

function Get-CollectedNodes(
  [string]$Suite,
  [string]$Prefix,
  [int]$ExpectedCount,
  [string]$ExpectedDigest
) {
  $safe = $Suite.Replace('/', '-').Replace(':', '-')
  $name = "$project-collect-$safe"
  $script:containers.Add($name)
  & $script:DockerExe create --name $name --label "com.docker.compose.project=$project" `
    --network none --read-only --tmpfs "/tmp:size=256m,noexec,nosuid" `
    $script:QualificationImage python -m pytest --collect-only -q $Suite | Out-Null
  Assert-NativeSuccess "cannot create $Suite collection container"
  $output = @(& $script:DockerExe start --attach $name 2>&1)
  Assert-NativeSuccess "$Suite collection failed"
  $nodes = @(
    $output | ForEach-Object {
      $line = [string]$_
      $separator = $line.IndexOf("::", [StringComparison]::Ordinal)
      if ($separator -ge 0) { $line.Substring(0, $separator).Replace('\', '/') + $line.Substring($separator) }
    } | Where-Object { $_ -and $_.StartsWith($Prefix, [StringComparison]::Ordinal) -and $_.Contains("::") }
  )
  $nodes = Get-OrdinalSortedStrings $nodes
  if ($nodes.Count -eq 0 -or @($nodes | Select-Object -Unique).Count -ne $nodes.Count) {
    throw "$Suite collection has an empty or duplicate inventory"
  }
  if (
    $nodes.Count -ne $ExpectedCount -or
    $ExpectedDigest -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-InventoryDigest $nodes) -cne $ExpectedDigest
  ) { throw "$Suite collection differs from the frozen v0.9 inventory" }
  return ,$nodes
}

function Invoke-ImagePytest {
  param(
    [string]$Id,
    [string]$NetworkMode,
    [string[]]$Environment,
    [string[]]$PytestArguments,
    [string]$OutputPath,
    [string]$Workdir = "/qualification-source",
    [string[]]$Mounts = @()
  )
  $container = "$project-$Id"
  $volume = "$container-output"
  $script:containers.Add($container)
  $script:volumes.Add($volume)
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $volume | Out-Null
  Assert-NativeSuccess "cannot create $Id output volume"
  $arguments = @(
    "create", "--name", $container, "--label", "com.docker.compose.project=$project",
    "--network", $NetworkMode, "--read-only", "--tmpfs", "/tmp:size=768m,noexec,nosuid",
    "--mount", "type=volume,source=$volume,target=/qualification-output", "--workdir", $Workdir
  )
  foreach ($mount in $Mounts) { $arguments += @("--mount", $mount) }
  foreach ($entry in $Environment) { $arguments += @("-e", $entry) }
  $arguments += @($script:QualificationImage, "python", "-m", "pytest", "-p", "no:cacheprovider")
  $arguments += $PytestArguments
  & $script:DockerExe @arguments | Out-Null
  Assert-NativeSuccess "cannot create $Id test container"
  & $script:DockerExe start --attach $container
  Assert-NativeSuccess "$Id tests failed"
  & $script:DockerExe cp "${container}:/qualification-output/result.xml" $OutputPath | Out-Null
  Assert-NativeSuccess "cannot copy $Id JUnit capture"
}

function Merge-JUnit([string[]]$Inputs, [string]$Output) {
  $target = [Xml.XmlDocument]::new()
  $target.AppendChild($target.CreateXmlDeclaration("1.0", "utf-8", $null)) | Out-Null
  $rootNode = $target.CreateElement("testsuites")
  $target.AppendChild($rootNode) | Out-Null
  $suite = $target.CreateElement("testsuite")
  $suite.SetAttribute("name", "pytest")
  $rootNode.AppendChild($suite) | Out-Null
  $cases = [Collections.Generic.List[Xml.XmlNode]]::new()
  $subtests = 0
  foreach ($input in $Inputs) {
    [xml]$source = Get-Content -LiteralPath $input -Raw
    foreach ($sourceSuite in @($source.SelectNodes("//testsuite"))) {
      $direct = @($sourceSuite.SelectNodes("testcase"))
      if ($direct.Count -gt 0) {
        $reported = 0
        if (-not [int]::TryParse($sourceSuite.GetAttribute("tests"), [ref]$reported) -or $reported -lt $direct.Count) {
          throw "JUnit subtest aggregate is invalid: $input"
        }
        $subtests += $reported - $direct.Count
      }
    }
    foreach ($case in @($source.SelectNodes("//testcase"))) { $cases.Add($target.ImportNode($case, $true)) }
  }
  foreach ($case in $cases) { $suite.AppendChild($case) | Out-Null }
  $skipped = @($cases | Where-Object { $_.SelectSingleNode("skipped") }).Count
  $failures = @($cases | Where-Object { $_.SelectSingleNode("failure") }).Count
  $errors = @($cases | Where-Object { $_.SelectSingleNode("error") }).Count
  $suite.SetAttribute("tests", [string]($cases.Count + $subtests))
  $suite.SetAttribute("skipped", [string]$skipped)
  $suite.SetAttribute("failures", [string]$failures)
  $suite.SetAttribute("errors", [string]$errors)
  $settings = [Xml.XmlWriterSettings]::new()
  $settings.Encoding = [Text.UTF8Encoding]::new($false)
  $settings.Indent = $false
  $writer = [Xml.XmlWriter]::Create($Output, $settings)
  try { $target.Save($writer) }
  finally { $writer.Dispose() }
}

function Merge-JavaScriptJUnit([string[]]$Inputs, [string]$Output) {
  $target = [Xml.XmlDocument]::new()
  $target.AppendChild($target.CreateXmlDeclaration("1.0", "utf-8", $null)) | Out-Null
  $rootNode = $target.CreateElement("testsuites")
  $target.AppendChild($rootNode) | Out-Null
  $totals = [ordered]@{ tests = 0; failures = 0; skipped = 0; errors = 0 }
  $duration = 0.0
  foreach ($input in $Inputs) {
    [xml]$source = Get-Content -LiteralPath $input -Raw
    $sourceSuites = @($source.SelectNodes("/testsuites/testsuite | /testsuite"))
    if ($sourceSuites.Count -eq 0) { throw "JavaScript JUnit suite inventory is empty: $input" }
    foreach ($sourceSuite in $sourceSuites) {
      foreach ($name in @($totals.Keys)) {
        $value = 0
        if (-not [int]::TryParse($sourceSuite.GetAttribute($name), [ref]$value)) {
          throw "JavaScript JUnit $name aggregate is invalid: $input"
        }
        $totals[$name] += $value
      }
      $suiteDuration = 0.0
      if (-not [double]::TryParse(
        $sourceSuite.GetAttribute("time"),
        [Globalization.NumberStyles]::Float,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$suiteDuration
      )) { throw "JavaScript JUnit time aggregate is invalid: $input" }
      $duration += $suiteDuration
      $rootNode.AppendChild($target.ImportNode($sourceSuite, $true)) | Out-Null
    }
  }
  foreach ($name in $totals.Keys) { $rootNode.SetAttribute($name, [string]$totals[$name]) }
  $rootNode.SetAttribute("time", $duration.ToString("0.######", [Globalization.CultureInfo]::InvariantCulture))
  $settings = [Xml.XmlWriterSettings]::new()
  $settings.Encoding = [Text.UTF8Encoding]::new($false)
  $settings.Indent = $false
  $writer = [Xml.XmlWriter]::Create($Output, $settings)
  try { $target.Save($writer) }
  finally { $writer.Dispose() }
}

function Invoke-LockedHostPytest([string]$WorkingDirectory, [string[]]$Arguments, [string]$Label) {
  $code = @'
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import pytest
raise SystemExit(pytest.main(sys.argv[3:]))
'@
  Push-Location $WorkingDirectory
  try {
    & $script:LockedPython -I -c $code $script:SitePackages $WorkingDirectory @Arguments
    Assert-NativeSuccess "$Label failed"
  }
  finally { Pop-Location }
}

function Write-ProcessDiagnostics([string]$Label, [string[]]$LogPaths) {
  foreach ($path in $LogPaths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      Write-Host "--- $Label $(Split-Path -Leaf $path) ---"
      try { Get-Content -LiteralPath $path -Tail 200 | ForEach-Object { Write-Host $_ } }
      catch { Write-Host "unable to read $Label diagnostic log: $($_.Exception.Message)" }
    }
  }
}

function Wait-Http(
  [string]$Uri,
  [int]$Seconds = 60,
  [Diagnostics.Process]$Process = $null,
  [string]$ProcessLabel = "service",
  [string[]]$LogPaths = @()
) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
      if ($response.StatusCode -eq 200) { return }
    }
    catch { }
    if ($null -ne $Process) {
      $Process.Refresh()
      if ($Process.HasExited) {
        Write-ProcessDiagnostics $ProcessLabel $LogPaths
        throw "$ProcessLabel exited with code $($Process.ExitCode) before $Uri became ready"
      }
    }
    Start-Sleep -Milliseconds 250
  } until ((Get-Date) -ge $deadline)
  Write-ProcessDiagnostics $ProcessLabel $LogPaths
  throw "timed out waiting for $Uri"
}

function Get-JUnitFragment([string]$Path, [string]$Kind) {
  $line = @(& $script:LockedPython -I $script:Validator --junit-summary $Path --junit-kind $Kind)
  Assert-NativeSuccess "JUnit summary validation failed: $Path"
  if ($line.Count -ne 1) { throw "JUnit summary output differs: $Path" }
  return ($line[0] | ConvertFrom-Json)
}

function Assert-ExactInventory([string[]]$Expected, [object[]]$Observed, [string]$Label) {
  [string[]]$actual = @($Observed | ForEach-Object { [string]$_ })
  if (($Expected -join "`0") -cne ($actual -join "`0")) { throw "$Label collection/JUnit bijection differs" }
}

function New-SuiteRecord([string]$Id, [string]$Kind, [string]$Capture, [object]$Summary, [string]$NetworkMode) {
  return [ordered]@{
    kind = $Kind
    capture = $Capture
    collected_nodes = @($Summary.collected_nodes)
    inventory_sha256 = [string]$Summary.inventory_sha256
    test_count = [int]$Summary.test_count
    subtest_count = [int]$Summary.subtest_count
    passed_count = [int]$Summary.passed_count
    skipped_count = [int]$Summary.skipped_count
    failure_count = [int]$Summary.failure_count
    error_count = [int]$Summary.error_count
    duration_seconds = [double]$Summary.duration_seconds
    network_mode = $NetworkMode
  }
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
Assert-NativeSuccess "release toolchain validation failed"
$script:DockerExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
$script:ComposeExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_COMPOSE_EXE)
$script:LockedPython = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
$script:SitePackages = Join-Path $env:TEMP "openbexi-spell-v05-py313-site"
$script:Validator = Join-Path $root "scripts/validate_candidate_evidence_v09.py"
if (-not (Test-Path -LiteralPath $script:SitePackages -PathType Container)) { throw "locked CPython host dependency site is missing" }

Push-Location $root
try {
  $resolvedSource = (git rev-parse --verify "$SourceCommit^{commit}").Trim()
  Assert-NativeSuccess "source commit lookup failed"
  if ($resolvedSource -cne $SourceCommit) { throw "source commit is not the exact supplied object" }
  $head = (git rev-parse --verify HEAD).Trim()
  Assert-NativeSuccess "HEAD lookup failed"
  if ($head -cne $SourceCommit) { throw "candidate qualification requires HEAD at the explicit source commit" }
  $sourceParents = (git show -s --format=%P $SourceCommit).Trim()
  Assert-NativeSuccess "candidate parent lookup failed"
  if ($sourceParents -cne "92f3b4b82908d44e28b9506749e498386a428c27") {
    throw "candidate source must have the exact Gate 0A commit as its sole parent"
  }
  $status = @(git status --porcelain=v1 --untracked-files=all)
  Assert-NativeSuccess "worktree status lookup failed"
  if ($status.Count -ne 0) { throw "candidate qualification requires a clean explicit source freeze" }
  git merge-base --is-ancestor v0.8.0 $SourceCommit
  Assert-NativeSuccess "v0.8.0 is not an ancestor of the candidate source"
  git diff --quiet v0.8.0 $SourceCommit -- artifacts/v0.8
  Assert-NativeSuccess "tracked v0.8 artifacts changed in the candidate source"
  & $script:LockedPython -I (Join-Path $root "scripts/accepted_v08_release_v09.py") --root $root | Out-Null
  Assert-NativeSuccess "accepted external v0.8 release validation failed"

  New-Item -ItemType Directory -Path $candidateRoot, $captureRoot -Force | Out-Null
  $candidateArchive = Join-Path $scratchRoot "source.zip"
  git archive --format=zip --output=$candidateArchive $SourceCommit
  Assert-NativeSuccess "candidate source export failed"
  Expand-Archive -LiteralPath $candidateArchive -DestinationPath $candidateRoot

  $manualLedger = Get-ManualLedgerMap (Join-Path $candidateRoot "SPELL_DOCUMENTATION_REVIEW.md")
  $manualSource = Join-Path $root "SPELL-DOCUMENTATION"
  if (-not (Test-Path -LiteralPath $manualSource -PathType Container)) {
    throw "external-manual source directory is missing"
  }
  $manualRootItem = Get-Item -LiteralPath $manualSource -Force
  if ($manualRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "external-manual source directory is unsafe"
  }
  $sourceManuals = @(Get-ChildItem -LiteralPath $manualSource -Force)
  if (
    $sourceManuals.Count -ne $manualLedger.Count -or
    @($sourceManuals | Where-Object {
      $_.PSIsContainer -or
      ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      -not $manualLedger.Contains($_.Name)
    }).Count -ne 0
  ) { throw "external-manual source inventory differs from the committed ledger" }
  $stagedManualRoot = Join-Path $candidateRoot "SPELL-DOCUMENTATION"
  New-Item -ItemType Directory -Path $stagedManualRoot | Out-Null
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $sourceManual = Join-Path $manualSource $entry.Key
    if ((Get-LowerSha256 $sourceManual) -cne $entry.Value) {
      throw "external-manual source hash differs: $($entry.Key)"
    }
    $stagedManual = Join-Path $stagedManualRoot $entry.Key
    Copy-Item -LiteralPath $sourceManual -Destination $stagedManual
    if ((Get-LowerSha256 $stagedManual) -cne $entry.Value) {
      throw "staged external-manual hash differs: $($entry.Key)"
    }
  }

  if (Test-Path -LiteralPath $legacyV08Root) { throw "v0.8.0 historical checkout path already exists" }
  git -C $root worktree add --detach --quiet $legacyV08Root v0.8.0
  Assert-NativeSuccess "v0.8.0 detached worktree checkout failed"
  $legacyV08RootOwned = $true
  $legacyV08Head = (git -C $legacyV08Root rev-parse HEAD).Trim()
  if ($legacyV08Head -cne "d6e01222de3bf52013279e48a099b6ae7ded121d") { throw "v0.8.0 detached export identity differs" }
  $legacyV08ManualRoot = Join-Path $legacyV08Root "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $legacyV08ManualRoot) {
    throw "v0.8.0 detached export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $legacyV08ManualRoot -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $legacyV08Manual = Join-Path $legacyV08ManualRoot $entry.Key
    if (
      -not (Test-Path -LiteralPath $legacyV08Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $legacyV08Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $legacyV08Manual) -cne $entry.Value
    ) { throw "v0.8.0 staged external manual differs: $($entry.Key)" }
  }
  & $script:LockedPython -I (Join-Path $root "scripts/accepted_v08_release_v09.py") --root $legacyV08Root | Out-Null
  Assert-NativeSuccess "accepted v0.8 release binding differs in v0.8 export"

  if (Test-Path -LiteralPath $legacyRoot) { throw "v0.7.0 historical checkout path already exists" }
  git -C $root worktree add --detach --quiet $legacyRoot v0.7.0
  Assert-NativeSuccess "v0.7.0 detached worktree checkout failed"
  $legacyRootOwned = $true
  $legacyHead = (git -C $legacyRoot rev-parse HEAD).Trim()
  if ($legacyHead -cne "cf18e9d887ba0476cbcc3d8194e321332a3ae864") { throw "v0.7.0 detached export identity differs" }
  $legacyManualRoot = Join-Path $legacyRoot "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $legacyManualRoot) {
    throw "v0.7.0 detached export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $legacyManualRoot -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $legacyManual = Join-Path $legacyManualRoot $entry.Key
    if (
      -not (Test-Path -LiteralPath $legacyManual -PathType Leaf) -or
      ((Get-Item -LiteralPath $legacyManual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $legacyManual) -cne $entry.Value
    ) { throw "v0.7.0 staged external manual differs: $($entry.Key)" }
  }
  $acceptedArchiveSha256 = "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
  $acceptedSidecarSha256 = "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
  $acceptedSidecarText = "$acceptedArchiveSha256  openbexi-spell-v0.7.0.tar.gz`n"
  foreach ($releaseName in @("openbexi-spell-v0.7.0.tar.gz", "openbexi-spell-v0.7.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.7/$releaseName"
    if (-not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or (Get-Item -LiteralPath $releaseSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
      throw "v0.7.0 canonical release input is missing or unsafe: $releaseName"
    }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $acceptedSidecarSha256
    } else { $acceptedArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "v0.7.0 canonical release input hash differs: $releaseName"
    }
    $releaseDestination = Join-Path $legacyRoot "artifacts/v0.7/$releaseName"
    Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
    if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
      throw "v0.7.0 staged release input hash differs: $releaseName"
    }
  }
  if ([IO.File]::ReadAllText((Join-Path $legacyRoot "artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedSidecarText) {
    throw "v0.7.0 staged release sidecar bytes differ"
  }

  if (Test-Path -LiteralPath $legacyV06Root) { throw "v0.6.0 historical checkout path already exists" }
  git -C $root worktree add --detach --quiet $legacyV06Root v0.6.0
  Assert-NativeSuccess "v0.6.0 detached worktree checkout failed"
  $legacyV06RootOwned = $true
  $legacyV06Head = (git -C $legacyV06Root rev-parse HEAD).Trim()
  if ($legacyV06Head -cne "05ec783a6e54a76e0548bdd536c18538f6bff51b") { throw "v0.6.0 detached export identity differs" }
  $legacyV06ManualRoot = Join-Path $legacyV06Root "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $legacyV06ManualRoot) {
    throw "v0.6.0 detached export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $legacyV06ManualRoot -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $legacyV06Manual = Join-Path $legacyV06ManualRoot $entry.Key
    if (
      -not (Test-Path -LiteralPath $legacyV06Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $legacyV06Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $legacyV06Manual) -cne $entry.Value
    ) { throw "v0.6.0 staged external manual differs: $($entry.Key)" }
  }
  $acceptedV06ArchiveSha256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
  $acceptedV06SidecarSha256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
  $acceptedV06SidecarText = "$acceptedV06ArchiveSha256  openbexi-spell-v0.6.0.tar.gz`n"
  foreach ($releaseName in @("openbexi-spell-v0.6.0.tar.gz", "openbexi-spell-v0.6.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.6/$releaseName"
    if (-not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or (Get-Item -LiteralPath $releaseSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
      throw "v0.6.0 canonical release input is missing or unsafe: $releaseName"
    }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $acceptedV06SidecarSha256
    } else { $acceptedV06ArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "v0.6.0 canonical release input hash differs: $releaseName"
    }
    foreach ($releaseRoot in @($legacyV06Root, $legacyRoot)) {
      $releaseDestination = Join-Path $releaseRoot "artifacts/v0.6/$releaseName"
      Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
      if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
        throw "v0.6.0 staged release input hash differs: $releaseName"
      }
    }
  }
  foreach ($releaseRoot in @($legacyV06Root, $legacyRoot)) {
    if ([IO.File]::ReadAllText((Join-Path $releaseRoot "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedV06SidecarText) {
      throw "staged v0.6.0 release sidecar bytes differ"
    }
  }
  & $script:LockedPython -I (Join-Path $root "scripts/accepted_v06_release_v07.py") --root $legacyV06Root | Out-Null
  Assert-NativeSuccess "accepted v0.6 release binding differs in v0.6 export"
  & $script:LockedPython -I (Join-Path $root "scripts/accepted_v06_release_v07.py") --root $legacyRoot | Out-Null
  Assert-NativeSuccess "accepted v0.6 release binding differs in v0.7 export"

  $inheritedRelative = "artifacts/v0.4/.qualification/runtime-captures/46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d/regression"
  $inheritedSource = Join-Path $root $inheritedRelative
  if (-not (Test-Path -LiteralPath $inheritedSource -PathType Container) -or
      (Get-Item -LiteralPath $inheritedSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
      @(Get-ChildItem -LiteralPath $inheritedSource -Recurse -Force | Where-Object { $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) }).Count -ne 0) {
    throw "v0.7.0 inherited regression input is missing or unsafe"
  }
  $inheritedDestination = Join-Path $legacyRoot $inheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $inheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $inheritedSource -Destination $inheritedDestination -Recurse
  $legacyV06InheritedDestination = Join-Path $legacyV06Root $inheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $legacyV06InheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $inheritedSource -Destination $legacyV06InheritedDestination -Recurse

  if (Test-Path -LiteralPath $legacyV05Root) { throw "v0.5.0 historical checkout path already exists" }
  git -C $root worktree add --detach --quiet $legacyV05Root v0.5.0
  Assert-NativeSuccess "v0.5.0 detached worktree checkout failed"
  $legacyV05RootOwned = $true
  $legacyV05Head = (git -C $legacyV05Root rev-parse HEAD).Trim()
  if ($legacyV05Head -cne "e7b6bb9428833437e0160040541eb840deee7cca") { throw "v0.5.0 detached export identity differs" }
  $legacyV05ManualRoot = Join-Path $legacyV05Root "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $legacyV05ManualRoot) {
    throw "v0.5.0 detached export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $legacyV05ManualRoot -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $legacyV05Manual = Join-Path $legacyV05ManualRoot $entry.Key
    if (
      -not (Test-Path -LiteralPath $legacyV05Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $legacyV05Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $legacyV05Manual) -cne $entry.Value
    ) { throw "v0.5.0 staged external manual differs: $($entry.Key)" }
  }
  $acceptedV05ArchiveSha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
  $acceptedV05SidecarSha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
  $acceptedV05SidecarText = "$acceptedV05ArchiveSha256  openbexi-spell-v0.5.0.tar.gz`n"
  foreach ($releaseName in @("openbexi-spell-v0.5.0.tar.gz", "openbexi-spell-v0.5.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.5/$releaseName"
    if (-not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or (Get-Item -LiteralPath $releaseSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
      throw "v0.5.0 canonical release input is missing or unsafe: $releaseName"
    }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $acceptedV05SidecarSha256
    } else { $acceptedV05ArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "v0.5.0 canonical release input hash differs: $releaseName"
    }
    foreach ($releaseRoot in @($legacyV05Root, $legacyV06Root, $legacyRoot)) {
      $releaseDestination = Join-Path $releaseRoot "artifacts/v0.5/$releaseName"
      Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
      if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
        throw "v0.5.0 staged release input hash differs: $releaseName"
      }
    }
  }
  if ([IO.File]::ReadAllText((Join-Path $legacyV05Root "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedV05SidecarText) {
    throw "v0.5.0 staged release sidecar bytes differ"
  }
  if ([IO.File]::ReadAllText((Join-Path $legacyRoot "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedV05SidecarText) {
    throw "v0.7.0 staged inherited v0.5 release sidecar bytes differ"
  }
  if ([IO.File]::ReadAllText((Join-Path $legacyV06Root "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedV05SidecarText) {
    throw "v0.6.0 staged inherited v0.5 release sidecar bytes differ"
  }
  $legacyV05InheritedDestination = Join-Path $legacyV05Root $inheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $legacyV05InheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $inheritedSource -Destination $legacyV05InheritedDestination -Recurse

  $gateOutput = @(& $script:LockedPython -I (Join-Path $root "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0a.py"))
  Assert-NativeSuccess "Gate 0A validation failed"
  $gateMarker = "gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0"
  if (@($gateOutput | Where-Object { $_ -ceq $gateMarker }).Count -ne 1) { throw "Gate 0A success marker differs" }

  $runtimeBaseline = Get-RuntimeResources
  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    --label "org.openbexi.spell.v09.source.commit=$SourceCommit" `
    -f (Join-Path $candidateRoot "scripts/qualification-v09.Dockerfile") `
    -t $qualificationTag $candidateRoot
  Assert-NativeSuccess "candidate qualification image build failed"
  $script:QualificationImage = (& $script:DockerExe image inspect $qualificationTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "candidate qualification image lookup failed"
  if ($script:QualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "qualification image identity is invalid" }
  $qualificationImage = $script:QualificationImage
  $runtimeVersion = @(& $script:DockerExe run --rm --network none --read-only --entrypoint python $qualificationImage --version) -join "`n"
  Assert-NativeSuccess "qualification runtime probe failed"
  if ($runtimeVersion.Trim() -cne "Python 3.13.14") { throw "qualification image is not Python 3.13.14" }

  $observedOfflineImageId = @(
    & $script:DockerExe image inspect $offlinePlaywrightImage --format "{{.Id}}"
  ) -join "`n"
  Assert-NativeSuccess "pinned offline Playwright image is not preinstalled"
  if ($observedOfflineImageId.Trim() -cne $offlinePlaywrightImageId) {
    throw "pinned offline Playwright image identity differs"
  }
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" `
    $offlineCacheVolume | Out-Null
  Assert-NativeSuccess "cannot create offline npm cache volume"
  $volumes.Add($offlineCacheVolume)
  & $script:DockerExe run --rm --read-only --tmpfs "/tmp:size=2g,nosuid" `
    --label "com.docker.compose.project=$project" `
    --mount "type=bind,source=$(Join-Path $candidateRoot 'frontend'),target=/source,readonly" `
    --mount "type=volume,source=$offlineCacheVolume,target=/npm-cache" `
    -e "NPM_CONFIG_CACHE=/npm-cache" $offlinePlaywrightImage bash -ceu `
    "mkdir -p /tmp/work; cp /source/package.json /source/package-lock.json /tmp/work/; cd /tmp/work; npm ci --ignore-scripts --no-audit --no-fund --cache /npm-cache; npm cache verify --cache /npm-cache"
  Assert-NativeSuccess "cannot seed the verified offline npm cache"

  $backendNodes = Get-CollectedNodes "backend/tests" "backend/tests/" 923 `
    "cb1e76d67e36de5844976c6576999d2322823e3b33318913757ba332db78dd68"
  $driverNodes = Get-CollectedNodes "driver_host/tests" "driver_host/tests/" 82 `
    "a3c0a451d7292c46c2f06fe6924c1b35d9c1b2031940f67a862555d38d534593"
  $toolingNodes = Get-CollectedNodes "scripts/tests" "scripts/tests/" 1050 `
    "1022465fb4518a89ea3a6ae762bd96db77887215a2c8de9313e1a0cf4e2f7509"

  $sqliteXml = Join-Path $captureRoot "backend-sqlite.xml"
  Invoke-ImagePytest "backend-sqlite" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("backend/tests", "-q", "--junitxml=/qualification-output/result.xml") $sqliteXml

  & $script:DockerExe build --pull=false --provenance=false --label "com.docker.compose.project=$project" `
    -f (Join-Path $candidateRoot "driver_host/postgres.Dockerfile") -t $postgresTag $candidateRoot
  Assert-NativeSuccess "candidate PostgreSQL image build failed"
  $postgresImage = (& $script:DockerExe image inspect $postgresTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "candidate PostgreSQL image lookup failed"
  if ($postgresImage -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "PostgreSQL image identity is invalid" }
  & $script:DockerExe network create --internal --label "com.docker.compose.project=$project" $network | Out-Null
  Assert-NativeSuccess "candidate network creation failed"
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $postgresVolume | Out-Null
  Assert-NativeSuccess "candidate PostgreSQL volume creation failed"
  $volumes.Add($postgresVolume)
  $databasePassword = "v09-candidate-pg-$runId"
  & $script:DockerExe run -d --name $postgresContainer --label "com.docker.compose.project=$project" `
    --network $network --mount "type=volume,source=$postgresVolume,target=/var/lib/postgresql/18/docker" `
    -e "POSTGRES_USER=spell" -e "POSTGRES_PASSWORD=$databasePassword" -e "POSTGRES_DB=spell_test" $postgresImage | Out-Null
  Assert-NativeSuccess "candidate PostgreSQL start failed"
  $containers.Add($postgresContainer)
  $ready = $false
  $consecutive = 0
  $deadline = (Get-Date).AddSeconds(60)
  do {
    & $script:DockerExe exec $postgresContainer pg_isready -U spell -d spell_test 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $consecutive += 1 } else { $consecutive = 0 }
    $ready = $consecutive -ge 2
    if (-not $ready) { Start-Sleep -Milliseconds 250 }
  } until ($ready -or (Get-Date) -ge $deadline)
  if (-not $ready) { throw "candidate PostgreSQL did not become ready" }
  & $script:DockerExe exec $postgresContainer createdb -U spell spell_migration_test
  Assert-NativeSuccess "distinct migration database creation failed"
  foreach ($databaseName in @("spell_test", "spell_migration_test")) {
    $observed = @(& $script:DockerExe exec $postgresContainer psql -U spell -d $databaseName -Atqc "SELECT current_database()") -join "`n"
    Assert-NativeSuccess "database identity probe failed"
    if ($observed.Trim() -cne $databaseName) { throw "database identity differs: $databaseName" }
  }
  $applicationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_test"
  $migrationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_migration_test"
  $dockerNodes = Get-OrdinalSortedStrings @(
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_driver_isolation.py::test_live_bundle_builders_are_networkless_independent_and_reproducible"
  )
  $postgresBaseXml = Join-Path $captureRoot "backend-postgresql-base.xml"
  $postgresArguments = @("backend/tests", "-q")
  foreach ($node in $dockerNodes) { $postgresArguments += "--deselect=$node" }
  $postgresArguments += "--junitxml=/qualification-output/result.xml"
  Invoke-ImagePytest "backend-postgresql" $network @(
    "PYTHONDONTWRITEBYTECODE=1", "SPELL_TEST_DATABASE_URL=$applicationUrl", "SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl"
  ) $postgresArguments $postgresBaseXml

  $dockerHostXml = Join-Path $captureRoot "backend-docker-host.xml"
  $savedHostEnvironment = [ordered]@{}
  foreach ($name in @("SPELL_RUN_COMPOSE_RUNTIME_TESTS", "SPELL_TEST_DATABASE_URL", "SPELL_MIGRATION_TEST_DATABASE_URL", "PYTHONPATH")) {
    $savedHostEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
  }
  try {
    $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS = "1"
    $env:SPELL_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_test"
    $env:SPELL_MIGRATION_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_migration_test"
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Invoke-LockedHostPytest $candidateRoot @($dockerNodes + @("-q", "--junitxml=$dockerHostXml")) "host-only Docker inspection tests"
  }
  finally {
    foreach ($entry in $savedHostEnvironment.GetEnumerator()) {
      if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
      else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
    }
  }
  $postgresXml = Join-Path $captureRoot "backend-postgresql.xml"
  Merge-JUnit @($postgresBaseXml, $dockerHostXml) $postgresXml

  $driverXml = Join-Path $captureRoot "driver-host.xml"
  Invoke-ImagePytest "driver-host" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("driver_host/tests", "-q", "--junitxml=/qualification-output/result.xml") $driverXml

  $rerouted = [ordered]@{
    "scripts/tests/test_release_v05.py::test_current_v05_product_package_fingerprint_is_constructible" = "v0.5.0-export"
    "scripts/tests/test_validate_release_evidence_v05.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication" = "v0.5.0-export"
    "scripts/tests/test_validate_release_evidence_v05.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz-archive SHA-256 differs]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256-sidecar bytes differ]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_tag_claim_rejects_raw_object_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_release_evidence_v06.py::test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_candidate_evidence_v06.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic" = "locked-windows-host-current-root"
    "scripts/tests/test_release_v06.py::test_current_v06_product_package_fingerprint_is_constructible" = "v0.6.0-export"
    "scripts/tests/test_validate_release_evidence_v06.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication" = "v0.6.0-export"
    "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_tag_blobs_archive_and_sidecar_are_exact" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz-workspace archive SHA-256 differs]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256-workspace sidecar bytes differ]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_raw_tag_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_tagged_blob_payload_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_cli_emits_one_canonical_json_object" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v06_release_v07.py::test_v07_powershell_assertion_is_parseable_and_reuses_canonical_validator" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_candidate_evidence_v07.py::test_v07_candidate_runner_parses_as_powershell" = "locked-windows-host"
    "scripts/tests/test_validate_release_evidence_v07.py::test_v07_inherited_v06_binding_includes_external_archive_sidecar_and_tag" = "locked-windows-host-current-root"
    "scripts/tests/test_qualification_image_v07.py::test_v07_qualification_baseline_inputs_exist_as_regular_files" = "v0.7.0-export"
    "scripts/tests/test_source_fingerprint_v07.py::test_v07_source_fingerprint_includes_gate_0a_and_contract_inputs" = "v0.7.0-export"
    "scripts/tests/test_validate_candidate_evidence_v07.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic" = "v0.7.0-export"
    "scripts/tests/test_release_v07.py::test_current_v07_product_package_fingerprint_is_constructible" = "v0.7.0-export"
    "scripts/tests/test_validate_release_evidence_v07.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication" = "v0.7.0-export"
    "scripts/tests/test_validate_release_evidence_v07.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_tag_blobs_archive_and_sidecar_are_exact" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz-workspace archive SHA-256 differs]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256-workspace sidecar bytes differ]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_raw_tag_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_tagged_blob_payload_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_cli_emits_one_canonical_json_object" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v07_release_v08.py::test_v08_powershell_assertion_is_parseable_and_reuses_canonical_validator" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_candidate_evidence_v08.py::test_v08_candidate_runner_parses_as_powershell" = "locked-windows-host"
    "scripts/tests/test_validate_release_evidence_v08.py::test_v08_inherited_v07_binding_includes_external_archive_sidecar_and_tag" = "locked-windows-host-current-root"
    "scripts/tests/test_qualify_release_v08.py::test_v08_final_runner_parses_as_powershell" = "locked-windows-host"
    "scripts/tests/test_release_v08.py::test_v08_package_publication_fault_rolls_back_executably" = "locked-windows-host"
    "scripts/tests/test_qualification_image_v08.py::test_v08_qualification_baseline_inputs_exist_as_regular_files" = "v0.8.0-export"
    "scripts/tests/test_source_fingerprint_v08.py::test_v08_source_fingerprint_includes_gate_0a_and_contract_inputs" = "v0.8.0-export"
    "scripts/tests/test_validate_candidate_evidence_v08.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic" = "v0.8.0-export"
    "scripts/tests/test_release_v08.py::test_current_v08_product_package_fingerprint_is_constructible" = "v0.8.0-export"
    "scripts/tests/test_validate_release_evidence_v08.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication" = "v0.8.0-export"
    "scripts/tests/test_validate_release_evidence_v08.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_tag_blobs_archive_and_sidecar_are_exact" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz-workspace archive SHA-256 differs]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256-workspace sidecar bytes differ]" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_raw_tag_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_tagged_blob_payload_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_artifact_tree_mutation" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_cli_emits_one_canonical_json_object" = "locked-windows-host-current-root"
    "scripts/tests/test_accepted_v08_release_v09.py::test_v09_powershell_assertion_is_parseable_and_reuses_canonical_validator" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_candidate_evidence_v09.py::test_v09_candidate_runner_parses_as_powershell" = "locked-windows-host"
    "scripts/tests/test_validate_release_evidence_v09.py::test_v09_inherited_v08_binding_includes_external_archive_sidecar_and_tag" = "locked-windows-host-current-root"
    "scripts/tests/test_validate_release_evidence_v09.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    $offlineToolingNode = "locked-windows-offline"
  }
  $toolingBaseXml = Join-Path $captureRoot "tooling-base.xml"
  $toolingArguments = @("scripts/tests", "-q")
  foreach ($node in $rerouted.Keys) { $toolingArguments += "--deselect=$node" }
  $toolingArguments += "--junitxml=/qualification-output/result.xml"
  $manualEvidenceMount = "type=bind,source=$stagedManualRoot,target=/qualification-source/SPELL-DOCUMENTATION,readonly"
  Invoke-ImagePytest "tooling" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    $toolingArguments $toolingBaseXml -Mounts @($manualEvidenceMount)
  $toolingV05Xml = Join-Path $captureRoot "tooling-v05.xml"
  $legacyV05Nodes = @($rerouted.Keys | Where-Object { $rerouted[$_] -ceq "v0.5.0-export" })
  Invoke-LockedHostPytest $legacyV05Root @($legacyV05Nodes + @("-q", "--junitxml=$toolingV05Xml")) "detached v0.5.0 historical-current tests"
  $toolingV06Xml = Join-Path $captureRoot "tooling-v06.xml"
  $legacyV06Nodes = @($rerouted.Keys | Where-Object { $rerouted[$_] -ceq "v0.6.0-export" })
  Invoke-LockedHostPytest $legacyV06Root @($legacyV06Nodes + @("-q", "--junitxml=$toolingV06Xml")) "detached v0.6.0 historical-current tests"
  $toolingLegacyXml = Join-Path $captureRoot "tooling-v07.xml"
  $legacyNodes = @($rerouted.Keys | Where-Object { $rerouted[$_] -ceq "v0.7.0-export" })
  Invoke-LockedHostPytest $legacyRoot @($legacyNodes + @("-q", "--junitxml=$toolingLegacyXml")) "detached v0.7.0 historical-current tests"
  $toolingV08Xml = Join-Path $captureRoot "tooling-v08.xml"
  $legacyV08Nodes = @($rerouted.Keys | Where-Object { $rerouted[$_] -ceq "v0.8.0-export" })
  Invoke-LockedHostPytest $legacyV08Root @($legacyV08Nodes + @("-q", "--junitxml=$toolingV08Xml")) "detached v0.8.0 historical-current tests"
  $toolingHostXml = Join-Path $captureRoot "tooling-host.xml"
  $rootToolingNodes = @($rerouted.Keys | Where-Object {
    $rerouted[$_].StartsWith("locked-windows-host", [StringComparison]::Ordinal)
  })
  Invoke-LockedHostPytest $root @(
    $rootToolingNodes + @("-q", "--junitxml=$toolingHostXml")
  ) "host Git/external-release-dependent tooling tests"
  $toolingXml = Join-Path $captureRoot "tooling.xml"
  $toolingOfflineXml = Join-Path $captureRoot "tooling-offline.xml"

  $soakNodes = @(
    "backend/tests/test_development_authoring_v09.py::test_retained_import_apply_discard_race_and_idempotent_replay",
    "backend/tests/test_development_bundle_builder_v09.py::test_timeout_and_late_worker_leave_no_protocol_or_bundle_output",
    "backend/tests/test_development_bundle_builder_v09.py::test_two_independent_workers_reproduce_exact_bundle_bytes",
    "backend/tests/test_development_history_external_v09.py::test_selected_history_diff_revert_and_three_way_conflict_resolution",
    "backend/tests/test_development_runtime_race_v09.py::test_promoted_runtime_exact_digest_withdrawal_and_existing_pin_continuity",
    "backend/tests/test_development_runtime_race_v09.py::test_sqlite_idempotency_races_and_restart_job_recovery",
    "backend/tests/test_development_service_v09.py::test_running_check_can_be_cancelled_without_partial_publish"
  )
  foreach ($node in $soakNodes) { if ($node -notin $backendNodes) { throw "soak node is absent: $node" } }
  $soakContainer = "$project-backend-v09-soak"
  $soakVolume = "$soakContainer-output"
  $containers.Add($soakContainer)
  $volumes.Add($soakVolume)
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $soakVolume | Out-Null
  Assert-NativeSuccess "cannot create soak output volume"
  $soakCode = @'
import json, pathlib, subprocess, sys, time
output = pathlib.Path(sys.argv.pop(1))
nodes = sys.argv[1:]
if not nodes or len(nodes) != len(set(nodes)):
    raise SystemExit("soak node inventory is empty or contains a duplicate")
runs = []
for iteration in range(1, 6):
    started = time.monotonic()
    completed = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *nodes, "-q"], check=False)
    runs.append({"iteration": iteration, "exit_code": completed.returncode, "duration_seconds": round(time.monotonic() - started, 6)})
document = {"profile":"v09-cross-feature-replay-soak","iterations":5,"nodes":sorted(nodes),"runs":runs,"passed":all(item["exit_code"] == 0 for item in runs)}
output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
raise SystemExit(0 if document["passed"] else 1)
'@
  $soakLauncher = "import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))"
  $soakPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($soakCode))
  $soakArguments = @(
    "create", "--name", $soakContainer, "--label", "com.docker.compose.project=$project", "--network", $network,
    "--read-only", "--tmpfs", "/tmp:size=768m,noexec,nosuid", "--mount", "type=volume,source=$soakVolume,target=/qualification-output",
    "-e", "SPELL_TEST_DATABASE_URL=$applicationUrl", "-e", "SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl",
    $qualificationImage, "python", "-c", $soakLauncher, $soakPayload, "/qualification-output/result.json"
  )
  foreach ($node in $soakNodes) { $soakArguments += [string]$node }
  & $script:DockerExe @soakArguments | Out-Null
  Assert-NativeSuccess "cannot create v0.9 soak container"
  & $script:DockerExe start --attach $soakContainer
  Assert-NativeSuccess "v0.9 replay soak failed"
  $soakJson = Join-Path $captureRoot "backend-v09-soak.json"
  & $script:DockerExe cp "${soakContainer}:/qualification-output/result.json" $soakJson | Out-Null
  Assert-NativeSuccess "cannot copy v0.9 soak capture"

  $nodeCommands = @(Get-Command node -CommandType Application -ErrorAction Stop)
  if ($nodeCommands.Count -eq 0) { throw "Node executable is unavailable" }
  $nodeExe = [string]($nodeCommands[0].Source)
  $nodeBin = Split-Path -Parent $nodeExe
  $npmExe = Join-Path $nodeBin "npm.cmd"
  $npxExe = Join-Path $nodeBin "npx.cmd"
  foreach ($tool in @($nodeExe, $npmExe, $npxExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
      throw "coherent Node toolchain executable is missing: $tool"
    }
  }
  $nodeVersion = @(& $nodeExe --version) -join "`n"
  Assert-NativeSuccess "Node version probe failed"
  $npmVersion = @(& $npmExe --version) -join "`n"
  Assert-NativeSuccess "npm version probe failed"
  Push-Location (Join-Path $candidateRoot "frontend")
  try {
    & $npmExe ci --ignore-scripts --no-audit --no-fund
    Assert-NativeSuccess "frontend npm ci failed"
    & $npxExe playwright install chromium
    Assert-NativeSuccess "pinned Playwright Chromium installation failed"
    $playwrightVersion = @(& $npxExe playwright --version) -join "`n"
    Assert-NativeSuccess "Playwright version probe failed"
    $chromiumPath = @(& $nodeExe -e "const {chromium}=require('playwright'); process.stdout.write(chromium.executablePath())") -join "`n"
    Assert-NativeSuccess "Chromium path probe failed"
    if (-not (Test-Path -LiteralPath $chromiumPath -PathType Leaf)) { throw "Playwright Chromium executable is missing" }
    $chromiumVersion = @(& $nodeExe -e "const {chromium}=require('playwright');(async()=>{const browser=await chromium.launch({headless:true});process.stdout.write(browser.version());await browser.close();})().catch(error=>{console.error(error);process.exit(1)})") -join "`n"
    Assert-NativeSuccess "Chromium runtime version probe failed"
    if (-not $chromiumVersion.Trim()) { throw "Chromium runtime version is empty" }

    $vitestXml = Join-Path $captureRoot "frontend-vitest.xml"
    & $npmExe test -- --reporter=junit "--outputFile=$vitestXml"
    Assert-NativeSuccess "frontend Vitest suite failed"
    & $npmExe run build
    Assert-NativeSuccess "frontend build failed"
    $distRoot = Join-Path $candidateRoot "frontend/dist"
    $outputFiles = @(
      Get-ChildItem -LiteralPath $distRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{
          path = "dist/" + $_.FullName.Substring($distRoot.Length + 1).Replace('\', '/')
          bytes = [int64]$_.Length
          sha256 = Get-LowerSha256 $_.FullName
        }
      }
    )
    if ($outputFiles.Count -eq 0) { throw "frontend build output is empty" }
    $buildCapture = [ordered]@{
      command = "npm run build"
      exit_code = 0
      package_lock_sha256 = Get-LowerSha256 (Join-Path $candidateRoot "frontend/package-lock.json")
      output_files = $outputFiles
      passed = $true
    }
    [IO.File]::WriteAllText((Join-Path $captureRoot "frontend-build.json"), (($buildCapture | ConvertTo-Json -Compress -Depth 20) + "`n"), [Text.UTF8Encoding]::new($false))

    $offlineEnvironmentNames = @(
      "SPELL_V09_OFFLINE_PROOF", "SPELL_V09_OFFLINE_SOURCE_ROOT",
      "SPELL_V09_OFFLINE_NPM_CACHE_VOLUME", "SPELL_V09_OFFLINE_DOCKER_EXE",
      "SPELL_V09_OFFLINE_QUALIFICATION_IMAGE"
    )
    $savedOfflineEnvironment = [ordered]@{}
    foreach ($name in $offlineEnvironmentNames) {
      $savedOfflineEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
      $env:SPELL_V09_OFFLINE_PROOF = "1"
      $env:SPELL_V09_OFFLINE_SOURCE_ROOT = $candidateRoot
      $env:SPELL_V09_OFFLINE_NPM_CACHE_VOLUME = $offlineCacheVolume
      $env:SPELL_V09_OFFLINE_DOCKER_EXE = $script:DockerExe
      $env:SPELL_V09_OFFLINE_QUALIFICATION_IMAGE = $qualificationImage
      Invoke-LockedHostPytest $candidateRoot @(
        $offlineToolingNode, "-q", "--junitxml=$toolingOfflineXml"
      ) "v0.9 offline package qualification"
    }
    finally {
      foreach ($entry in $savedOfflineEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
      $savedOfflineEnvironment = $null
    }
    Merge-JUnit @(
      $toolingBaseXml, $toolingV05Xml, $toolingV06Xml, $toolingLegacyXml,
      $toolingV08Xml, $toolingHostXml, $toolingOfflineXml
    ) $toolingXml

    $savedMockEnvironment = [ordered]@{}
    foreach ($name in @(
      "CI", "SPELL_REAL_BACKEND", "SPELL_E2E_TOKEN",
      "SPELL_E2E_OPERATOR_TOKEN", "SPELL_E2E_ADMIN_TOKEN", "SPELL_E2E_BASE_URL",
      "SPELL_E2E_PREVIEW_PORT", "SPELL_E2E_ARTIFACT_DIRECTORY",
      "SPELL_E2E_OUTPUT_DIRECTORY", "PLAYWRIGHT_JUNIT_OUTPUT_FILE"
    )) {
      $savedMockEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
      if (Get-NetTCPConnection -State Listen -LocalPort 4173 -ErrorAction SilentlyContinue) { throw "required mocked-browser port 4173 is already in use" }
      Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_ADMIN_TOKEN -ErrorAction SilentlyContinue
      $env:CI = "1"
      $env:SPELL_E2E_PREVIEW_PORT = "4173"
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:4173"
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = Join-Path $captureRoot "browser-mocked-artifacts"
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-mocked-output"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = Join-Path $captureRoot "frontend-playwright-mocked.xml"
      & $npxExe playwright test e2e/operator-workspace.spec.ts e2e/driver-projection.spec.ts `
        e2e/data-services.spec.ts e2e/development-workspace.spec.ts `
        --reporter=junit --retries=0
      Assert-NativeSuccess "mocked desktop/mobile Playwright suite failed"
    }
    finally {
      foreach ($entry in $savedMockEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
      $savedMockEnvironment = $null
    }

    foreach ($port in @(8080, 4173)) {
      if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { throw "required loopback port $port is already in use" }
    }
    $browserRoot = Join-Path $captureRoot "browser"
    New-Item -ItemType Directory -Path $browserRoot -Force | Out-Null
    $launcher = Join-Path $scratchRoot "backend-launch.py"
    $launcherBody = @'
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8080, log_level="warning")
'@
    [IO.File]::WriteAllText($launcher, $launcherBody, [Text.UTF8Encoding]::new($false))
    $savedLiveEnvironment = [ordered]@{}
    foreach ($name in @(
      "DATABASE_URL", "SPELL_DATA_DIR", "SPELL_V0007_BACKUP_DIR",
      "SPELL_PROCEDURES_DIR", "SPELL_JWT_HS256_SECRET",
      "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_DRIVER_ENABLED",
      "SPELL_REAL_BACKEND", "SPELL_E2E_TOKEN", "SPELL_E2E_OPERATOR_TOKEN",
      "SPELL_E2E_ADMIN_TOKEN", "SPELL_E2E_BASE_URL",
      "SPELL_E2E_ARTIFACT_DIRECTORY", "SPELL_E2E_OUTPUT_DIRECTORY",
      "SPELL_BROWSER_RUN_ID", "PLAYWRIGHT_JUNIT_OUTPUT_FILE", "CI"
    )) {
      $savedLiveEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
      $dbPath = (Join-Path $scratchRoot "browser.db").Replace('\', '/')
      $liveDataRoot = Join-Path $scratchRoot "browser-data"
      $liveBackupRoot = Join-Path $scratchRoot "browser-migration-backups"
      New-Item -ItemType Directory -Path $liveDataRoot, $liveBackupRoot -Force | Out-Null
      $env:DATABASE_URL = "sqlite:///$dbPath"
      $env:SPELL_DATA_DIR = $liveDataRoot
      $env:SPELL_V0007_BACKUP_DIR = $liveBackupRoot
      $env:SPELL_PROCEDURES_DIR = (Join-Path $candidateRoot "procedures")
      $env:SPELL_JWT_HS256_SECRET = "v09-candidate-jwt-$runId"
      $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "true"
      $env:SPELL_DRIVER_ENABLED = "false"
      $backendStdout = Join-Path $scratchRoot "backend.stdout.log"
      $backendStderr = Join-Path $scratchRoot "backend.stderr.log"
      $frontendStdout = Join-Path $scratchRoot "frontend.stdout.log"
      $frontendStderr = Join-Path $scratchRoot "frontend.stderr.log"
      $backendProcess = Start-Process -FilePath $script:LockedPython -WindowStyle Hidden -PassThru `
        -ArgumentList @("-I", $launcher, $script:SitePackages, $candidateRoot) `
        -RedirectStandardOutput $backendStdout `
        -RedirectStandardError $backendStderr
      $frontendProcess = Start-Process -FilePath $npmExe -WindowStyle Hidden -PassThru `
        -WorkingDirectory (Join-Path $candidateRoot "frontend") `
        -ArgumentList @("run", "preview", "--", "--strictPort", "--host", "127.0.0.1", "--port", "4173") `
        -RedirectStandardOutput $frontendStdout `
        -RedirectStandardError $frontendStderr
      Wait-Http -Uri "http://127.0.0.1:8080/api/v1/health" -Seconds 60 `
        -Process $backendProcess -ProcessLabel "live backend" `
        -LogPaths @($backendStdout, $backendStderr)
      Wait-Http -Uri "http://127.0.0.1:4173/" -Seconds 60 `
        -Process $frontendProcess -ProcessLabel "frontend preview" `
        -LogPaths @($frontendStdout, $frontendStderr)
      Push-Location $candidateRoot
      try {
        $operatorToken = @(
          & $script:LockedPython -I (Join-Path $candidateRoot "scripts/issue_dev_token.py") `
            --subject "v09-candidate-development-author" --role operator --lifetime 600
        ) -join "`n"
        Assert-NativeSuccess "candidate browser operator token issuance failed"
        $adminToken = @(
          & $script:LockedPython -I (Join-Path $candidateRoot "scripts/issue_dev_token.py") `
            --subject "v09-candidate-development-reviewer" --role admin --lifetime 600
        ) -join "`n"
        Assert-NativeSuccess "candidate browser admin token issuance failed"
      }
      finally { Pop-Location }
      if (
        $operatorToken -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' -or
        $adminToken -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' -or
        $operatorToken -ceq $adminToken
      ) { throw "candidate browser role tokens are invalid or not distinct" }
      $env:SPELL_REAL_BACKEND = "1"
      $env:SPELL_E2E_TOKEN = $operatorToken
      $env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken
      $env:SPELL_E2E_ADMIN_TOKEN = $adminToken
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:4173"
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = $browserRoot
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-live-base-output"
      $env:SPELL_BROWSER_RUN_ID = $runId
      $liveBaseXml = Join-Path $captureRoot "frontend-playwright-live-base.xml"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $liveBaseXml
      $env:CI = "1"
      $realSpecs = @(
        "e2e/integration.spec.ts", "e2e/data-services-real.spec.ts"
      )
      & $npxExe playwright test @realSpecs --reporter=junit --retries=0 --workers=1
      Assert-NativeSuccess "candidate-export live desktop/mobile Playwright suite failed"
      $operatorToken = $null
      $adminToken = $null
      Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_ADMIN_TOKEN -ErrorAction SilentlyContinue
    }
    finally {
      $operatorToken = $null
      $adminToken = $null
      Stop-OwnedProcess $frontendProcess
      Stop-OwnedProcess $backendProcess
      $frontendProcess = $null
      $backendProcess = $null
      foreach ($entry in $savedLiveEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
      $savedLiveEnvironment = $null
    }

    $telemetryEnvironmentNames = @(
      "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_BACKEND_IMAGE_ID",
      "SPELL_BROWSER_CAPTURE_DIRECTORY", "SPELL_BROWSER_RUN_ID",
      "SPELL_BROWSER_SECRET_CANARY", "SPELL_DB_PASSWORD", "SPELL_DRIVER_ENABLED",
      "SPELL_DRIVER_IMAGE_ID", "SPELL_E2E_ARTIFACT_DIRECTORY", "SPELL_E2E_BASE_URL",
      "SPELL_E2E_TOKEN", "SPELL_E2E_OPERATOR_TOKEN", "SPELL_E2E_ADMIN_TOKEN",
      "SPELL_E2E_OUTPUT_DIRECTORY", "SPELL_JWT_HS256_SECRET", "SPELL_NPM_VERSION",
      "SPELL_PKI_IMAGE_ID", "SPELL_POSTGRES_IMAGE_ID", "SPELL_PROXY_IMAGE_ID",
      "SPELL_PROXY_PORT", "SPELL_QUALIFICATION_IMAGE_ID", "SPELL_REAL_BACKEND",
      "SPELL_SOURCE_FINGERPRINT", "SPELL_TELEMETRY_CONTEXT_ID",
      "PLAYWRIGHT_JUNIT_OUTPUT_FILE", "CI"
    )
    $savedTelemetryEnvironment = [ordered]@{}
    foreach ($name in $telemetryEnvironmentNames) {
      $savedTelemetryEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
      Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_ADMIN_TOKEN -ErrorAction SilentlyContinue
      $browserFingerprint = (@(
        & $script:LockedPython -I $script:Validator --root $root --fingerprints $SourceCommit
      )[0] | ConvertFrom-Json).source_fingerprint_sha256
      Assert-NativeSuccess "telemetry browser source fingerprint calculation failed"
      if ([string]$browserFingerprint -cnotmatch '^[0-9a-f]{64}$') {
        throw "telemetry browser source fingerprint is invalid"
      }
      $env:SPELL_DB_PASSWORD = "v09-browser-db-$runId"
      $env:SPELL_JWT_HS256_SECRET = "v09-browser-service-secret-$runId"
      $env:SPELL_BROWSER_SECRET_CANARY = $env:SPELL_JWT_HS256_SECRET
      $env:SPELL_DRIVER_ENABLED = "true"
      $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "true"
      $env:SPELL_PROXY_PORT = [string](Get-FreeLoopbackPort)
      $env:SPELL_BROWSER_CAPTURE_DIRECTORY = $browserRoot
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = $browserRoot
      $env:SPELL_BROWSER_RUN_ID = $runId
      $env:SPELL_NPM_VERSION = $npmVersion.Trim()
      $env:SPELL_SOURCE_FINGERPRINT = [string]$browserFingerprint
      $env:SPELL_TELEMETRY_CONTEXT_ID = "v09-telemetry-synthetic-context"
      $env:CI = "1"

      $browserComposeTouched = $true
      Push-Location $candidateRoot
      try {
        & $script:ComposeExe -p $browserProject --profile driver -f compose.yaml `
          up -d --build --wait
        Assert-NativeSuccess "real telemetry browser Compose stack failed to become healthy"
      }
      finally { Pop-Location }

      $env:SPELL_BACKEND_IMAGE_ID = Get-ComposeImageId "backend"
      $builderAImageId = Get-ComposeImageId "bundle-builder-a"
      $builderBImageId = Get-ComposeImageId "bundle-builder-b"
      if (
        $builderAImageId -cne $env:SPELL_BACKEND_IMAGE_ID -or
        $builderBImageId -cne $env:SPELL_BACKEND_IMAGE_ID
      ) { throw "bundle builders do not share the exact backend image" }
      Assert-ComposeServiceNetworkNone "bundle-builder-a"
      Assert-ComposeServiceNetworkNone "bundle-builder-b"
      $env:SPELL_DRIVER_IMAGE_ID = Get-ComposeImageId "spell-driver"
      $env:SPELL_PKI_IMAGE_ID = Get-ComposeImageId "pki-init"
      $env:SPELL_POSTGRES_IMAGE_ID = Get-ComposeImageId "postgres"
      $env:SPELL_PROXY_IMAGE_ID = Get-ComposeImageId "proxy"
      $env:SPELL_QUALIFICATION_IMAGE_ID = $qualificationImage

      $tokenLines = @(
        & $script:ComposeExe -p $browserProject --profile driver `
          -f (Join-Path $candidateRoot "compose.yaml") exec -T backend `
          python /app/scripts/issue_dev_token.py `
          --subject v09-browser-viewer --role viewer --lifetime 600
      )
      Assert-NativeSuccess "real telemetry browser viewer token issuance failed"
      $token = $tokenLines | Where-Object {
        $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
      } | Select-Object -Last 1
      if (-not $token) { throw "real telemetry browser viewer token is invalid" }
      $tokenLines = $null
      $operatorTokenLines = @(
        & $script:ComposeExe -p $browserProject --profile driver `
          -f (Join-Path $candidateRoot "compose.yaml") exec -T backend `
          python /app/scripts/issue_dev_token.py `
          --subject v09-candidate-development-author --role operator --lifetime 600
      )
      Assert-NativeSuccess "real Compose browser operator token issuance failed"
      $operatorToken = $operatorTokenLines | Where-Object {
        $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
      } | Select-Object -Last 1
      $operatorTokenLines = $null
      $adminTokenLines = @(
        & $script:ComposeExe -p $browserProject --profile driver `
          -f (Join-Path $candidateRoot "compose.yaml") exec -T backend `
          python /app/scripts/issue_dev_token.py `
          --subject v09-candidate-development-reviewer --role admin --lifetime 600
      )
      Assert-NativeSuccess "real Compose browser admin token issuance failed"
      $adminToken = $adminTokenLines | Where-Object {
        $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
      } | Select-Object -Last 1
      $adminTokenLines = $null
      if (
        -not $operatorToken -or -not $adminToken -or
        $token -ceq $operatorToken -or $token -ceq $adminToken -or
        $operatorToken -ceq $adminToken
      ) { throw "real Compose browser role tokens are invalid or not distinct" }
      $env:SPELL_E2E_TOKEN = $token
      $env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken
      $env:SPELL_E2E_ADMIN_TOKEN = $adminToken
      $env:SPELL_REAL_BACKEND = "1"
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:$($env:SPELL_PROXY_PORT)"
      $developmentXml = Join-Path $captureRoot "frontend-playwright-live-development.xml"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $developmentXml
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-live-development-output"
      & $npxExe playwright test e2e/development-workspace-real.spec.ts `
        --reporter=junit --retries=0 --workers=1
      Assert-NativeSuccess "real Compose development desktop/mobile Playwright suite failed"

      $seedLines = @(
        & $script:ComposeExe -p $browserProject --profile driver `
          -f (Join-Path $candidateRoot "compose.yaml") exec -T backend `
          python /app/scripts/seed_observation_v07.py `
          --context-id $env:SPELL_TELEMETRY_CONTEXT_ID `
          --confirm LOCAL_SYNTHETIC_NON_CUI_ONLY --timeout-seconds 45
      )
      Assert-NativeSuccess "real telemetry browser observation seed failed"
      $seedJson = $seedLines | Where-Object { $_ -cmatch '^\{.*\}$' } | Select-Object -Last 1
      if (-not $seedJson) { throw "real telemetry browser seed output is invalid" }
      $seed = $seedJson | ConvertFrom-Json
      if (
        $seed.context_id -cne $env:SPELL_TELEMETRY_CONTEXT_ID -or
        @($seed.item_ids).Count -ne 3 -or
        [string]$seed.through_sequence -cnotmatch '^[1-9][0-9]*$'
      ) { throw "real telemetry browser seed identity differs" }

      $headers = @{ Authorization = "Bearer $token" }
      $ready = $false
      $deadline = (Get-Date).AddSeconds(45)
      do {
        try {
          $driverTime = Invoke-RestMethod -Headers $headers `
            -Uri "$($env:SPELL_E2E_BASE_URL)/api/v1/driver-time?context_id=$($env:SPELL_TELEMETRY_CONTEXT_ID)"
          $snapshot = Invoke-RestMethod -Headers $headers `
            -Uri "$($env:SPELL_E2E_BASE_URL)/api/v1/telemetry/snapshot?context_id=$($env:SPELL_TELEMETRY_CONTEXT_ID)"
          $ready = (
            $null -ne $driverTime.driver_time -and
            $snapshot.synchronization_state -ceq "COMPLETE" -and
            @($snapshot.items).Count -eq 3 -and
            @($snapshot.items | Where-Object {
              $_.quality -cne "GOOD" -or $_.validity -cne "VALID" -or
              $_.freshness -cne "FRESH" -or $null -eq $_.alarm
            }).Count -eq 0
          )
        }
        catch { $ready = $false }
        if (-not $ready) { Start-Sleep -Milliseconds 250 }
      } until ($ready -or (Get-Date) -ge $deadline)
      if (-not $ready) { throw "real telemetry browser projection did not become ready" }

      $telemetryXml = Join-Path $captureRoot "frontend-playwright-live-telemetry.xml"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $telemetryXml
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-live-telemetry-output"
      & $npxExe playwright test e2e/telemetry-observation-real.spec.ts `
        --reporter=junit --retries=0 --workers=1
      Assert-NativeSuccess "real telemetry desktop/mobile Playwright suite failed"
      Merge-JavaScriptJUnit @($liveBaseXml, $developmentXml) `
        (Join-Path $captureRoot "frontend-playwright-live.xml")
      $token = $null
      $operatorToken = $null
      $adminToken = $null
    }
    finally {
      $tokenLines = $null
      $operatorTokenLines = $null
      $adminTokenLines = $null
      $token = $null
      $operatorToken = $null
      $adminToken = $null
      if ($browserComposeTouched) {
        $down = Invoke-ComposeCleanup @(
          "-p", $browserProject, "--profile", "driver",
          "-f", (Join-Path $candidateRoot "compose.yaml"),
          "down", "--rmi", "local", "-v", "--remove-orphans"
        )
        $browserCleanupFailed = $down.ExitCode -ne 0
        if (-not $browserCleanupFailed) { $browserComposeTouched = $false }
      }
      foreach ($entry in $savedTelemetryEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
      $savedTelemetryEnvironment = $null
    }
  }
  finally { Pop-Location }
}
catch { $failure = $_ }
finally {
  Stop-OwnedProcess $frontendProcess
  Stop-OwnedProcess $backendProcess
  if ($browserComposeTouched) {
    $down = Invoke-ComposeCleanup @(
      "-p", $browserProject, "--profile", "driver",
      "-f", (Join-Path $candidateRoot "compose.yaml"),
      "down", "--rmi", "local", "-v", "--remove-orphans"
    )
    $browserCleanupFailed = $down.ExitCode -ne 0
    if (-not $browserCleanupFailed) { $browserComposeTouched = $false }
  }
  foreach ($container in $containers) { Invoke-DockerCleanup @("rm", "-f", $container) | Out-Null }
  foreach ($volume in $volumes) { Invoke-DockerCleanup @("volume", "rm", "-f", $volume) | Out-Null }
  Invoke-DockerCleanup @("network", "rm", $network) | Out-Null
  foreach ($tag in $imageTags) { Invoke-DockerCleanup @("image", "rm", $tag) | Out-Null }
  if ($null -ne $runtimeBaseline) { $runtimeResourcesTornDown = Remove-NewRuntimeResources $runtimeBaseline }
  try {
    $remainingContainers = @(Get-DockerInspectionLines `
      -Arguments @("ps", "-aq", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate container cleanup") + @(Get-DockerInspectionLines `
      -Arguments @("ps", "-aq", "--filter", "label=com.docker.compose.project=$browserProject") `
      -Label "telemetry browser container cleanup")
    $remainingNetworks = @(Get-DockerInspectionLines `
      -Arguments @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate network cleanup") + @(Get-DockerInspectionLines `
      -Arguments @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$browserProject") `
      -Label "telemetry browser network cleanup")
    $remainingVolumes = @(Get-DockerInspectionLines `
      -Arguments @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate volume cleanup") + @(Get-DockerInspectionLines `
      -Arguments @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$browserProject") `
      -Label "telemetry browser volume cleanup")
    $remainingImages = @(Get-DockerInspectionLines `
      -Arguments @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate image cleanup") + @(Get-DockerInspectionLines `
      -Arguments @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$browserProject") `
      -Label "telemetry browser image cleanup")
    $resourcesTornDown = -not $browserCleanupFailed -and @($remainingContainers | Where-Object { $_ }).Count -eq 0 -and @($remainingNetworks | Where-Object { $_ }).Count -eq 0 -and @($remainingVolumes | Where-Object { $_ }).Count -eq 0
    $imageTagsRemoved = -not $browserCleanupFailed -and @($remainingImages | Where-Object { $_ }).Count -eq 0
  }
  catch {
    $cleanupInspectionFailure = $_
    $resourcesTornDown = $false
    $imageTagsRemoved = $false
  }
  $runtimeProcessesStopped = -not (Get-NetTCPConnection -State Listen -LocalPort 8080,4173 -ErrorAction SilentlyContinue)
  if ($legacyV08RootOwned) {
    $savedErrorAction = $ErrorActionPreference
    try {
      $ErrorActionPreference = "Continue"
      & git -C $root worktree remove --force $legacyV08Root 2>$null | Out-Null
      $legacyV08CleanupFailed = $LASTEXITCODE -ne 0
      if (-not $legacyV08CleanupFailed) { $legacyV08RootOwned = $false }
    }
    finally { $ErrorActionPreference = $savedErrorAction }
  }
  if ($legacyRootOwned) {
    $savedErrorAction = $ErrorActionPreference
    try {
      $ErrorActionPreference = "Continue"
      & git -C $root worktree remove --force $legacyRoot 2>$null | Out-Null
      $legacyCleanupFailed = $LASTEXITCODE -ne 0
      if (-not $legacyCleanupFailed) { $legacyRootOwned = $false }
    }
    finally { $ErrorActionPreference = $savedErrorAction }
  }
  if ($legacyV06RootOwned) {
    $savedErrorAction = $ErrorActionPreference
    try {
      $ErrorActionPreference = "Continue"
      & git -C $root worktree remove --force $legacyV06Root 2>$null | Out-Null
      $legacyV06CleanupFailed = $LASTEXITCODE -ne 0
      if (-not $legacyV06CleanupFailed) { $legacyV06RootOwned = $false }
    }
    finally { $ErrorActionPreference = $savedErrorAction }
  }
  if ($legacyV05RootOwned) {
    $savedErrorAction = $ErrorActionPreference
    try {
      $ErrorActionPreference = "Continue"
      & git -C $root worktree remove --force $legacyV05Root 2>$null | Out-Null
      $legacyV05CleanupFailed = $LASTEXITCODE -ne 0
      if (-not $legacyV05CleanupFailed) { $legacyV05RootOwned = $false }
    }
    finally { $ErrorActionPreference = $savedErrorAction }
  }
  Pop-Location
}

if ($failure) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  $cleanupMessages = @()
  if ($legacyV08CleanupFailed) { $cleanupMessages += "v0.8.0 historical checkout teardown failed" }
  if ($legacyCleanupFailed) { $cleanupMessages += "v0.7.0 historical checkout teardown failed" }
  if ($legacyV06CleanupFailed) { $cleanupMessages += "v0.6.0 historical checkout teardown failed" }
  if ($legacyV05CleanupFailed) { $cleanupMessages += "v0.5.0 historical checkout teardown failed" }
  if ($browserCleanupFailed) { $cleanupMessages += "real telemetry browser Compose teardown failed" }
  if ($cleanupInspectionFailure) { $cleanupMessages += $cleanupInspectionFailure.Exception.Message }
  if ($cleanupMessages.Count -gt 0) {
    throw "candidate qualification failed: $($failure.Exception.Message); cleanup also failed: $($cleanupMessages -join '; ')"
  }
  throw $failure
}
if ($legacyCleanupFailed) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "v0.7.0 historical checkout teardown failed"
}
if ($legacyV06CleanupFailed) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "v0.6.0 historical checkout teardown failed"
}
if ($legacyV05CleanupFailed) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "v0.5.0 historical checkout teardown failed"
}
if ($browserCleanupFailed) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "real telemetry browser Compose teardown failed"
}
if ($cleanupInspectionFailure) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw $cleanupInspectionFailure
}
if (-not $resourcesTornDown -or -not $runtimeResourcesTornDown -or -not $runtimeProcessesStopped -or -not $imageTagsRemoved) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "candidate qualification teardown verification failed"
}

try {
  New-Item -ItemType Directory -Path (Join-Path $stageRoot "tests"), (Join-Path $stageRoot "browser") -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $candidateRoot "artifacts/v0.9/work-package/schema.json") -Destination (Join-Path $stageRoot "schema.json")
  $captureMap = [ordered]@{
    "tests/backend-sqlite.xml" = Join-Path $captureRoot "backend-sqlite.xml"
    "tests/backend-postgresql.xml" = Join-Path $captureRoot "backend-postgresql.xml"
    "tests/backend-docker-host.xml" = Join-Path $captureRoot "backend-docker-host.xml"
    "tests/backend-v09-soak.json" = Join-Path $captureRoot "backend-v09-soak.json"
    "tests/driver-host.xml" = Join-Path $captureRoot "driver-host.xml"
    "tests/tooling.xml" = Join-Path $captureRoot "tooling.xml"
    "tests/frontend-vitest.xml" = Join-Path $captureRoot "frontend-vitest.xml"
    "tests/frontend-build.json" = Join-Path $captureRoot "frontend-build.json"
    "tests/frontend-playwright-mocked.xml" = Join-Path $captureRoot "frontend-playwright-mocked.xml"
    "tests/frontend-playwright-live.xml" = Join-Path $captureRoot "frontend-playwright-live.xml"
    "browser/desktop-as-run-report.png" = Join-Path $captureRoot "browser/desktop-as-run-report.png"
    "browser/desktop-v03-validation.png" = Join-Path $captureRoot "browser/desktop-v03-validation.png"
    "browser/mobile-durable-prompt.png" = Join-Path $captureRoot "browser/mobile-durable-prompt.png"
    "browser/v09-development-real-chromium.png" = Join-Path $captureRoot "browser/v09-development-real-chromium.png"
    "browser/v09-development-real-mobile.png" = Join-Path $captureRoot "browser/v09-development-real-mobile.png"
    "browser/v09-development-real-continuity-chromium.png" = Join-Path $captureRoot "browser/v09-development-real-continuity-chromium.png"
    "browser/v09-development-real-continuity-mobile.png" = Join-Path $captureRoot "browser/v09-development-real-continuity-mobile.png"
    "browser/telemetry-observation-desktop.png" = Join-Path $captureRoot "browser/telemetry-observation-desktop.png"
    "browser/telemetry-observation-mobile.png" = Join-Path $captureRoot "browser/telemetry-observation-mobile.png"
    "browser/telemetry-observation-desktop.json" = Join-Path $captureRoot "browser/telemetry-observation-desktop.json"
    "browser/telemetry-observation-mobile.json" = Join-Path $captureRoot "browser/telemetry-observation-mobile.json"
  }
  foreach ($entry in $captureMap.GetEnumerator()) {
    if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) { throw "required capture is missing: $($entry.Key)" }
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $stageRoot $entry.Key)
  }

  $sqliteSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/backend-sqlite.xml") "python"
  $postgresSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/backend-postgresql.xml") "python"
  $dockerSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/backend-docker-host.xml") "python"
  $driverSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/driver-host.xml") "python"
  $toolingSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/tooling.xml") "python"
  $vitestSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/frontend-vitest.xml") "javascript"
  $mockedSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/frontend-playwright-mocked.xml") "javascript"
  $liveSummary = Get-JUnitFragment (Join-Path $stageRoot "tests/frontend-playwright-live.xml") "javascript"
  foreach ($frozen in @(
    @($vitestSummary, 105, "81667150bb1df07891eebfb7bf06a852e007554bdc6ba17ec18437abec495899", "frontend Vitest"),
    @($mockedSummary, 20, "10ad9cd8182a116b3ce3570cba7cd7d20b654f10c2859c4d1a9c7371a10f1f3b", "mocked browser"),
    @($liveSummary, 14, "65995d29961887422abeba749ab726ae884bccebfb84c5896c6610a3a67e8fad", "live browser")
  )) {
    if (
      @($frozen[0].collected_nodes).Count -ne [int]$frozen[1] -or
      (Get-InventoryDigest @($frozen[0].collected_nodes)) -cne [string]$frozen[2]
    ) { throw "$($frozen[3]) differs from the frozen v0.9 inventory" }
  }
  Assert-ExactInventory $backendNodes $sqliteSummary.collected_nodes "backend SQLite"
  Assert-ExactInventory $backendNodes $postgresSummary.collected_nodes "backend PostgreSQL"
  Assert-ExactInventory $dockerNodes $dockerSummary.collected_nodes "backend Docker host"
  Assert-ExactInventory $driverNodes $driverSummary.collected_nodes "driver host"
  Assert-ExactInventory $toolingNodes $toolingSummary.collected_nodes "tooling"

  $soak = Get-Content -LiteralPath (Join-Path $stageRoot "tests/backend-v09-soak.json") -Raw | ConvertFrom-Json
  $soakDuration = [Math]::Round([double](($soak.runs | Measure-Object -Property duration_seconds -Sum).Sum), 6)
  $soakSummary = [pscustomobject]@{
    collected_nodes = @($soak.nodes); inventory_sha256 = Get-InventoryDigest @($soak.nodes)
    test_count = [int]$soak.iterations * @($soak.nodes).Count; subtest_count = 0; passed_count = [int]$soak.iterations * @($soak.nodes).Count
    skipped_count = 0; failure_count = 0; error_count = 0; duration_seconds = $soakDuration
  }
  $build = Get-Content -LiteralPath (Join-Path $stageRoot "tests/frontend-build.json") -Raw | ConvertFrom-Json
  $buildSummary = [pscustomobject]@{
    collected_nodes = @("frontend::npm-run-build"); inventory_sha256 = Get-InventoryDigest @("frontend::npm-run-build")
    test_count = 1; subtest_count = 0; passed_count = 1; skipped_count = 0; failure_count = 0; error_count = 0; duration_seconds = 0.0
  }
  $suites = [ordered]@{
    backend_sqlite = New-SuiteRecord "backend_sqlite" "python" "tests/backend-sqlite.xml" $sqliteSummary "none"
    backend_postgresql = New-SuiteRecord "backend_postgresql" "python" "tests/backend-postgresql.xml" $postgresSummary "internal"
    backend_docker_host = New-SuiteRecord "backend_docker_host" "python" "tests/backend-docker-host.xml" $dockerSummary "host-docker-inspection"
    backend_v09_soak = New-SuiteRecord "backend_v09_soak" "soak" "tests/backend-v09-soak.json" $soakSummary "internal"
    driver_host = New-SuiteRecord "driver_host" "python" "tests/driver-host.xml" $driverSummary "none"
    tooling = New-SuiteRecord "tooling" "python" "tests/tooling.xml" $toolingSummary "none"
    frontend_vitest = New-SuiteRecord "frontend_vitest" "javascript" "tests/frontend-vitest.xml" $vitestSummary "none"
    frontend_build = New-SuiteRecord "frontend_build" "build" "tests/frontend-build.json" $buildSummary "none"
    frontend_playwright_mocked = New-SuiteRecord "frontend_playwright_mocked" "javascript" "tests/frontend-playwright-mocked.xml" $mockedSummary "loopback-mocked"
    frontend_playwright_live = New-SuiteRecord "frontend_playwright_live" "javascript" "tests/frontend-playwright-live.xml" $liveSummary "loopback-live-backend"
  }
  $identityLines = @(& $script:LockedPython -I $script:Validator --identity-map `
    --junit "backend_sqlite=python=$(Join-Path $stageRoot 'tests/backend-sqlite.xml')" `
    --junit "backend_postgresql=python=$(Join-Path $stageRoot 'tests/backend-postgresql.xml')" `
    --junit "backend_docker_host=python=$(Join-Path $stageRoot 'tests/backend-docker-host.xml')" `
    --junit "driver_host=python=$(Join-Path $stageRoot 'tests/driver-host.xml')" `
    --junit "tooling=python=$(Join-Path $stageRoot 'tests/tooling.xml')" `
    --junit "frontend_vitest=javascript=$(Join-Path $stageRoot 'tests/frontend-vitest.xml')" `
    --junit "frontend_playwright_mocked=javascript=$(Join-Path $stageRoot 'tests/frontend-playwright-mocked.xml')" `
    --junit "frontend_playwright_live=javascript=$(Join-Path $stageRoot 'tests/frontend-playwright-live.xml')")
  Assert-NativeSuccess "45-ID concrete proof expansion failed"
  if ($identityLines.Count -ne 1) { throw "45-ID concrete proof output differs" }
  $workPackages = $identityLines[0] | ConvertFrom-Json

  $fingerprints = (@(& $script:LockedPython -I $script:Validator --root $root --fingerprints $SourceCommit)[0] | ConvertFrom-Json)
  Assert-NativeSuccess "source fingerprint calculation failed"
  $sourceTree = (git rev-parse "$SourceCommit^{tree}").Trim()
  $sourceParent = (git show -s --format=%P $SourceCommit).Trim()
  $baselineV08 = (@(& $script:LockedPython -I $script:Validator --root $root --tree-fingerprint v0.8.0 artifacts/v0.8)[0] | ConvertFrom-Json).sha256
  $sourceV08 = (@(& $script:LockedPython -I $script:Validator --root $root --tree-fingerprint $SourceCommit artifacts/v0.8)[0] | ConvertFrom-Json).sha256

  $gatePaths = @(
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.9-gate-0a.json",
    "SPELL_v0.9_Pre-Implementation.md",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v09_gate_0a.py"
  )
  $gateHashes = [ordered]@{}
  foreach ($path in $gatePaths) { $gateHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }
  $contractPaths = @(
    "contracts/v09/manifest.json", "contracts/v09/project_workspace.json",
    "contracts/v09/language_services.json", "contracts/v09/dictionary_catalog_authoring.json",
    "contracts/v09/semantic_checks.json", "contracts/v09/import_export_external_changes.json",
    "contracts/v09/collaboration_history.json", "contracts/v09/immutable_bundles.json",
    "contracts/v09/promotion_registry.json"
  )
  $contractHashes = [ordered]@{}
  foreach ($path in $contractPaths) { $contractHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }
  $toolchainPaths = @(
    "scripts/release-toolchain-v04.json", "scripts/qualification-v09.Dockerfile",
    "scripts/qualification-v09.Dockerfile.dockerignore", "frontend/package-lock.json",
    "artifacts/v0.9/work-package/schema.json"
  )
  $toolchainHashes = [ordered]@{}
  foreach ($path in $toolchainPaths) { $toolchainHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }

  $toolingSkips = @($toolingSummary.skipped_nodes)
  $skipRecords = @(
    $toolingSkips | ForEach-Object {
      $reason = if ($_ -like "*supply_chain_v04.py*") { "WINDOWS_POWERSHELL_HOST_CONTRACT_NOT_APPLICABLE_IN_LOCKED_LINUX_IMAGE" }
        elseif ($_ -like "*release_v05.py*" -or $_ -like "*release_v06.py*" -or $_ -like "*release_v07.py*" -or $_ -like "*release_v09.py*" -or $_ -like "*qualify_release_v04.py*" -or $_ -like "*qualify_release_v05.py*" -or $_ -like "*qualify_release_v06.py*" -or $_ -like "*qualify_release_v07.py*" -or $_ -like "*qualify_release_v09.py*") { "POWERSHELL_UNAVAILABLE_IN_LOCKED_LINUX_IMAGE" }
        else { "OPERATING_SYSTEM_SPECIFIC_CONTRACT_NOT_APPLICABLE_IN_LOCKED_LINUX_IMAGE" }
      [ordered]@{ node = [string]$_; reason = $reason }
    }
  )
  $rerouteRecords = @($rerouted.GetEnumerator() | ForEach-Object { [ordered]@{ node = $_.Key; execution_source = $_.Value; status = "passed" } })
  $allIdentities = @()
  foreach ($package in $workPackages.PSObject.Properties) { $allIdentities += @($package.Value.test_ids.PSObject.Properties.Name) }
  function New-AssuranceRecord([string[]]$Suffixes) {
    [string[]]$ids = Get-OrdinalSortedStrings @($allIdentities | Where-Object { $id = $_; @($Suffixes | Where-Object { $id.EndsWith($_, [StringComparison]::Ordinal) }).Count -gt 0 })
    $proofCount = 0
    foreach ($id in $ids) {
      if ($id -cnotmatch '^(V09-DEV-00[1-9])-[A-Z0-9-]+$') {
        throw "work-package test identity is invalid: $id"
      }
      $packageId = $Matches[1]
      $proofCount += @($workPackages.$packageId.test_ids.$id.proofs).Count
    }
    return [ordered]@{ test_ids = $ids; proof_count = $proofCount; all_pass = $true }
  }
  $durationMap = [ordered]@{}
  foreach ($suite in $suites.GetEnumerator()) { $durationMap[$suite.Key] = [double]$suite.Value.duration_seconds }
  $totalDuration = [Math]::Round([double](($durationMap.Values | Measure-Object -Sum).Sum), 6)

  $artifactHashes = [ordered]@{ "schema.json" = Get-LowerSha256 (Join-Path $stageRoot "schema.json") }
  foreach ($entry in $captureMap.GetEnumerator()) { $artifactHashes[$entry.Key] = Get-LowerSha256 (Join-Path $stageRoot $entry.Key) }
  $manifest = [ordered]@{
    schema_version = "spell.v09.candidate-qualification/1"
    product_version = "0.9.0-candidate"
    scope_profile = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
    source = [ordered]@{
      commit = $SourceCommit; tree = $sourceTree; parent = $sourceParent
      source_fingerprint_sha256 = [string]$fingerprints.source_fingerprint_sha256
      product_fingerprint_sha256 = [string]$fingerprints.product_fingerprint_sha256
    }
    gate_0a = [ordered]@{ gate_id = "V09-GATE-0A"; status = "PASS"; validator_output = $gateMarker; owner_marker = "V09-GATE-0A OWNER-APPROVAL: APPROVED"; files_sha256 = $gateHashes }
    contracts = [ordered]@{ manifest_schema = "spell.v09.contract-manifest/1"; files_sha256 = $contractHashes }
    toolchain = [ordered]@{
      python = "3.13.14"; docker = (& $script:DockerExe version --format "{{.Client.Version}}").Trim()
      node = $nodeVersion.Trim(); npm = $npmVersion.Trim(); playwright = $playwrightVersion.Trim(); chromium = $chromiumVersion.Trim()
      files_sha256 = $toolchainHashes; qualification_image_id = $qualificationImage
    }
    database = [ordered]@{
      application_name = "spell_test"; migration_name = "spell_migration_test"; distinct_names = $true
      both_environment_variables_bound = $true; postgresql_zero_skips = $true; network_internal = $true
      host_port_published = $false; postgres_image_id = $postgresImage
    }
    suites = $suites
    work_packages = $workPackages
    assurance = [ordered]@{
      fault_recovery = New-AssuranceRecord @("RECOVERY", "FAULT-RECOVERY")
      security = New-AssuranceRecord @("SECURITY")
      concurrency = New-AssuranceRecord @("RACE")
      performance = [ordered]@{
        profile = "BOUNDED_CANDIDATE_QUALIFICATION"; suite_duration_seconds = $durationMap
        total_duration_seconds = $totalDuration; maximum_suite_seconds = 900.0
        replay_inventory_bijection = $true; soak_iterations = [int]$soak.iterations; all_pass = $true
      }
    }
    historical_platform_skips = [ordered]@{
      classification = "EXPLICIT_PLATFORM_SKIPS_AND_EXECUTED_SOURCE_SCOPED_REROUTES"
      skipped_nodes = $skipRecords; rerouted_tests = $rerouteRecords
      mapped_test_ids_skipped = @(); accepted_failures = @()
    }
    v0_8_immutability = [ordered]@{
      baseline_tag = "v0.8.0"; baseline_tree_fingerprint_sha256 = [string]$baselineV08
      source_tree_fingerprint_sha256 = [string]$sourceV08; git_diff_empty = $true
      accepted_archive_path = "artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz"
      accepted_archive_sha256 = "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
      accepted_sidecar_path = "artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256"
      accepted_sidecar_sha256 = "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
      accepted_tag_object = "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae"
      accepted_tag_archive_claim = "Final archive SHA-256: 87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
    }
    secret_scan = [ordered]@{
      scanner = "validate_candidate_evidence_v09.py/bounded-patterns-1"
      files_scanned = $artifactHashes.Count; findings = @(); waivers = @(); passed = $true
    }
    artifacts = $artifactHashes
    teardown = [ordered]@{
      project = $project; resources_torn_down = $true; runtime_processes_stopped = $true
      image_tags_removed = $true; scratch_removed = $true
    }
    overall_pass = $true
  }
  [IO.File]::WriteAllText((Join-Path $stageRoot "qualification.json"), (($manifest | ConvertTo-Json -Compress -Depth 100) + "`n"), [Text.UTF8Encoding]::new($false))
  $databasePassword = $null
  $applicationUrl = $null
  $migrationUrl = $null
  Remove-Item -LiteralPath $scratchRoot -Recurse -Force
  $savedErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $validation = @(& $script:LockedPython -I $script:Validator --root $root --evidence-root $stageRoot 2>&1)
    $validationExitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedErrorAction }
  if ($validationExitCode -ne 0) {
    throw "candidate staging evidence validation failed: $($validation -join '; ')"
  }
  if ($validation.Count -ne 1) { throw "candidate validator output differs" }

  $existingManifest = Join-Path $canonicalRoot "qualification.json"
  if ((Test-Path -LiteralPath $existingManifest) -and -not $Replace) { throw "candidate evidence already exists; pass -Replace to republish" }
  if (Test-Path -LiteralPath $canonicalRoot) { Move-Item -LiteralPath $canonicalRoot -Destination $backupRoot }
  try {
    Move-Item -LiteralPath $stageRoot -Destination $canonicalRoot
    & $script:LockedPython -I $script:Validator --root $root --evidence-root $canonicalRoot | Out-Null
    Assert-NativeSuccess "published candidate evidence validation failed"
    if (Test-Path -LiteralPath $backupRoot) { Remove-Item -LiteralPath $backupRoot -Recurse -Force }
  }
  catch {
    if (Test-Path -LiteralPath $canonicalRoot) { Remove-Item -LiteralPath $canonicalRoot -Recurse -Force }
    if (Test-Path -LiteralPath $backupRoot) { Move-Item -LiteralPath $backupRoot -Destination $canonicalRoot }
    throw
  }
  $finalValidation = @(& $script:LockedPython -I $script:Validator --root $root --evidence-root $canonicalRoot)
  Assert-NativeSuccess "final candidate evidence validation failed"
  Write-Output $finalValidation
}
finally {
  if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
}
