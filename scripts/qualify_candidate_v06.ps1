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
$project = "spell-v06-candidate-$runId"
$qualificationTag = "openbexi-spell-v06-candidate-qualification:$runId"
$postgresTag = "openbexi-spell-v06-candidate-postgres:$runId"
$network = "$project-internal"
$postgresContainer = "$project-postgres"
$postgresVolume = "$project-postgres-data"
$artifactRoot = Join-Path $root "artifacts/v0.6"
$scratchRoot = Join-Path $artifactRoot ".qualification/candidate-$runId"
$candidateRoot = Join-Path $scratchRoot "source"
$legacyRoot = Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"
$legacyRootFull = [IO.Path]::GetFullPath($legacyRoot)
$tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $legacyRootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
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
$legacyRootOwned = $false
$legacyCleanupFailed = $false
$cleanupInspectionFailure = $null

if ($LocalConfirmation -cne "LOCAL_SYNTHETIC_NON_CUI_ONLY") {
  throw "v0.6 candidate qualification requires the exact local synthetic non-CUI confirmation"
}

function Assert-NativeSuccess([string]$Message) {
  if ($LASTEXITCODE -ne 0) { throw $Message }
}

function Get-LowerSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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

function Get-CollectedNodes([string]$Suite, [string]$Prefix) {
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

function Wait-Http([string]$Uri, [int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
      if ($response.StatusCode -eq 200) { return }
    }
    catch { Start-Sleep -Milliseconds 250 }
  } until ((Get-Date) -ge $deadline)
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
$script:LockedPython = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
$script:SitePackages = Join-Path $env:TEMP "openbexi-spell-v05-py313-site"
$script:Validator = Join-Path $root "scripts/validate_candidate_evidence_v06.py"
if (-not (Test-Path -LiteralPath $script:SitePackages -PathType Container)) { throw "locked CPython host dependency site is missing" }

Push-Location $root
try {
  $resolvedSource = (git rev-parse --verify "$SourceCommit^{commit}").Trim()
  Assert-NativeSuccess "source commit lookup failed"
  if ($resolvedSource -cne $SourceCommit) { throw "source commit is not the exact supplied object" }
  $head = (git rev-parse --verify HEAD).Trim()
  Assert-NativeSuccess "HEAD lookup failed"
  if ($head -cne $SourceCommit) { throw "candidate qualification requires HEAD at the explicit source commit" }
  $status = @(git status --porcelain=v1 --untracked-files=all)
  Assert-NativeSuccess "worktree status lookup failed"
  if ($status.Count -ne 0) { throw "candidate qualification requires a clean explicit source freeze" }
  git merge-base --is-ancestor v0.5.0 $SourceCommit
  Assert-NativeSuccess "v0.5.0 is not an ancestor of the candidate source"
  git diff --quiet v0.5.0 $SourceCommit -- artifacts/v0.5
  Assert-NativeSuccess "tracked v0.5 artifacts changed in the candidate source"
  & $script:LockedPython -I (Join-Path $root "scripts/accepted_v05_release_v06.py") --root $root | Out-Null
  Assert-NativeSuccess "accepted external v0.5 release validation failed"

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

  if (Test-Path -LiteralPath $legacyRoot) { throw "v0.5.0 historical checkout path already exists" }
  git -C $root worktree add --detach --quiet $legacyRoot v0.5.0
  Assert-NativeSuccess "v0.5.0 detached worktree checkout failed"
  $legacyRootOwned = $true
  $legacyHead = (git -C $legacyRoot rev-parse HEAD).Trim()
  if ($legacyHead -cne "e7b6bb9428833437e0160040541eb840deee7cca") { throw "v0.5.0 detached export identity differs" }
  $legacyManualRoot = Join-Path $legacyRoot "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $legacyManualRoot) {
    throw "v0.5.0 detached export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $legacyManualRoot -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $legacyManual = Join-Path $legacyManualRoot $entry.Key
    if (
      -not (Test-Path -LiteralPath $legacyManual -PathType Leaf) -or
      ((Get-Item -LiteralPath $legacyManual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $legacyManual) -cne $entry.Value
    ) { throw "v0.5.0 staged external manual differs: $($entry.Key)" }
  }
  $acceptedArchiveSha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
  $acceptedSidecarSha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
  $acceptedSidecarText = "$acceptedArchiveSha256  openbexi-spell-v0.5.0.tar.gz`n"
  foreach ($releaseName in @("openbexi-spell-v0.5.0.tar.gz", "openbexi-spell-v0.5.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.5/$releaseName"
    if (-not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or (Get-Item -LiteralPath $releaseSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
      throw "v0.5.0 canonical release input is missing or unsafe: $releaseName"
    }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $acceptedSidecarSha256
    } else { $acceptedArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "v0.5.0 canonical release input hash differs: $releaseName"
    }
    $releaseDestination = Join-Path $legacyRoot "artifacts/v0.5/$releaseName"
    Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
    if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
      throw "v0.5.0 staged release input hash differs: $releaseName"
    }
  }
  if ([IO.File]::ReadAllText((Join-Path $legacyRoot "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $acceptedSidecarText) {
    throw "v0.5.0 staged release sidecar bytes differ"
  }
  $inheritedRelative = "artifacts/v0.4/.qualification/runtime-captures/46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d/regression"
  $inheritedSource = Join-Path $root $inheritedRelative
  if (-not (Test-Path -LiteralPath $inheritedSource -PathType Container) -or
      (Get-Item -LiteralPath $inheritedSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
      @(Get-ChildItem -LiteralPath $inheritedSource -Recurse -Force | Where-Object { $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) }).Count -ne 0) {
    throw "v0.5.0 inherited regression input is missing or unsafe"
  }
  $inheritedDestination = Join-Path $legacyRoot $inheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $inheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $inheritedSource -Destination $inheritedDestination -Recurse

  $gateOutput = @(& $script:LockedPython -I (Join-Path $root "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0a.py"))
  Assert-NativeSuccess "Gate 0A validation failed"
  $gateMarker = "gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0"
  if (@($gateOutput | Where-Object { $_ -ceq $gateMarker }).Count -ne 1) { throw "Gate 0A success marker differs" }

  $runtimeBaseline = Get-RuntimeResources
  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    --label "org.openbexi.spell.v06.source.commit=$SourceCommit" `
    -f (Join-Path $candidateRoot "scripts/qualification-v06.Dockerfile") `
    -t $qualificationTag $candidateRoot
  Assert-NativeSuccess "candidate qualification image build failed"
  $script:QualificationImage = (& $script:DockerExe image inspect $qualificationTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "candidate qualification image lookup failed"
  if ($script:QualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "qualification image identity is invalid" }
  $qualificationImage = $script:QualificationImage
  $runtimeVersion = @(& $script:DockerExe run --rm --network none --read-only --entrypoint python $qualificationImage --version) -join "`n"
  Assert-NativeSuccess "qualification runtime probe failed"
  if ($runtimeVersion.Trim() -cne "Python 3.13.14") { throw "qualification image is not Python 3.13.14" }

  $backendNodes = Get-CollectedNodes "backend/tests" "backend/tests/"
  $driverNodes = Get-CollectedNodes "driver_host/tests" "driver_host/tests/"
  $toolingNodes = Get-CollectedNodes "scripts/tests" "scripts/tests/"

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
  $databasePassword = "v06-candidate-pg-$runId"
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
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access"
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
    "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar" = "locked-windows-host"
    "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell" = "locked-windows-host"
    "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably" = "locked-windows-host"
  }
  $toolingBaseXml = Join-Path $captureRoot "tooling-base.xml"
  $toolingArguments = @("scripts/tests", "-q")
  foreach ($node in $rerouted.Keys) { $toolingArguments += "--deselect=$node" }
  $toolingArguments += "--junitxml=/qualification-output/result.xml"
  Invoke-ImagePytest "tooling" "none" @("PYTHONDONTWRITEBYTECODE=1") $toolingArguments $toolingBaseXml
  $toolingLegacyXml = Join-Path $captureRoot "tooling-v05.xml"
  $legacyNodes = @($rerouted.Keys | Where-Object { $rerouted[$_] -ceq "v0.5.0-export" })
  Invoke-LockedHostPytest $legacyRoot @($legacyNodes + @("-q", "--junitxml=$toolingLegacyXml")) "detached v0.5.0 historical-current tests"
  $toolingHostXml = Join-Path $captureRoot "tooling-host.xml"
  $rootToolingNodes = @($rerouted.Keys | Where-Object {
    $rerouted[$_].StartsWith("locked-windows-host", [StringComparison]::Ordinal)
  })
  Invoke-LockedHostPytest $root @(
    $rootToolingNodes + @("-q", "--junitxml=$toolingHostXml")
  ) "host Git/external-release-dependent tooling tests"
  $toolingXml = Join-Path $captureRoot "tooling.xml"
  Merge-JUnit @($toolingBaseXml, $toolingLegacyXml, $toolingHostXml) $toolingXml

  $soakNodes = @(
    "backend/tests/test_supervisor_v06_runtime.py::test_concurrent_command_delivery_queues_one_application_revision",
    "backend/tests/test_v06_operator_workspace.py::test_cross_feature_application_reservation_prevents_lost_update",
    "backend/tests/test_v06_operator_workspace.py::test_prompt_controller_loss_grace_starts_at_loss_and_reacquire_clears_it"
  )
  foreach ($node in $soakNodes) { if ($node -notin $backendNodes) { throw "soak node is absent: $node" } }
  $soakContainer = "$project-backend-v06-soak"
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
for iteration in range(1, 4):
    started = time.monotonic()
    completed = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *nodes, "-q"], check=False)
    runs.append({"iteration": iteration, "exit_code": completed.returncode, "duration_seconds": round(time.monotonic() - started, 6)})
document = {"profile":"v06-cross-feature-replay-soak","iterations":3,"nodes":sorted(nodes),"runs":runs,"passed":all(item["exit_code"] == 0 for item in runs)}
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
  Assert-NativeSuccess "cannot create v0.6 soak container"
  & $script:DockerExe start --attach $soakContainer
  Assert-NativeSuccess "v0.6 replay soak failed"
  $soakJson = Join-Path $captureRoot "backend-v06-soak.json"
  & $script:DockerExe cp "${soakContainer}:/qualification-output/result.json" $soakJson | Out-Null
  Assert-NativeSuccess "cannot copy v0.6 soak capture"

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

    $savedCi = $env:CI
    $savedJunit = $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE
    try {
      if (Get-NetTCPConnection -State Listen -LocalPort 4173 -ErrorAction SilentlyContinue) { throw "required mocked-browser port 4173 is already in use" }
      $env:CI = "1"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = Join-Path $captureRoot "frontend-playwright-mocked.xml"
      & $npxExe playwright test e2e/operator-workspace.spec.ts --reporter=junit
      Assert-NativeSuccess "mocked desktop/mobile Playwright suite failed"
    }
    finally {
      if ($null -eq $savedCi) { Remove-Item Env:CI -ErrorAction SilentlyContinue } else { $env:CI = $savedCi }
      if ($null -eq $savedJunit) { Remove-Item Env:PLAYWRIGHT_JUNIT_OUTPUT_FILE -ErrorAction SilentlyContinue } else { $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $savedJunit }
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
    foreach ($name in @("DATABASE_URL", "SPELL_PROCEDURES_DIR", "SPELL_JWT_HS256_SECRET", "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_DRIVER_ENABLED", "SPELL_REAL_BACKEND", "SPELL_E2E_TOKEN", "SPELL_E2E_BASE_URL", "SPELL_E2E_ARTIFACT_DIRECTORY", "PLAYWRIGHT_JUNIT_OUTPUT_FILE", "CI")) {
      $savedLiveEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
      $dbPath = (Join-Path $scratchRoot "browser.db").Replace('\', '/')
      $env:DATABASE_URL = "sqlite:///$dbPath"
      $env:SPELL_PROCEDURES_DIR = (Join-Path $candidateRoot "procedures")
      $env:SPELL_JWT_HS256_SECRET = "v06-candidate-jwt-$runId"
      $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "true"
      $env:SPELL_DRIVER_ENABLED = "false"
      $backendProcess = Start-Process -FilePath $script:LockedPython -WindowStyle Hidden -PassThru `
        -ArgumentList @("-I", $launcher, $script:SitePackages, $candidateRoot) `
        -RedirectStandardOutput (Join-Path $scratchRoot "backend.stdout.log") `
        -RedirectStandardError (Join-Path $scratchRoot "backend.stderr.log")
      $frontendProcess = Start-Process -FilePath $npmExe -WindowStyle Hidden -PassThru `
        -WorkingDirectory (Join-Path $candidateRoot "frontend") `
        -ArgumentList @("run", "preview", "--", "--strictPort", "--host", "127.0.0.1", "--port", "4173") `
        -RedirectStandardOutput (Join-Path $scratchRoot "frontend.stdout.log") `
        -RedirectStandardError (Join-Path $scratchRoot "frontend.stderr.log")
      Wait-Http "http://127.0.0.1:8080/api/v1/health" 60
      Wait-Http "http://127.0.0.1:4173/" 60
      Push-Location $candidateRoot
      try {
        $token = @(& $script:LockedPython -I (Join-Path $candidateRoot "scripts/issue_dev_token.py") --subject "candidate-operator" --role operator --lifetime 600) -join "`n"
        Assert-NativeSuccess "candidate browser token issuance failed"
      }
      finally { Pop-Location }
      if ($token -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') { throw "candidate browser token is invalid" }
      $env:SPELL_REAL_BACKEND = "1"
      $env:SPELL_E2E_TOKEN = $token
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:4173"
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = $browserRoot
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = Join-Path $captureRoot "frontend-playwright-live.xml"
      $env:CI = "1"
      & $npxExe playwright test e2e/integration.spec.ts --reporter=junit
      Assert-NativeSuccess "live desktop/mobile Playwright suite failed"
      $token = $null
    }
    finally {
      Stop-OwnedProcess $frontendProcess
      Stop-OwnedProcess $backendProcess
      $frontendProcess = $null
      $backendProcess = $null
      foreach ($entry in $savedLiveEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
    }
  }
  finally { Pop-Location }
}
catch { $failure = $_ }
finally {
  Stop-OwnedProcess $frontendProcess
  Stop-OwnedProcess $backendProcess
  foreach ($container in $containers) { Invoke-DockerCleanup @("rm", "-f", $container) | Out-Null }
  foreach ($volume in $volumes) { Invoke-DockerCleanup @("volume", "rm", "-f", $volume) | Out-Null }
  Invoke-DockerCleanup @("network", "rm", $network) | Out-Null
  foreach ($tag in $imageTags) { Invoke-DockerCleanup @("image", "rm", $tag) | Out-Null }
  if ($null -ne $runtimeBaseline) { $runtimeResourcesTornDown = Remove-NewRuntimeResources $runtimeBaseline }
  try {
    $remainingContainers = @(Get-DockerInspectionLines `
      -Arguments @("ps", "-aq", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate container cleanup")
    $remainingNetworks = @(Get-DockerInspectionLines `
      -Arguments @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate network cleanup")
    $remainingVolumes = @(Get-DockerInspectionLines `
      -Arguments @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate volume cleanup")
    $remainingImages = @(Get-DockerInspectionLines `
      -Arguments @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$project") `
      -Label "candidate image cleanup")
    $resourcesTornDown = @($remainingContainers | Where-Object { $_ }).Count -eq 0 -and @($remainingNetworks | Where-Object { $_ }).Count -eq 0 -and @($remainingVolumes | Where-Object { $_ }).Count -eq 0
    $imageTagsRemoved = @($remainingImages | Where-Object { $_ }).Count -eq 0
  }
  catch {
    $cleanupInspectionFailure = $_
    $resourcesTornDown = $false
    $imageTagsRemoved = $false
  }
  $runtimeProcessesStopped = -not (Get-NetTCPConnection -State Listen -LocalPort 8080,4173 -ErrorAction SilentlyContinue)
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
  Pop-Location
}

if ($failure) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  $cleanupMessages = @()
  if ($legacyCleanupFailed) { $cleanupMessages += "v0.5.0 historical checkout teardown failed" }
  if ($cleanupInspectionFailure) { $cleanupMessages += $cleanupInspectionFailure.Exception.Message }
  if ($cleanupMessages.Count -gt 0) {
    throw "candidate qualification failed: $($failure.Exception.Message); cleanup also failed: $($cleanupMessages -join '; ')"
  }
  throw $failure
}
if ($legacyCleanupFailed) {
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  throw "v0.5.0 historical checkout teardown failed"
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
  Copy-Item -LiteralPath (Join-Path $candidateRoot "artifacts/v0.6/work-package/schema.json") -Destination (Join-Path $stageRoot "schema.json")
  $captureMap = [ordered]@{
    "tests/backend-sqlite.xml" = Join-Path $captureRoot "backend-sqlite.xml"
    "tests/backend-postgresql.xml" = Join-Path $captureRoot "backend-postgresql.xml"
    "tests/backend-docker-host.xml" = Join-Path $captureRoot "backend-docker-host.xml"
    "tests/backend-v06-soak.json" = Join-Path $captureRoot "backend-v06-soak.json"
    "tests/driver-host.xml" = Join-Path $captureRoot "driver-host.xml"
    "tests/tooling.xml" = Join-Path $captureRoot "tooling.xml"
    "tests/frontend-vitest.xml" = Join-Path $captureRoot "frontend-vitest.xml"
    "tests/frontend-build.json" = Join-Path $captureRoot "frontend-build.json"
    "tests/frontend-playwright-mocked.xml" = Join-Path $captureRoot "frontend-playwright-mocked.xml"
    "tests/frontend-playwright-live.xml" = Join-Path $captureRoot "frontend-playwright-live.xml"
    "browser/desktop-as-run-report.png" = Join-Path $captureRoot "browser/desktop-as-run-report.png"
    "browser/desktop-v03-validation.png" = Join-Path $captureRoot "browser/desktop-v03-validation.png"
    "browser/mobile-durable-prompt.png" = Join-Path $captureRoot "browser/mobile-durable-prompt.png"
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
  Assert-ExactInventory $backendNodes $sqliteSummary.collected_nodes "backend SQLite"
  Assert-ExactInventory $backendNodes $postgresSummary.collected_nodes "backend PostgreSQL"
  Assert-ExactInventory $dockerNodes $dockerSummary.collected_nodes "backend Docker host"
  Assert-ExactInventory $driverNodes $driverSummary.collected_nodes "driver host"
  Assert-ExactInventory $toolingNodes $toolingSummary.collected_nodes "tooling"

  $soak = Get-Content -LiteralPath (Join-Path $stageRoot "tests/backend-v06-soak.json") -Raw | ConvertFrom-Json
  $soakDuration = [Math]::Round([double](($soak.runs | Measure-Object -Property duration_seconds -Sum).Sum), 6)
  $soakSummary = [pscustomobject]@{
    collected_nodes = @($soak.nodes); inventory_sha256 = Get-InventoryDigest @($soak.nodes)
    test_count = 3 * @($soak.nodes).Count; subtest_count = 0; passed_count = 3 * @($soak.nodes).Count
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
    backend_v06_soak = New-SuiteRecord "backend_v06_soak" "soak" "tests/backend-v06-soak.json" $soakSummary "internal"
    driver_host = New-SuiteRecord "driver_host" "python" "tests/driver-host.xml" $driverSummary "none"
    tooling = New-SuiteRecord "tooling" "python" "tests/tooling.xml" $toolingSummary "none"
    frontend_vitest = New-SuiteRecord "frontend_vitest" "javascript" "tests/frontend-vitest.xml" $vitestSummary "none"
    frontend_build = New-SuiteRecord "frontend_build" "build" "tests/frontend-build.json" $buildSummary "none"
    frontend_playwright_mocked = New-SuiteRecord "frontend_playwright_mocked" "javascript" "tests/frontend-playwright-mocked.xml" $mockedSummary "loopback-mocked"
    frontend_playwright_live = New-SuiteRecord "frontend_playwright_live" "javascript" "tests/frontend-playwright-live.xml" $liveSummary "loopback-live-backend"
  }
  $identityLines = @(& $script:LockedPython -I $script:Validator --identity-map `
    --junit "backend_postgresql=python=$(Join-Path $stageRoot 'tests/backend-postgresql.xml')" `
    --junit "frontend_playwright_mocked=javascript=$(Join-Path $stageRoot 'tests/frontend-playwright-mocked.xml')" `
    --junit "frontend_playwright_live=javascript=$(Join-Path $stageRoot 'tests/frontend-playwright-live.xml')")
  Assert-NativeSuccess "45-ID concrete proof expansion failed"
  $workPackages = $identityLines[0] | ConvertFrom-Json

  $fingerprints = (@(& $script:LockedPython -I $script:Validator --root $root --fingerprints $SourceCommit)[0] | ConvertFrom-Json)
  Assert-NativeSuccess "source fingerprint calculation failed"
  $sourceTree = (git rev-parse "$SourceCommit^{tree}").Trim()
  $sourceParent = (git show -s --format=%P $SourceCommit).Trim()
  $baselineV05 = (@(& $script:LockedPython -I $script:Validator --root $root --tree-fingerprint v0.5.0 artifacts/v0.5)[0] | ConvertFrom-Json).sha256
  $sourceV05 = (@(& $script:LockedPython -I $script:Validator --root $root --tree-fingerprint $SourceCommit artifacts/v0.5)[0] | ConvertFrom-Json).sha256

  $gatePaths = @(
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.6-gate-0a.json",
    "SPELL_v0.6_Pre-Implementation.md",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0a.py"
  )
  $gateHashes = [ordered]@{}
  foreach ($path in $gatePaths) { $gateHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }
  $contractPaths = @(
    "contracts/v06/manifest.json", "contracts/v06/command_state.json", "contracts/v06/prompt_behavior.json",
    "contracts/v06/schedule_behavior.json", "contracts/v06/inspection_and_actions.json",
    "contracts/v06/startproc_behavior.json", "contracts/v06/lease_modes.json"
  )
  $contractHashes = [ordered]@{}
  foreach ($path in $contractPaths) { $contractHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }
  $toolchainPaths = @(
    "scripts/release-toolchain-v04.json", "scripts/qualification-v06.Dockerfile",
    "scripts/qualification-v06.Dockerfile.dockerignore", "frontend/package-lock.json",
    "artifacts/v0.6/work-package/schema.json"
  )
  $toolchainHashes = [ordered]@{}
  foreach ($path in $toolchainPaths) { $toolchainHashes[$path] = Get-LowerSha256 (Join-Path $candidateRoot $path) }

  $toolingSkips = @($toolingSummary.skipped_nodes)
  $skipRecords = @(
    $toolingSkips | ForEach-Object {
      $reason = if ($_ -like "*supply_chain_v04.py*") { "WINDOWS_POWERSHELL_HOST_CONTRACT_NOT_APPLICABLE_IN_LOCKED_LINUX_IMAGE" }
        elseif ($_ -like "*release_v05.py*" -or $_ -like "*qualify_release_v04.py*") { "POWERSHELL_UNAVAILABLE_IN_LOCKED_LINUX_IMAGE" }
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
      $packageId = $id.Substring(0, 10)
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
    schema_version = "spell.v06.candidate-qualification/1"
    product_version = "0.6.0-candidate"
    scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
    source = [ordered]@{
      commit = $SourceCommit; tree = $sourceTree; parent = $sourceParent
      source_fingerprint_sha256 = [string]$fingerprints.source_fingerprint_sha256
      product_fingerprint_sha256 = [string]$fingerprints.product_fingerprint_sha256
    }
    gate_0a = [ordered]@{ gate_id = "V06-GATE-0A"; status = "PASS"; validator_output = $gateMarker; owner_marker = "V06-GATE-0A OWNER-APPROVAL: APPROVED"; files_sha256 = $gateHashes }
    contracts = [ordered]@{ manifest_schema = "spell.v06.contract-manifest/1"; files_sha256 = $contractHashes }
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
        replay_inventory_bijection = $true; soak_iterations = 3; all_pass = $true
      }
    }
    historical_platform_skips = [ordered]@{
      classification = "EXPLICIT_PLATFORM_SKIPS_AND_EXECUTED_SOURCE_SCOPED_REROUTES"
      skipped_nodes = $skipRecords; rerouted_tests = $rerouteRecords
      mapped_test_ids_skipped = @(); accepted_failures = @()
    }
    v0_5_immutability = [ordered]@{
      baseline_tag = "v0.5.0"; baseline_tree_fingerprint_sha256 = [string]$baselineV05
      source_tree_fingerprint_sha256 = [string]$sourceV05; git_diff_empty = $true
      accepted_archive_path = "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz"
      accepted_archive_sha256 = $acceptedArchiveSha256
      accepted_sidecar_path = "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"
      accepted_sidecar_sha256 = $acceptedSidecarSha256
      accepted_tag_object = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
      accepted_tag_archive_claim = "Final archive SHA-256: $acceptedArchiveSha256"
    }
    secret_scan = [ordered]@{
      scanner = "validate_candidate_evidence_v06.py/bounded-patterns-1"
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
