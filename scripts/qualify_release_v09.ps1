[CmdletBinding(DefaultParameterSetName = "Run")]
param(
  [Parameter(Mandatory = $true, ParameterSetName = "Run")]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$LocalConfirmation,
  [Parameter(ParameterSetName = "Run")]
  [ValidatePattern('^(HEAD|[0-9a-f]{40})$')]
  [string]$SourceCommit = "HEAD",
  [Parameter(ParameterSetName = "Run")]
  [switch]$Replace,
  [Parameter(Mandatory = $true, ParameterSetName = "Validate")]
  [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$root = Split-Path -Parent $PSScriptRoot
$gate0aCommit = "92f3b4b82908d44e28b9506749e498386a428c27"
$v05ArchiveSha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
$v05SidecarSha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
$v05SidecarText = "$v05ArchiveSha256  openbexi-spell-v0.5.0.tar.gz`n"
$v06ArchiveSha256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
$v06SidecarSha256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
$v06SidecarText = "$v06ArchiveSha256  openbexi-spell-v0.6.0.tar.gz`n"
$v07ArchiveSha256 = "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
$v07SidecarSha256 = "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
$v07SidecarText = "$v07ArchiveSha256  openbexi-spell-v0.7.0.tar.gz`n"
$v08ArchiveSha256 = "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
$v08SidecarSha256 = "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
$v08SidecarText = "$v08ArchiveSha256  openbexi-spell-v0.8.0.tar.gz`n"
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
$project = "spell-v09-final-$runId"
$qualificationTag = "openbexi-spell-v09-final-qualification:$runId"
$postgresTag = "openbexi-spell-v09-final-postgres:$runId"
$postgresNetwork = "$project-postgresql-internal"
$postgresContainer = "$project-postgresql"
$postgresVolume = "$project-postgresql-data"
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
$browserProject = "$project-browser"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$finalSuiteIds = @(
  "backend_sqlite", "backend_postgresql", "backend_docker_host", "driver_host", "tooling",
  "frontend_unit", "frontend_build", "browser_mocked", "browser_real"
)
$sqliteAllowedSkips = @(
  "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
  "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
  "backend/tests/test_driver_isolation.py::test_live_bundle_builders_are_networkless_independent_and_reproducible",
  "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
  "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
  "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
  "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
  "backend/tests/test_data_migration_recovery_v08.py::test_v0007_postgresql_schema_and_fingerprint_match_sqlite_contract",
  "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
  "backend/tests/test_development_postgresql_v09.py::test_v0008_postgresql_schema_and_logical_fingerprint_match_contract",
  "backend/tests/test_development_postgresql_v09.py::test_postgresql_development_idempotency_race_and_catalog_promotion",
  "backend/tests/test_data_catalog_v08.py::test_catalog_dependency_graph_is_verified_on_postgresql",
  "backend/tests/test_data_containers_v08.py::test_two_owners_can_use_the_same_container_id_on_postgresql",
  "backend/tests/test_data_migration_recovery_v08.py::test_postgresql_backup_reconstructs_exact_isolated_manual_target",
  "backend/tests/test_dictionary_exchange_v08.py::test_two_owners_can_use_the_same_dictionary_id_on_postgresql",
  "backend/tests/test_migrations.py::test_v0007_postgresql_preflight_fails_closed_before_ddl",
  "backend/tests/test_shared_data_v08.py::test_two_owners_can_use_the_same_namespace_id_on_postgresql",
  "backend/tests/test_shared_data_v08.py::test_postgresql_latest_revision_reconstruction_uses_parent_row_locks"
)
$gate0bMarker = (
  "gate=PASS work_packages=9 identities=45 failed=0 skipped=0 " +
  "claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED"
)

function Assert-NativeSuccess([string]$Message) {
  if ($LASTEXITCODE -ne 0) { throw $Message }
}

function Get-LowerSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-V08ArtifactsUnchanged {
  param([Parameter(Mandatory = $true)][string]$Commit)
  $expectedTree = "899dd791fbfd5aa8720c3ce836d5cc2208bac6b9"
  $tree = @(& git rev-parse "${Commit}:artifacts/v0.8") -join "`n"
  Assert-NativeSuccess "cannot inspect accepted v0.8 artifact tree"
  if ($tree.Trim() -cne $expectedTree) { throw "accepted v0.8 artifacts changed in source commit" }
  & git diff --quiet v0.8.0 $Commit -- artifacts/v0.8
  Assert-NativeSuccess "accepted v0.8 artifact bytes differ from v0.8.0"
  & git diff --quiet -- artifacts/v0.8
  Assert-NativeSuccess "accepted v0.8 artifacts have a working-tree change"
  $status = @(& git status --porcelain --untracked-files=all -- artifacts/v0.8)
  Assert-NativeSuccess "cannot inspect accepted v0.8 artifact worktree"
  if ($status.Count -ne 0) { throw "accepted v0.8 artifacts have an untracked change" }
  & (Join-Path $PSScriptRoot "assert_accepted_v08_release_v09.ps1") -Root $root | Out-Null
}

function Get-OrdinalStrings {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [object[]]$Values
  )
  [string[]]$items = @($Values | ForEach-Object { [string]$_ })
  [Array]::Sort($items, [StringComparer]::Ordinal)
  return $items
}

function Assert-ExactSet {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [object[]]$Expected,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [object[]]$Actual,
    [Parameter(Mandatory = $true)][string]$Label
  )
  [string[]]$expectedSorted = @(Get-OrdinalStrings $Expected)
  [string[]]$actualSorted = @(Get-OrdinalStrings $Actual)
  for ($index = 1; $index -lt $expectedSorted.Count; $index += 1) {
    if ($expectedSorted[$index] -ceq $expectedSorted[$index - 1]) {
      throw "$Label expected inventory contains a duplicate"
    }
  }
  for ($index = 1; $index -lt $actualSorted.Count; $index += 1) {
    if ($actualSorted[$index] -ceq $actualSorted[$index - 1]) {
      throw "$Label actual inventory contains a duplicate"
    }
  }
  if (
    $expectedSorted.Count -ne $actualSorted.Count -or
    ($expectedSorted -join "`0") -cne ($actualSorted -join "`0")
  ) { throw "$Label exact inventory differs" }
}

function Assert-ExactProperties {
  param(
    [Parameter(Mandatory = $true)][object]$Value,
    [Parameter(Mandatory = $true)][string[]]$Expected,
    [Parameter(Mandatory = $true)][string]$Label
  )
  if ($null -eq $Value) { throw "$Label is missing" }
  Assert-ExactSet $Expected @($Value.PSObject.Properties.Name) "$Label fields"
}

function Get-InventoryDigest {
  param([Parameter(Mandatory = $true)][string[]]$Nodes)
  [string[]]$sorted = @(Get-OrdinalStrings $Nodes)
  $payload = [Text.Encoding]::UTF8.GetBytes(($sorted -join "`n") + "`n")
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace("-", "").ToLowerInvariant()
  }
  finally { $hasher.Dispose() }
}

function Get-ManualLedgerMap {
  param([Parameter(Mandatory = $true)][string]$Path)
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

function Get-TreeDigest {
  param([Parameter(Mandatory = $true)][string]$Directory)
  $full = [IO.Path]::GetFullPath($Directory).TrimEnd('\', '/')
  $prefix = "$full$([IO.Path]::DirectorySeparatorChar)"
  $files = @(Get-ChildItem -LiteralPath $full -Recurse -File -Force)
  if ($files.Count -eq 0) { throw "frontend build produced no files" }
  $relative = @($files | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "frontend build contains a reparse point"
    }
    $_.FullName.Substring($prefix.Length).Replace('\', '/')
  })
  [string[]]$relative = @(Get-OrdinalStrings $relative)
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    foreach ($name in $relative) {
      $nameBytes = [Text.Encoding]::UTF8.GetBytes($name)
      [void]$hasher.TransformBlock($nameBytes, 0, $nameBytes.Length, $nameBytes, 0)
      $separator = [byte[]]@(0)
      [void]$hasher.TransformBlock($separator, 0, 1, $separator, 0)
      $bytes = [IO.File]::ReadAllBytes((Join-Path $full $name.Replace('/', '\')))
      [void]$hasher.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
      [void]$hasher.TransformBlock($separator, 0, 1, $separator, 0)
    }
    [void]$hasher.TransformFinalBlock([byte[]]@(), 0, 0)
    return [pscustomobject]@{
      FileCount = $relative.Count
      Sha256 = ([BitConverter]::ToString($hasher.Hash)).Replace("-", "").ToLowerInvariant()
    }
  }
  finally { $hasher.Dispose() }
}

function Invoke-DockerCleanup {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  [string[]]$lines = @()
  [int]$code = -1
  $saved = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:DockerExe @Arguments 2>&1)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $saved }
  return [pscustomobject]@{ ExitCode = [int]$code; Lines = [string[]]$lines }
}

function Invoke-ComposeCleanup {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  if (-not $script:ComposeExe) { throw "locked Compose executable is unavailable for cleanup" }
  $saved = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:ComposeExe @Arguments 2>&1)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $saved }
  return [pscustomobject]@{ ExitCode = [int]$code; Lines = [string[]]$lines }
}

function Get-BrowserComposeImageId {
  param([Parameter(Mandatory = $true)][string]$Service)
  $container = @(
    & $script:ComposeExe -p $browserProject --profile driver `
      -f (Join-Path $sourceRoot "compose.yaml") ps -a -q $Service
  ) | Where-Object { $_.Trim() } | Select-Object -Last 1
  Assert-NativeSuccess "cannot resolve the $Service final-browser container"
  if (-not $container) { throw "the $Service final-browser container is missing" }
  $image = (& $script:DockerExe inspect --format "{{.Image}}" $container).Trim()
  Assert-NativeSuccess "cannot resolve the $Service final-browser image"
  if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "the $Service final-browser image identity is invalid"
  }
  return $image
}

function Assert-BrowserComposeServiceNetworkNone {
  param([Parameter(Mandatory = $true)][string]$Service)
  [string[]]$containers = @(
    & $script:ComposeExe -p $browserProject --profile driver `
      -f (Join-Path $sourceRoot "compose.yaml") ps -a -q $Service
  ) | Where-Object { $_.Trim() }
  Assert-NativeSuccess "cannot resolve the $Service final-browser container"
  if ($containers.Count -ne 1) {
    throw "the $Service final-browser container inventory differs"
  }
  $networkMode = @(
    & $script:DockerExe inspect --format "{{.HostConfig.NetworkMode}}" $containers[0]
  ) -join "`n"
  Assert-NativeSuccess "cannot inspect the $Service final-browser network mode"
  if ($networkMode.Trim() -cne "none") {
    throw "the $Service final-browser network mode is not none"
  }
}

function Wait-ContainerChecked {
  param(
    [Parameter(Mandatory = $true)][string]$Container,
    [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
    [Parameter(Mandatory = $true)][string]$FailureMessage
  )
  & $script:DockerExe start $Container | Out-Null
  Assert-NativeSuccess "cannot start $Container"
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  do {
    $stateLine = @(& $script:DockerExe inspect $Container --format "{{json .State}}" 2>$null) -join "`n"
    Assert-NativeSuccess "cannot inspect $Container"
    $state = $stateLine | ConvertFrom-Json
    if ($state.Running -ne $true) { break }
    Start-Sleep -Milliseconds 500
  } while ([DateTime]::UtcNow -lt $deadline)
  if ($state.Running -eq $true) {
    Invoke-DockerCleanup @("rm", "-f", $Container) | Out-Null
    throw "$FailureMessage (timeout after $TimeoutSeconds seconds)"
  }
  if ([int]$state.ExitCode -ne 0) {
    @(& $script:DockerExe logs $Container 2>&1) | Write-Host
    throw "$FailureMessage (exit $($state.ExitCode))"
  }
}

function Get-CollectedNodes {
  param(
    [Parameter(Mandatory = $true)][string]$Suite,
    [Parameter(Mandatory = $true)][string]$Prefix,
    [int]$ExpectedCount = 0,
    [string]$ExpectedDigest = ""
  )
  $name = "$project-collect-$($Suite.Replace('/', '-'))"
  $script:Containers.Add($name)
  & $script:DockerExe create --name $name `
    --label "com.docker.compose.project=$project" --network none --read-only `
    --tmpfs "/tmp:size=512m,noexec,nosuid" $script:QualificationImage `
    python -m pytest --collect-only -q $Suite | Out-Null
  Assert-NativeSuccess "cannot create $Suite collection container"
  Wait-ContainerChecked $name 600 "$Suite collection failed"
  $output = @(& $script:DockerExe logs $name 2>&1)
  Assert-NativeSuccess "cannot read $Suite collection output"
  $nodes = @(
    $output | ForEach-Object {
      $line = [string]$_
      $separator = $line.IndexOf("::", [StringComparison]::Ordinal)
      if ($separator -ge 0) {
        $line.Substring(0, $separator).Replace('\', '/') + $line.Substring($separator)
      }
      else { $line }
    } | Where-Object {
      $_.StartsWith($Prefix, [StringComparison]::Ordinal) -and $_.Contains("::")
    }
  )
  [string[]]$nodes = @(Get-OrdinalStrings $nodes)
  if ($nodes.Count -eq 0 -or @($nodes | Select-Object -Unique).Count -ne $nodes.Count) {
    throw "$Suite collection inventory is empty or ambiguous"
  }
  if ($ExpectedCount -gt 0) {
    if ($ExpectedDigest -cnotmatch '^[0-9a-f]{64}$') {
      throw "$Suite immutable inventory digest is invalid"
    }
    if ($nodes.Count -ne $ExpectedCount) {
      throw "$Suite collection count differs from the immutable inventory"
    }
    if ((Get-InventoryDigest $nodes) -cne $ExpectedDigest) {
      throw "$Suite collection digest differs from the immutable inventory"
    }
  }
  return $nodes
}

function Invoke-ImagePytest {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$Network,
    [Parameter(Mandatory = $true)][string[]]$Environment,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$Output,
    [string[]]$Mounts = @()
  )
  $container = "$project-$Id"
  $volume = "$container-output"
  $script:Containers.Add($container)
  $script:Volumes.Add($volume)
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $volume | Out-Null
  Assert-NativeSuccess "cannot create $Id output volume"
  $create = @(
    "create", "--name", $container, "--label", "com.docker.compose.project=$project",
    "--network", $Network, "--read-only", "--tmpfs", "/tmp:size=1g,noexec,nosuid",
    "--mount", "type=volume,source=$volume,target=/qualification-output"
  )
  foreach ($mount in $Mounts) { $create += @("--mount", $mount) }
  foreach ($entry in $Environment) { $create += @("-e", $entry) }
  $create += @($script:QualificationImage, "python", "-m", "pytest") + $Arguments
  & $script:DockerExe @create | Out-Null
  Assert-NativeSuccess "cannot create $Id test container"
  Wait-ContainerChecked $container 3600 "$Id tests failed"
  & $script:DockerExe cp "${container}:/qualification-output/result.xml" $Output | Out-Null
  Assert-NativeSuccess "cannot copy $Id JUnit capture"
}

function Convert-ClassnameToPytestNode([string]$Classname, [string]$Name) {
  $parts = @($Classname.Split('.'))
  $indexes = @(for ($index = 0; $index -lt $parts.Count; $index += 1) {
    if ($parts[$index].StartsWith("test_", [StringComparison]::Ordinal)) { $index }
  })
  if ($indexes.Count -eq 0) { return "$Classname::$Name" }
  $module = [int]$indexes[-1]
  $path = ($parts[0..$module] -join "/") + ".py"
  if ($module + 1 -lt $parts.Count) {
    $path += "::" + ($parts[($module + 1)..($parts.Count - 1)] -join "::")
  }
  return "$path::$Name"
}

function Get-JUnitResult {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Length -le 0 -or $item.Length -gt 33554432) { throw "JUnit capture has invalid size: $Path" }
  $raw = [IO.File]::ReadAllText($Path)
  if ($raw -match '<!DOCTYPE|<!ENTITY') { throw "JUnit capture contains a DTD or entity declaration" }
  [xml]$document = $raw
  $nodes = [Collections.Generic.List[string]]::new()
  $skips = [Collections.Generic.List[string]]::new()
  $passed = 0; $failures = 0; $errors = 0
  foreach ($case in @($document.SelectNodes("//testcase"))) {
    $classname = [string]$case.classname
    $name = [string]$case.name
    if (-not $classname -or -not $name) { throw "JUnit capture contains an unnamed testcase" }
    $node = Convert-ClassnameToPytestNode $classname $name
    if ($nodes.Contains($node)) { throw "JUnit capture contains a duplicate testcase: $node" }
    $nodes.Add($node)
    $statuses = @($case.ChildNodes | Where-Object { $_.Name -in @("skipped", "failure", "error") })
    if ($statuses.Count -gt 1) { throw "JUnit testcase has an ambiguous status: $node" }
    if ($statuses.Count -eq 0) { $passed += 1 }
    elseif ($statuses[0].Name -ceq "skipped") { $skips.Add($node) }
    elseif ($statuses[0].Name -ceq "failure") { $failures += 1 }
    else { $errors += 1 }
  }
  if ($nodes.Count -eq 0) { throw "JUnit capture contains no testcases" }
  $reportedTests = 0
  $coveredCases = 0
  foreach ($suite in @($document.SelectNodes("//testsuite"))) {
    $direct = @($suite.SelectNodes("testcase"))
    if ($direct.Count -eq 0) { continue }
    $suiteTests = 0; $suiteSkipped = 0; $suiteFailures = 0; $suiteErrors = 0
    if (
      -not [int]::TryParse($suite.GetAttribute("tests"), [ref]$suiteTests) -or
      -not [int]::TryParse($suite.GetAttribute("skipped"), [ref]$suiteSkipped) -or
      -not [int]::TryParse($suite.GetAttribute("failures"), [ref]$suiteFailures) -or
      -not [int]::TryParse($suite.GetAttribute("errors"), [ref]$suiteErrors)
    ) { throw "JUnit suite aggregate is not an integer" }
    $expectedSkipped = @($direct | Where-Object { $_.SelectSingleNode("skipped") }).Count
    $expectedFailures = @($direct | Where-Object { $_.SelectSingleNode("failure") }).Count
    $expectedErrors = @($direct | Where-Object { $_.SelectSingleNode("error") }).Count
    if (
      $suiteTests -lt $direct.Count -or $suiteSkipped -ne $expectedSkipped -or
      $suiteFailures -ne $expectedFailures -or $suiteErrors -ne $expectedErrors
    ) { throw "JUnit suite aggregate differs" }
    $reportedTests += $suiteTests
    $coveredCases += $direct.Count
  }
  if ($coveredCases -ne $nodes.Count -or $reportedTests -lt $nodes.Count) {
    throw "JUnit testcase aggregate is incomplete"
  }
  return [pscustomobject]@{
    Nodes = [string[]]@(Get-OrdinalStrings $nodes.ToArray())
    SkippedNodes = [string[]]@(Get-OrdinalStrings $skips.ToArray())
    TestCount = $nodes.Count; SubtestCount = $reportedTests - $nodes.Count
    PassedCount = $passed; SkippedCount = $skips.Count
    FailureCount = $failures; ErrorCount = $errors
  }
}

function Merge-JUnit {
  param(
    [Parameter(Mandatory = $true)][string[]]$Inputs,
    [Parameter(Mandatory = $true)][string]$Output
  )
  $target = [Xml.XmlDocument]::new()
  [void]$target.AppendChild($target.CreateXmlDeclaration("1.0", "utf-8", $null))
  $suites = $target.CreateElement("testsuites")
  [void]$target.AppendChild($suites)
  $suite = $target.CreateElement("testsuite")
  $suite.SetAttribute("name", "merged qualification")
  [void]$suites.AppendChild($suite)
  $reportedTests = 0
  foreach ($input in $Inputs) {
    $inputResult = Get-JUnitResult $input
    $reportedTests += $inputResult.TestCount + $inputResult.SubtestCount
    [xml]$source = Get-Content -LiteralPath $input -Raw
    foreach ($case in @($source.SelectNodes("//testcase"))) {
      [void]$suite.AppendChild($target.ImportNode($case, $true))
    }
  }
  $cases = @($suite.SelectNodes("testcase"))
  if ($reportedTests -lt $cases.Count) { throw "merged JUnit testcase aggregate is invalid" }
  $suite.SetAttribute("tests", [string]$reportedTests)
  $suite.SetAttribute("skipped", [string]@($cases | Where-Object { $_.SelectSingleNode("skipped") }).Count)
  $suite.SetAttribute("failures", [string]@($cases | Where-Object { $_.SelectSingleNode("failure") }).Count)
  $suite.SetAttribute("errors", [string]@($cases | Where-Object { $_.SelectSingleNode("error") }).Count)
  $settings = [Xml.XmlWriterSettings]::new()
  $settings.Encoding = $utf8NoBom
  $settings.Indent = $false
  $writer = [Xml.XmlWriter]::Create($Output, $settings)
  try { $target.Save($writer) }
  finally { $writer.Dispose() }
}

function Normalize-BrowserJUnit {
  param([Parameter(Mandatory = $true)][string]$Path)
  [xml]$document = Get-Content -LiteralPath $Path -Raw
  foreach ($suite in @($document.SelectNodes("//testsuite"))) {
    $projectName = ([string]$suite.hostname).ToLowerInvariant()
    if ($projectName -cnotmatch '^[a-z0-9_-]+$') { throw "browser JUnit project identity is invalid" }
    foreach ($case in @($suite.SelectNodes("testcase"))) {
      $case.SetAttribute("classname", "browser_$projectName.$([string]$case.classname)")
    }
  }
  $settings = [Xml.XmlWriterSettings]::new()
  $settings.Encoding = $utf8NoBom
  $settings.Indent = $false
  $writer = [Xml.XmlWriter]::Create($Path, $settings)
  try { $document.Save($writer) }
  finally { $writer.Dispose() }
}

function Get-PlaywrightNodes {
  param([Parameter(Mandatory = $true)][object]$Document)
  $nodes = [Collections.Generic.List[string]]::new()
  function Add-Suite([object]$Suite) {
    foreach ($spec in @($Suite.specs)) {
      foreach ($test in @($spec.tests)) {
        $projectName = [string]$test.projectName
        $fileName = [string]$spec.file
        $nodes.Add("browser_$projectName.$fileName::$([string]$spec.title)")
      }
    }
    $children = $Suite.PSObject.Properties["suites"]
    if ($null -ne $children) {
      foreach ($child in @($children.Value)) { Add-Suite $child }
    }
  }
  foreach ($suite in @($Document.suites)) { Add-Suite $suite }
  [string[]]$values = @(Get-OrdinalStrings $nodes.ToArray())
  if ($values.Count -eq 0 -or @($values | Select-Object -Unique).Count -ne $values.Count) {
    throw "Playwright collection inventory is empty or ambiguous"
  }
  return $values
}

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try { $listener.Start(); return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
  finally { $listener.Stop() }
}

function Get-RuntimeResources {
  $result = [ordered]@{}
  $result.containers = @(& $script:DockerExe ps -a --format "{{.Names}}" |
    Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
  $result.networks = @(& $script:DockerExe network ls --format "{{.Name}}" |
    Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
  $result.volumes = @(& $script:DockerExe volume ls --format "{{.Name}}" |
    Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
  $result.images = @(& $script:DockerExe image ls --format "{{.Repository}}:{{.Tag}}" |
    Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" })
  return $result
}

function Remove-NewRuntimeResources {
  param([Parameter(Mandatory = $true)][Collections.IDictionary]$Before)
  $current = Get-RuntimeResources
  foreach ($name in @($current.containers | Where-Object { $_ -notin $Before.containers })) {
    Invoke-DockerCleanup @("rm", "-f", [string]$name) | Out-Null
  }
  foreach ($name in @($current.networks | Where-Object { $_ -notin $Before.networks })) {
    Invoke-DockerCleanup @("network", "rm", [string]$name) | Out-Null
  }
  foreach ($name in @($current.volumes | Where-Object { $_ -notin $Before.volumes })) {
    Invoke-DockerCleanup @("volume", "rm", "-f", [string]$name) | Out-Null
  }
  foreach ($name in @($current.images | Where-Object { $_ -notin $Before.images })) {
    Invoke-DockerCleanup @("image", "rm", [string]$name) | Out-Null
  }
  $after = Get-RuntimeResources
  return (
    @($after.containers | Where-Object { $_ -notin $Before.containers }).Count -eq 0 -and
    @($after.networks | Where-Object { $_ -notin $Before.networks }).Count -eq 0 -and
    @($after.volumes | Where-Object { $_ -notin $Before.volumes }).Count -eq 0 -and
    @($after.images | Where-Object { $_ -notin $Before.images }).Count -eq 0
  )
}

function Assert-JUnitContract {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string[]]$CollectedNodes,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]$AllowedSkips,
    [Parameter(Mandatory = $true)][string]$Label,
    [int]$ExpectedSubtests = 0
  )
  $result = Get-JUnitResult $Path
  Assert-ExactSet $CollectedNodes $result.Nodes "$Label collection/run bijection"
  Assert-ExactSet $AllowedSkips $result.SkippedNodes "$Label skipped nodes"
  if ($result.FailureCount -ne 0 -or $result.ErrorCount -ne 0) {
    throw "$Label contains a failure or error"
  }
  if ($result.SubtestCount -ne $ExpectedSubtests) {
    throw "$Label subtest aggregate differs"
  }
  if ($AllowedSkips.Count -eq 0 -and $result.SkippedCount -ne 0) { throw "$Label contains a skip" }
  return $result
}

function New-JUnitSuiteDeclaration {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][object]$Result,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]$AllowedSkips
  )
  return [ordered]@{
    kind = "junit"
    capture = "artifacts/v0.9/final/tests/$($Id.Replace('_', '-')).xml"
    sha256 = Get-LowerSha256 $Path
    test_count = [int]$Result.TestCount
    subtest_count = [int]$Result.SubtestCount
    passed_count = [int]$Result.PassedCount
    skipped_count = [int]$Result.SkippedCount
    failure_count = [int]$Result.FailureCount
    error_count = [int]$Result.ErrorCount
    allowed_skipped_nodes = [string[]]$AllowedSkips
  }
}

function Assert-FinalToolchain {
  param([Parameter(Mandatory = $true)][object]$Toolchain)
  $fields = @(
    "python", "docker", "node", "npm", "playwright", "chromium", "files_sha256",
    "candidate_qualification_image_id", "final_qualification_image_id"
  )
  Assert-ExactProperties $Toolchain $fields "final qualification toolchain"
  foreach ($field in @("candidate_qualification_image_id", "final_qualification_image_id")) {
    if ([string]$Toolchain.$field -cnotmatch '^sha256:[0-9a-f]{64}$') {
      throw "final qualification image identity is invalid: $field"
    }
  }
  $candidatePath = Join-Path $root "artifacts/v0.9/work-package/qualification.json"
  $candidate = Get-Content -LiteralPath $candidatePath -Raw | ConvertFrom-Json
  $candidateFields = @(
    "python", "docker", "node", "npm", "playwright", "chromium", "files_sha256",
    "qualification_image_id"
  )
  Assert-ExactProperties $candidate.toolchain $candidateFields "candidate qualification toolchain"
  foreach ($field in @("python", "docker", "node", "npm", "playwright", "chromium")) {
    if ([string]$Toolchain.$field -cne [string]$candidate.toolchain.$field) {
      throw "final qualification toolchain immutable binding differs: $field"
    }
  }
  if (
    ($Toolchain.files_sha256 | ConvertTo-Json -Compress -Depth 100) -cne
    ($candidate.toolchain.files_sha256 | ConvertTo-Json -Compress -Depth 100)
  ) { throw "final qualification toolchain file binding differs" }
  if (
    [string]$Toolchain.candidate_qualification_image_id -cne
    [string]$candidate.toolchain.qualification_image_id
  ) { throw "final qualification candidate image binding differs" }
}

function Assert-FinalPublication {
  param([Parameter(Mandatory = $true)][string]$FinalRoot)
  & (Join-Path $PSScriptRoot "assert_accepted_v08_release_v09.ps1") -Root $root | Out-Null
  $finalFull = [IO.Path]::GetFullPath($FinalRoot)
  $testsRoot = Join-Path $finalFull "tests"
  $summaryPath = Join-Path $finalFull "qualification.json"
  if (
    -not (Test-Path -LiteralPath $summaryPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $testsRoot -PathType Container)
  ) { throw "final qualification publication is incomplete" }
  Assert-ExactSet @("qualification.json", "tests") @(
    Get-ChildItem -LiteralPath $finalFull -Force | ForEach-Object { $_.Name }
  ) "final qualification root"
  $expectedCaptureNames = @(
    "backend-sqlite.xml", "backend-postgresql.xml", "backend-docker-host.xml", "driver-host.xml", "tooling.xml",
    "frontend-unit.json", "frontend-build.json", "browser-mocked.xml", "browser-real.xml"
  )
  Assert-ExactSet $expectedCaptureNames @(
    Get-ChildItem -LiteralPath $testsRoot -Force | ForEach-Object { $_.Name }
  ) "final qualification captures"
  $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
  Assert-ExactProperties $summary @(
    "schema_version", "product_version", "scope_profile", "qualified_source",
    "source_fingerprint_sha256", "product_package_sha256", "work_package", "gate_0b",
    "toolchain", "suites", "teardown", "accepted_v08_release", "accepted_exceptions", "overall_pass"
  ) "final qualification summary"
  if (
    $summary.schema_version -cne "spell.v09.final-qualification/1" -or
    $summary.product_version -cne "0.9.0" -or
    $summary.scope_profile -cne "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT" -or
    $summary.overall_pass -ne $true -or @($summary.accepted_exceptions).Count -ne 0
  ) { throw "final qualification summary header differs" }
  Assert-ExactProperties $summary.accepted_v08_release @(
    "archive_sha256", "sidecar_sha256", "tag_object", "tag_archive_claim"
  ) "final qualification accepted v0.8 release"
  if (
    [string]$summary.accepted_v08_release.archive_sha256 -cne $v08ArchiveSha256 -or
    [string]$summary.accepted_v08_release.sidecar_sha256 -cne $v08SidecarSha256 -or
    [string]$summary.accepted_v08_release.tag_object -cne "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae" -or
    [string]$summary.accepted_v08_release.tag_archive_claim -cne "Final archive SHA-256: $v08ArchiveSha256"
  ) { throw "final qualification accepted v0.8 release binding differs" }
  Assert-FinalToolchain $summary.toolchain
  $suiteIds = @($summary.suites.PSObject.Properties.Name)
  if (($suiteIds -join "`0") -cne ($finalSuiteIds -join "`0")) {
    throw "final qualification suite order differs"
  }
  foreach ($item in @(Get-ChildItem -LiteralPath $finalFull -Recurse -Force)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "final qualification contains a reparse point"
    }
  }
  foreach ($id in $finalSuiteIds) {
    $suite = $summary.suites.$id
    if ($id -ceq "frontend_build") {
      Assert-ExactProperties $suite @(
        "kind", "capture", "sha256", "passed", "dist_file_count", "dist_sha256"
      ) "final suite $id"
    }
    else {
      Assert-ExactProperties $suite @(
        "kind", "capture", "sha256", "test_count", "subtest_count", "passed_count",
        "skipped_count", "failure_count", "error_count", "allowed_skipped_nodes"
      ) "final suite $id"
    }
    $capture = Join-Path $root ([string]$suite.capture)
    if (-not $finalFull.Equals([IO.Path]::GetFullPath((Join-Path $root "artifacts/v0.9/final")))) {
      $capture = Join-Path $testsRoot ([IO.Path]::GetFileName([string]$suite.capture))
    }
    if ((Get-LowerSha256 $capture) -cne [string]$suite.sha256) {
      throw "final qualification capture hash differs: $id"
    }
    $expectedSubtests = if ($id -ceq "tooling") { 36 } else { 0 }
    if ($id -ne "frontend_build" -and [int]$suite.subtest_count -ne $expectedSubtests) {
      throw "final qualification subtest count differs: $id"
    }
    if ($id -ne "frontend_build" -and $id -ne "frontend_unit") {
      $result = Get-JUnitResult $capture
      foreach ($pair in @(
        @("test_count", "TestCount"), @("subtest_count", "SubtestCount"),
        @("passed_count", "PassedCount"),
        @("skipped_count", "SkippedCount"), @("failure_count", "FailureCount"),
        @("error_count", "ErrorCount")
      )) {
        if ([int]$suite.($pair[0]) -ne [int]$result.($pair[1])) {
          throw "final qualification capture count differs: $id/$($pair[0])"
        }
      }
    }
  }
  return $summary
}

if ($ValidateOnly) {
  $validated = Assert-FinalPublication (Join-Path $root "artifacts/v0.9/final")
  [ordered]@{
    schema_version = "spell.v09.final-qualification-validation/1"
    qualified_source_commit = [string]$validated.qualified_source.commit
    suite_count = $finalSuiteIds.Count
    overall_pass = $true
  } | ConvertTo-Json -Compress | Write-Output
  return
}

if ($LocalConfirmation -cne "LOCAL_SYNTHETIC_NON_CUI_ONLY") {
  throw "v0.9 final qualification requires the exact local synthetic non-CUI confirmation"
}
$validatorSource = [IO.File]::ReadAllText(
  (Join-Path $root "scripts/validate_candidate_evidence_v09.py"),
  [Text.Encoding]::UTF8
)
if ($validatorSource -cnotmatch '(?m)^PRODUCT_INVENTORY_FROZEN = True$') {
  throw "v0.9 product qualification inventory is not frozen"
}

$tempRoot = Join-Path $env:TEMP "spell-v09-final-$runId"
$tempFull = [IO.Path]::GetFullPath($tempRoot)
$tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $tempFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a qualification path outside the temporary root"
}
$sourceRoot = Join-Path $tempRoot "source"
$captureRoot = Join-Path $tempRoot "captures"
$archivePath = Join-Path $tempRoot "source.zip"
$v05Worktree = Join-Path $env:TEMP "sv5-$($runId.Substring(0, 12))"
$v05WorktreeFull = [IO.Path]::GetFullPath($v05Worktree)
if (-not $v05WorktreeFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing an accepted-v0.5 tooling export outside the temporary root"
}
$v06Worktree = Join-Path $env:TEMP "sv6-$($runId.Substring(0, 12))"
$v06WorktreeFull = [IO.Path]::GetFullPath($v06Worktree)
if (-not $v06WorktreeFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing an accepted-v0.6 tooling export outside the temporary root"
}
$v07Worktree = Join-Path $env:TEMP "sv7-$($runId.Substring(0, 12))"
$v07WorktreeFull = [IO.Path]::GetFullPath($v07Worktree)
if (-not $v07WorktreeFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing an accepted-v0.7 tooling export outside the temporary root"
}
$v08Worktree = Join-Path $env:TEMP "sv8-$($runId.Substring(0, 12))"
$v08WorktreeFull = [IO.Path]::GetFullPath($v08Worktree)
if (-not $v08WorktreeFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing an accepted-v0.8 tooling export outside the temporary root"
}
$artifactRoot = Join-Path $root "artifacts/v0.9"
$scratchRoot = Join-Path $artifactRoot ".qualification/final-$runId"
$publicationStage = Join-Path $scratchRoot "publication"
$publicationBackup = Join-Path $scratchRoot "backup"
$canonicalFinal = Join-Path $artifactRoot "final"
$externalManualSource = Join-Path $root "SPELL-DOCUMENTATION"

$script:Containers = [Collections.Generic.List[string]]::new()
$script:Volumes = [Collections.Generic.List[string]]::new()
$script:ImageTags = [Collections.Generic.List[string]]::new()
$script:DockerExe = $null
$script:ComposeExe = $null
$script:ImageTags.Add($qualificationTag)
$script:ImageTags.Add($postgresTag)
$failure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$browserComposeStarted = $false
$runtimeBaseline = $null
$runtimeResourcesTornDown = $false
$qualificationResourcesTornDown = $false
$browserDbPassword = $null
$browserJwtSecret = $null
$browserProxyPort = $null
$browserToken = $null
$v05WorktreeOwned = $false
$v06WorktreeOwned = $false
$v07WorktreeOwned = $false
$v08WorktreeOwned = $false

New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null
New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null
New-Item -ItemType Directory -Path $publicationStage -Force | Out-Null

Push-Location $root
try {
  $status = @(& git status --porcelain=v1 --untracked-files=all -- . `
    ":(exclude)artifacts/v0.9/final/**" ":(exclude)artifacts/v0.9/.qualification/**")
  Assert-NativeSuccess "cannot inspect qualification worktree"
  if ($status.Count -ne 0) { throw "final qualification requires a clean tracked product/release worktree" }

  $headCommit = (& git rev-parse --verify "HEAD^{commit}").Trim()
  Assert-NativeSuccess "cannot resolve release HEAD"
  $resolvedSource = (& git rev-parse --verify "$SourceCommit^{commit}").Trim()
  Assert-NativeSuccess "cannot resolve frozen qualification commit"
  $resolvedTree = (& git rev-parse --verify "$resolvedSource^{tree}").Trim()
  Assert-NativeSuccess "cannot resolve frozen qualification tree"
  $candidatePath = Join-Path $root "artifacts/v0.9/work-package/qualification.json"
  $candidateEvidence = Get-Content -LiteralPath $candidatePath -Raw | ConvertFrom-Json
  $candidateCommit = [string]$candidateEvidence.source.commit
  if ($candidateCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw "candidate evidence source commit is invalid"
  }
  & git merge-base --is-ancestor $candidateCommit $resolvedSource
  Assert-NativeSuccess "implementation candidate is not an ancestor of frozen source"
  & git merge-base --is-ancestor $gate0aCommit $resolvedSource
  Assert-NativeSuccess "Gate 0A is not an ancestor of frozen source"
  & git merge-base --is-ancestor $resolvedSource $headCommit
  Assert-NativeSuccess "frozen source is not an ancestor of release HEAD"
  Assert-V08ArtifactsUnchanged $resolvedSource
  if ($resolvedSource -cne $headCommit) {
    $closeout = @(& git diff --name-only $resolvedSource $headCommit)
    Assert-NativeSuccess "cannot inspect frozen-source-to-HEAD delta"
    foreach ($path in $closeout) {
      if (
        -not ([string]$path).StartsWith("artifacts/v0.9/", [StringComparison]::Ordinal) -or
        ([string]$path).Contains("/.qualification/") -or
        ([string]$path).EndsWith(".tar.gz") -or ([string]$path).EndsWith(".tar.gz.sha256")
      ) { throw "release HEAD differs from frozen source outside canonical v0.9 evidence: $path" }
    }
  }

  foreach ($required in @(
    "scripts/qualification-v09.Dockerfile",
    "scripts/qualification-v09.Dockerfile.dockerignore",
    "scripts/qualify_release_v09.ps1",
    "scripts/validate_release_evidence_v09.py",
    "artifacts/v0.9/work-package/schema.json",
    "artifacts/v0.9/work-package/qualification.json",
    "SPELL_DOCUMENTATION_REVIEW.md",
    "SPELL_v0.9_Gate_0B.md"
  )) {
    & git cat-file -e "${resolvedSource}:$required"
    Assert-NativeSuccess "frozen source lacks required tracked input: $required"
  }

  & git archive --format=zip --output=$archivePath $resolvedSource
  Assert-NativeSuccess "frozen qualification source export failed"
  Expand-Archive -LiteralPath $archivePath -DestinationPath $sourceRoot

  $manualLedger = Get-ManualLedgerMap (Join-Path $sourceRoot "SPELL_DOCUMENTATION_REVIEW.md")
  if ($manualLedger.Count -ne 7) {
    throw "external-manual ledger must bind exactly seven files"
  }
  if (-not (Test-Path -LiteralPath $externalManualSource -PathType Container)) {
    throw "external-manual source directory is missing"
  }
  $manualRootItem = Get-Item -LiteralPath $externalManualSource -Force
  if ($manualRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "external-manual source directory is unsafe"
  }
  $sourceManuals = @(Get-ChildItem -LiteralPath $externalManualSource -Force)
  if (
    $sourceManuals.Count -ne $manualLedger.Count -or
    @($sourceManuals | Where-Object {
      $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      -not $manualLedger.Contains($_.Name)
    }).Count -ne 0
  ) { throw "external-manual source inventory differs from the committed ledger" }
  $stagedManualRoot = Join-Path $sourceRoot "SPELL-DOCUMENTATION"
  New-Item -ItemType Directory -Path $stagedManualRoot | Out-Null
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $sourceManual = Join-Path $externalManualSource $entry.Key
    if ((Get-LowerSha256 $sourceManual) -cne $entry.Value) {
      throw "external-manual source hash differs: $($entry.Key)"
    }
    $stagedManual = Join-Path $stagedManualRoot $entry.Key
    Copy-Item -LiteralPath $sourceManual -Destination $stagedManual
    if ((Get-LowerSha256 $stagedManual) -cne $entry.Value) {
      throw "staged external-manual hash differs: $($entry.Key)"
    }
  }

  & (Join-Path $sourceRoot "scripts/assert_release_toolchain_v04.ps1") | Out-Null
  Assert-NativeSuccess "release toolchain validation failed"
  $script:DockerExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
  $composeExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_COMPOSE_EXE)
  $script:ComposeExe = $composeExe
  $lockedPython = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
  $runtimeBaseline = Get-RuntimeResources
  $pythonVersion = @(& $lockedPython --version) -join "`n"
  Assert-NativeSuccess "cannot inspect locked Python"
  if ($pythonVersion.Trim() -cne "Python 3.13.14") { throw "final qualification requires Python 3.13.14" }

  $fingerprintCode = @'
import pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from scripts.source_fingerprint_v09 import source_fingerprint_v09
from scripts.build_reproducible_v09 import product_package_sha256_v09
print(source_fingerprint_v09(root))
print(product_package_sha256_v09(root))
'@
  $fingerprints = @(& $lockedPython -I -c $fingerprintCode $sourceRoot)
  Assert-NativeSuccess "cannot compute frozen source/product fingerprints"
  if (
    $fingerprints.Count -ne 2 -or $fingerprints[0] -cnotmatch '^[0-9a-f]{64}$' -or
    $fingerprints[1] -cnotmatch '^[0-9a-f]{64}$'
  ) { throw "frozen source/product fingerprint output is invalid" }
  $sourceFingerprint = [string]$fingerprints[0]
  $productPackageSha256 = [string]$fingerprints[1]

  $candidateValidator = Join-Path $root "scripts/validate_candidate_evidence_v09.py"
  $candidateValidation = @(& $lockedPython -I $candidateValidator --root $root)
  Assert-NativeSuccess "candidate work-package validation failed"
  if (@($candidateValidation | Where-Object { $_ -cmatch '^\{.+\}$' }).Count -ne 1) {
    throw "candidate work-package validator did not emit one success document"
  }
  $gateValidatorRelative = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py"
  )
  $gateValidation = @(& $lockedPython -I (Join-Path $root $gateValidatorRelative))
  Assert-NativeSuccess "Gate 0B validation failed"
  if ($gateValidation.Count -ne 1 -or $gateValidation[0] -cne $gate0bMarker) {
    throw "Gate 0B success marker differs"
  }

  $candidateEvidencePath = Join-Path $sourceRoot "artifacts/v0.9/work-package/qualification.json"
  $candidateEvidence = Get-Content -LiteralPath $candidateEvidencePath -Raw | ConvertFrom-Json
  $schemaRelative = "artifacts/v0.9/work-package/schema.json"
  $schemaPath = Join-Path $sourceRoot $schemaRelative
  $schemaItem = Get-Item -LiteralPath $schemaPath -Force
  $schemaBinding = $candidateEvidence.toolchain.files_sha256.PSObject.Properties[$schemaRelative]
  if (
    -not $schemaItem.PSIsContainer -and
    -not ($schemaItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
    $null -ne $schemaBinding -and
    [string]$schemaBinding.Value -cmatch '^[0-9a-f]{64}$' -and
    (Get-LowerSha256 $schemaPath) -ceq [string]$schemaBinding.Value
  ) {
    $schemaSha256 = [string]$schemaBinding.Value
  }
  else { throw "frozen candidate schema binding differs" }

  $qualificationDockerfile = Join-Path $sourceRoot "scripts/qualification-v09.Dockerfile"
  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    --label "org.openbexi.spell.v09.implementation.commit=$candidateCommit" `
    --label "org.openbexi.spell.v09.source.commit=$resolvedSource" `
    --label "org.openbexi.spell.v09.source.tree=$resolvedTree" `
    -f $qualificationDockerfile -t $qualificationTag $sourceRoot
  Assert-NativeSuccess "frozen-source qualification image build failed"
  $script:QualificationImage = (& $script:DockerExe image inspect $qualificationTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "cannot resolve qualification image"
  if ($script:QualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "qualification image identity is invalid"
  }
  $runtimeVersion = @(& $script:DockerExe run --rm --network none --read-only `
    --label "com.docker.compose.project=$project" --entrypoint python `
    $script:QualificationImage --version) -join "`n"
  Assert-NativeSuccess "qualification image Python probe failed"
  if ($runtimeVersion.Trim() -cne "Python 3.13.14") {
    throw "qualification image does not use Python 3.13.14"
  }
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
  $script:Volumes.Add($offlineCacheVolume)
  & $script:DockerExe run --rm --read-only --tmpfs "/tmp:size=2g,nosuid" `
    --label "com.docker.compose.project=$project" `
    --mount "type=bind,source=$(Join-Path $sourceRoot 'frontend'),target=/source,readonly" `
    --mount "type=volume,source=$offlineCacheVolume,target=/npm-cache" `
    -e "NPM_CONFIG_CACHE=/npm-cache" $offlinePlaywrightImage bash -ceu `
    "mkdir -p /tmp/work; cp /source/package.json /source/package-lock.json /tmp/work/; cd /tmp/work; npm ci --ignore-scripts --no-audit --no-fund --cache /npm-cache; npm cache verify --cache /npm-cache"
  Assert-NativeSuccess "cannot seed the verified offline npm cache"

  $imageInputHashes = [ordered]@{ $schemaRelative = $schemaSha256 }
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $imageInputHashes["SPELL-DOCUMENTATION/$($entry.Key)"] = [string]$entry.Value
  }
  $imageInputProbe = @'
import base64, hashlib, json, pathlib, sys
root = pathlib.Path("/qualification-source")
expected = json.loads(base64.b64decode(sys.argv[1]))
manual_prefix = "SPELL-DOCUMENTATION/"
expected_manuals = sorted(path for path in expected if path.startswith(manual_prefix))
manual_root = root / "SPELL-DOCUMENTATION"
if not manual_root.is_dir() or manual_root.is_symlink():
    raise SystemExit("qualification image external-manual directory is missing or unsafe")
actual_manuals = sorted(
    manual_prefix + path.name
    for path in manual_root.iterdir()
    if path.is_file() and not path.is_symlink()
)
if actual_manuals != expected_manuals or len(expected_manuals) != 7:
    raise SystemExit("qualification image external-manual inventory differs")
for relative, wanted in expected.items():
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"qualification image input is missing or unsafe: {relative}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != wanted:
        raise SystemExit(f"qualification image input hash differs: {relative}")
print("qualification-inputs=PASS files=8")
'@
  $imageInputProbeLauncher = "import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))"
  $imageInputProbePayload = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($imageInputProbe)
  )
  $imageInputHashesPayload = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(($imageInputHashes | ConvertTo-Json -Compress))
  )
  $imageInputProbeResult = @(& $script:DockerExe run --rm --network none --read-only `
    --label "com.docker.compose.project=$project" --entrypoint python `
    $script:QualificationImage -I -c $imageInputProbeLauncher $imageInputProbePayload `
    $imageInputHashesPayload)
  Assert-NativeSuccess "qualification image input probe failed"
  if (
    $imageInputProbeResult.Count -ne 1 -or
    $imageInputProbeResult[0] -cne "qualification-inputs=PASS files=8"
  ) { throw "qualification image input probe marker differs" }

  [string[]]$backendNodes = @(Get-CollectedNodes "backend/tests" "backend/tests/" 923 `
    "cb1e76d67e36de5844976c6576999d2322823e3b33318913757ba332db78dd68")
  [string[]]$driverNodes = @(Get-CollectedNodes "driver_host/tests" "driver_host/tests/" 82 `
    "a3c0a451d7292c46c2f06fe6924c1b35d9c1b2031940f67a862555d38d534593")
  [string[]]$toolingNodes = @(Get-CollectedNodes "scripts/tests" "scripts/tests/" 1050 `
    "1022465fb4518a89ea3a6ae762bd96db77887215a2c8de9313e1a0cf4e2f7509")
  [string[]]$candidateToolingNodes = @($candidateEvidence.suites.tooling.collected_nodes)
  if (
    $candidateToolingNodes.Count -le 0 -or
    (Get-InventoryDigest $candidateToolingNodes) -cne
      [string]$candidateEvidence.suites.tooling.inventory_sha256
  ) { throw "candidate tooling inventory binding differs" }
  $currentToolingSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($node in $toolingNodes) { [void]$currentToolingSet.Add($node) }
  if (@($candidateToolingNodes | Where-Object { -not $currentToolingSet.Contains($_) }).Count -ne 0) {
    throw "final tooling inventory omits an immutable candidate node"
  }

  $sqliteXml = Join-Path $captureRoot "backend-sqlite.xml"
  Invoke-ImagePytest "backend-sqlite" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("backend/tests", "-q", "--junitxml=/qualification-output/result.xml") $sqliteXml

  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    -f (Join-Path $sourceRoot "driver_host/postgres.Dockerfile") -t $postgresTag $sourceRoot
  Assert-NativeSuccess "frozen-source PostgreSQL image build failed"
  $postgresImage = (& $script:DockerExe image inspect $postgresTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "cannot resolve PostgreSQL image"
  if ($postgresImage -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "PostgreSQL image identity is invalid" }
  & $script:DockerExe network create --internal --label "com.docker.compose.project=$project" $postgresNetwork | Out-Null
  Assert-NativeSuccess "cannot create PostgreSQL qualification network"
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $postgresVolume | Out-Null
  Assert-NativeSuccess "cannot create PostgreSQL qualification volume"
  $script:Volumes.Add($postgresVolume)
  $databasePassword = "v09-final-pg-$runId"
  & $script:DockerExe run -d --name $postgresContainer `
    --label "com.docker.compose.project=$project" --network $postgresNetwork `
    --mount "type=volume,source=$postgresVolume,target=/var/lib/postgresql/18/docker" `
    -e "POSTGRES_USER=spell" -e "POSTGRES_PASSWORD=$databasePassword" `
    -e "POSTGRES_DB=spell_test" $postgresImage | Out-Null
  Assert-NativeSuccess "cannot start final PostgreSQL container"
  $script:Containers.Add($postgresContainer)
  $ready = $false; $consecutiveReady = 0; $deadline = [DateTime]::UtcNow.AddSeconds(90)
  do {
    $pidOne = @(& $script:DockerExe exec $postgresContainer sh -ec 'cat /proc/1/comm' 2>$null) -join "`n"
    & $script:DockerExe exec $postgresContainer pg_isready -U spell -d spell_test 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0 -and $pidOne.Trim() -ceq "postgres") { $consecutiveReady += 1 }
    else { $consecutiveReady = 0 }
    $ready = $consecutiveReady -ge 2
    if (-not $ready) { Start-Sleep -Milliseconds 250 }
  } until ($ready -or [DateTime]::UtcNow -ge $deadline)
  if (-not $ready) { throw "PostgreSQL qualification service did not become ready" }
  & $script:DockerExe exec $postgresContainer createdb -U spell spell_migration_test
  Assert-NativeSuccess "cannot create distinct migration qualification database"
  foreach ($databaseName in @("spell_test", "spell_migration_test")) {
    $observed = @(& $script:DockerExe exec $postgresContainer psql -U spell -d $databaseName `
      -Atqc "SELECT current_database()") -join "`n"
    Assert-NativeSuccess "cannot verify qualification database $databaseName"
    if ($observed.Trim() -cne $databaseName) { throw "qualification database identity differs: $databaseName" }
  }
  $applicationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_test"
  $migrationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_migration_test"
  $runtimeNodes = @(
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_driver_isolation.py::test_live_bundle_builders_are_networkless_independent_and_reproducible"
  )
  foreach ($node in $runtimeNodes) {
    if ($node -notin $backendNodes) { throw "Docker inspection backend node is absent: $node" }
  }
  $postgresBaseXml = Join-Path $captureRoot "backend-postgresql-base.xml"
  $postgresArguments = @("backend/tests", "-q")
  foreach ($node in $runtimeNodes) { $postgresArguments += "--deselect=$node" }
  $postgresArguments += "--junitxml=/qualification-output/result.xml"
  Invoke-ImagePytest "backend-postgresql" $postgresNetwork @(
    "PYTHONDONTWRITEBYTECODE=1", "SPELL_TEST_DATABASE_URL=$applicationUrl",
    "SPELL_MIGRATION_TEST_DATABASE_URL=$migrationUrl"
  ) $postgresArguments $postgresBaseXml

  $sitePackages = Join-Path $env:TEMP "openbexi-spell-v05-py313-site"
  if (-not (Test-Path -LiteralPath $sitePackages -PathType Container)) {
    throw "locked CPython host dependency site is missing"
  }
  $dependencyProbe = @'
import importlib.metadata, json, sys
sys.path.insert(0, sys.argv[1])
expected = {"pytest":"9.1.1","sqlalchemy":"2.0.51","fastapi":"0.139.2","psycopg":"3.3.4"}
actual = {name: importlib.metadata.version(name) for name in expected}
if actual != expected: raise SystemExit("locked host dependency versions differ")
print(json.dumps(actual, sort_keys=True, separators=(",", ":")))
'@
  $probe = @($dependencyProbe | & $lockedPython -I - $sitePackages)
  Assert-NativeSuccess "locked CPython host dependency validation failed"
  if ($probe.Count -ne 1) { throw "locked host dependency probe output differs" }
  $pytestCode = @'
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import pytest
raise SystemExit(pytest.main(sys.argv[3:]))
'@
  $postgresRuntimeXml = Join-Path $captureRoot "backend-postgresql-runtime.xml"
  $savedRuntime = $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS
  $savedTestUrl = $env:SPELL_TEST_DATABASE_URL
  $savedMigrationUrl = $env:SPELL_MIGRATION_TEST_DATABASE_URL
  $savedPythonPath = $env:PYTHONPATH
  $savedPath = $env:PATH
  try {
    $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS = "1"
    $env:SPELL_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_test"
    $env:SPELL_MIGRATION_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_migration_test"
    $env:PATH = "$(Split-Path -Parent $script:DockerExe);$savedPath"
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Push-Location $sourceRoot
    try {
      & $lockedPython -I -c $pytestCode $sitePackages $sourceRoot `
        @runtimeNodes -q "--junitxml=$postgresRuntimeXml"
      Assert-NativeSuccess "locked-host Docker inspection tests failed"
    }
    finally { Pop-Location }
  }
  finally {
    if ($null -eq $savedRuntime) { Remove-Item Env:SPELL_RUN_COMPOSE_RUNTIME_TESTS -ErrorAction SilentlyContinue } else { $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS = $savedRuntime }
    if ($null -eq $savedTestUrl) { Remove-Item Env:SPELL_TEST_DATABASE_URL -ErrorAction SilentlyContinue } else { $env:SPELL_TEST_DATABASE_URL = $savedTestUrl }
    if ($null -eq $savedMigrationUrl) { Remove-Item Env:SPELL_MIGRATION_TEST_DATABASE_URL -ErrorAction SilentlyContinue } else { $env:SPELL_MIGRATION_TEST_DATABASE_URL = $savedMigrationUrl }
    if ($null -eq $savedPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $savedPythonPath }
    $env:PATH = $savedPath
  }
  $postgresXml = $postgresBaseXml
  $dockerHostXml = $postgresRuntimeXml

  $driverXml = Join-Path $captureRoot "driver-host.xml"
  Invoke-ImagePytest "driver-host" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("driver_host/tests", "-q", "--junitxml=/qualification-output/result.xml") $driverXml

  $hostToolingNodes = @(
    $toolingNodes | Where-Object {
      $_ -in @(
        "scripts/tests/test_qualify_release_v09.py::test_v09_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v09.py::test_v09_package_scans_candidate_manifest_and_tooling_structurally",
        "scripts/tests/test_release_v09.py::test_v09_package_rejects_duplicate_or_mislocated_evidence_canaries",
        "scripts/tests/test_release_v09.py::test_v09_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v09.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v08.py::test_v08_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v08.py::test_v08_package_scans_candidate_manifest_and_tooling_structurally",
        "scripts/tests/test_release_v08.py::test_v08_package_rejects_duplicate_or_mislocated_evidence_canaries",
        "scripts/tests/test_release_v08.py::test_v08_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v08.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v07.py::test_v07_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v07.py::test_v07_package_scans_candidate_manifest_and_tooling_structurally",
        "scripts/tests/test_release_v07.py::test_v07_package_rejects_duplicate_or_mislocated_evidence_canaries",
        "scripts/tests/test_release_v07.py::test_v07_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v07.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_qualify_release_v05.py::test_v05_final_runner_parses_as_powershell",
        "scripts/tests/test_release_v05.py::test_v05_package_publication_fault_rolls_back_executably",
        "scripts/tests/test_validate_release_evidence_v05.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar",
        "scripts/tests/test_validate_candidate_evidence_v09.py::test_v09_candidate_runner_parses_as_powershell",
        "scripts/tests/test_validate_candidate_evidence_v08.py::test_v08_candidate_runner_parses_as_powershell",
        "scripts/tests/test_validate_candidate_evidence_v07.py::test_v07_candidate_runner_parses_as_powershell",
        "scripts/tests/test_qualify_release_v04.py::test_cleanup_inspection_distinguishes_absence_from_transport_failure",
        "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_rejects_children_of_a_reused_root_pid",
        "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_preserves_descendant_first_cleanup",
        "scripts/tests/test_qualify_release_v04.py::test_plan_only_executes_without_starting_the_release_gate"
      ) -or $_.StartsWith(
        "scripts/tests/test_supply_chain_v04.py::test_executable_toolchain_assertion_rejects_ambiguous_json[",
        [StringComparison]::Ordinal
      )
    }
  )
  if ($hostToolingNodes.Count -ne 30) { throw "host-only tooling node inventory differs" }
  $offlineToolingNodes = @($offlineToolingNode)
  if ($offlineToolingNode -notin $toolingNodes) {
    throw "v0.9 offline package tooling node is absent"
  }
  $rootExternalToolingNodes = @(
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz-archive SHA-256 differs]",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256-sidecar bytes differ]",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_tag_claim_rejects_raw_object_mutation",
    "scripts/tests/test_validate_release_evidence_v06.py::test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag",
    "scripts/tests/test_validate_candidate_evidence_v06.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
    "scripts/tests/test_validate_release_evidence_v07.py::test_v07_inherited_v06_binding_includes_external_archive_sidecar_and_tag",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_tag_blobs_archive_and_sidecar_are_exact",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz-workspace archive SHA-256 differs]",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256-workspace sidecar bytes differ]",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_raw_tag_mutation",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_tagged_blob_payload_mutation",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_cli_emits_one_canonical_json_object",
    "scripts/tests/test_accepted_v06_release_v07.py::test_v07_powershell_assertion_is_parseable_and_reuses_canonical_validator",
    "scripts/tests/test_validate_release_evidence_v08.py::test_v08_inherited_v07_binding_includes_external_archive_sidecar_and_tag",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_tag_blobs_archive_and_sidecar_are_exact",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz-workspace archive SHA-256 differs]",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256-workspace sidecar bytes differ]",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_raw_tag_mutation",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_tagged_blob_payload_mutation",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_cli_emits_one_canonical_json_object",
    "scripts/tests/test_accepted_v07_release_v08.py::test_v08_powershell_assertion_is_parseable_and_reuses_canonical_validator",
    "scripts/tests/test_validate_release_evidence_v09.py::test_v09_inherited_v08_binding_includes_external_archive_sidecar_and_tag",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_tag_blobs_archive_and_sidecar_are_exact",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz-workspace archive SHA-256 differs]",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_external_pair_rejects_byte_mutation[artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256-workspace sidecar bytes differ]",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_raw_tag_mutation",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_tagged_blob_payload_mutation",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_rejects_artifact_tree_mutation",
    "scripts/tests/test_accepted_v08_release_v09.py::test_accepted_v08_cli_emits_one_canonical_json_object",
    "scripts/tests/test_accepted_v08_release_v09.py::test_v09_powershell_assertion_is_parseable_and_reuses_canonical_validator"
  )
  foreach ($node in $rootExternalToolingNodes) {
    if ($node -notin $toolingNodes) { throw "external accepted-release tooling node is absent: $node" }
  }
  if ($rootExternalToolingNodes.Count -ne 31) { throw "current-root external tooling node inventory differs" }
  $v05ExportToolingNodes = @(
    "scripts/tests/test_release_v05.py::test_current_v05_product_package_fingerprint_is_constructible",
    "scripts/tests/test_validate_release_evidence_v05.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication"
  )
  foreach ($node in $v05ExportToolingNodes) {
    if ($node -notin $toolingNodes) { throw "accepted-v0.5 tooling node is absent: $node" }
  }
  $v06ExportToolingNodes = @(
    "scripts/tests/test_release_v06.py::test_current_v06_product_package_fingerprint_is_constructible",
    "scripts/tests/test_validate_release_evidence_v06.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication"
  )
  foreach ($node in $v06ExportToolingNodes) {
    if ($node -notin $toolingNodes) { throw "accepted-v0.6 tooling node is absent: $node" }
  }
  $v07ExportToolingNodes = @(
    "scripts/tests/test_qualification_image_v07.py::test_v07_qualification_baseline_inputs_exist_as_regular_files",
    "scripts/tests/test_source_fingerprint_v07.py::test_v07_source_fingerprint_includes_gate_0a_and_contract_inputs",
    "scripts/tests/test_validate_candidate_evidence_v07.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
    "scripts/tests/test_release_v07.py::test_current_v07_product_package_fingerprint_is_constructible",
    "scripts/tests/test_validate_release_evidence_v07.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication"
  )
  foreach ($node in $v07ExportToolingNodes) {
    if ($node -notin $toolingNodes) { throw "accepted-v0.7 tooling node is absent: $node" }
  }
  $v08ExportToolingNodes = @(
    "scripts/tests/test_qualification_image_v08.py::test_v08_qualification_baseline_inputs_exist_as_regular_files",
    "scripts/tests/test_source_fingerprint_v08.py::test_v08_source_fingerprint_includes_gate_0a_and_contract_inputs",
    "scripts/tests/test_validate_candidate_evidence_v08.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic",
    "scripts/tests/test_release_v08.py::test_current_v08_product_package_fingerprint_is_constructible",
    "scripts/tests/test_validate_release_evidence_v08.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication"
  )
  foreach ($node in $v08ExportToolingNodes) {
    if ($node -notin $toolingNodes) { throw "accepted-v0.8 tooling node is absent: $node" }
  }
  $toolingBaseXml = Join-Path $captureRoot "tooling-base.xml"
  $toolingArguments = @("scripts/tests", "-q")
  foreach ($node in @($hostToolingNodes) + @($offlineToolingNodes) + @($rootExternalToolingNodes) + @($v05ExportToolingNodes) + @($v06ExportToolingNodes) + @($v07ExportToolingNodes) + @($v08ExportToolingNodes)) {
    $toolingArguments += "--deselect=$node"
  }
  $toolingArguments += "--junitxml=/qualification-output/result.xml"
  $manualEvidenceMount = "type=bind,source=$stagedManualRoot,target=/qualification-source/SPELL-DOCUMENTATION,readonly"
  Invoke-ImagePytest "tooling" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    $toolingArguments $toolingBaseXml -Mounts @($manualEvidenceMount)
  $toolingHostXml = Join-Path $captureRoot "tooling-host.xml"
  Push-Location $sourceRoot
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $sourceRoot `
      @hostToolingNodes -q "--junitxml=$toolingHostXml"
    Assert-NativeSuccess "locked-host Windows tooling tests failed"
  }
  finally { Pop-Location }
  $toolingRootXml = Join-Path $captureRoot "tooling-current-root.xml"
  Push-Location $root
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $root `
      @rootExternalToolingNodes -q "--junitxml=$toolingRootXml"
    Assert-NativeSuccess "locked-host accepted-release external tests failed"
  }
  finally { Pop-Location }
  & git -C $root worktree add --detach $v05Worktree v0.5.0 | Out-Null
  Assert-NativeSuccess "cannot create accepted-v0.5 tooling export"
  $v05WorktreeOwned = $true
  $v05Head = (@(& git -C $v05Worktree rev-parse --verify HEAD) -join "`n").Trim()
  Assert-NativeSuccess "cannot inspect accepted-v0.5 tooling export"
  if ($v05Head -cne "e7b6bb9428833437e0160040541eb840deee7cca") {
    throw "accepted-v0.5 tooling export identity differs"
  }

  $v05ManualDestination = Join-Path $v05Worktree "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $v05ManualDestination) {
    throw "accepted-v0.5 tooling export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $v05ManualDestination -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $v05Manual = Join-Path $v05ManualDestination $entry.Key
    if (
      -not (Test-Path -LiteralPath $v05Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $v05Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $v05Manual) -cne $entry.Value
    ) { throw "accepted-v0.5 staged external manual differs: $($entry.Key)" }
  }
  & git -C $root worktree add --detach $v06Worktree v0.6.0 | Out-Null
  Assert-NativeSuccess "cannot create accepted-v0.6 tooling export"
  $v06WorktreeOwned = $true
  $v06Head = (@(& git -C $v06Worktree rev-parse --verify HEAD) -join "`n").Trim()
  Assert-NativeSuccess "cannot inspect accepted-v0.6 tooling export"
  if ($v06Head -cne "05ec783a6e54a76e0548bdd536c18538f6bff51b") {
    throw "accepted-v0.6 tooling export identity differs"
  }

  $v06ManualDestination = Join-Path $v06Worktree "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $v06ManualDestination) {
    throw "accepted-v0.6 tooling export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $v06ManualDestination -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $v06Manual = Join-Path $v06ManualDestination $entry.Key
    if (
      -not (Test-Path -LiteralPath $v06Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $v06Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $v06Manual) -cne $entry.Value
    ) { throw "accepted-v0.6 staged external manual differs: $($entry.Key)" }
  }
  & git -C $root worktree add --detach $v07Worktree v0.7.0 | Out-Null
  Assert-NativeSuccess "cannot create accepted-v0.7 tooling export"
  $v07WorktreeOwned = $true
  $v07Head = (@(& git -C $v07Worktree rev-parse --verify HEAD) -join "`n").Trim()
  Assert-NativeSuccess "cannot inspect accepted-v0.7 tooling export"
  if ($v07Head -cne "cf18e9d887ba0476cbcc3d8194e321332a3ae864") {
    throw "accepted-v0.7 tooling export identity differs"
  }

  $v07ManualDestination = Join-Path $v07Worktree "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $v07ManualDestination) {
    throw "accepted-v0.7 tooling export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $v07ManualDestination -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $v07Manual = Join-Path $v07ManualDestination $entry.Key
    if (
      -not (Test-Path -LiteralPath $v07Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $v07Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $v07Manual) -cne $entry.Value
    ) { throw "accepted-v0.7 staged external manual differs: $($entry.Key)" }
  }

  & (Join-Path $PSScriptRoot "assert_accepted_v07_release_v08.ps1") -Root $v07Worktree | Out-Null
  Assert-NativeSuccess "accepted-v0.7 tracked release binding differs in detached worktree"

  & git -C $root worktree add --detach $v08Worktree v0.8.0 | Out-Null
  Assert-NativeSuccess "cannot create accepted-v0.8 tooling export"
  $v08WorktreeOwned = $true
  $v08Head = (@(& git -C $v08Worktree rev-parse --verify HEAD) -join "`n").Trim()
  Assert-NativeSuccess "cannot inspect accepted-v0.8 tooling export"
  if ($v08Head -cne "d6e01222de3bf52013279e48a099b6ae7ded121d") {
    throw "accepted-v0.8 tooling export identity differs"
  }

  $v08ManualDestination = Join-Path $v08Worktree "SPELL-DOCUMENTATION"
  if (Test-Path -LiteralPath $v08ManualDestination) {
    throw "accepted-v0.8 tooling export unexpectedly contains external manuals"
  }
  Copy-Item -LiteralPath $stagedManualRoot -Destination $v08ManualDestination -Recurse
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $v08Manual = Join-Path $v08ManualDestination $entry.Key
    if (
      -not (Test-Path -LiteralPath $v08Manual -PathType Leaf) -or
      ((Get-Item -LiteralPath $v08Manual -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      (Get-LowerSha256 $v08Manual) -cne $entry.Value
    ) { throw "accepted-v0.8 staged external manual differs: $($entry.Key)" }
  }
  & (Join-Path $PSScriptRoot "assert_accepted_v08_release_v09.ps1") -Root $v08Worktree | Out-Null
  Assert-NativeSuccess "accepted-v0.8 tracked release binding differs in detached worktree"

  foreach ($releaseName in @("openbexi-spell-v0.6.0.tar.gz", "openbexi-spell-v0.6.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.6/$releaseName"
    if (
      -not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or
      ((Get-Item -LiteralPath $releaseSource -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
    ) { throw "accepted-v0.6 canonical release input is missing or unsafe: $releaseName" }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $v06SidecarSha256
    } else { $v06ArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "accepted-v0.6 canonical release input hash differs: $releaseName"
    }
    foreach ($releaseRoot in @($v06Worktree, $v07Worktree)) {
      $releaseDestination = Join-Path $releaseRoot "artifacts/v0.6/$releaseName"
      Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
      if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
        throw "accepted-v0.6 staged release input hash differs: $releaseName"
      }
    }
  }
  foreach ($releaseRoot in @($v06Worktree, $v07Worktree)) {
    if ([IO.File]::ReadAllText((Join-Path $releaseRoot "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $v06SidecarText) {
      throw "accepted-v0.6 staged release sidecar bytes differ"
    }
  }
  & (Join-Path $PSScriptRoot "assert_accepted_v06_release_v07.ps1") -Root $v06Worktree | Out-Null
  Assert-NativeSuccess "accepted-v0.6 tracked release binding differs in v0.6 worktree"
  & (Join-Path $PSScriptRoot "assert_accepted_v06_release_v07.ps1") -Root $v07Worktree | Out-Null
  Assert-NativeSuccess "accepted-v0.6 tracked release binding differs in v0.7 worktree"

  foreach ($releaseName in @("openbexi-spell-v0.5.0.tar.gz", "openbexi-spell-v0.5.0.tar.gz.sha256")) {
    $releaseSource = Join-Path $root "artifacts/v0.5/$releaseName"
    if (
      -not (Test-Path -LiteralPath $releaseSource -PathType Leaf) -or
      ((Get-Item -LiteralPath $releaseSource -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
    ) { throw "accepted-v0.5 canonical release input is missing or unsafe: $releaseName" }
    $expectedReleaseSha = if ($releaseName.EndsWith(".sha256", [StringComparison]::Ordinal)) {
      $v05SidecarSha256
    } else { $v05ArchiveSha256 }
    if ((Get-LowerSha256 $releaseSource) -cne $expectedReleaseSha) {
      throw "accepted-v0.5 canonical release input hash differs: $releaseName"
    }
    foreach ($releaseRoot in @($v05Worktree, $v06Worktree, $v07Worktree)) {
      $releaseDestination = Join-Path $releaseRoot "artifacts/v0.5/$releaseName"
      Copy-Item -LiteralPath $releaseSource -Destination $releaseDestination
      if ((Get-LowerSha256 $releaseDestination) -cne $expectedReleaseSha) {
        throw "accepted-v0.5 staged release input hash differs: $releaseName"
      }
    }
  }
  foreach ($releaseRoot in @($v05Worktree, $v06Worktree, $v07Worktree)) {
    if ([IO.File]::ReadAllText((Join-Path $releaseRoot "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256"), [Text.Encoding]::ASCII) -cne $v05SidecarText) {
      throw "accepted-v0.5 staged release sidecar bytes differ"
    }
  }

  $v07InheritedRelative = (
    "artifacts/v0.4/.qualification/runtime-captures/" +
    "46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d/regression"
  )
  $v07InheritedSource = Join-Path $root $v07InheritedRelative
  $v07InheritedItem = if (Test-Path -LiteralPath $v07InheritedSource -PathType Container) {
    Get-Item -LiteralPath $v07InheritedSource -Force
  } else { $null }
  if (
    $null -eq $v07InheritedItem -or
    ($v07InheritedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    @(Get-ChildItem -LiteralPath $v07InheritedSource -Recurse -Force | Where-Object {
      $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0
  ) { throw "accepted-v0.7 inherited regression input is missing or unsafe" }
  $v07InheritedDestination = Join-Path $v07Worktree $v07InheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $v07InheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $v07InheritedSource -Destination $v07InheritedDestination -Recurse

  $v05InheritedDestination = Join-Path $v05Worktree $v07InheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $v05InheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $v07InheritedSource -Destination $v05InheritedDestination -Recurse

  $v06InheritedDestination = Join-Path $v06Worktree $v07InheritedRelative
  New-Item -ItemType Directory -Path (Split-Path -Parent $v06InheritedDestination) -Force | Out-Null
  Copy-Item -LiteralPath $v07InheritedSource -Destination $v06InheritedDestination -Recurse

  $toolingV05Xml = Join-Path $captureRoot "tooling-v05-export.xml"
  Push-Location $v05Worktree
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $v05Worktree `
      @v05ExportToolingNodes -q "--junitxml=$toolingV05Xml"
    Assert-NativeSuccess "accepted-v0.5 export tooling tests failed"
  }
  finally { Pop-Location }

  $toolingV06Xml = Join-Path $captureRoot "tooling-v06-export.xml"
  Push-Location $v06Worktree
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $v06Worktree `
      @v06ExportToolingNodes -q "--junitxml=$toolingV06Xml"
    Assert-NativeSuccess "accepted-v0.6 export tooling tests failed"
  }
  finally { Pop-Location }

  $toolingV07Xml = Join-Path $captureRoot "tooling-v07-export.xml"
  Push-Location $v07Worktree
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $v07Worktree `
      @v07ExportToolingNodes -q "--junitxml=$toolingV07Xml"
    Assert-NativeSuccess "accepted-v0.7 export tooling tests failed"
  }
  finally { Pop-Location }
  $toolingV08Xml = Join-Path $captureRoot "tooling-v08-export.xml"
  Push-Location $v08Worktree
  try {
    & $lockedPython -I -c $pytestCode $sitePackages $v08Worktree `
      @v08ExportToolingNodes -q "--junitxml=$toolingV08Xml"
    Assert-NativeSuccess "accepted-v0.8 export tooling tests failed"
  }
  finally { Pop-Location }
  $toolingXml = Join-Path $captureRoot "tooling.xml"
  $toolingOfflineXml = Join-Path $captureRoot "tooling-offline.xml"

  $nodeVersion = @(& node --version) -join "`n"
  Assert-NativeSuccess "cannot inspect Node.js"
  $npmVersion = @(& npm --version) -join "`n"
  Assert-NativeSuccess "cannot inspect npm"
  if ($nodeVersion.Trim() -cne "v24.13.0" -or $npmVersion.Trim() -cne "11.6.2") {
    throw "frontend qualification requires Node.js v24.13.0 and npm 11.6.2"
  }
  $frontendRoot = Join-Path $sourceRoot "frontend"
  Push-Location $frontendRoot
  try {
    & npm ci --ignore-scripts --no-audit
    Assert-NativeSuccess "locked frontend dependency installation failed"
    $playwrightVersion = @(& node -p "require('@playwright/test/package.json').version") -join "`n"
    Assert-NativeSuccess "cannot inspect Playwright version"
    if ($playwrightVersion.Trim() -cne "1.61.1") { throw "Playwright version differs from approved environment" }

    $vitestList = Join-Path $captureRoot "frontend-unit-list.json"
    & npx vitest list "--json=$vitestList"
    Assert-NativeSuccess "frontend unit collection failed"
    $vitestCapture = Join-Path $captureRoot "frontend-unit.json"
    & npx vitest run --reporter=json "--outputFile=$vitestCapture"
    Assert-NativeSuccess "frontend unit tests failed"
    $listed = Get-Content -LiteralPath $vitestList -Raw | ConvertFrom-Json
    $vitest = Get-Content -LiteralPath $vitestCapture -Raw | ConvertFrom-Json
    $expectedFrontendNodes = @($listed | ForEach-Object {
      $path = [IO.Path]::GetFullPath([string]$_.file)
      $prefix = [IO.Path]::GetFullPath($frontendRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
      if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Vitest collection path escapes frontend" }
      "frontend/$($path.Substring($prefix.Length).Replace('\', '/'))::$(([string]$_.name).Replace(' > ', ' '))"
    })
    $actualFrontendNodes = @($vitest.testResults | ForEach-Object {
      $path = [IO.Path]::GetFullPath([string]$_.name)
      $prefix = [IO.Path]::GetFullPath($frontendRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
      if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Vitest result path escapes frontend"
      }
      $relative = $path.Substring($prefix.Length).Replace('\', '/')
      $_.name = "frontend/$relative"
      foreach ($assertion in @($_.assertionResults)) {
        "frontend/$relative::$([string]$assertion.fullName)"
      }
    })
    Assert-ExactSet $expectedFrontendNodes $actualFrontendNodes "frontend unit collection/run bijection"
    if (
      $actualFrontendNodes.Count -ne 105 -or
      (Get-InventoryDigest $actualFrontendNodes) -cne
        "c83f5602f8f0fe945ba3029662974089aadc08ec9df6dc2127ca2c46b37036f4"
    ) { throw "frontend unit collection differs from the frozen v0.9 inventory" }
    if (
      $vitest.success -ne $true -or [int]$vitest.numTotalTests -le 0 -or
      [int]$vitest.numPassedTests -ne [int]$vitest.numTotalTests -or
      [int]$vitest.numFailedTests -ne 0 -or [int]$vitest.numPendingTests -ne 0 -or
      [int]$vitest.numTodoTests -ne 0 -or [int]$vitest.numFailedTestSuites -ne 0 -or
      [int]$vitest.numPendingTestSuites -ne 0
    ) { throw "frontend unit result is not an exact zero-skip pass" }
    [IO.File]::WriteAllText(
      $vitestCapture,
      "$(($vitest | ConvertTo-Json -Compress -Depth 100))`n",
      $utf8NoBom
    )

    & npm run build
    Assert-NativeSuccess "frontend build failed"
    $dist = Get-TreeDigest (Join-Path $frontendRoot "dist")
    $frontendBuildCapture = Join-Path $captureRoot "frontend-build.json"
    $buildDocument = [ordered]@{
      schema_version = "spell.v09.frontend-build/1"
      product_version = "0.9.0"
      source_fingerprint_sha256 = $sourceFingerprint
      command = @("npm", "run", "build")
      return_code = 0
      passed = $true
      dist_file_count = [int]$dist.FileCount
      dist_sha256 = [string]$dist.Sha256
    }
    [IO.File]::WriteAllText($frontendBuildCapture, "$(($buildDocument | ConvertTo-Json -Compress -Depth 10))`n", $utf8NoBom)

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
      $env:SPELL_V09_OFFLINE_SOURCE_ROOT = $sourceRoot
      $env:SPELL_V09_OFFLINE_NPM_CACHE_VOLUME = $offlineCacheVolume
      $env:SPELL_V09_OFFLINE_DOCKER_EXE = $script:DockerExe
      $env:SPELL_V09_OFFLINE_QUALIFICATION_IMAGE = $script:QualificationImage
      Push-Location $sourceRoot
      try {
        & $lockedPython -I -c $pytestCode $sitePackages $sourceRoot `
          $offlineToolingNode -q "--junitxml=$toolingOfflineXml"
        Assert-NativeSuccess "v0.9 offline package qualification failed"
      }
      finally { Pop-Location }
    }
    finally {
      foreach ($entry in $savedOfflineEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) { Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process") }
      }
      $savedOfflineEnvironment = $null
    }
    Merge-JUnit @(
      $toolingBaseXml, $toolingHostXml, $toolingRootXml, $toolingV05Xml,
      $toolingV06Xml, $toolingV07Xml, $toolingV08Xml, $toolingOfflineXml
    ) $toolingXml

    $savedBrowser = @{}
    foreach ($name in @(
      "CI", "SPELL_REAL_BACKEND", "SPELL_E2E_TOKEN",
      "SPELL_E2E_OPERATOR_TOKEN", "SPELL_E2E_ADMIN_TOKEN", "SPELL_E2E_BASE_URL",
      "SPELL_E2E_PREVIEW_PORT", "PLAYWRIGHT_JUNIT_OUTPUT_FILE",
      "SPELL_E2E_ARTIFACT_DIRECTORY", "SPELL_E2E_OUTPUT_DIRECTORY",
      "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_BACKEND_IMAGE_ID",
      "SPELL_BROWSER_CAPTURE_DIRECTORY", "SPELL_BROWSER_RUN_ID",
      "SPELL_BROWSER_SECRET_CANARY", "SPELL_DRIVER_IMAGE_ID", "SPELL_NPM_VERSION",
      "SPELL_PKI_IMAGE_ID", "SPELL_POSTGRES_IMAGE_ID", "SPELL_PROXY_IMAGE_ID",
      "SPELL_QUALIFICATION_IMAGE_ID", "SPELL_SOURCE_FINGERPRINT",
      "SPELL_TELEMETRY_CONTEXT_ID"
    )) { $savedBrowser[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }
    try {
      $env:CI = "true"
      Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_ADMIN_TOKEN -ErrorAction SilentlyContinue
      $mockPort = Get-FreeLoopbackPort
      $env:SPELL_E2E_PREVIEW_PORT = [string]$mockPort
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:$mockPort"
      $mockXml = Join-Path $captureRoot "browser-mocked.xml"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $mockXml
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = Join-Path $captureRoot "browser-artifacts"
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-mocked-output"
      $mockSpecs = @(
        "e2e/auth.spec.ts", "e2e/console.spec.ts", "e2e/driver-projection.spec.ts",
        "e2e/operator-workspace.spec.ts", "e2e/data-services.spec.ts",
        "e2e/development-workspace.spec.ts"
      )
      $mockListRaw = @(& npx playwright test @mockSpecs --list --reporter=json)
      Assert-NativeSuccess "mocked browser collection failed"
      [string[]]$mockNodes = @(
        Get-PlaywrightNodes (($mockListRaw -join "`n") | ConvertFrom-Json)
      )
      if (
        $mockNodes.Count -ne 28 -or
        (Get-InventoryDigest $mockNodes) -cne
          "5d464ea49f8757f93601f6ddac0c4d1c2d3566db5aaedacb06a9b17c92f8da8c"
      ) { throw "mocked browser collection differs from the frozen v0.9 inventory" }
      & npx playwright test @mockSpecs --reporter=junit --retries=0
      Assert-NativeSuccess "mocked browser qualification failed"
      Normalize-BrowserJUnit $mockXml
      $mockResult = Assert-JUnitContract $mockXml $mockNodes @() "mocked browser"

      Pop-Location
      $savedDbPassword = $env:SPELL_DB_PASSWORD
      $savedJwtSecret = $env:SPELL_JWT_HS256_SECRET
      $savedDriverEnabled = $env:SPELL_DRIVER_ENABLED
      $savedProxyPort = $env:SPELL_PROXY_PORT
      $browserDbPassword = "v09-final-browser-db-$runId"
      $browserJwtSecret = "v09-final-browser-jwt-$runId-material"
      $browserProxyPort = [string](Get-FreeLoopbackPort)
      $env:SPELL_DB_PASSWORD = $browserDbPassword
      $env:SPELL_JWT_HS256_SECRET = $browserJwtSecret
      $env:SPELL_BROWSER_SECRET_CANARY = $browserJwtSecret
      $env:SPELL_DRIVER_ENABLED = "true"
      $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "true"
      $env:SPELL_PROXY_PORT = $browserProxyPort
      $env:SPELL_BROWSER_CAPTURE_DIRECTORY = Join-Path $captureRoot "browser-real-captures"
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = $env:SPELL_BROWSER_CAPTURE_DIRECTORY
      $env:SPELL_BROWSER_RUN_ID = $runId
      $env:SPELL_NPM_VERSION = $npmVersion.Trim()
      $env:SPELL_SOURCE_FINGERPRINT = $sourceFingerprint
      $env:SPELL_TELEMETRY_CONTEXT_ID = "v09-telemetry-synthetic-context"
      Push-Location $sourceRoot
      $browserComposeStarted = $true
      & $composeExe -p $browserProject --profile driver `
        -f (Join-Path $sourceRoot "compose.yaml") up -d --build --wait
      Assert-NativeSuccess "real-browser simulator stack failed to become healthy"
      $env:SPELL_BACKEND_IMAGE_ID = Get-BrowserComposeImageId "backend"
      $builderAImageId = Get-BrowserComposeImageId "bundle-builder-a"
      $builderBImageId = Get-BrowserComposeImageId "bundle-builder-b"
      if (
        $builderAImageId -cne $env:SPELL_BACKEND_IMAGE_ID -or
        $builderBImageId -cne $env:SPELL_BACKEND_IMAGE_ID
      ) { throw "bundle builders do not share the exact backend image" }
      Assert-BrowserComposeServiceNetworkNone "bundle-builder-a"
      Assert-BrowserComposeServiceNetworkNone "bundle-builder-b"
      $env:SPELL_DRIVER_IMAGE_ID = Get-BrowserComposeImageId "spell-driver"
      $env:SPELL_PKI_IMAGE_ID = Get-BrowserComposeImageId "pki-init"
      $env:SPELL_POSTGRES_IMAGE_ID = Get-BrowserComposeImageId "postgres"
      $env:SPELL_PROXY_IMAGE_ID = Get-BrowserComposeImageId "proxy"
      $env:SPELL_QUALIFICATION_IMAGE_ID = $script:QualificationImage
      $operatorTokenLines = @(& $composeExe -p $browserProject --profile driver `
        -f (Join-Path $sourceRoot "compose.yaml") `
        exec -T backend python /app/scripts/issue_dev_token.py `
        --subject v09-final-development-author --role operator --lifetime 900)
      Assert-NativeSuccess "cannot issue short-lived real-browser operator token"
      $operatorToken = $operatorTokenLines | Where-Object { $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' } | Select-Object -Last 1
      $operatorTokenLines = $null
      $adminTokenLines = @(& $composeExe -p $browserProject --profile driver `
        -f (Join-Path $sourceRoot "compose.yaml") `
        exec -T backend python /app/scripts/issue_dev_token.py `
        --subject v09-final-development-reviewer --role admin --lifetime 900)
      Assert-NativeSuccess "cannot issue short-lived real-browser admin token"
      $adminToken = $adminTokenLines | Where-Object { $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' } | Select-Object -Last 1
      $adminTokenLines = $null
      if (-not $operatorToken -or -not $adminToken -or $operatorToken -ceq $adminToken) {
        throw "real-browser role token output is invalid or not distinct"
      }
      Pop-Location
      Push-Location $frontendRoot
      $env:SPELL_REAL_BACKEND = "1"
      $env:SPELL_E2E_TOKEN = $adminToken
      $env:SPELL_E2E_OPERATOR_TOKEN = $operatorToken
      $env:SPELL_E2E_ADMIN_TOKEN = $adminToken
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:$($env:SPELL_PROXY_PORT)"
      $realXml = Join-Path $captureRoot "browser-real.xml"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = $realXml
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "browser-real-output"
      $seedLines = @(& $composeExe -p $browserProject --profile driver `
        -f (Join-Path $sourceRoot "compose.yaml") `
        exec -T backend python /app/scripts/seed_observation_v07.py `
        --context-id $env:SPELL_TELEMETRY_CONTEXT_ID `
        --confirm LOCAL_SYNTHETIC_NON_CUI_ONLY --timeout-seconds 45)
      Assert-NativeSuccess "real telemetry browser observation seed failed"
      $seedJson = $seedLines | Where-Object { $_ -cmatch '^\{.*\}$' } | Select-Object -Last 1
      if (-not $seedJson) { throw "real telemetry browser seed output is invalid" }
      $seed = $seedJson | ConvertFrom-Json
      if (
        $seed.context_id -cne $env:SPELL_TELEMETRY_CONTEXT_ID -or
        @($seed.item_ids).Count -ne 3 -or
        [string]$seed.through_sequence -cnotmatch '^[1-9][0-9]*$'
      ) { throw "real telemetry browser seed identity differs" }
      $headers = @{ Authorization = "Bearer $adminToken" }
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
      $realSpecs = @(
        "e2e/integration.spec.ts", "e2e/telemetry-observation-real.spec.ts",
        "e2e/data-services-real.spec.ts", "e2e/development-workspace-real.spec.ts"
      )
      $realListRaw = @(& npx playwright test @realSpecs --list --reporter=json)
      Assert-NativeSuccess "real browser collection failed"
      [string[]]$realNodes = @(
        Get-PlaywrightNodes (($realListRaw -join "`n") | ConvertFrom-Json)
      )
      if (
        $realNodes.Count -ne 16 -or
        (Get-InventoryDigest $realNodes) -cne
          "5ade56130bff336341ff06246d069e8ee5249ce8d6298e58cfa29c2b47fe5866"
      ) { throw "real browser collection differs from the frozen v0.9 inventory" }
      & npx playwright test @realSpecs --reporter=junit --retries=0 --workers=1
      Assert-NativeSuccess "real browser qualification failed"
      $operatorToken = $null
      $adminToken = $null
      Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_OPERATOR_TOKEN -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_ADMIN_TOKEN -ErrorAction SilentlyContinue
      Normalize-BrowserJUnit $realXml
      $realResult = Assert-JUnitContract $realXml $realNodes @() "real browser"
    }
    finally {
      $operatorTokenLines = $null
      $adminTokenLines = $null
      $operatorToken = $null
      $adminToken = $null
      $headers = $null
      foreach ($entry in $savedBrowser.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
      }
      $savedBrowser = $null
      if (Get-Variable savedDbPassword -ErrorAction SilentlyContinue) {
        $env:SPELL_DB_PASSWORD = $savedDbPassword
        $env:SPELL_JWT_HS256_SECRET = $savedJwtSecret
        $env:SPELL_DRIVER_ENABLED = $savedDriverEnabled
        $env:SPELL_PROXY_PORT = $savedProxyPort
        $savedDbPassword = $null
        $savedJwtSecret = $null
        $savedDriverEnabled = $null
        $savedProxyPort = $null
      }
    }
  }
  finally {
    while ((Get-Location).Path -cne $root) { Pop-Location }
  }

  $sqliteResult = Assert-JUnitContract $sqliteXml $backendNodes $sqliteAllowedSkips "backend SQLite"
  [string[]]$postgresNodes = @($backendNodes | Where-Object { $_ -notin $runtimeNodes })
  $postgresResult = Assert-JUnitContract $postgresXml $postgresNodes @() "backend PostgreSQL"
  $dockerHostResult = Assert-JUnitContract $dockerHostXml $runtimeNodes @() "backend Docker host"
  $driverResult = Assert-JUnitContract $driverXml $driverNodes @() "driver host"
  $toolingResult = Assert-JUnitContract $toolingXml $toolingNodes @() "tooling" 36
  $fingerprintsAfter = @(& $lockedPython -I -c $fingerprintCode $sourceRoot)
  Assert-NativeSuccess "cannot recompute frozen source/product fingerprints"
  if (
    $fingerprintsAfter.Count -ne 2 -or $fingerprintsAfter[0] -cne $sourceFingerprint -or
    $fingerprintsAfter[1] -cne $productPackageSha256
  ) { throw "frozen source or product bytes changed during qualification" }
  Assert-V08ArtifactsUnchanged $resolvedSource
}
catch { $failure = $_ }
finally {
  if ($v05WorktreeOwned) {
    & git -C $root worktree remove --force $v05Worktree | Out-Null
    if ($LASTEXITCODE -ne 0) { $cleanupFailures.Add("accepted-v0.5 tooling export teardown failed") }
    $v05WorktreeOwned = $false
  }
  if ($v06WorktreeOwned) {
    & git -C $root worktree remove --force $v06Worktree | Out-Null
    if ($LASTEXITCODE -ne 0) { $cleanupFailures.Add("accepted-v0.6 tooling export teardown failed") }
    $v06WorktreeOwned = $false
  }
  if ($v07WorktreeOwned) {
    & git -C $root worktree remove --force $v07Worktree | Out-Null
    if ($LASTEXITCODE -ne 0) { $cleanupFailures.Add("accepted-v0.7 tooling export teardown failed") }
    $v07WorktreeOwned = $false
  }
  if ($v08WorktreeOwned) {
    & git -C $root worktree remove --force $v08Worktree | Out-Null
    if ($LASTEXITCODE -ne 0) { $cleanupFailures.Add("accepted-v0.8 tooling export teardown failed") }
    $v08WorktreeOwned = $false
  }
  if ($script:DockerExe) {
    try {
      if ($browserComposeStarted) {
        $cleanupDbPassword = $env:SPELL_DB_PASSWORD
        $cleanupJwtSecret = $env:SPELL_JWT_HS256_SECRET
        $cleanupDriverEnabled = $env:SPELL_DRIVER_ENABLED
        $cleanupProxyPort = $env:SPELL_PROXY_PORT
        try {
          $env:SPELL_DB_PASSWORD = $browserDbPassword
          $env:SPELL_JWT_HS256_SECRET = $browserJwtSecret
          $env:SPELL_DRIVER_ENABLED = "false"
          $env:SPELL_PROXY_PORT = $browserProxyPort
          Push-Location $sourceRoot
          try {
            $down = Invoke-ComposeCleanup @(
              "-p", $browserProject, "--profile", "driver", "-f",
              (Join-Path $sourceRoot "compose.yaml"), "down",
              "--rmi", "local", "-v", "--remove-orphans"
            )
            if ($down.ExitCode -ne 0) { $cleanupFailures.Add("browser Compose teardown failed") }
          }
          finally { Pop-Location }
        }
        finally {
          $env:SPELL_DB_PASSWORD = $cleanupDbPassword
          $env:SPELL_JWT_HS256_SECRET = $cleanupJwtSecret
          $env:SPELL_DRIVER_ENABLED = $cleanupDriverEnabled
          $env:SPELL_PROXY_PORT = $cleanupProxyPort
        }
      }
    }
    catch { $cleanupFailures.Add("browser Compose teardown failed: $($_.Exception.Message)") }
    foreach ($container in $script:Containers) {
      Invoke-DockerCleanup @("rm", "-f", $container) | Out-Null
    }
    foreach ($volume in $script:Volumes) {
      Invoke-DockerCleanup @("volume", "rm", "-f", $volume) | Out-Null
    }
    Invoke-DockerCleanup @("network", "rm", $postgresNetwork) | Out-Null
    foreach ($tag in $script:ImageTags) { Invoke-DockerCleanup @("image", "rm", $tag) | Out-Null }
    if ($runtimeBaseline) { $runtimeResourcesTornDown = Remove-NewRuntimeResources $runtimeBaseline }
    foreach ($ownerProject in @($project, $browserProject)) {
      $queries = @(
        @("ps", "-aq", "--filter", "label=com.docker.compose.project=$ownerProject"),
        @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$ownerProject"),
        @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$ownerProject"),
        @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$ownerProject")
      )
      foreach ($query in $queries) {
        [pscustomobject]$inspection = Invoke-DockerCleanup ([string[]]$query)
        if ($inspection.ExitCode -ne 0 -or @($inspection.Lines | Where-Object { $_ }).Count -ne 0) {
          $cleanupFailures.Add("owned Docker resource teardown could not be verified: $ownerProject")
        }
      }
    }
  }
  else { $runtimeResourcesTornDown = $true }
  $qualificationResourcesTornDown = $cleanupFailures.Count -eq 0
  try { Pop-Location } catch { $cleanupFailures.Add("working-directory restoration failed") }
}

$databasePassword = $null; $applicationUrl = $null; $migrationUrl = $null
$browserDbPassword = $null; $browserJwtSecret = $null; $browserToken = $null
if (-not $runtimeResourcesTornDown) { $cleanupFailures.Add("runtime test resources remain") }
if ($failure -or $cleanupFailures.Count -ne 0) {
  if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
  if ($failure) { throw $failure }
  throw "final qualification teardown failed: $($cleanupFailures -join '; ')"
}

try {
  New-Item -ItemType Directory -Path (Join-Path $publicationStage "tests") -Force | Out-Null
  $captureMap = [ordered]@{
    "backend-sqlite.xml" = $sqliteXml
    "backend-postgresql.xml" = $postgresXml
    "backend-docker-host.xml" = $dockerHostXml
    "driver-host.xml" = $driverXml
    "tooling.xml" = $toolingXml
    "frontend-unit.json" = $vitestCapture
    "frontend-build.json" = $frontendBuildCapture
    "browser-mocked.xml" = $mockXml
    "browser-real.xml" = $realXml
  }
  foreach ($entry in $captureMap.GetEnumerator()) {
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $publicationStage "tests/$($entry.Key)")
  }

  $suites = [ordered]@{}
  $suites.backend_sqlite = New-JUnitSuiteDeclaration "backend_sqlite" `
    (Join-Path $publicationStage "tests/backend-sqlite.xml") $sqliteResult $sqliteAllowedSkips
  $suites.backend_postgresql = New-JUnitSuiteDeclaration "backend_postgresql" `
    (Join-Path $publicationStage "tests/backend-postgresql.xml") $postgresResult @()
  $suites.backend_docker_host = New-JUnitSuiteDeclaration "backend_docker_host" `
    (Join-Path $publicationStage "tests/backend-docker-host.xml") $dockerHostResult @()
  $suites.driver_host = New-JUnitSuiteDeclaration "driver_host" `
    (Join-Path $publicationStage "tests/driver-host.xml") $driverResult @()
  $suites.tooling = New-JUnitSuiteDeclaration "tooling" `
    (Join-Path $publicationStage "tests/tooling.xml") $toolingResult @()
  $suites.frontend_unit = [ordered]@{
    kind = "vitest-json"; capture = "artifacts/v0.9/final/tests/frontend-unit.json"
    sha256 = Get-LowerSha256 (Join-Path $publicationStage "tests/frontend-unit.json")
    test_count = [int]$vitest.numTotalTests; subtest_count = 0
    passed_count = [int]$vitest.numPassedTests; skipped_count = 0
    failure_count = 0; error_count = 0; allowed_skipped_nodes = @()
  }
  $suites.frontend_build = [ordered]@{
    kind = "frontend-build"; capture = "artifacts/v0.9/final/tests/frontend-build.json"
    sha256 = Get-LowerSha256 (Join-Path $publicationStage "tests/frontend-build.json")
    passed = $true; dist_file_count = [int]$dist.FileCount; dist_sha256 = [string]$dist.Sha256
  }
  $suites.browser_mocked = New-JUnitSuiteDeclaration "browser_mocked" `
    (Join-Path $publicationStage "tests/browser-mocked.xml") $mockResult @()
  $suites.browser_real = New-JUnitSuiteDeclaration "browser_real" `
    (Join-Path $publicationStage "tests/browser-real.xml") $realResult @()

  $workPackageRelative = "artifacts/v0.9/work-package/qualification.json"
  $workPackageValidatorRelative = "scripts/validate_candidate_evidence_v09.py"
  $gateScopeRelative = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.9-gate-0b.json"
  )
  $gateDocumentRelative = "SPELL_v0.9_Gate_0B.md"
  $gateValidatorRelative = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py"
  )
  $finalToolchain = [ordered]@{
    python = [string]$candidateEvidence.toolchain.python
    docker = [string]$candidateEvidence.toolchain.docker
    node = [string]$candidateEvidence.toolchain.node
    npm = [string]$candidateEvidence.toolchain.npm
    playwright = [string]$candidateEvidence.toolchain.playwright
    chromium = [string]$candidateEvidence.toolchain.chromium
    files_sha256 = $candidateEvidence.toolchain.files_sha256
    candidate_qualification_image_id = [string]$candidateEvidence.toolchain.qualification_image_id
    final_qualification_image_id = [string]$script:QualificationImage
  }
  $summary = [ordered]@{
    schema_version = "spell.v09.final-qualification/1"
    product_version = "0.9.0"
    scope_profile = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
    qualified_source = [ordered]@{ commit = $resolvedSource; tree = $resolvedTree }
    source_fingerprint_sha256 = $sourceFingerprint
    product_package_sha256 = $productPackageSha256
    work_package = [ordered]@{
      evidence_path = $workPackageRelative
      evidence_sha256 = Get-LowerSha256 (Join-Path $sourceRoot $workPackageRelative)
      validator_path = $workPackageValidatorRelative
      validator_sha256 = Get-LowerSha256 (Join-Path $sourceRoot $workPackageValidatorRelative)
      candidate_commit = $candidateCommit
    }
    gate_0b = [ordered]@{
      scope_path = $gateScopeRelative
      scope_sha256 = Get-LowerSha256 (Join-Path $sourceRoot $gateScopeRelative)
      document_path = $gateDocumentRelative
      document_sha256 = Get-LowerSha256 (Join-Path $sourceRoot $gateDocumentRelative)
      validator_path = $gateValidatorRelative
      validator_sha256 = Get-LowerSha256 (Join-Path $sourceRoot $gateValidatorRelative)
      success_marker = $gate0bMarker
    }
    toolchain = $finalToolchain
    suites = $suites
    accepted_v08_release = [ordered]@{
      archive_sha256 = $v08ArchiveSha256
      sidecar_sha256 = $v08SidecarSha256
      tag_object = "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae"
      tag_archive_claim = "Final archive SHA-256: $v08ArchiveSha256"
    }
    teardown = [ordered]@{
      qualification_resources_torn_down = $true
      runtime_test_resources_torn_down = $true
      temporary_evidence_removed = $true
      secrets_retained = $false
    }
    accepted_exceptions = @()
    overall_pass = $true
  }
  $summaryJson = $summary | ConvertTo-Json -Compress -Depth 100
  [IO.File]::WriteAllText((Join-Path $publicationStage "qualification.json"), "$summaryJson`n", $utf8NoBom)

  Remove-Item -LiteralPath $tempRoot -Recurse -Force
  $validatedSummary = Assert-FinalPublication $publicationStage
  if (
    [string]$validatedSummary.qualified_source.commit -cne $resolvedSource -or
    [string]$validatedSummary.source_fingerprint_sha256 -cne $sourceFingerprint -or
    [string]$validatedSummary.product_package_sha256 -cne $productPackageSha256
  ) { throw "staged final qualification source binding differs" }

  if (Test-Path -LiteralPath $canonicalFinal) {
    if (-not $Replace) { throw "final v0.9 qualification already exists; pass -Replace to republish" }
    Move-Item -LiteralPath $canonicalFinal -Destination $publicationBackup
  }
  try {
    Move-Item -LiteralPath $publicationStage -Destination $canonicalFinal
    $published = Assert-FinalPublication $canonicalFinal
    if (Test-Path -LiteralPath $publicationBackup) {
      Remove-Item -LiteralPath $publicationBackup -Recurse -Force
    }
  }
  catch {
    if (Test-Path -LiteralPath $canonicalFinal) { Remove-Item -LiteralPath $canonicalFinal -Recurse -Force }
    if (Test-Path -LiteralPath $publicationBackup) {
      Move-Item -LiteralPath $publicationBackup -Destination $canonicalFinal
    }
    throw
  }
  [ordered]@{
    schema_version = "spell.v09.final-qualification-publication/1"
    qualified_source_commit = $resolvedSource
    qualified_source_tree = $resolvedTree
    source_fingerprint_sha256 = $sourceFingerprint
    product_package_sha256 = $productPackageSha256
    suite_count = $finalSuiteIds.Count
    published = $true
  } | ConvertTo-Json -Compress | Write-Output
}
finally {
  if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
  if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
}
