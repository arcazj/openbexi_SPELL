param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$LocalConfirmation,
  [switch]$Replace
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$implementationCommit = "aefa658ce01d49a7879d0471b50425ac3bcf9e2d"
$implementationTree = "958c43e867228b536fd21c0da59d5530e9fe155b"
$implementationParent = "d13397f51241c6bac10289ea21b69aafff66b1fb"
$qualificationCommit = "ef26e53f5ecccabef1fff03ec86d71b0c93edd2b"
$qualificationTree = "f646a40bcd70ec9ebc28f3ebf3783e54c1c8f9a1"
$qualificationParent = "05a1c89c21b500270476b172d86d0758945d23d7"
$correctionPath = "backend/tests/test_driver_isolation.py"
$correctionBlob = "60ed5164ffe190ccbb5cee91ffe619eba7c8c9c2"
$correctionSha256 = "d0eca2c56705068027b910991719971838d5f84033806f9a0ff9de0f7b3e0756"
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
$project = "spell-v05-candidate-$runId"
$qualificationTag = "openbexi-spell-v05-candidate-qualification:$runId"
$postgresTag = "openbexi-spell-v05-candidate-postgres:$runId"
$network = "$project-internal"
$postgresContainer = "$project-postgres"
$postgresVolume = "$project-postgres-data"
$containers = [Collections.Generic.List[string]]::new()
$volumes = [Collections.Generic.List[string]]::new()
$imageTags = [Collections.Generic.List[string]]::new()
$imageTags.Add($qualificationTag)
$imageTags.Add($postgresTag)
$failure = $null
$resourcesTornDown = $false
$runtimeResourcesTornDown = $false
$imageTagsRemoved = $false
$hostRuntimeCompleted = $false

if ($LocalConfirmation -cne "LOCAL_SYNTHETIC_NON_CUI_ONLY") {
  throw "V05-IR-001 qualification requires the exact local synthetic non-CUI confirmation"
}

function Get-LowerSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-DockerCleanup {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:DockerExe @Arguments 2>$null)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  return [pscustomobject]@{
    ExitCode = [int]$code
    Lines = [string[]]@($lines | ForEach-Object { [string]$_ })
  }
}

function Assert-NativeSuccess([string]$Message) {
  if ($LASTEXITCODE -ne 0) { throw $Message }
}

function Get-OrdinalSortedStrings {
  param([Parameter(Mandatory = $true)][object[]]$Values)
  [string[]]$items = @($Values | ForEach-Object { [string]$_ })
  [Array]::Sort($items, [StringComparer]::Ordinal)
  return $items
}

function Get-InventoryDigest {
  param([Parameter(Mandatory = $true)][string[]]$Nodes)
  $payload = [Text.Encoding]::UTF8.GetBytes(($Nodes -join "`n") + "`n")
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

function Get-CollectedNodes {
  param(
    [Parameter(Mandatory = $true)][string]$Suite,
    [Parameter(Mandatory = $true)][string]$ExpectedPrefix,
    [Parameter(Mandatory = $true)][int]$ExpectedCount,
    [Parameter(Mandatory = $true)][string]$ExpectedDigest
  )
  $name = "$project-collect-$($Suite.Replace('/', '-'))"
  $script:containers.Add($name)
  & $script:DockerExe create --name $name `
    --label "com.docker.compose.project=$project" `
    --network none --read-only --tmpfs "/tmp:size=256m,noexec,nosuid" `
    $script:QualificationImage python -m pytest --collect-only -q $Suite | Out-Null
  Assert-NativeSuccess "cannot create the $Suite collection container"
  $output = @(& $script:DockerExe start --attach $name 2>&1)
  Assert-NativeSuccess "$Suite collection failed"
  $nodes = @(
    $output |
      ForEach-Object {
        $line = [string]$_
        $separator = $line.IndexOf("::", [StringComparison]::Ordinal)
        if ($separator -ge 0) {
          $line.Substring(0, $separator).Replace('\', '/') + $line.Substring($separator)
        }
        else { $line }
      } |
      Where-Object { $_.StartsWith($ExpectedPrefix, [StringComparison]::Ordinal) -and $_.Contains("::") }
  )
  $nodes = Get-OrdinalSortedStrings $nodes
  if (@($nodes | Select-Object -Unique).Count -ne $nodes.Count) {
    throw "$Suite collection contains duplicate node IDs"
  }
  $summary = @($output | Where-Object { [string]$_ -match "^$ExpectedCount tests collected in " })
  if ($summary.Count -ne 1 -or $nodes.Count -ne $ExpectedCount) {
    throw "$Suite collection count differs from the immutable candidate inventory"
  }
  $digest = Get-InventoryDigest $nodes
  if ($digest -cne $ExpectedDigest) {
    throw "$Suite collection digest differs from the immutable candidate inventory"
  }
  return ,$nodes
}

function Invoke-ImagePytest {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$Network,
    [Parameter(Mandatory = $true)][string[]]$Environment,
    [Parameter(Mandatory = $true)][string[]]$PytestArguments,
    [Parameter(Mandatory = $true)][string]$OutputPath
  )
  $container = "$project-$Id"
  $volume = "$container-output"
  $script:containers.Add($container)
  $script:volumes.Add($volume)
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $volume | Out-Null
  Assert-NativeSuccess "cannot create the $Id output volume"
  $arguments = @(
    "create", "--name", $container,
    "--label", "com.docker.compose.project=$project",
    "--network", $Network,
    "--read-only", "--tmpfs", "/tmp:size=768m,noexec,nosuid",
    "--mount", "type=volume,source=$volume,target=/qualification-output"
  )
  foreach ($entry in $Environment) { $arguments += @("-e", $entry) }
  $arguments += @($script:QualificationImage, "python", "-m", "pytest")
  $arguments += $PytestArguments
  & $script:DockerExe @arguments | Out-Null
  Assert-NativeSuccess "cannot create the $Id test container"
  & $script:DockerExe start --attach $container
  Assert-NativeSuccess "$Id tests failed"
  & $script:DockerExe cp "${container}:/qualification-output/result.xml" $OutputPath | Out-Null
  Assert-NativeSuccess "cannot copy the $Id JUnit capture"
}

function Get-JUnitSummary {
  param([Parameter(Mandatory = $true)][string]$Path)
  [xml]$document = Get-Content -LiteralPath $Path -Raw
  $cases = @($document.SelectNodes("//testcase"))
  $reportedTests = 0
  foreach ($suite in @($document.SelectNodes("//testsuite"))) {
    $directCases = @($suite.SelectNodes("testcase"))
    if ($directCases.Count -gt 0) {
      $value = $suite.GetAttribute("tests")
      $parsed = 0
      if (-not [int]::TryParse($value, [ref]$parsed) -or $parsed -lt $directCases.Count) {
        throw "JUnit testcase aggregate is invalid: $Path"
      }
      $reportedTests += $parsed
    }
  }
  $skipped = @($cases | Where-Object { $_.SelectSingleNode("skipped") }).Count
  $failures = @($cases | Where-Object { $_.SelectSingleNode("failure") }).Count
  $errors = @($cases | Where-Object { $_.SelectSingleNode("error") }).Count
  return [ordered]@{
    test_count = $cases.Count
    subtest_count = $reportedTests - $cases.Count
    passed_count = $cases.Count - $skipped - $failures - $errors
    skipped_count = $skipped
    failure_count = $failures
    error_count = $errors
  }
}

function Merge-JUnit {
  param(
    [Parameter(Mandatory = $true)][string[]]$Inputs,
    [Parameter(Mandatory = $true)][string]$Output
  )
  $target = [Xml.XmlDocument]::new()
  $declaration = $target.CreateXmlDeclaration("1.0", "utf-8", $null)
  $target.AppendChild($declaration) | Out-Null
  $suites = $target.CreateElement("testsuites")
  $suites.SetAttribute("name", "pytest tests")
  $target.AppendChild($suites) | Out-Null
  $suite = $target.CreateElement("testsuite")
  $suite.SetAttribute("name", "pytest")
  $suites.AppendChild($suite) | Out-Null
  $cases = [Collections.Generic.List[Xml.XmlNode]]::new()
  foreach ($input in $Inputs) {
    [xml]$source = Get-Content -LiteralPath $input -Raw
    foreach ($case in @($source.SelectNodes("//testcase"))) {
      $cases.Add($target.ImportNode($case, $true))
    }
  }
  foreach ($case in $cases) { $suite.AppendChild($case) | Out-Null }
  $skipped = @($cases | Where-Object { $_.SelectSingleNode("skipped") }).Count
  $failures = @($cases | Where-Object { $_.SelectSingleNode("failure") }).Count
  $errors = @($cases | Where-Object { $_.SelectSingleNode("error") }).Count
  $suite.SetAttribute("tests", [string]$cases.Count)
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

function Get-RuntimeResources {
  $result = [ordered]@{}
  $result.containers = @(
    & $script:DockerExe ps -a --format "{{.Names}}" |
      Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" }
  )
  $result.networks = @(
    & $script:DockerExe network ls --format "{{.Name}}" |
      Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" }
  )
  $result.volumes = @(
    & $script:DockerExe volume ls --format "{{.Name}}" |
      Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" }
  )
  $result.images = @(
    & $script:DockerExe image ls --format "{{.Repository}}:{{.Tag}}" |
      Where-Object { $_ -like "spell-v04-isolation-*" -or $_ -like "spell-v04-restart-*" }
  )
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

function Get-IdentityMap {
  param([Parameter(Mandatory = $true)][string[]]$BackendNodes)
  function Select-Nodes([string]$fragment) {
    return @(Get-OrdinalSortedStrings @($BackendNodes | Where-Object { $_.Contains($fragment) }))
  }
  function Select-Exact([string[]]$values) {
    foreach ($value in $values) {
      if ($value -notin $BackendNodes) { throw "identity node is missing: $value" }
    }
    return @(Get-OrdinalSortedStrings $values)
  }
  $unit = Select-Nodes "backend/tests/test_ir_v03.py::test_v05_ir_001_unit_"
  $parser = Select-Exact @(
    "backend/tests/test_ir_v03.py::test_v05_ir_001_unit_accepts_complete_parser_golden_ir_without_rewriting_input",
    "backend/tests/test_ir_boundaries.py::test_parser_postvalidation_rejects_invalid_compiler_output",
    "backend/tests/test_procedure_parser.py::test_parser_creates_ir_without_executing_source",
    "backend/tests/test_procedure_parser.py::test_v03_compiles_typed_control_flow_and_local_calls_to_flat_ir"
  )
  $supervisorExact = @(
    "backend/tests/test_ir_boundaries.py::test_initial_start_accepts_a_valid_first_prompt",
    "backend/tests/test_ir_boundaries.py::test_supervisor_rejects_tampered_ir_before_generation_or_process_allocation",
    "backend/tests/test_ir_boundaries.py::test_rejection_audit_failure_still_prevents_worker_allocation"
  )
  Select-Exact $supervisorExact | Out-Null
  $supervisor = @(
    $BackendNodes | Where-Object {
      $_ -in $supervisorExact -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_persisted_row_mutations_fail_closed_before_worker_allocation[")
    }
  )
  $workerExact = "backend/tests/test_ir_v03.py::test_v05_ir_001_worker_facing_validation_rejects_unsized_steps"
  Select-Exact @($workerExact) | Out-Null
  $worker = @(
    $BackendNodes | Where-Object {
      $_ -ceq $workerExact -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_worker_rejects_ir_before_started_ack_checkpoint_prompt_or_effect[") -or
      $_.Contains("backend/tests/test_worker_expressions.py::test_expression_evaluator_rejects_invalid_runtime_ir[")
    }
  )
  $compat = Select-Exact @(
    "backend/tests/test_ir_v03.py::test_v05_ir_001_unit_accepts_complete_parser_golden_ir_without_rewriting_input",
    "backend/tests/test_ir_v03.py::test_v05_ir_001_compat_validates_recovery_checkpoint_without_byte_changes",
    "backend/tests/test_ir_boundaries.py::test_initial_start_accepts_a_valid_first_prompt",
    "backend/tests/test_procedure_parser.py::test_parser_creates_ir_without_executing_source",
    "backend/tests/test_procedure_parser.py::test_v03_compiles_typed_control_flow_and_local_calls_to_flat_ir",
    "backend/tests/test_v03_execution.py::test_typed_variables_survive_prompt_crash_and_recovery",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_sqlite_database_without_record_drift",
    "backend/tests/test_worker_expressions.py::test_worker_restores_checkpointed_variables_at_recovery_step"
  )
  $adversarial = @(
    $BackendNodes | Where-Object {
      $_.Contains("backend/tests/test_ir_v03.py::test_v05_ir_001_adversarial_") -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_supervisor_rejects_") -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_persisted_row_mutations_fail_closed_before_worker_allocation[") -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_rejection_audit_failure_") -or
      $_.Contains("backend/tests/test_ir_boundaries.py::test_worker_rejects_ir_before_") -or
      $_ -ceq $workerExact
    }
  )
  $raw = [ordered]@{
    "V05-IR-001-UNIT" = $unit
    "V05-IR-001-PARSER" = $parser
    "V05-IR-001-SUPERVISOR" = $supervisor
    "V05-IR-001-WORKER" = $worker
    "V05-IR-001-COMPAT" = $compat
    "V05-IR-001-ADVERSARIAL" = $adversarial
  }
  $expected = @{
    "V05-IR-001-UNIT" = 9
    "V05-IR-001-PARSER" = 4
    "V05-IR-001-SUPERVISOR" = 9
    "V05-IR-001-WORKER" = 7
    "V05-IR-001-COMPAT" = 8
    "V05-IR-001-ADVERSARIAL" = 38
  }
  $result = [ordered]@{}
  foreach ($entry in $raw.GetEnumerator()) {
    $nodes = Get-OrdinalSortedStrings @($entry.Value)
    if (@($nodes | Select-Object -Unique).Count -ne $nodes.Count -or $nodes.Count -ne $expected[$entry.Key]) {
      throw "$($entry.Key) exact node mapping differs"
    }
    $result[$entry.Key] = [ordered]@{
      nodes = $nodes
      environments = @("sqlite", "postgresql")
      passed_count = 2 * $nodes.Count
      skipped_count = 0
    }
  }
  return $result
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
Assert-NativeSuccess "release toolchain validation failed"
$script:DockerExe = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
$lockedPython = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
$toolchainLock = Join-Path $root "scripts/release-toolchain-v04.json"
$validator = Join-Path $root "scripts/validate_candidate_evidence_v05.py"
$qualificationDockerfile = Join-Path $root "scripts/qualification-v05.Dockerfile"
$qualificationDockerignore = Join-Path $root "scripts/qualification-v05.Dockerfile.dockerignore"
$externalManualSource = Join-Path $root "SPELL-DOCUMENTATION"
$inheritedRunRelative = "artifacts/v0.4/.qualification/runtime-captures/46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d/regression/run.json"
$inheritedRun = Join-Path $root $inheritedRunRelative
if (-not (Test-Path -LiteralPath $inheritedRun -PathType Leaf)) {
  throw "required inherited v0.4 regression run is missing"
}

$tempRoot = Join-Path $env:TEMP "spell-v05-candidate-$runId"
$tempRootFull = [IO.Path]::GetFullPath($tempRoot)
$tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $tempRootFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing a candidate qualification path outside the temporary root"
}
$candidateRoot = Join-Path $tempRoot "candidate"
$captureRoot = Join-Path $tempRoot "captures"
$archivePath = Join-Path $tempRoot "candidate.zip"
$runtimeBaseline = Get-RuntimeResources
$publicationParent = Join-Path $root "artifacts/v0.5"
$publicationStage = Join-Path $publicationParent ".work-package-stage-$runId"
$canonicalRoot = Join-Path $publicationParent "work-package"
$publicationBackup = Join-Path $publicationParent ".work-package-backup-$runId"

New-Item -ItemType Directory -Path $candidateRoot -Force | Out-Null
New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null

Push-Location $root
try {
  $resolvedImplementation = (git rev-parse --verify "$implementationCommit^{commit}").Trim()
  Assert-NativeSuccess "implementation candidate commit lookup failed"
  $resolvedImplementationTree = (git rev-parse --verify "$implementationCommit^{tree}").Trim()
  Assert-NativeSuccess "implementation candidate tree lookup failed"
  $resolvedImplementationParent = (git rev-parse --verify "$implementationCommit^").Trim()
  Assert-NativeSuccess "implementation candidate parent lookup failed"
  if (
    $resolvedImplementation -cne $implementationCommit -or
    $resolvedImplementationTree -cne $implementationTree -or
    $resolvedImplementationParent -cne $implementationParent
  ) {
    throw "immutable implementation candidate Git identity differs"
  }
  $resolvedQualification = (git rev-parse --verify "$qualificationCommit^{commit}").Trim()
  Assert-NativeSuccess "qualification source commit lookup failed"
  $resolvedQualificationTree = (git rev-parse --verify "$qualificationCommit^{tree}").Trim()
  Assert-NativeSuccess "qualification source tree lookup failed"
  $resolvedQualificationParent = (git rev-parse --verify "$qualificationCommit^").Trim()
  Assert-NativeSuccess "qualification source parent lookup failed"
  if (
    $resolvedQualification -cne $qualificationCommit -or
    $resolvedQualificationTree -cne $qualificationTree -or
    $resolvedQualificationParent -cne $qualificationParent
  ) {
    throw "immutable qualification source Git identity differs"
  }
  git merge-base --is-ancestor $implementationCommit $qualificationCommit
  Assert-NativeSuccess "implementation candidate is not an ancestor of qualification source"
  git archive --format=zip --output=$archivePath $qualificationCommit
  Assert-NativeSuccess "qualification source Git archive failed"
  Expand-Archive -LiteralPath $archivePath -DestinationPath $candidateRoot

  $manualLedger = Get-ManualLedgerMap (Join-Path $candidateRoot "SPELL_DOCUMENTATION_REVIEW.md")
  if (-not (Test-Path -LiteralPath $externalManualSource -PathType Container) -or
      (Get-Item -LiteralPath $externalManualSource).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw "external-manual source directory is missing or unsafe"
  }
  $sourceManuals = @(
    Get-ChildItem -LiteralPath $externalManualSource -Force |
      Where-Object { -not $_.PSIsContainer }
  )
  if ($sourceManuals.Count -ne $manualLedger.Count -or
      @($sourceManuals | Where-Object { $_.Name -notin $manualLedger.Keys }).Count -ne 0) {
    throw "external-manual source inventory differs from the committed ledger"
  }
  $stagedManualRoot = Join-Path $candidateRoot "SPELL-DOCUMENTATION"
  New-Item -ItemType Directory -Path $stagedManualRoot | Out-Null
  foreach ($entry in $manualLedger.GetEnumerator()) {
    $source = Join-Path $externalManualSource $entry.Key
    $sourceItem = Get-Item -LiteralPath $source
    if ($sourceItem.PSIsContainer -or
        $sourceItem.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        (Get-LowerSha256 $source) -cne $entry.Value) {
      throw "external-manual file is missing, unsafe, or hash-mismatched: $($entry.Key)"
    }
    $destination = Join-Path $stagedManualRoot $entry.Key
    Copy-Item -LiteralPath $source -Destination $destination
    if ((Get-LowerSha256 $destination) -cne $entry.Value) {
      throw "staged external-manual hash differs: $($entry.Key)"
    }
  }

  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    --label "org.openbexi.spell.v05.implementation.commit=$implementationCommit" `
    --label "org.openbexi.spell.v05.qualification.commit=$qualificationCommit" `
    --label "org.openbexi.spell.v05.qualification.tree=$qualificationTree" `
    -f $qualificationDockerfile `
    -t $qualificationTag $candidateRoot
  Assert-NativeSuccess "immutable candidate qualification image build failed"
  $script:QualificationImage = (& $script:DockerExe image inspect $qualificationTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "candidate qualification image lookup failed"
  if ($script:QualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "candidate qualification image identity is invalid"
  }
  $runtimeVersion = @(
    & $script:DockerExe run --rm --network none --read-only `
      --label "com.docker.compose.project=$project" `
      --entrypoint python $script:QualificationImage --version
  ) -join "`n"
  Assert-NativeSuccess "candidate qualification runtime probe failed"
  if ($runtimeVersion.Trim() -cne "Python 3.13.14") {
    throw "candidate qualification image does not use Python 3.13.14"
  }

  $backendNodes = Get-CollectedNodes "backend/tests" "backend/tests/" 269 `
    "802b3aa602e209cca204a4d17e1e71eb65cec408d59f575b0b3269d2424d771b"
  $driverNodes = Get-CollectedNodes "driver_host/tests" "driver_host/tests/" 77 `
    "fa97a356d4d76ed4650e04f73785b02ffe3f4b4d5c3655869c0a9ba2d7aff66a"
  $toolingNodes = Get-CollectedNodes "scripts/tests" "scripts/tests/" 334 `
    "328ecc2e76375a745ad007e1e15eba14652a4e7d23064fe77640c342fa8f7098"

  $sqliteXml = Join-Path $captureRoot "backend-sqlite.xml"
  Invoke-ImagePytest "backend-sqlite" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("backend/tests", "-q", "--junitxml=/qualification-output/result.xml") $sqliteXml

  & $script:DockerExe build --pull=false --provenance=false `
    --label "com.docker.compose.project=$project" `
    -f (Join-Path $candidateRoot "driver_host/postgres.Dockerfile") `
    -t $postgresTag $candidateRoot
  Assert-NativeSuccess "candidate PostgreSQL image build failed"
  $postgresImage = (& $script:DockerExe image inspect $postgresTag --format "{{.Id}}").Trim()
  Assert-NativeSuccess "candidate PostgreSQL image lookup failed"
  if ($postgresImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "candidate PostgreSQL image identity is invalid"
  }
  & $script:DockerExe network create --internal --label "com.docker.compose.project=$project" $network | Out-Null
  Assert-NativeSuccess "cannot create the candidate PostgreSQL internal network"
  & $script:DockerExe volume create --label "com.docker.compose.project=$project" $postgresVolume | Out-Null
  Assert-NativeSuccess "cannot create the candidate PostgreSQL volume"
  $volumes.Add($postgresVolume)
  $databasePassword = "v05-candidate-pg-$runId"
  & $script:DockerExe run -d --name $postgresContainer `
    --label "com.docker.compose.project=$project" `
    --network $network --mount "type=volume,source=$postgresVolume,target=/var/lib/postgresql/18/docker" `
    -e "POSTGRES_USER=spell" -e "POSTGRES_PASSWORD=$databasePassword" `
    -e "POSTGRES_DB=spell_test" $postgresImage | Out-Null
  Assert-NativeSuccess "cannot start the candidate PostgreSQL container"
  $containers.Add($postgresContainer)
  $ready = $false
  $consecutiveReadyProbes = 0
  $deadline = (Get-Date).AddSeconds(60)
  do {
    $pidOneCommand = @(
      & $script:DockerExe exec $postgresContainer sh -ec 'cat /proc/1/comm' 2>$null
    ) -join "`n"
    $pidOneIsFinalServer = $LASTEXITCODE -eq 0 -and $pidOneCommand.Trim() -ceq "postgres"
    & $script:DockerExe exec $postgresContainer pg_isready -U spell -d spell_test 2>$null | Out-Null
    if ($pidOneIsFinalServer -and $LASTEXITCODE -eq 0) {
      $consecutiveReadyProbes += 1
    }
    else { $consecutiveReadyProbes = 0 }
    $ready = $consecutiveReadyProbes -ge 2
    if (-not $ready) { Start-Sleep -Milliseconds 250 }
  } until ($ready -or (Get-Date) -ge $deadline)
  if (-not $ready) { throw "candidate PostgreSQL did not become ready" }
  & $script:DockerExe exec $postgresContainer createdb -U spell spell_migration_test
  Assert-NativeSuccess "cannot create the distinct candidate migration database"
  foreach ($databaseName in @("spell_test", "spell_migration_test")) {
    $observed = @(
      & $script:DockerExe exec $postgresContainer psql -U spell -d $databaseName `
        -Atqc "SELECT current_database()"
    ) -join "`n"
    Assert-NativeSuccess "candidate PostgreSQL database identity probe failed"
    if ($observed.Trim() -cne $databaseName) {
      throw "candidate PostgreSQL database identity differs: $databaseName"
    }
  }

  $applicationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_test"
  $migrationUrl = "postgresql+psycopg://spell:$databasePassword@${postgresContainer}:5432/spell_migration_test"
  $postgresBaseXml = Join-Path $captureRoot "backend-postgresql-base.xml"
  $runtimeNodes = @(
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access"
  )
  $postgresArguments = @("backend/tests", "-q")
  foreach ($node in $runtimeNodes) { $postgresArguments += "--deselect=$node" }
  $postgresArguments += "--junitxml=/qualification-output/result.xml"
  Invoke-ImagePytest "backend-postgresql" $network @(
    "PYTHONDONTWRITEBYTECODE=1",
    "SPELL_TEST_DATABASE_URL=$applicationUrl",
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
if actual != expected:
    raise SystemExit("locked host dependency versions differ")
print(json.dumps(actual, sort_keys=True, separators=(",", ":")))
'@
  $probeOutput = @($dependencyProbe | & $lockedPython -I - $sitePackages 2>&1)
  Assert-NativeSuccess "locked CPython host dependency validation failed"
  if ($probeOutput.Count -ne 1) { throw "locked host dependency probe output differs" }

  $postgresRuntimeXml = Join-Path $captureRoot "backend-postgresql-runtime.xml"
  $savedRunCompose = $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS
  $savedTestUrl = $env:SPELL_TEST_DATABASE_URL
  $savedMigrationUrl = $env:SPELL_MIGRATION_TEST_DATABASE_URL
  $savedPythonPath = $env:PYTHONPATH
  try {
    $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS = "1"
    $env:SPELL_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_test"
    $env:SPELL_MIGRATION_TEST_DATABASE_URL = "postgresql+psycopg://spell:REDACTED@invalid/spell_migration_test"
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    $pytestCode = @'
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import pytest
raise SystemExit(pytest.main(sys.argv[3:]))
'@
    Push-Location $candidateRoot
    try {
      $runtimeArguments = @(
        $sitePackages, $candidateRoot,
        $runtimeNodes[0], $runtimeNodes[1],
        "-q", "--junitxml=$postgresRuntimeXml"
      )
      & $lockedPython -I -c $pytestCode @runtimeArguments
      Assert-NativeSuccess "locked-host Docker inspection tests failed"
      $hostRuntimeCompleted = $true
    }
    finally { Pop-Location }
  }
  finally {
    if ($null -eq $savedRunCompose) { Remove-Item Env:SPELL_RUN_COMPOSE_RUNTIME_TESTS -ErrorAction SilentlyContinue }
    else { $env:SPELL_RUN_COMPOSE_RUNTIME_TESTS = $savedRunCompose }
    if ($null -eq $savedTestUrl) { Remove-Item Env:SPELL_TEST_DATABASE_URL -ErrorAction SilentlyContinue }
    else { $env:SPELL_TEST_DATABASE_URL = $savedTestUrl }
    if ($null -eq $savedMigrationUrl) { Remove-Item Env:SPELL_MIGRATION_TEST_DATABASE_URL -ErrorAction SilentlyContinue }
    else { $env:SPELL_MIGRATION_TEST_DATABASE_URL = $savedMigrationUrl }
    if ($null -eq $savedPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
    else { $env:PYTHONPATH = $savedPythonPath }
  }
  $postgresXml = Join-Path $captureRoot "backend-postgresql.xml"
  Merge-JUnit @($postgresBaseXml, $postgresRuntimeXml) $postgresXml

  $driverXml = Join-Path $captureRoot "driver-host.xml"
  Invoke-ImagePytest "driver-host" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("driver_host/tests", "-q", "--junitxml=/qualification-output/result.xml") $driverXml
  $toolingXml = Join-Path $captureRoot "tooling.xml"
  Invoke-ImagePytest "tooling" "none" @("PYTHONDONTWRITEBYTECODE=1") `
    @("scripts/tests", "-q", "--junitxml=/qualification-output/result.xml") $toolingXml
}
catch { $failure = $_ }
finally {
  foreach ($container in $containers) {
    Invoke-DockerCleanup @("rm", "-f", $container) | Out-Null
  }
  foreach ($volume in $volumes) {
    Invoke-DockerCleanup @("volume", "rm", "-f", $volume) | Out-Null
  }
  Invoke-DockerCleanup @("network", "rm", $network) | Out-Null
  foreach ($tag in $imageTags) {
    Invoke-DockerCleanup @("image", "rm", $tag) | Out-Null
  }
  $runtimeResourcesTornDown = Remove-NewRuntimeResources $runtimeBaseline
  $remainingContainers = @(Invoke-DockerCleanup @("ps", "-aq", "--filter", "label=com.docker.compose.project=$project")).Lines
  $remainingNetworks = @(Invoke-DockerCleanup @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")).Lines
  $remainingVolumes = @(Invoke-DockerCleanup @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")).Lines
  $remainingImages = @(Invoke-DockerCleanup @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")).Lines
  $resourcesTornDown = @($remainingContainers | Where-Object { $_ }).Count -eq 0 -and
    @($remainingNetworks | Where-Object { $_ }).Count -eq 0 -and
    @($remainingVolumes | Where-Object { $_ }).Count -eq 0
  $imageTagsRemoved = @($remainingImages | Where-Object { $_ }).Count -eq 0
  Pop-Location
}

if ($failure) {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
  throw $failure
}
if (-not $resourcesTornDown -or -not $runtimeResourcesTornDown -or -not $imageTagsRemoved -or -not $hostRuntimeCompleted) {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
  throw "candidate qualification teardown verification failed"
}

try {
New-Item -ItemType Directory -Path (Join-Path $publicationStage "tests") -Force | Out-Null
$captures = [ordered]@{
  "tests/backend-sqlite.xml" = Join-Path $captureRoot "backend-sqlite.xml"
  "tests/backend-postgresql.xml" = Join-Path $captureRoot "backend-postgresql.xml"
  "tests/driver-host.xml" = Join-Path $captureRoot "driver-host.xml"
  "tests/tooling.xml" = Join-Path $captureRoot "tooling.xml"
}
$artifactHashes = [ordered]@{}
foreach ($entry in $captures.GetEnumerator()) {
  $destination = Join-Path $publicationStage $entry.Key
  Copy-Item -LiteralPath $entry.Value -Destination $destination
  $artifactHashes[$entry.Key] = Get-LowerSha256 $destination
}

$sqliteSummary = Get-JUnitSummary (Join-Path $publicationStage "tests/backend-sqlite.xml")
$postgresSummary = Get-JUnitSummary (Join-Path $publicationStage "tests/backend-postgresql.xml")
$driverSummary = Get-JUnitSummary (Join-Path $publicationStage "tests/driver-host.xml")
$toolingSummary = Get-JUnitSummary (Join-Path $publicationStage "tests/tooling.xml")

$suites = [ordered]@{}
foreach ($definition in @(
  @("backend_sqlite", "tests/backend-sqlite.xml", $backendNodes, $sqliteSummary, "none"),
  @("backend_postgresql", "tests/backend-postgresql.xml", $backendNodes, $postgresSummary, "internal"),
  @("driver_host", "tests/driver-host.xml", $driverNodes, $driverSummary, "none"),
  @("tooling", "tests/tooling.xml", $toolingNodes, $toolingSummary, "none")
)) {
  $summary = $definition[3]
  $suites[$definition[0]] = [ordered]@{
    capture = $definition[1]
    collected_nodes = [string[]]$definition[2]
    inventory_sha256 = Get-InventoryDigest ([string[]]$definition[2])
    test_count = [int]$summary.test_count
    subtest_count = [int]$summary.subtest_count
    passed_count = [int]$summary.passed_count
    skipped_count = [int]$summary.skipped_count
    failure_count = [int]$summary.failure_count
    error_count = [int]$summary.error_count
    network_mode = $definition[4]
  }
}

$changedPaths = @(
  [ordered]@{ path = "backend/ir_v03.py"; blob = "87f202e9e3ff192e348c2aea9f7009ea7fc95841" },
  [ordered]@{ path = "backend/procedure_parser.py"; blob = "cf6fdf5645d3818e8b7b2c7abdca796d4d1c506b" },
  [ordered]@{ path = "backend/supervisor.py"; blob = "6b903d97c7777cd163b776fe5c0a2bebc1c2721c" },
  [ordered]@{ path = "backend/tests/test_driver_isolation.py"; blob = "d829838cbd1b0186adb7a075e9c9edfb661c321c" },
  [ordered]@{ path = "backend/tests/test_ir_boundaries.py"; blob = "750b3640615e6aa19d3d40914f966cccb63e59d8" },
  [ordered]@{ path = "backend/tests/test_ir_v03.py"; blob = "e142c9b67dadbad71d62207542a7c395f896f9c6" },
  [ordered]@{ path = "backend/tests/test_procedure_parser.py"; blob = "a9f3c22d2362e83d810b4476d2435407ca2a01ab" },
  [ordered]@{ path = "backend/tests/test_worker_expressions.py"; blob = "fe97a2f57e7ec85093b893526030afbfeff59fb3" },
  [ordered]@{ path = "backend/worker.py"; blob = "513fb00afea31b948e6cdcfed3c2911c2eff42e5" }
)

$manifest = [ordered]@{
  schema_version = "spell.v05.candidate-qualification/1"
  product_version = "0.5.0-candidate"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
  implementation_candidate = [ordered]@{
    commit = $implementationCommit
    tree = $implementationTree
    parent = $implementationParent
    changed_paths = $changedPaths
  }
  qualification_source = [ordered]@{
    commit = $qualificationCommit
    tree = $qualificationTree
    parent = $qualificationParent
    correction = [ordered]@{
      path = $correctionPath
      blob = $correctionBlob
      sha256 = $correctionSha256
    }
  }
  toolchain = [ordered]@{
    lock_path = "scripts/release-toolchain-v04.json"
    lock_sha256 = Get-LowerSha256 $toolchainLock
    python_version = "3.13.14"
    python_sha256 = Get-LowerSha256 $lockedPython
    qualification_dockerfile_path = "scripts/qualification-v05.Dockerfile"
    qualification_dockerfile_sha256 = Get-LowerSha256 $qualificationDockerfile
    qualification_dockerignore_path = "scripts/qualification-v05.Dockerfile.dockerignore"
    qualification_dockerignore_sha256 = Get-LowerSha256 $qualificationDockerignore
    qualification_image_id = $script:QualificationImage
    external_manuals = [ordered]@{
      directory = "SPELL-DOCUMENTATION"
      ledger_path = "SPELL_DOCUMENTATION_REVIEW.md"
      ledger_sha256 = $manualLedgerSha256
      files = $manualLedger
    }
  }
  database = [ordered]@{
    application_name = "spell_test"
    migration_name = "spell_migration_test"
    distinct_names = $true
    both_environment_variables_bound = $true
    postgresql_zero_skips = $true
    network_internal = $true
    host_port_published = $false
    postgres_image_id = $postgresImage
  }
  suites = $suites
  identities = Get-IdentityMap $backendNodes
  inherited_v04 = [ordered]@{
    classification = "INHERITED_SUPPORT_ONLY_NOT_DIRECT_V05_PROOF"
    supports = @("compatibility", "browser", "performance")
    result_path = $inheritedRunRelative
    result_sha256 = Get-LowerSha256 $inheritedRun
    source_fingerprint_sha256 = "46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d"
    direct_v05_proof = $false
  }
  artifacts = $artifactHashes
  teardown = [ordered]@{
    project = $project
    resources_torn_down = $true
    runtime_proxy_stopped = $true
    runtime_test_resources_torn_down = $true
    image_tags_removed = $true
  }
  overall_pass = $true
}
$manifestJson = $manifest | ConvertTo-Json -Compress -Depth 100
[IO.File]::WriteAllText(
  (Join-Path $publicationStage "qualification.json"),
  "$manifestJson`n",
  [Text.UTF8Encoding]::new($false)
)
$databasePassword = $null
$applicationUrl = $null
$migrationUrl = $null

$validationLines = @(
  & $lockedPython -I $validator --root $root --evidence-root $publicationStage
)
Assert-NativeSuccess "candidate qualification staging evidence validation failed"
$validation = $validationLines | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
if (-not $validation) { throw "candidate evidence validator emitted no success JSON" }

New-Item -ItemType Directory -Path $publicationParent -Force | Out-Null
if (Test-Path -LiteralPath $canonicalRoot) {
  if (-not $Replace) { throw "candidate evidence already exists; pass -Replace to republish" }
  if (Test-Path -LiteralPath $publicationBackup) { throw "candidate evidence backup path already exists" }
  Move-Item -LiteralPath $canonicalRoot -Destination $publicationBackup
}
try {
  Move-Item -LiteralPath $publicationStage -Destination $canonicalRoot
  & $lockedPython -I $validator --root $root --evidence-root $canonicalRoot | Out-Null
  Assert-NativeSuccess "published candidate evidence validation failed"
  if (Test-Path -LiteralPath $publicationBackup) {
    Remove-Item -LiteralPath $publicationBackup -Recurse -Force
  }
}
catch {
  if (Test-Path -LiteralPath $canonicalRoot) {
    Remove-Item -LiteralPath $canonicalRoot -Recurse -Force
  }
  if (Test-Path -LiteralPath $publicationBackup) {
    Move-Item -LiteralPath $publicationBackup -Destination $canonicalRoot
  }
  throw
}
finally {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}

Write-Output $validation
}
finally {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
  if (Test-Path -LiteralPath $publicationStage) {
    Remove-Item -LiteralPath $publicationStage -Recurse -Force
  }
}
