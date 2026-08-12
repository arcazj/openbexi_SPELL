param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("V04-SC-004", "V04-SC-005", "V04-SC-006")]
  [string]$TestId
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runId = [guid]::NewGuid().ToString("N")
$rawRoot = $null
$executionImages = $null
$sourceFingerprint = $null

function Get-V03EvidenceSnapshot([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    return [pscustomobject]@{
      FileCount = 0
      Digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
  $base = [IO.Path]::GetFullPath($path).TrimEnd('\', '/')
  $items = @(Get-ChildItem -LiteralPath $path -Recurse -Force)
  if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
    throw "retained v0.3 evidence contains a reparse point"
  }
  $files = @($items | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)
  $lines = @(
    $files | ForEach-Object {
      $relative = $_.FullName.Substring($base.Length).TrimStart('\', '/').Replace('\', '/')
      "$relative`0$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower())"
    }
  )
  $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { $digest = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace("-", "").ToLower() }
  finally { $hasher.Dispose() }
  return [pscustomobject]@{ FileCount = $files.Count; Digest = $digest }
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE
$PythonBootstrap = "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));p=sys.argv.pop(1);sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
. (Join-Path $PSScriptRoot "release_docker_resources_v04.ps1")
. (Join-Path $PSScriptRoot "stage_supply_provenance_v04.ps1")
$runTags = [Collections.Generic.List[string]]::new()
$runContainers = [Collections.Generic.List[string]]::new()
$runImageIds = [Collections.Generic.List[string]]::new()
$runVolumes = [Collections.Generic.List[string]]::new()
$cleanup = $null

if ($TestId -in @("V04-SC-004", "V04-SC-006")) {
  $rawRoot = Join-Path $env:TEMP "spell-v04-$($TestId.ToLower())-raw-$runId"
  $rawFull = [IO.Path]::GetFullPath($rawRoot)
  $tempFull = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
  if (-not $rawFull.StartsWith("$tempFull$([IO.Path]::DirectorySeparatorChar)")) {
    throw "refusing a supply provenance path outside the temporary root"
  }
  if (Test-Path -LiteralPath $rawRoot) { throw "$TestId raw provenance path exists" }
  New-Item -ItemType Directory -Path $rawRoot | Out-Null
}

function Remove-SupplyRawDirectory {
  if ($null -ne $rawRoot -and (Test-Path -LiteralPath $rawRoot -PathType Container)) {
    Remove-Item -LiteralPath $rawRoot -Recurse -Force
  }
}

function Remove-SupplyRunVolumes([string[]]$Volumes) {
  $failures = [Collections.Generic.List[string]]::new()
  foreach ($volume in @($Volumes | Where-Object { $_ } | Select-Object -Unique)) {
    $removal = Invoke-V04DockerCleanupCommand $DockerExe @("volume", "rm", $volume)
    if ($removal.ExitCode -ne 0) {
      $failures.Add("cannot remove run volume $volume")
      continue
    }
    $verification = Invoke-V04DockerCleanupCommand $DockerExe @("volume", "inspect", $volume)
    if ($verification.ExitCode -eq 0) { $failures.Add("run volume remains: $volume") }
  }
  if ($failures.Count -gt 0) { throw ($failures -join "; ") }
}

function Invoke-SupplyChainCollector {
Push-Location $root
try {
  $v03Before = $null
  if ($TestId -eq "V04-SC-005") {
    $v03Before = Get-V03EvidenceSnapshot (Join-Path $root "artifacts/v0.3")
  }
  if ($TestId -eq "V04-SC-004") {
    $tag = "openbexi-spell-v04-offline-generator:$runId"
    $runTags.Add($tag)
    & $DockerExe build --pull=false --provenance=false -f scripts/generator-v04.Dockerfile -t $tag .
    if ($LASTEXITCODE -ne 0) { throw "v0.4 offline generator image build failed" }
    $image = (& $DockerExe image inspect $tag --format "{{.Id}}").Trim()
    $runImageIds.Add($image)
    $provenanceVolume = "spell-v04-sc004-provenance-$runId"
    $runVolumes.Add($provenanceVolume)
    & $DockerExe volume create --label "openbexi.spell.v04.run=$runId" `
      $provenanceVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot create the v0.4 SC004 provenance volume" }
    $initializer = "spell-v04-sc004-init-$PID-$runId"
    $runContainers.Add($initializer)
    & $DockerExe create --name $initializer --network none --read-only --user 0:0 `
      --mount "type=volume,source=$provenanceVolume,target=/provenance" `
      --entrypoint python $image -c "import os; os.chown('/provenance', 10004, 10004)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot initialize the v0.4 SC004 provenance volume" }
    & $DockerExe start --attach $initializer | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot prepare the v0.4 SC004 provenance volume" }
    $container = "spell-v04-sc004-$PID-$runId"
    $runContainers.Add($container)
    & $DockerExe create --name $container --network none --read-only `
      --tmpfs /tmp:size=256m,noexec,nosuid `
      --mount "type=volume,source=$provenanceVolume,target=/provenance" $image `
      --provenance-output /provenance/sc004 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot create the v0.4 offline generator probe" }
    $probeOutput = @(& $DockerExe start --attach $container)
    if ($LASTEXITCODE -ne 0) { throw "v0.4 offline generation/reproducibility probe failed" }
    & $DockerExe cp "${container}:/provenance/sc004/." $rawRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot retain the two SC004 child results" }
    $probeLine = $probeOutput | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
    if (-not $probeLine) { throw "V04-SC-004 probe emitted no JSON" }
    $probeResult = $probeLine | ConvertFrom-Json
    if ($probeResult.test_id -cne "V04-SC-004") {
      throw "V04-SC-004 probe returned the wrong test ID"
    }
    $script:executionImages = [ordered]@{ generator = $image }
    $script:sourceFingerprint = [string]$probeResult.source_fingerprint_sha256
    Write-Output ($probeResult | ConvertTo-Json -Compress -Depth 100)
    return
  }

  if ($TestId -eq "V04-SC-006") {
    $serverPlatform = (& $DockerExe version --format "{{.Server.Os}}/{{.Server.Arch}}").Trim()
    if ($LASTEXITCODE -ne 0 -or $serverPlatform -cne "linux/amd64") {
      throw "declared platform oci-compose-linux-amd64 is unavailable: $serverPlatform"
    }
    $driverATag = "openbexi-spell-v04-lifecycle-driver-a:$runId"
    $driverBTag = "openbexi-spell-v04-lifecycle-driver-b:$runId"
    $pkiTag = "openbexi-spell-v04-lifecycle-pki:$runId"
    foreach ($tag in @($driverATag, $driverBTag, $pkiTag)) { $runTags.Add($tag) }
    & $DockerExe build --pull=false --provenance=false `
      --build-arg SPELL_PACKAGE_VERSION=0.4.0 `
      -f driver_host/Dockerfile -t $driverATag .
    if ($LASTEXITCODE -ne 0) { throw "v0.4 lifecycle driver A image build failed" }
    & $DockerExe build --pull=false --provenance=false `
      --build-arg SPELL_PACKAGE_VERSION=0.4.1-test `
      -f driver_host/Dockerfile -t $driverBTag .
    if ($LASTEXITCODE -ne 0) { throw "v0.4 lifecycle driver B image build failed" }
    & $DockerExe build --pull=false --provenance=false `
      --build-arg SPELL_PACKAGE_VERSION=0.4.0 `
      -f driver_host/pki.Dockerfile -t $pkiTag .
    if ($LASTEXITCODE -ne 0) { throw "v0.4 lifecycle PKI image build failed" }
    $driverAImage = (& $DockerExe image inspect $driverATag --format "{{.Id}}").Trim()
    $driverBImage = (& $DockerExe image inspect $driverBTag --format "{{.Id}}").Trim()
    $pkiImage = (& $DockerExe image inspect $pkiTag --format "{{.Id}}").Trim()
    foreach ($image in @($driverAImage, $driverBImage, $pkiImage)) {
      $runImageIds.Add($image)
    }
    if ($LASTEXITCODE -ne 0) { throw "cannot capture exact lifecycle image IDs" }
    if ($driverAImage -ceq $driverBImage) {
      throw "lifecycle upgrade images are not distinct"
    }

    $priorDb = $env:SPELL_DB_PASSWORD
    $priorJwt = $env:SPELL_JWT_HS256_SECRET
    try {
      $env:SPELL_DB_PASSWORD = "synthetic-qualification-password"
      $env:SPELL_JWT_HS256_SECRET = "synthetic-qualification-jwt-secret-32-bytes"
      $lifecycleOutput = @(
        $PythonBootstrap | & $PythonExe - $root `
          (Join-Path $root "scripts/driver_compose_lifecycle_v04.py") --root $root qualify `
          --driver-image-a $driverAImage `
          --driver-image-b $driverBImage `
          --pki-image $pkiImage `
          --run-id $runId `
          --provenance-output (Join-Path $rawRoot "lifecycle-cases.json")
      )
      $lifecycleExitCode = $LASTEXITCODE
    }
    finally {
      if ($null -eq $priorDb) { Remove-Item Env:SPELL_DB_PASSWORD -ErrorAction SilentlyContinue }
      else { $env:SPELL_DB_PASSWORD = $priorDb }
      if ($null -eq $priorJwt) { Remove-Item Env:SPELL_JWT_HS256_SECRET -ErrorAction SilentlyContinue }
      else { $env:SPELL_JWT_HS256_SECRET = $priorJwt }
    }
    if ($lifecycleExitCode -ne 0) { throw "$TestId real Compose lifecycle qualification failed" }
    $lifecycleLines = @($lifecycleOutput | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    if ($lifecycleLines.Count -eq 0) { throw "$TestId lifecycle qualification emitted no JSON" }
    try { $result = $lifecycleLines[-1] | ConvertFrom-Json }
    catch { throw "$TestId lifecycle qualification emitted invalid JSON: $($_.Exception.Message)" }
    if ($result.test_id -cne $TestId) { throw "$TestId lifecycle qualification returned the wrong test id" }
    $script:executionImages = [ordered]@{
      driver_a = $driverAImage
      driver_b = $driverBImage
      pki_init = $pkiImage
    }
    $script:sourceFingerprint = [string]$result.source_fingerprint_sha256
    Write-Output ($result | ConvertTo-Json -Compress -Depth 100)
    return
  }

  $tag = "openbexi-spell-v04-package-probe:$runId"
  $runTags.Add($tag)
  & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile -t $tag .
  if ($LASTEXITCODE -ne 0) { throw "v0.4 package probe image build failed" }
  $image = (& $DockerExe image inspect $tag --format "{{.Id}}").Trim()
  $runImageIds.Add($image)
  if ($TestId -eq "V04-SC-005") {
    $container = "spell-v04-sc005-$PID-$runId"
    $runContainers.Add($container)
    $probeOutput = @(
      & $DockerExe run --rm --name $container --network none --read-only `
        --tmpfs /tmp:size=256m,noexec,nosuid `
        --entrypoint python $image scripts/supply_chain_v04.py --root /workspace probe-sc-005
    )
    $probeExitCode = $LASTEXITCODE
    if ($probeExitCode -ne 0) { throw "$TestId qualification probe failed" }
    $v03After = Get-V03EvidenceSnapshot (Join-Path $root "artifacts/v0.3")
    if (
      $v03Before.FileCount -ne $v03After.FileCount -or
      $v03Before.Digest -cne $v03After.Digest
    ) { throw "retained v0.3 evidence changed during v0.4 isolation qualification" }
    $probeLines = @($probeOutput | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    if ($probeLines.Count -eq 0) { throw "$TestId qualification probe emitted no JSON" }
    try { $result = $probeLines[-1] | ConvertFrom-Json }
    catch { throw "$TestId qualification probe emitted invalid JSON: $($_.Exception.Message)" }
    if ($result.test_id -cne $TestId) { throw "$TestId qualification returned the wrong test id" }
    $result.assertions = @($result.assertions) + @(
      [pscustomobject]@{ id = "host-v03-evidence-remained-byte-identical"; passed = $true }
    )
    $result.metrics | Add-Member -NotePropertyName retained_v03_file_count `
      -NotePropertyValue $v03After.FileCount -Force
    Write-Output ($result | ConvertTo-Json -Compress -Depth 100)
    return
  }
  if ($LASTEXITCODE -ne 0) { throw "$TestId qualification probe failed" }
}
finally { Pop-Location }
}

$collectorOutput = @()
$originalFailure = $null
$cleanupFailure = $null
try { $collectorOutput = @(Invoke-SupplyChainCollector) }
catch { $originalFailure = $_ }
finally {
  try {
    $cleanup = Remove-V04RunDockerResources -DockerExe $DockerExe -Tags $runTags.ToArray() `
      -Containers $runContainers.ToArray() -ImageIds $runImageIds.ToArray()
  }
  catch { $cleanupFailure = $_.Exception }
  try { Remove-SupplyRunVolumes $runVolumes.ToArray() }
  catch {
    if ($null -eq $cleanupFailure) {
      $cleanupFailure = $_.Exception
    }
    else {
      $cleanupFailure = [InvalidOperationException]::new(
        "Docker resource cleanup failed: $($cleanupFailure.Message); " +
        "volume cleanup also failed: $($_.Exception.Message)",
        $cleanupFailure
      )
    }
  }
}
if ($null -ne $originalFailure) {
  Remove-SupplyRawDirectory
  if ($null -ne $cleanupFailure) {
    throw [InvalidOperationException]::new(
      "Gate 5 collector failed and cleanup also failed: $($cleanupFailure.Message)",
      $originalFailure.Exception
    )
  }
  throw $originalFailure
}
if ($null -ne $cleanupFailure) {
  Remove-SupplyRawDirectory
  throw $cleanupFailure
}

try {
  $jsonIndex = -1
  for ($index = 0; $index -lt $collectorOutput.Count; $index += 1) {
    if ([string]$collectorOutput[$index] -cmatch '^\{.+\}$') { $jsonIndex = $index }
  }
  if ($jsonIndex -lt 0) { throw "$TestId collector emitted no final JSON result" }
  $result = [string]$collectorOutput[$jsonIndex] | ConvertFrom-Json
  $result.metrics | Add-Member -NotePropertyName retained_shared_image_count `
    -NotePropertyValue @($cleanup.retained_shared_image_ids).Count -Force
  $result.metrics | Add-Member -NotePropertyName retained_shared_image_ids `
    -NotePropertyValue @($cleanup.retained_shared_image_ids) -Force
  if ($TestId -in @("V04-SC-004", "V04-SC-006")) {
    if ($sourceFingerprint -cne [string]$result.source_fingerprint_sha256) {
      throw "$TestId provenance source differs from the collector result"
    }
    $result = Add-V04SupplyProvenanceMetrics -Root $root -PythonExe $PythonExe `
      -TestId $TestId -RunId $runId -SourceFingerprint $sourceFingerprint `
      -RawDirectory $rawRoot -Result $result -ExecutionImages $executionImages
  }
  $collectorOutput[$jsonIndex] = $result | ConvertTo-Json -Compress -Depth 100
  $collectorOutput | Write-Output
}
finally { Remove-SupplyRawDirectory }
