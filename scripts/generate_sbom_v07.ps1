$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts/v0.7"
$output = Join-Path $artifactRoot "sbom"
$runId = [guid]::NewGuid().ToString("N")
$staging = Join-Path $artifactRoot ".sbom-staging-$runId"
$backup = Join-Path $artifactRoot ".sbom-backup-$runId"
$fingerprintTag = "openbexi-spell-v07-sbom-source:$runId"
$validatorTag = "openbexi-spell-v07-sbom-validator:$runId"
$fingerprintProperty = "openbexi:source-fingerprint-sha256"
$imageIdProperty = "openbexi:scanned-image-id"
$utf8NoBom = [Text.UTF8Encoding]::new($false)

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE
$SbomExe = $env:SPELL_RELEASE_SBOM_EXE
. (Join-Path $PSScriptRoot "release_docker_resources_v04.ps1")
$runTags = [Collections.Generic.List[string]]::new()
$runTags.Add($fingerprintTag)
$runTags.Add($validatorTag)
$runContainers = [Collections.Generic.List[string]]::new()
$runImageIds = [Collections.Generic.List[string]]::new()
$fingerprintRunCount = 0
$result = $null
$cleanup = $null
$validatorDocument = $null

function Assert-V06ArtifactsUnchanged {
  $tree = @(& git rev-parse "HEAD:artifacts/v0.6") -join "`n"
  if (
    $LASTEXITCODE -ne 0 -or
    $tree.Trim() -cne "18cb672a45c538539f78278962ea5822b9f52441"
  ) { throw "accepted v0.6 artifact tree differs" }
  & git diff --quiet v0.6.0 HEAD -- artifacts/v0.6
  if ($LASTEXITCODE -ne 0) { throw "accepted v0.6 artifacts differ from v0.6.0" }
  & git diff --quiet -- artifacts/v0.6
  if ($LASTEXITCODE -ne 0) { throw "accepted v0.6 artifacts have a working-tree change" }
  $status = @(& git status --porcelain --untracked-files=all -- artifacts/v0.6)
  if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    throw "accepted v0.6 artifacts have an untracked change"
  }
  & (Join-Path $PSScriptRoot "assert_accepted_v06_release_v07.ps1") -Root $root | Out-Null
}

$definitions = [ordered]@{
  "backend.cdx.json" = [ordered]@{
    Tag = "openbexi-spell-v07-backend-sbom:$runId"
    Dockerfile = "backend/Dockerfile"
    Target = $null
    Subject = "openbexi_spell-backend:0.7"
    Image = $null
    Licenses = [ordered]@{
      "fastapi" = "MIT"; "grpcio" = "Apache-2.0"; "protobuf" = "BSD-3-Clause"
      "psycopg" = "LGPL-3.0-only"; "pydantic" = "MIT"; "sqlalchemy" = "MIT"
      "uvicorn" = "BSD-3-Clause"
    }
  }
  "driver.cdx.json" = [ordered]@{
    Tag = "openbexi-spell-v07-driver-sbom:$runId"
    Dockerfile = "driver_host/Dockerfile"
    Target = $null
    Subject = "openbexi_spell-driver:0.7"
    Image = $null
    Licenses = [ordered]@{ "grpcio" = "Apache-2.0"; "protobuf" = "BSD-3-Clause" }
  }
  "frontend.cdx.json" = [ordered]@{
    Tag = "openbexi-spell-v07-frontend-sbom:$runId"
    Dockerfile = "proxy/Dockerfile"
    Target = "frontend-build"
    Subject = "openbexi_spell-frontend:0.7"
    Image = $null
    Licenses = [ordered]@{
      "@reduxjs/toolkit" = "MIT"; "echarts" = "Apache-2.0"; "lucide-react" = "ISC"
      "react" = "MIT"; "react-dom" = "MIT"; "react-redux" = "MIT"
    }
  }
  "proxy.cdx.json" = [ordered]@{
    Tag = "openbexi-spell-v07-proxy-sbom:$runId"
    Dockerfile = "proxy/Dockerfile"
    Target = $null
    Subject = "openbexi_spell-proxy:0.7"
    Image = $null
    Licenses = [ordered]@{ "nginx" = "BSD-2-Clause" }
  }
}
foreach ($definition in $definitions.Values) { $runTags.Add([string]$definition.Tag) }

function Get-SourceFingerprint {
  & $DockerExe build --pull=false --provenance=false -f scripts/package-v07.Dockerfile `
    -t $fingerprintTag . | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "v0.7 SBOM fingerprint image build failed" }
  $image = (& $DockerExe image inspect $fingerprintTag --format "{{.Id}}").Trim()
  $runImageIds.Add($image)
  $script:fingerprintRunCount += 1
  $container = "spell-v07-sbom-fingerprint-$PID-$script:fingerprintRunCount-$runId"
  $runContainers.Add($container)
  $value = @(
    & $DockerExe run --rm --name $container --network none --entrypoint python $image `
      scripts/source_fingerprint_v07.py --root /workspace
  ) | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value) { throw "v0.7 SBOM source fingerprint is invalid" }
  return $value
}

$artifactRootFull = [IO.Path]::GetFullPath($artifactRoot).TrimEnd('\', '/')
foreach ($candidate in @($output, $staging, $backup)) {
  $candidateFull = [IO.Path]::GetFullPath($candidate)
  if (-not $candidateFull.StartsWith("$artifactRootFull$([IO.Path]::DirectorySeparatorChar)")) {
    throw "refusing to use an SBOM path outside artifacts/v0.7: $candidateFull"
  }
}

New-Item -ItemType Directory -Force $artifactRoot | Out-Null
New-Item -ItemType Directory $staging | Out-Null
try {
  Push-Location $root
  try {
    Assert-V06ArtifactsUnchanged
    $sourceBefore = Get-SourceFingerprint
    & $DockerExe build --pull=false --provenance=false -f scripts/supply-chain-v04.Dockerfile `
      --target sbom-validator -t $validatorTag .
    if ($LASTEXITCODE -ne 0) { throw "offline CycloneDX validator image build failed" }
    $validatorImage = (& $DockerExe image inspect $validatorTag --format "{{.Id}}").Trim()
    if ($validatorImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
      throw "offline CycloneDX validator image identity is invalid"
    }
    $runImageIds.Add($validatorImage)
    if ((Get-SourceFingerprint) -cne $sourceBefore) {
      throw "source changed while the offline CycloneDX validator was built"
    }
    foreach ($entry in $definitions.GetEnumerator()) {
      $arguments = @(
        "build", "--pull=false", "--provenance=false", "-f", $entry.Value.Dockerfile,
        "-t", $entry.Value.Tag
      )
      if ($entry.Value.Target) { $arguments += @("--target", $entry.Value.Target) }
      $arguments += "."
      & $DockerExe @arguments
      if ($LASTEXITCODE -ne 0) { throw "image build failed for $($entry.Key)" }
      $entry.Value.Image = (& $DockerExe image inspect $entry.Value.Tag --format "{{.Id}}").Trim()
      if ($entry.Value.Image -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw "image identity is invalid for $($entry.Key)"
      }
      $runImageIds.Add([string]$entry.Value.Image)
    }
    if (@($definitions.Values | ForEach-Object { $_.Image } | Sort-Object -Unique).Count -ne 4) {
      throw "the four v0.7 SBOM inputs do not have distinct image identities"
    }
    $source = Get-SourceFingerprint
    if ($source -cne $sourceBefore) { throw "source changed during v0.7 image builds" }

    $sbomVersion = @(& $SbomExe sbom version 2>$null) -join "`n"
    if (
      $LASTEXITCODE -ne 0 -or
      $sbomVersion -notmatch 'Application:\s+docker-sbom \(0\.6\.0\)' -or
      $sbomVersion -notmatch 'Provider:\s+syft \(v0\.43\.0\)'
    ) { throw "Docker SBOM 0.7.0 with Syft v0.43.0 is required" }

    foreach ($entry in $definitions.GetEnumerator()) {
      $path = Join-Path $staging $entry.Key
      & $SbomExe sbom $entry.Value.Image --format cyclonedx-json --output $path
      if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed for $($entry.Key)" }
      $inventory = Get-Content -Raw $path | ConvertFrom-Json
      if ($inventory.bomFormat -ne "CycloneDX" -or @($inventory.components).Count -lt 1) {
        throw "invalid or empty CycloneDX inventory: $($entry.Key)"
      }
      $inventory.PSObject.Properties.Remove("serialNumber")
      $inventory.metadata.PSObject.Properties.Remove("timestamp")
      $inventory.metadata.component.name = $entry.Value.Subject
      $inventory.metadata.component.version = $entry.Value.Image
      $properties = @(
        $inventory.metadata.properties | Where-Object {
          $_ -and $_.name -ne $fingerprintProperty -and $_.name -ne $imageIdProperty
        }
      )
      $properties += [pscustomobject]@{ name = $fingerprintProperty; value = $source }
      $properties += [pscustomobject]@{ name = $imageIdProperty; value = $entry.Value.Image }
      $inventory.metadata | Add-Member -Force -NotePropertyName properties -NotePropertyValue $properties

      foreach ($license in $entry.Value.Licenses.GetEnumerator()) {
        $matches = @($inventory.components | Where-Object { $_.name.ToLowerInvariant() -eq $license.Key })
        if ($matches.Count -ne 1) {
          throw "$($entry.Key) has ambiguous or missing component $($license.Key)"
        }
        $existingLicenses = @($matches[0].licenses | Where-Object { $_ })
        if ($existingLicenses.Count -eq 0) {
          $matches[0] | Add-Member -Force -NotePropertyName licenses `
            -NotePropertyValue @([pscustomobject]@{ license = [pscustomobject]@{ id = $license.Value } })
        }
      }
      $normalized = ($inventory | ConvertTo-Json -Depth 100).Replace("`r`n", "`n").Replace("`r", "`n")
      [IO.File]::WriteAllText($path, "$normalized`n", $utf8NoBom)
    }

    $validatorContainer = "spell-v07-sbom-validator-$PID-$runId"
    $runContainers.Add($validatorContainer)
    $validatorMountSource = [IO.Path]::GetFullPath($staging)
    $validatorMount = "type=bind,src=$validatorMountSource,dst=/validation,readonly"
    $validatorOutput = @(& $DockerExe run --rm --name $validatorContainer --network none --read-only `
      --cap-drop ALL --security-opt no-new-privileges --mount $validatorMount $validatorImage)
    if ($LASTEXITCODE -ne 0) { throw "offline CycloneDX schema validation failed" }
    $validatorLine = $validatorOutput | Where-Object { $_ -cmatch '^\{.+\}$' } |
      Select-Object -Last 1
    if (-not $validatorLine) { throw "offline CycloneDX validator emitted no JSON" }
    try { $validatorDocument = $validatorLine | ConvertFrom-Json }
    catch { throw "offline CycloneDX validator emitted invalid JSON: $($_.Exception.Message)" }
    if (
      $validatorDocument.schema_version -cne "spell.v04.cyclonedx-validation/1" -or
      $validatorDocument.validator.distribution -cne "cyclonedx-python-lib" -or
      $validatorDocument.validator.version -cne "11.11.0" -or
      $validatorDocument.validator.class -cne "cyclonedx.validation.json.JsonStrictValidator" -or
      (@($validatorDocument.validated_files) -join ',') -cne ($definitions.Keys -join ',') -or
      [int]$validatorDocument.schema_validation_count -ne 4 -or
      $validatorDocument.network_mode -cne "none" -or
      $validatorDocument.negative_tamper_rejected -ne $true
    ) { throw "offline CycloneDX validator result differs from the release contract" }

    $checksumLines = @(
      $definitions.Keys | ForEach-Object {
        $path = Join-Path $staging $_
        "$((Get-FileHash $path -Algorithm SHA256).Hash.ToLower())  $_"
      }
    )
    [IO.File]::WriteAllText(
      (Join-Path $staging "SHA256SUMS"), "$($checksumLines -join "`n")`n", [Text.Encoding]::ASCII
    )
    if ((Get-SourceFingerprint) -cne $source) { throw "source changed during v0.7 SBOM generation" }
    Assert-V06ArtifactsUnchanged
  }
  finally { Pop-Location }

  if (Test-Path -LiteralPath $output) { Move-Item -LiteralPath $output -Destination $backup }
  try { Move-Item -LiteralPath $staging -Destination $output }
  catch {
    if ((Test-Path $backup) -and -not (Test-Path $output)) { Move-Item $backup $output }
    throw
  }
  if (Test-Path $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }

  $result = [ordered]@{
    test_id = "V07-SC-002"
    source_fingerprint_sha256 = $source
    assertions = @(
      [ordered]@{ id = "exact-four-cyclonedx-inventories-generated"; passed = $true }
      [ordered]@{ id = "subjects-and-image-identities-are-distinct"; passed = $true }
      [ordered]@{ id = "source-and-image-digests-are-bound"; passed = $true }
      [ordered]@{ id = "required-component-licenses-are-recorded"; passed = $true }
      [ordered]@{ id = "checksum-manifest-matches-inventory-bytes"; passed = $true }
      [ordered]@{ id = "offline-strict-cyclonedx-schemas-validated"; passed = $true }
      [ordered]@{ id = "cyclonedx-negative-tamper-was-rejected"; passed = $true }
    )
    metrics = [ordered]@{
      sbom_count = 4
      distinct_image_count = 4
      image_names = @("backend", "driver", "frontend", "proxy")
      licensed_inventory_count = 4
      schema_validation_count = [int]$validatorDocument.schema_validation_count
      schema_validator = "cyclonedx-python-lib/11.11.0 JsonStrictValidator"
      negative_tamper_rejected = $true
    }
    accepted_v06_release = [ordered]@{
      archive_sha256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
      sidecar_sha256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
      tag_object = "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919"
      tag_archive_claim = "Final archive SHA-256: b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
    }
  }
}
finally {
  try {
    if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    if (Test-Path $backup) {
      if (-not (Test-Path $output)) { Move-Item -LiteralPath $backup -Destination $output }
      else { Remove-Item -LiteralPath $backup -Recurse -Force }
    }
  }
  finally {
    $cleanup = Remove-V04RunDockerResources -DockerExe $DockerExe -Tags $runTags.ToArray() `
      -Containers $runContainers.ToArray() -ImageIds $runImageIds.ToArray()
  }
}
if ($null -ne $result) {
  $result.metrics.retained_shared_image_count = @($cleanup.retained_shared_image_ids).Count
  $result.metrics.retained_shared_image_ids = @($cleanup.retained_shared_image_ids)
  $result | ConvertTo-Json -Depth 8 -Compress | Write-Output
}
