$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts"
$output = Join-Path $artifactRoot "sbom"
$stageId = [guid]::NewGuid().ToString("N")
$staging = Join-Path $artifactRoot ".sbom-staging-$stageId"
$backup = Join-Path $artifactRoot ".sbom-backup-$stageId"
$backendImageTag = "openbexi_spell-backend-sbom-input:$stageId"
$proxyImageTag = "openbexi_spell-proxy-sbom-input:$stageId"
$frontendImageTag = "openbexi_spell-frontend-sbom-input:$stageId"
$fingerprintImageTag = "openbexi_spell-sbom-fingerprint-input:$stageId"
$fingerprintProperty = "openbexi:source-fingerprint-sha256"
$imageIdProperty = "openbexi:scanned-image-id"
$requiredComponents = [ordered]@{
  "backend.cdx.json" = @(
    "fastapi", "psycopg", "pydantic", "python-dotenv", "sqlalchemy", "uvicorn"
  )
  "proxy.cdx.json" = @("nginx")
  "frontend.cdx.json" = @(
    "react", "react-dom", "react-redux", "@reduxjs/toolkit", "echarts", "lucide-react"
  )
}

function Get-SourceFingerprint {
  docker build --pull=false -f (Join-Path $root "scripts/package.Dockerfile") `
    -t $fingerprintImageTag $root | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "SBOM fingerprint input image build failed" }
  $fingerprintImage = (
    docker image inspect $fingerprintImageTag --format "{{.Id}}"
  ).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $fingerprintImage) {
    throw "SBOM fingerprint input image ID lookup failed"
  }
  $fingerprintOutput = @(
    docker run --rm --network none --entrypoint python $fingerprintImage `
      scripts/source_fingerprint.py --root /workspace
  )
  if ($LASTEXITCODE -ne 0) { throw "SBOM source fingerprint calculation failed" }
  $fingerprint = $fingerprintOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $fingerprint) { throw "SBOM source fingerprint output was invalid" }
  return $fingerprint
}

$artifactRootFull = [IO.Path]::GetFullPath($artifactRoot)
foreach ($temporaryPath in @($staging, $backup)) {
  $temporaryFull = [IO.Path]::GetFullPath($temporaryPath)
  if (-not $temporaryFull.StartsWith("$artifactRootFull$([IO.Path]::DirectorySeparatorChar)")) {
    throw "Refusing to use SBOM temporary path outside artifacts: $temporaryFull"
  }
}

New-Item -ItemType Directory -Force $artifactRoot | Out-Null
New-Item -ItemType Directory $staging | Out-Null

try {
  $sourceFingerprintBeforeBuild = Get-SourceFingerprint

  docker build --pull=false --provenance=false `
    -f (Join-Path $root "backend/Dockerfile") `
    -t $backendImageTag $root
  if ($LASTEXITCODE -ne 0) { throw "Backend SBOM input image build failed" }
  $backendImage = (docker image inspect $backendImageTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $backendImage) {
    throw "Backend SBOM input image ID lookup failed"
  }

  docker build --pull=false --provenance=false `
    -f (Join-Path $root "proxy/Dockerfile") `
    -t $proxyImageTag $root
  if ($LASTEXITCODE -ne 0) { throw "Proxy SBOM input image build failed" }
  $proxyImage = (docker image inspect $proxyImageTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $proxyImage) {
    throw "Proxy SBOM input image ID lookup failed"
  }

  docker build --pull=false --provenance=false --target frontend-build `
    -f (Join-Path $root "proxy/Dockerfile") `
    -t $frontendImageTag $root
  if ($LASTEXITCODE -ne 0) { throw "Frontend SBOM input image build failed" }
  $frontendImage = (docker image inspect $frontendImageTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $frontendImage) {
    throw "Frontend SBOM input image ID lookup failed"
  }

  $sourceFingerprint = Get-SourceFingerprint
  if ($sourceFingerprint -cne $sourceFingerprintBeforeBuild) {
    throw "Source changed while SBOM input images were being built"
  }

  $sbomVersion = @(docker sbom version 2>$null) -join "`n"
  if (
    $LASTEXITCODE -ne 0 -or
    $sbomVersion -notmatch 'Application:\s+docker-sbom \(0\.6\.0\)' -or
    $sbomVersion -notmatch 'Provider:\s+syft \(v0\.43\.0\)'
  ) {
    throw "Docker SBOM 0.6.0 with Syft v0.43.0 is required"
  }

  $sources = [ordered]@{
    "backend.cdx.json" = [pscustomobject]@{
      Image = $backendImage
      Subject = "openbexi_spell-backend:latest"
    }
    "proxy.cdx.json" = [pscustomobject]@{
      Image = $proxyImage
      Subject = "openbexi_spell-proxy:latest"
    }
    "frontend.cdx.json" = [pscustomobject]@{
      Image = $frontendImage
      Subject = "openbexi_spell-frontend-sbom:0.3"
    }
  }
  foreach ($entry in $sources.GetEnumerator()) {
    $destination = Join-Path $staging $entry.Key
    docker sbom $entry.Value.Image --format cyclonedx-json --output $destination
    if ($LASTEXITCODE -ne 0) {
      throw "SBOM generation failed for immutable image $($entry.Value.Image)"
    }
  }

  $inventories = @{}
  $utf8NoBom = [Text.UTF8Encoding]::new($false)
  foreach ($name in $sources.Keys) {
    $path = Join-Path $staging $name
    $inventory = Get-Content -Raw $path | ConvertFrom-Json
    if ($inventory.bomFormat -ne "CycloneDX" -or -not $inventory.specVersion) {
      throw "Invalid CycloneDX inventory: $name"
    }
    if (@($inventory.components).Count -eq 0) {
      throw "CycloneDX inventory has no components: $name"
    }
    if (
      $null -eq $inventory.metadata -or
      $null -eq $inventory.metadata.component -or
      $inventory.metadata.component.type -ne "container" -or
      $inventory.metadata.component.version -cnotmatch '^sha256:[0-9a-f]{64}$'
    ) {
      throw "CycloneDX inventory has the wrong subject: $name"
    }
    $inventory.PSObject.Properties.Remove("serialNumber")
    $inventory.metadata.PSObject.Properties.Remove("timestamp")
    $inventory.metadata.component.name = $sources[$name].Subject
    $inventory.metadata.component.version = $sources[$name].Image
    $properties = @(
      $inventory.metadata.properties |
        Where-Object {
          $_.name -ne $fingerprintProperty -and $_.name -ne $imageIdProperty
        }
    )
    $properties += [pscustomobject]@{
      name = $fingerprintProperty
      value = $sourceFingerprint
    }
    $properties += [pscustomobject]@{
      name = $imageIdProperty
      value = $sources[$name].Image
    }
    $inventory.metadata | Add-Member -Force -NotePropertyName "properties" `
      -NotePropertyValue $properties
    $normalized = $inventory | ConvertTo-Json -Depth 100
    $normalized = $normalized.Replace("`r`n", "`n").Replace("`r", "`n")
    [IO.File]::WriteAllText($path, "$normalized`n", $utf8NoBom)
    $inventories[$name] = $inventory
  }

  foreach ($name in $requiredComponents.Keys) {
    $componentNames = @($inventories[$name].components | ForEach-Object { $_.name })
    foreach ($required in $requiredComponents[$name]) {
      if ($required -notin $componentNames) {
        throw "$name is missing required component: $required"
      }
    }
  }

  $sourceFingerprintAfterScan = Get-SourceFingerprint
  if ($sourceFingerprintAfterScan -cne $sourceFingerprint) {
    throw "Source changed while SBOM inventories were being generated"
  }

  $sbomPaths = $sources.Keys | ForEach-Object { Join-Path $staging $_ }
  $checksumLines = @(Get-FileHash $sbomPaths -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLower())  $([IO.Path]::GetFileName($_.Path))" } |
    ForEach-Object { $_ })
  [IO.File]::WriteAllText(
    (Join-Path $staging "SHA256SUMS"),
    "$($checksumLines -join "`n")`n",
    [Text.Encoding]::ASCII
  )

  if (Test-Path -LiteralPath $output) {
    Move-Item -LiteralPath $output -Destination $backup
  }
  try {
    Move-Item -LiteralPath $staging -Destination $output
  }
  catch {
    if ((Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $output)) {
      Move-Item -LiteralPath $backup -Destination $output
    }
    throw
  }
  if (Test-Path -LiteralPath $backup) {
    Remove-Item -LiteralPath $backup -Recurse -Force
  }
}
finally {
  if (Test-Path -LiteralPath $staging) {
    Remove-Item -LiteralPath $staging -Recurse -Force
  }
  if (Test-Path -LiteralPath $backup) {
    if (-not (Test-Path -LiteralPath $output)) {
      Move-Item -LiteralPath $backup -Destination $output
    }
    else {
      Remove-Item -LiteralPath $backup -Recurse -Force
    }
  }
}
