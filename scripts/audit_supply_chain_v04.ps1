$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$nonce = [guid]::NewGuid().ToString("N")
$auditTag = "openbexi-spell-v04-supply-chain-audit:$nonce"
$currentTag = "openbexi-spell-v04-supply-chain-current:$nonce"
$rawRoot = Join-Path $env:TEMP "spell-v04-sc001-raw-$nonce"
$rawRootFull = [IO.Path]::GetFullPath($rawRoot)
$tempRootFull = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
if (-not $rawRootFull.StartsWith("$tempRootFull$([IO.Path]::DirectorySeparatorChar)")) {
  throw "refusing an SC001 raw evidence path outside the temporary root"
}
if (Test-Path -LiteralPath $rawRoot) { throw "SC001 raw evidence path already exists" }

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE
$ScoutExe = $env:SPELL_RELEASE_SCOUT_EXE
$ComposeExe = $env:SPELL_RELEASE_COMPOSE_EXE
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE
. (Join-Path $PSScriptRoot "release_docker_resources_v04.ps1")
. (Join-Path $PSScriptRoot "stage_supply_provenance_v04.ps1")
$runTags = [Collections.Generic.List[string]]::new()
$runTags.Add($auditTag)
$runTags.Add($currentTag)
$runContainers = [Collections.Generic.List[string]]::new()
$runImageIds = [Collections.Generic.List[string]]::new()
$fingerprintRunCount = 0
$resultDocument = $null
$executionImages = $null
$cleanup = $null

function Invoke-SupplyNative {
  param([Parameter(Mandatory = $true)][scriptblock]$Action)
  $savedPreference = $ErrorActionPreference
  try {
    $global:LASTEXITCODE = 0
    $ErrorActionPreference = "Continue"
    & $Action
  }
  finally {
    $ErrorActionPreference = $savedPreference
  }
}

function Get-CurrentSourceFingerprint {
  Invoke-SupplyNative {
    & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile `
      -t $currentTag .
  } | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "current v0.4 fingerprint image build failed" }
  $image = (Invoke-SupplyNative {
    & $DockerExe image inspect $currentTag --format "{{.Id}}"
  }).Trim()
  $runImageIds.Add($image)
  $script:fingerprintRunCount += 1
  $container = "spell-v04-audit-fingerprint-$PID-$script:fingerprintRunCount-$nonce"
  $runContainers.Add($container)
  $value = @(
    Invoke-SupplyNative {
      & $DockerExe run --rm --name $container --network none --entrypoint python $image `
        scripts/source_fingerprint_v04.py --root /workspace
    }
  ) | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value) { throw "current v0.4 source fingerprint is invalid" }
  return $value
}

New-Item -ItemType Directory -Path $rawRoot | Out-Null
Push-Location $root
try {
  Invoke-SupplyNative {
    & $DockerExe build --pull=false --provenance=false --build-arg "AUDIT_NONCE=$nonce" `
      -f scripts/supply-chain-v04.Dockerfile -t $auditTag .
  }
  if ($LASTEXITCODE -ne 0) { throw "v0.4 supply-chain audit failed" }
  $auditImage = (Invoke-SupplyNative {
    & $DockerExe image inspect $auditTag --format "{{.Id}}"
  }).Trim()
  if ($LASTEXITCODE -ne 0 -or $auditImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "v0.4 supply-chain audit image identity is invalid"
  }
  $runImageIds.Add($auditImage)

  $auditContainer = "spell-v04-supply-chain-audit-$PID-$nonce"
  $runContainers.Add($auditContainer)
  Invoke-SupplyNative {
    & $DockerExe create --name $auditContainer --network none $auditImage
  } | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "v0.4 supply-chain audit collector creation failed" }
  Invoke-SupplyNative {
    & $DockerExe cp "${auditContainer}:/supply-provenance/." $rawRoot
  } | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "cannot retain v0.4 structured dependency audits" }
  $result = @(Invoke-SupplyNative {
    & $DockerExe start --attach $auditContainer
  })
  if ($LASTEXITCODE -ne 0) { throw "v0.4 supply-chain audit collector failed" }
  $structured = $result | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
  if (-not $structured) { throw "v0.4 supply-chain audit collector emitted no JSON" }

  $current = Get-CurrentSourceFingerprint
  $document = $structured | ConvertFrom-Json
  if (-not $current -or $document.source_fingerprint_sha256 -cne $current) {
    throw "source changed while v0.4 supply-chain audits were running"
  }

  $imageDefinitions = @(
    @("backend", "backend/Dockerfile", ""),
    @("driver", "driver_host/Dockerfile", ""),
    @("frontend", "proxy/Dockerfile", "frontend-build"),
    @("proxy", "proxy/Dockerfile", "")
  )
  $auditedImages = [ordered]@{}
  foreach ($definition in $imageDefinitions) {
    $name = $definition[0]
    $dockerfile = $definition[1]
    $target = $definition[2]
    $tag = "openbexi-spell-v04-$name-audit:$nonce"
    $runTags.Add($tag)
    $arguments = @("build", "--pull=false", "--provenance=false", "-f", $dockerfile, "-t", $tag)
    if ($target) { $arguments += @("--target", $target) }
    $arguments += "."
    Invoke-SupplyNative { & $DockerExe @arguments } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "v0.4 $name audit image build failed" }
    $image = (Invoke-SupplyNative {
      & $DockerExe image inspect $tag --format "{{.Id}}"
    }).Trim()
    if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') {
      throw "v0.4 $name audit image identity is invalid"
    }
    $auditedImages[$name] = $image
    $runImageIds.Add($image)
    $scanPath = Join-Path $rawRoot "scout-$name.sarif.json"
    Invoke-SupplyNative {
      & $ScoutExe cves --only-severity critical,high --exit-code --format sarif `
        --output $scanPath $image
    }
    if ($LASTEXITCODE -ne 0) {
      throw "v0.4 $name image has an unresolved Critical/High vulnerability"
    }
    if (-not (Test-Path -LiteralPath $scanPath -PathType Leaf)) {
      throw "v0.4 $name image audit emitted no SARIF report"
    }
  }
  $pkiTag = "openbexi-spell-v04-pki-audit:$nonce"
  $runTags.Add($pkiTag)
  Invoke-SupplyNative {
    & $DockerExe build --pull=false --provenance=false -f driver_host/pki.Dockerfile -t $pkiTag .
  } | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "v0.4 pki-init dependency image build failed" }
  $pkiImage = (Invoke-SupplyNative {
    & $DockerExe image inspect $pkiTag --format "{{.Id}}"
  }).Trim()
  if ($pkiImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "v0.4 pki-init dependency image identity is invalid"
  }
  $runImageIds.Add($pkiImage)
  $postgresTag = "openbexi-spell-v04-postgres-audit:$nonce"
  $runTags.Add($postgresTag)
  Invoke-SupplyNative {
    & $DockerExe build --pull=false --provenance=false -f driver_host/postgres.Dockerfile -t $postgresTag .
  } | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "v0.4 PostgreSQL dependency image build failed" }
  $postgresImage = (Invoke-SupplyNative {
    & $DockerExe image inspect $postgresTag --format "{{.Id}}"
  }).Trim()
  if ($postgresImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "v0.4 PostgreSQL dependency image identity is invalid"
  }
  $runImageIds.Add($postgresImage)
  $priorDb = $env:SPELL_DB_PASSWORD
  $priorJwt = $env:SPELL_JWT_HS256_SECRET
  try {
    $env:SPELL_DB_PASSWORD = "synthetic-qualification-password"
    $env:SPELL_JWT_HS256_SECRET = "synthetic-qualification-jwt-secret-32-bytes"
    $composeRaw = Invoke-SupplyNative {
      & $ComposeExe --profile driver -f (Join-Path $root "compose.yaml") config --format json
    }
    if ($LASTEXITCODE -ne 0) { throw "cannot render Compose dependency configuration" }
    $compose = $composeRaw | ConvertFrom-Json
  }
  finally {
    if ($null -eq $priorDb) { Remove-Item Env:SPELL_DB_PASSWORD -ErrorAction SilentlyContinue }
    else { $env:SPELL_DB_PASSWORD = $priorDb }
    if ($null -eq $priorJwt) { Remove-Item Env:SPELL_JWT_HS256_SECRET -ErrorAction SilentlyContinue }
    else { $env:SPELL_JWT_HS256_SECRET = $priorJwt }
  }
  if (
    [string]$compose.services.postgres.build.dockerfile -cne "driver_host/postgres.Dockerfile" -or
    [string]$compose.services.postgres.user -cne "70:70"
  ) {
    throw "PostgreSQL Compose dependency does not use the hardened v0.4 build profile"
  }
  $dependencyImages = [ordered]@{
    pki_init = $pkiImage
    postgres = $postgresImage
  }
  foreach ($dependency in $dependencyImages.GetEnumerator()) {
    $scanPath = Join-Path $rawRoot "scout-$($dependency.Key).sarif.json"
    Invoke-SupplyNative {
      & $ScoutExe cves --only-severity critical,high --exit-code --format sarif `
        --output $scanPath $dependency.Value
    }
    if ($LASTEXITCODE -ne 0) {
      throw "v0.4 $($dependency.Key) dependency has an unresolved Critical/High vulnerability"
    }
    if (-not (Test-Path -LiteralPath $scanPath -PathType Leaf)) {
      throw "v0.4 $($dependency.Key) dependency audit emitted no SARIF report"
    }
  }
  if ((Get-CurrentSourceFingerprint) -cne $current) {
    throw "source changed while v0.4 image vulnerability audits were running"
  }
  $document.metrics.audit_tool_count = 4
  $document.metrics | Add-Member -NotePropertyName audited_image_count `
    -NotePropertyValue $auditedImages.Count -Force
  $document.metrics | Add-Member -NotePropertyName audited_image_ids `
    -NotePropertyValue $auditedImages -Force
  $document.metrics | Add-Member -NotePropertyName compose_dependency_audited_image_count `
    -NotePropertyValue $dependencyImages.Count -Force
  $document.metrics | Add-Member -NotePropertyName compose_dependency_audited_image_ids `
    -NotePropertyValue $dependencyImages -Force
  $document.assertions += [pscustomobject]@{
    id = "four-runtime-and-build-images-have-no-high-or-critical-findings"
    passed = $true
  }
  $document.assertions += [pscustomobject]@{
    id = "pki-init-and-hardened-postgres-compose-dependencies-have-no-high-or-critical-findings"
    passed = $true
  }
  $executionImages = [ordered]@{
    audit = $auditImage
    backend = [string]$auditedImages.backend
    driver = [string]$auditedImages.driver
    frontend = [string]$auditedImages.frontend
    pki_init = [string]$dependencyImages.pki_init
    postgres = [string]$dependencyImages.postgres
    proxy = [string]$auditedImages.proxy
  }
  $resultDocument = $document
}
finally {
  try { Pop-Location }
  finally {
    $cleanup = Remove-V04RunDockerResources -DockerExe $DockerExe -Tags $runTags.ToArray() `
      -Containers $runContainers.ToArray() -ImageIds $runImageIds.ToArray()
    if ($null -eq $resultDocument -and (Test-Path -LiteralPath $rawRoot -PathType Container)) {
      Remove-Item -LiteralPath $rawRoot -Recurse -Force
    }
  }
}
if ($null -ne $resultDocument) {
  try {
    $resultDocument.metrics | Add-Member -NotePropertyName retained_shared_image_count `
      -NotePropertyValue @($cleanup.retained_shared_image_ids).Count -Force
    $resultDocument.metrics | Add-Member -NotePropertyName retained_shared_image_ids `
      -NotePropertyValue @($cleanup.retained_shared_image_ids) -Force
    $resultDocument = Add-V04SupplyProvenanceMetrics -Root $root `
      -PythonExe $PythonExe -TestId "V04-SC-001" -RunId $nonce `
      -SourceFingerprint $current -RawDirectory $rawRoot -Result $resultDocument `
      -ExecutionImages $executionImages
    Write-Output ($resultDocument | ConvertTo-Json -Depth 20 -Compress)
  }
  finally {
    if (Test-Path -LiteralPath $rawRoot -PathType Container) {
      Remove-Item -LiteralPath $rawRoot -Recurse -Force
    }
  }
}
