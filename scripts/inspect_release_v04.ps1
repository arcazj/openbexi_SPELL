$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sbomRoot = Join-Path $root "artifacts/v0.4/sbom"
$qualificationRoot = Join-Path $root "artifacts/v0.4/.qualification"
$reportPath = Join-Path $qualificationRoot "image-inspection.json"
$runId = [guid]::NewGuid().ToString("N")
$probeTag = "openbexi-spell-v04-inspection-probe:$runId"
$pkiTag = "openbexi-spell-v04-pki-inspection:$runId"
$postgresTag = "openbexi-spell-v04-postgres-inspection:$runId"
$reportStaging = "$reportPath.staging-$runId"
$rawRoot = Join-Path $env:TEMP "spell-v04-sc003-raw-$runId"
$temporary = Join-Path $env:TEMP "spell-v04-image-inspection-$runId"
$temporaryFull = [IO.Path]::GetFullPath($temporary)
$rawRootFull = [IO.Path]::GetFullPath($rawRoot)
$tempRootFull = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
if (
  -not $temporaryFull.StartsWith("$tempRootFull$([IO.Path]::DirectorySeparatorChar)") -or
  -not $rawRootFull.StartsWith("$tempRootFull$([IO.Path]::DirectorySeparatorChar)")
) {
  throw "refusing to use an image-inspection path outside the temporary root"
}
if (Test-Path -LiteralPath $rawRoot) { throw "SC003 raw evidence path already exists" }
$imageDefinitions = [ordered]@{
  backend = [ordered]@{
    Inventory = "backend.cdx.json"
    Dockerfile = "backend/Dockerfile"
    Target = $null
    Tag = "openbexi-spell-v04-backend-inspection:$runId"
  }
  driver = [ordered]@{
    Inventory = "driver.cdx.json"
    Dockerfile = "driver_host/Dockerfile"
    Target = $null
    Tag = "openbexi-spell-v04-driver-inspection:$runId"
  }
  frontend = [ordered]@{
    Inventory = "frontend.cdx.json"
    Dockerfile = "proxy/Dockerfile"
    Target = "frontend-build"
    Tag = "openbexi-spell-v04-frontend-inspection:$runId"
  }
  proxy = [ordered]@{
    Inventory = "proxy.cdx.json"
    Dockerfile = "proxy/Dockerfile"
    Target = $null
    Tag = "openbexi-spell-v04-proxy-inspection:$runId"
  }
}
$scanned = 0
$secretFiles = 0
$pdfFiles = 0
$manualTextFiles = 0
$legacyArchives = 0
$runtimeJournals = 0
$runtimeGenerators = 0
$scannedLayers = 0
$layerScanFailures = 0
$hardeningFailures = @()
$composeConfiguration = $null

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE
$ComposeExe = $env:SPELL_RELEASE_COMPOSE_EXE
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE
. (Join-Path $PSScriptRoot "release_docker_resources_v04.ps1")
. (Join-Path $PSScriptRoot "stage_supply_provenance_v04.ps1")
$runTags = @($probeTag, $pkiTag, $postgresTag) + @(
  $imageDefinitions.Values | ForEach-Object { [string]$_.Tag }
)
$runContainers = [Collections.Generic.List[string]]::new()
$runImageIds = [Collections.Generic.List[string]]::new()
$result = $null
$executionImages = $null
$cleanup = $null

function Get-ImageId([string]$name) {
  $inventory = Get-Content -Raw `
    (Join-Path $sbomRoot $imageDefinitions[$name].Inventory) | ConvertFrom-Json
  $image = $inventory.metadata.component.version
  if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "invalid SBOM image ID for $name" }
  return $image
}

function Test-NonRootImage([string]$name, [string]$image) {
  $inspection = @(& $DockerExe image inspect $image | ConvertFrom-Json)[0]
  if ($LASTEXITCODE -ne 0 -or $null -eq $inspection) { throw "cannot inspect image $name" }
  $user = ([string]$inspection.Config.User).Trim()
  $principal = @($user.Split(':'))[0].Trim()
  [long]$numericPrincipal = -1
  $numericUser = [long]::TryParse(
    $principal,
    [Globalization.NumberStyles]::Integer,
    [Globalization.CultureInfo]::InvariantCulture,
    [ref]$numericPrincipal
  )
  if (
    -not $user -or
    $principal -cmatch '^0+$' -or
    ($numericUser -and $numericPrincipal -eq 0) -or
    $principal -ieq "root"
  ) {
    $script:hardeningFailures += "$name image has no non-root user"
  }
  if ($name -eq "backend") {
    if ($user -cne "10001:10001") {
      $script:hardeningFailures += "backend image user differs from the permanent service identity"
    }
    if ((@($inspection.Config.Entrypoint) -join "`0") -cne "python`0/app/backend/credential_bootstrap.py") {
      $script:hardeningFailures += "backend image credential bootstrap entrypoint differs"
    }
  }
  if ($name -eq "driver" -and $null -ne $inspection.Config.ExposedPorts) {
    $script:hardeningFailures += "driver image exposes a port"
  }
}

function Inspect-ImageLayers([string]$name, [string]$image) {
  $archive = Join-Path $temporary "$name-image.tar"
  & $DockerExe image save --output $archive $image
  if ($LASTEXITCODE -ne 0) { throw "cannot save image layers for $name" }
  $container = "spell-v04-layer-scan-$PID-$name-$runId"
  $runContainers.Add($container)
  try {
    & $DockerExe create --name $container --network none --cap-drop ALL `
      --security-opt no-new-privileges --entrypoint python $probeImage `
      scripts/inspect_image_archive_v04.py --archive /tmp/image.tar --image-id $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot create layer scanner for $name" }
    & $DockerExe cp $archive "${container}:/tmp/image.tar" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot copy image archive into layer scanner for $name" }
    $scanOutput = @(& $DockerExe start --attach $container)
    if ($LASTEXITCODE -ne 0) { throw "layer scanner failed for $name" }
  }
  finally { & $DockerExe rm --force $container 2>$null | Out-Null }
  $scanLine = $scanOutput | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
  if (-not $scanLine) { throw "layer scanner emitted no JSON for $name" }
  $result = $scanLine | ConvertFrom-Json
  if (
    $result.schema_version -cne "spell.v04.image-layer-inspection/1" -or
    $result.image_id -cne $image
  ) { throw "layer scanner identity differs for $name" }
  $script:scanned += [int]$result.scanned_file_count
  $script:secretFiles += [int]$result.secret_file_count
  $script:pdfFiles += [int]$result.pdf_file_count
  $script:manualTextFiles += [int]$result.manual_text_file_count
  $script:legacyArchives += [int]$result.legacy_archive_count
  $script:runtimeJournals += [int]$result.runtime_journal_count
  $script:runtimeGenerators += [int]$result.runtime_generator_count
  $script:scannedLayers += [int]$result.scanned_layer_count
  $script:layerScanFailures += [int]$result.layer_scan_failure_count
}

function Test-ComposeHardening {
  $priorDb = $env:SPELL_DB_PASSWORD
  $priorJwt = $env:SPELL_JWT_HS256_SECRET
  try {
    $env:SPELL_DB_PASSWORD = "synthetic-qualification-password"
    $env:SPELL_JWT_HS256_SECRET = "synthetic-qualification-jwt-secret-32-bytes"
    $raw = & $ComposeExe --profile driver -f (Join-Path $root "compose.yaml") config --format json
    if ($LASTEXITCODE -ne 0) { throw "cannot render Compose hardening configuration" }
    $compose = $raw | ConvertFrom-Json
    $script:composeConfiguration = $compose
  }
  finally {
    if ($null -eq $priorDb) { Remove-Item Env:SPELL_DB_PASSWORD -ErrorAction SilentlyContinue }
    else { $env:SPELL_DB_PASSWORD = $priorDb }
    if ($null -eq $priorJwt) { Remove-Item Env:SPELL_JWT_HS256_SECRET -ErrorAction SilentlyContinue }
    else { $env:SPELL_JWT_HS256_SECRET = $priorJwt }
  }
  $serviceNames = @($compose.services.PSObject.Properties.Name | Sort-Object)
  if (($serviceNames -join ',') -cne "backend,pki-init,postgres,proxy,spell-driver") {
    $script:hardeningFailures += "driver profile service set differs"
  }
  foreach ($name in @("backend", "proxy", "spell-driver")) {
    $service = $compose.services.$name
    if ($service.read_only -ne $true) { $script:hardeningFailures += "$name is not read-only" }
    if ("ALL" -notin @($service.cap_drop)) { $script:hardeningFailures += "$name does not drop all capabilities" }
    if ("no-new-privileges:true" -notin @($service.security_opt)) {
      $script:hardeningFailures += "$name lacks no-new-privileges"
    }
  }
  if ($null -ne $compose.services."spell-driver".ports) {
    $script:hardeningFailures += "driver service publishes a port"
  }
  if ($compose.networks."spell-driver-internal".internal -ne $true) {
    $script:hardeningFailures += "driver network is not internal"
  }
  $driverNetworks = @($compose.services."spell-driver".networks.PSObject.Properties.Name)
  if ($driverNetworks.Count -ne 1 -or $driverNetworks[0] -ne "spell-driver-internal") {
    $script:hardeningFailures += "driver is attached outside its internal network"
  }
  $backend = $compose.services.backend
  if ([string]$backend.user -cne "0:0") {
    $script:hardeningFailures += "backend bootstrap does not start with the constrained root identity"
  }
  if ((@($backend.cap_add | Sort-Object) -join ',') -cne "CHOWN,DAC_OVERRIDE,SETGID,SETUID") {
    $script:hardeningFailures += "backend bootstrap capabilities differ"
  }
  if ((@($backend.healthcheck.test) -join "`0") -cne "CMD`0python`0/app/backend/healthcheck.py") {
    $script:hardeningFailures += "backend healthcheck does not use the privilege-drop helper"
  }
  $expectedBackendTmpfs = @(
    "/run/spell-driver-client:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=10001,gid=10001",
    "/tmp:size=64m,noexec,nosuid"
  ) | Sort-Object
  if ((@($backend.tmpfs | Sort-Object) -join "`0") -cne ($expectedBackendTmpfs -join "`0")) {
    $script:hardeningFailures += "backend runtime credential tmpfs contract differs"
  }
  $backendVolumes = @($backend.volumes)
  if ($backendVolumes.Count -ne 1) {
    $script:hardeningFailures += "backend credential source mount set differs"
  }
  elseif ($backendVolumes[0] -is [string]) {
    if ([string]$backendVolumes[0] -cne "spell-driver-client-credentials:/run/spell-driver-client-source:ro") {
      $script:hardeningFailures += "backend credential source mount differs"
    }
  }
  elseif (
    [string]$backendVolumes[0].type -cne "volume" -or
    [string]$backendVolumes[0].source -cne "spell-driver-client-credentials" -or
    [string]$backendVolumes[0].target -cne "/run/spell-driver-client-source" -or
    $backendVolumes[0].read_only -ne $true
  ) { $script:hardeningFailures += "backend credential source mount differs" }
  $pki = $compose.services."pki-init"
  if ([string]$pki.user -cne "0:0" -or [string]$pki.network_mode -cne "none") {
    $script:hardeningFailures += "pki-init root exception is not constrained to network-none initialization"
  }
  if (
    "ALL" -notin @($pki.cap_drop) -or
    (@($pki.cap_add | Sort-Object) -join ',') -cne "CHOWN,DAC_OVERRIDE,FOWNER" -or
    "no-new-privileges:true" -notin @($pki.security_opt)
  ) { $script:hardeningFailures += "pki-init root exception capabilities differ" }
  $expectedPkiCommand = @(
    "--client-dir", "/run/spell-driver-client-source",
    "--server-dir", "/run/spell-driver-server",
    "--client-uid", "0", "--client-gid", "0",
    "--server-uid", "10002", "--server-gid", "10002"
  )
  if ((@($pki.command) -join "`0") -cne ($expectedPkiCommand -join "`0")) {
    $script:hardeningFailures += "pki-init one-time credential command differs"
  }
  if ("--force" -in @($pki.command)) {
    $script:hardeningFailures += "pki-init would overwrite retained credential epochs"
  }
  $pkiClientMount = @($pki.volumes | Where-Object {
    ($_ -is [string] -and $_ -clike "*:/run/spell-driver-client-source*") -or
    ($_ -isnot [string] -and [string]$_.target -ceq "/run/spell-driver-client-source")
  })
  if ($pkiClientMount.Count -ne 1) {
    $script:hardeningFailures += "pki-init client credential target differs"
  }
  elseif ($pkiClientMount[0] -is [string]) {
    if ([string]$pkiClientMount[0] -cne "spell-driver-client-credentials:/run/spell-driver-client-source") {
      $script:hardeningFailures += "pki-init client credential mount differs"
    }
  }
  elseif (
    [string]$pkiClientMount[0].type -cne "volume" -or
    [string]$pkiClientMount[0].source -cne "spell-driver-client-credentials" -or
    $pkiClientMount[0].read_only -eq $true
  ) { $script:hardeningFailures += "pki-init client credential mount differs" }
  foreach ($profiledService in @("pki-init", "spell-driver")) {
    if ((@($compose.services.$profiledService.profiles) -join ',') -cne "driver") {
      $script:hardeningFailures += "$profiledService profile declaration differs"
    }
  }
}

if (-not (Test-Path $sbomRoot)) { throw "run generate_sbom_v04.ps1 first" }
New-Item -ItemType Directory -Force $qualificationRoot | Out-Null
foreach ($path in @($reportPath, $reportStaging)) {
  if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      Remove-Item -LiteralPath $path -Force
    }
    else { throw "refusing unsafe image-inspection report path: $path" }
  }
}
New-Item -ItemType Directory $temporary | Out-Null
New-Item -ItemType Directory $rawRoot | Out-Null
try {
  $images = [ordered]@{}
  Push-Location $root
  try {
    & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile -t $probeTag . | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot build v0.4 inspection probe input" }
    $probeImage = (& $DockerExe image inspect $probeTag --format "{{.Id}}").Trim()
    $runImageIds.Add($probeImage)
    & $DockerExe build --pull=false --provenance=false -f driver_host/pki.Dockerfile -t $pkiTag . | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot build pki-init dependency image" }
    $pkiImage = (& $DockerExe image inspect $pkiTag --format "{{.Id}}").Trim()
    $runImageIds.Add($pkiImage)
    & $DockerExe build --pull=false --provenance=false -f driver_host/postgres.Dockerfile -t $postgresTag . | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot build PostgreSQL dependency image" }
    $postgresImage = (& $DockerExe image inspect $postgresTag --format "{{.Id}}").Trim()
    if ($postgresImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
      throw "PostgreSQL dependency image identity is invalid"
    }
    $runImageIds.Add($postgresImage)
    foreach ($entry in $imageDefinitions.GetEnumerator()) {
      $arguments = @(
        "build", "--pull=false", "--provenance=false", "-f", $entry.Value.Dockerfile,
        "-t", $entry.Value.Tag
      )
      if ($entry.Value.Target) { $arguments += @("--target", $entry.Value.Target) }
      $arguments += "."
      & $DockerExe @arguments | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "cannot rebuild $($entry.Key) SBOM subject for inspection"
      }
      $rebuiltImage = (& $DockerExe image inspect $entry.Value.Tag --format "{{.Id}}").Trim()
      if ($rebuiltImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw "rebuilt $($entry.Key) image identity is invalid"
      }
      $runImageIds.Add($rebuiltImage)
      $expectedImage = Get-ImageId $entry.Key
      if ($rebuiltImage -cne $expectedImage) {
        throw "rebuilt $($entry.Key) image identity differs from the SC002 SBOM"
      }
      $images[$entry.Key] = $rebuiltImage
    }
  }
  finally { Pop-Location }
  foreach ($name in $imageDefinitions.Keys) {
    $image = [string]$images[$name]
    Test-NonRootImage $name $image
    Inspect-ImageLayers $name $image
  }
  Test-ComposeHardening
  if (
    [string]$composeConfiguration.services.postgres.build.dockerfile -cne "driver_host/postgres.Dockerfile" -or
    [string]$composeConfiguration.services.postgres.user -cne "70:70"
  ) {
    throw "PostgreSQL Compose dependency does not use the hardened v0.4 build profile"
  }
  $dependencyImages = [ordered]@{
    pki_init = $pkiImage
    postgres = $postgresImage
  }
  Test-NonRootImage "postgres" $dependencyImages.postgres
  Inspect-ImageLayers "pki-init" $dependencyImages.pki_init
  Inspect-ImageLayers "postgres" $dependencyImages.postgres
  if ($hardeningFailures.Count -gt 0) { throw ($hardeningFailures -join "; ") }
  if (
    $secretFiles + $pdfFiles + $manualTextFiles + $legacyArchives + $runtimeJournals +
      $runtimeGenerators + $layerScanFailures -ne 0
  ) {
    throw "forbidden runtime image material was found"
  }

  $report = [ordered]@{
    schema_version = "spell.v04.image-inspection/1"
    image_names = @("backend", "driver", "frontend", "proxy")
    image_ids = $images
    compose_dependency_image_ids = $dependencyImages
    compose_dependency_configured_references = [ordered]@{
      pki_init = $pkiImage
      postgres = $postgresImage
    }
    compose_dependency_image_count = $dependencyImages.Count
    scanned_image_count = $images.Count + $dependencyImages.Count
    scanned_layer_count = $scannedLayers
    layer_scan_failure_count = $layerScanFailures
    scanned_file_count = $scanned
    secret_file_count = $secretFiles
    pdf_file_count = $pdfFiles
    manual_text_file_count = $manualTextFiles
    legacy_archive_count = $legacyArchives
    runtime_journal_count = $runtimeJournals
    runtime_generator_count = $runtimeGenerators
    hardening_failure_count = $hardeningFailures.Count
  }
  [IO.File]::WriteAllText(
    $reportStaging,
    "$(($report | ConvertTo-Json -Depth 8).Replace("`r`n", "`n").Replace("`r", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
  )
  Move-Item -LiteralPath $reportStaging -Destination $reportPath
  $reportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLower()
  Copy-Item -LiteralPath $reportPath -Destination (Join-Path $rawRoot "image-inspection.json")
  $retainedReport = Join-Path $rawRoot "image-inspection.json"
  if ((Get-FileHash -LiteralPath $retainedReport -Algorithm SHA256).Hash.ToLower() -cne $reportSha256) {
    throw "retained SC003 inspection bytes differ"
  }

  Push-Location $root
  try {
    $probeContainer = "spell-v04-inspection-probe-$PID-$runId"
    $runContainers.Add($probeContainer)
    $reportMount = "type=bind,src=$reportPath,dst=/inspection/image-inspection.json,readonly"
    $probeOutput = @(& $DockerExe run --rm --name $probeContainer --network none --read-only `
      --cap-drop ALL --security-opt no-new-privileges --mount $reportMount `
      --entrypoint python $probeImage `
      scripts/supply_chain_v04.py --root /workspace probe-sc-003 `
      --inspection-report /inspection/image-inspection.json `
      --inspection-report-sha256 $reportSha256)
    if ($LASTEXITCODE -ne 0) { throw "v0.4 package/source/image inspection probe failed" }
    $probeLine = $probeOutput | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
    if (-not $probeLine) { throw "v0.4 package/source/image inspection probe emitted no JSON" }
    $result = $probeLine | ConvertFrom-Json
    if ($result.metrics.inspection_report_sha256 -cne $reportSha256) {
      throw "v0.4 package/source/image inspection probe used substituted report bytes"
    }
    $executionImages = [ordered]@{
      backend = [string]$images.backend
      driver = [string]$images.driver
      frontend = [string]$images.frontend
      pki_init = [string]$dependencyImages.pki_init
      postgres = [string]$dependencyImages.postgres
      probe = $probeImage
      proxy = [string]$images.proxy
    }
  }
  finally { Pop-Location }
}
finally {
  try {
    if (Test-Path $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    if (Test-Path -LiteralPath $reportStaging -PathType Leaf) {
      Remove-Item -LiteralPath $reportStaging -Force
    }
  }
  finally {
    $cleanup = Remove-V04RunDockerResources -DockerExe $DockerExe -Tags $runTags `
      -Containers $runContainers.ToArray() -ImageIds $runImageIds.ToArray()
    if ($null -eq $result -and (Test-Path -LiteralPath $rawRoot -PathType Container)) {
      Remove-Item -LiteralPath $rawRoot -Recurse -Force
    }
  }
}
if ($null -ne $result) {
  try {
    $result.metrics | Add-Member -NotePropertyName retained_shared_image_count `
      -NotePropertyValue @($cleanup.retained_shared_image_ids).Count -Force
    $result.metrics | Add-Member -NotePropertyName retained_shared_image_ids `
      -NotePropertyValue @($cleanup.retained_shared_image_ids) -Force
    $result = Add-V04SupplyProvenanceMetrics -Root $root -PythonExe $PythonExe `
      -TestId "V04-SC-003" -RunId $runId `
      -SourceFingerprint ([string]$result.source_fingerprint_sha256) `
      -RawDirectory $rawRoot -Result $result -ExecutionImages $executionImages
    Write-Output ($result | ConvertTo-Json -Depth 20 -Compress)
  }
  finally {
    if (Test-Path -LiteralPath $rawRoot -PathType Container) {
      Remove-Item -LiteralPath $rawRoot -Recurse -Force
    }
  }
}
