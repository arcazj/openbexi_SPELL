$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts/v0.4"
$release = Join-Path $artifactRoot "openbexi-spell-v0.4.tar.gz"
$sidecar = "$release.sha256"
$runId = [guid]::NewGuid().ToString("N")
$tag = "openbexi-spell-v04-package-input:$runId"
$temporaryRoot = Join-Path $env:TEMP "spell-v04-package-$runId"
$stagedRelease = Join-Path $artifactRoot ".openbexi-spell-v0.4.tar.gz.staging-$runId"
$stagedSidecar = "$stagedRelease.sha256"
$backupRelease = Join-Path $artifactRoot ".openbexi-spell-v0.4.tar.gz.backup-$runId"
$backupSidecar = "$backupRelease.sha256"
$temporaryFull = [IO.Path]::GetFullPath($temporaryRoot)
$tempRootFull = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
if (-not $temporaryFull.StartsWith("$tempRootFull$([IO.Path]::DirectorySeparatorChar)")) {
  throw "refusing to use a package path outside the temporary root"
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "v0.4 release toolchain validation failed" }
$DockerExe = $env:SPELL_RELEASE_DOCKER_EXE
. (Join-Path $PSScriptRoot "release_docker_resources_v04.ps1")
$runTags = @($tag)
$runContainers = [Collections.Generic.List[string]]::new()
$runImageIds = [Collections.Generic.List[string]]::new()
$result = $null
$cleanup = $null

function Build-PackageFromImage([string]$image, [string]$suffix) {
  $container = "spell-v04-package-$PID-$suffix-$runId"
  $runContainers.Add($container)
  $destination = Join-Path $temporaryRoot "openbexi-spell-v0.4-$suffix.tar.gz"
  try {
    & $DockerExe create --name $container --network none $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot create v0.4 package container $suffix" }
    & $DockerExe start -a $container | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "v0.4 package build $suffix failed" }
    & $DockerExe cp "${container}:/workspace/artifacts/v0.4/openbexi-spell-v0.4.tar.gz" $destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot copy v0.4 package build $suffix" }
  }
  finally { & $DockerExe rm -f $container 2>$null | Out-Null }
  return $destination
}

New-Item -ItemType Directory -Force $artifactRoot | Out-Null
New-Item -ItemType Directory $temporaryRoot | Out-Null
try {
  Push-Location $root
  try {
    & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile -t $tag .
    if ($LASTEXITCODE -ne 0) { throw "immutable v0.4 package input image build failed" }
    $image = (& $DockerExe image inspect $tag --format "{{.Id}}").Trim()
    if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') {
      throw "immutable v0.4 package input image identity is invalid"
    }
    $runImageIds.Add($image)
    $validationContainer = "spell-v04-package-validation-$PID-$runId"
    $runContainers.Add($validationContainer)
    $validationOutput = @(
      & $DockerExe run --rm --name $validationContainer --network none --entrypoint python $image `
        scripts/validate_release_evidence_v04.py --root /workspace
    )
    if ($LASTEXITCODE -ne 0) { throw "v0.4 release evidence validation failed" }
    $validationLine = $validationOutput | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
    if (-not $validationLine) { throw "v0.4 release evidence validator emitted no JSON" }
    $validation = $validationLine | ConvertFrom-Json

    $first = Build-PackageFromImage $image "a"
    $second = Build-PackageFromImage $image "b"
    $firstHash = (Get-FileHash $first -Algorithm SHA256).Hash.ToLower()
    $secondHash = (Get-FileHash $second -Algorithm SHA256).Hash.ToLower()
    if ($firstHash -cne $secondHash) { throw "immutable v0.4 package builds differ" }

    & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile -t $tag . | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "current v0.4 package input image rebuild failed" }
    $currentImage = (& $DockerExe image inspect $tag --format "{{.Id}}").Trim()
    $runImageIds.Add($currentImage)
    $third = Build-PackageFromImage $currentImage "current"
    $thirdHash = (Get-FileHash $third -Algorithm SHA256).Hash.ToLower()
    if ($thirdHash -cne $firstHash) { throw "current-context v0.4 package differs" }
    & $DockerExe build --pull=false --provenance=false -f scripts/package-v04.Dockerfile -t $tag . | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "final v0.4 package context verification failed" }
    $finalContextImage = (& $DockerExe image inspect $tag --format "{{.Id}}").Trim()
    $runImageIds.Add($finalContextImage)
    if ($finalContextImage -cne $currentImage) {
      throw "package input changed immediately before v0.4 publication"
    }
  }
  finally { Pop-Location }

  $releaseExists = Test-Path -LiteralPath $release
  $sidecarExists = Test-Path -LiteralPath $sidecar
  if ($releaseExists -ne $sidecarExists) {
    throw "existing v0.4 package publication is incomplete"
  }
  foreach ($path in @($release, $sidecar, $stagedRelease, $stagedSidecar, $backupRelease, $backupSidecar)) {
    if (Test-Path -LiteralPath $path) {
      $item = Get-Item -Force -LiteralPath $path
      if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "refusing to use unsafe v0.4 package publication path: $path"
      }
      if ($path -notin @($release, $sidecar)) {
        throw "v0.4 package transaction path already exists: $path"
      }
    }
  }
  Copy-Item -LiteralPath $first -Destination $stagedRelease
  [IO.File]::WriteAllText(
    $stagedSidecar,
    "$firstHash  openbexi-spell-v0.4.tar.gz`n",
    [Text.Encoding]::ASCII
  )
  if ((Get-FileHash -LiteralPath $stagedRelease -Algorithm SHA256).Hash.ToLower() -cne $firstHash) {
    throw "staged v0.4 package hash differs before publication"
  }
  $oldPairBackedUp = $false
  try {
    if ($releaseExists) {
      Move-Item -LiteralPath $release -Destination $backupRelease
      try { Move-Item -LiteralPath $sidecar -Destination $backupSidecar }
      catch {
        Move-Item -LiteralPath $backupRelease -Destination $release
        throw
      }
      $oldPairBackedUp = $true
    }
    Move-Item -LiteralPath $stagedRelease -Destination $release
    Move-Item -LiteralPath $stagedSidecar -Destination $sidecar
    $publishedHash = (Get-FileHash -LiteralPath $release -Algorithm SHA256).Hash.ToLower()
    $publishedSidecar = [IO.File]::ReadAllText($sidecar, [Text.Encoding]::ASCII)
    if (
      $publishedHash -cne $firstHash -or
      $publishedSidecar -cne "$firstHash  openbexi-spell-v0.4.tar.gz`n"
    ) { throw "published v0.4 package pair failed final verification" }
  }
  catch {
    if (Test-Path -LiteralPath $release -PathType Leaf) { Remove-Item -LiteralPath $release -Force }
    if (Test-Path -LiteralPath $sidecar -PathType Leaf) { Remove-Item -LiteralPath $sidecar -Force }
    if ($oldPairBackedUp) {
      Move-Item -LiteralPath $backupRelease -Destination $release
      Move-Item -LiteralPath $backupSidecar -Destination $sidecar
      $oldPairBackedUp = $false
    }
    throw
  }
  if ($oldPairBackedUp) {
    Remove-Item -LiteralPath $backupRelease -Force
    Remove-Item -LiteralPath $backupSidecar -Force
    $oldPairBackedUp = $false
  }
  $result = [ordered]@{
    schema_version = "spell.v04.package-result/1"
    product_version = "0.4.0"
    source_fingerprint_sha256 = $validation.source_fingerprint_sha256
    evidence_fingerprint_sha256 = $validation.evidence_fingerprint_sha256
    package_input_image_id = $image
    current_package_input_image_id = $currentImage
    final_context_image_id = $finalContextImage
    package_sha256 = $firstHash
    package_build_count = 3
    package_process_count = 3
    package_byte_identical = $true
    output = "artifacts/v0.4/openbexi-spell-v0.4.tar.gz"
  }
}
finally {
  try {
    if (Test-Path $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
    foreach ($path in @($stagedRelease, $stagedSidecar)) {
      if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
  }
  finally {
    $cleanup = Remove-V04RunDockerResources -DockerExe $DockerExe -Tags $runTags `
      -Containers $runContainers.ToArray() -ImageIds $runImageIds.ToArray()
  }
}
if ($null -ne $result) {
  $result.retained_shared_image_ids = @($cleanup.retained_shared_image_ids)
  $result | ConvertTo-Json -Depth 5 -Compress | Write-Output
}
