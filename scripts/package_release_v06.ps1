$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts/v0.6"
$release = Join-Path $artifactRoot "openbexi-spell-v0.6.0.tar.gz"
$sidecar = "$release.sha256"
$runId = [guid]::NewGuid().ToString("N")
$qualificationRoot = Join-Path $artifactRoot ".qualification"
$scratchRoot = Join-Path $qualificationRoot "package-$runId"
$first = Join-Path $scratchRoot "package-a.tar.gz"
$second = Join-Path $scratchRoot "package-b.tar.gz"
$exportRoot = Join-Path $env:TEMP "spell-v06-package-exports-$runId"
$exportA = Join-Path $exportRoot "source-a"
$exportB = Join-Path $exportRoot "source-b"
$exportFirst = Join-Path $exportA "artifacts/v0.6/.qualification/package-a.tar.gz"
$exportSecond = Join-Path $exportB "artifacts/v0.6/.qualification/package-b.tar.gz"
$stagedRelease = Join-Path $artifactRoot ".openbexi-spell-v0.6.0.tar.gz.staging-$runId"
$stagedSidecar = "$stagedRelease.sha256"
$backupRelease = Join-Path $artifactRoot ".openbexi-spell-v0.6.0.tar.gz.backup-$runId"
$backupSidecar = "$backupRelease.sha256"

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Assert-V05ArtifactsUnchanged {
  $tree = @(& git -C $root rev-parse "HEAD:artifacts/v0.5") -join "`n"
  if (
    $LASTEXITCODE -ne 0 -or
    $tree.Trim() -cne "27542ec5db41ff29ba2af62824c8d39f442b95e8"
  ) { throw "accepted v0.5 artifact tree differs" }
  & git -C $root diff --quiet v0.5.0 HEAD -- artifacts/v0.5
  if ($LASTEXITCODE -ne 0) { throw "accepted v0.5 artifacts differ from v0.5.0" }
  & git -C $root diff --quiet -- artifacts/v0.5
  if ($LASTEXITCODE -ne 0) { throw "accepted v0.5 artifacts have a working-tree change" }
  $status = @(& git -C $root status --porcelain --untracked-files=all -- artifacts/v0.5)
  if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    throw "accepted v0.5 artifacts have an untracked change"
  }
  & (Join-Path $PSScriptRoot "assert_accepted_v05_release_v06.ps1") -Root $root | Out-Null
}

function Stage-AcceptedV05ExternalRelease([string]$BuildRoot) {
  $destinationRoot = Join-Path $BuildRoot "artifacts/v0.5"
  New-Item -ItemType Directory -Path $destinationRoot -Force | Out-Null
  foreach ($name in @("openbexi-spell-v0.5.0.tar.gz", "openbexi-spell-v0.5.0.tar.gz.sha256")) {
    $source = Join-Path $root "artifacts/v0.5/$name"
    $destination = Join-Path $destinationRoot $name
    if (Test-Path -LiteralPath $destination) {
      throw "independent package export unexpectedly contains accepted external input: $name"
    }
    Copy-Item -LiteralPath $source -Destination $destination
  }
  & (Join-Path $PSScriptRoot "assert_accepted_v05_release_v06.ps1") -Root $BuildRoot | Out-Null
}

function Invoke-PackageBuild([string]$BuildRoot, [string]$OutputPath) {
  $lines = @(& $PythonExe (Join-Path $BuildRoot "scripts/build_reproducible_v06.py") `
    --root $BuildRoot --output $OutputPath)
  if ($LASTEXITCODE -ne 0) { throw "v0.6 deterministic package build failed" }
  $jsonLine = $lines | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
  if (-not $jsonLine) { throw "v0.6 deterministic package build emitted no JSON" }
  return $jsonLine | ConvertFrom-Json
}

function Publish-V06PackagePair {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)] [string]$SourceRelease,
    [Parameter(Mandatory = $true)] [string]$StagedRelease,
    [Parameter(Mandatory = $true)] [string]$StagedSidecar,
    [Parameter(Mandatory = $true)] [string]$Release,
    [Parameter(Mandatory = $true)] [string]$Sidecar,
    [Parameter(Mandatory = $true)] [string]$BackupRelease,
    [Parameter(Mandatory = $true)] [string]$BackupSidecar,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedHash,
    [ValidateSet("None", "AfterArchivePublication")]
    [string]$TestOnlyFault = "None"
  )

  $paths = @(
    $SourceRelease, $StagedRelease, $StagedSidecar, $Release,
    $Sidecar, $BackupRelease, $BackupSidecar
  ) | ForEach-Object { [IO.Path]::GetFullPath($_) }
  if (@($paths | Sort-Object -Unique).Count -ne $paths.Count) {
    throw "v0.6 package transaction paths are not distinct"
  }

  $releaseExists = Test-Path -LiteralPath $Release
  $sidecarExists = Test-Path -LiteralPath $Sidecar
  if ($releaseExists -ne $sidecarExists) {
    throw "existing v0.6 package publication is incomplete"
  }
  foreach ($path in @($SourceRelease, $Release, $Sidecar)) {
    if (Test-Path -LiteralPath $path) {
      $item = Get-Item -Force -LiteralPath $path
      if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "refusing to use unsafe v0.6 package publication path: $path"
      }
    }
  }
  if (-not (Test-Path -LiteralPath $SourceRelease -PathType Leaf)) {
    throw "v0.6 package source archive is missing"
  }
  if ((Get-FileHash -LiteralPath $SourceRelease -Algorithm SHA256).Hash.ToLower() -cne $ExpectedHash) {
    throw "v0.6 package source archive hash differs"
  }
  foreach ($path in @($StagedRelease, $StagedSidecar, $BackupRelease, $BackupSidecar)) {
    if (Test-Path -LiteralPath $path) {
      $item = Get-Item -Force -LiteralPath $path
      if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "refusing to use unsafe v0.6 package publication path: $path"
      }
      throw "v0.6 package transaction path already exists: $path"
    }
  }

  $expectedSidecar = "$ExpectedHash  openbexi-spell-v0.6.0.tar.gz`n"
  $releaseBackedUp = $false
  $sidecarBackedUp = $false
  $releasePublished = $false
  $sidecarPublished = $false
  try {
    Copy-Item -LiteralPath $SourceRelease -Destination $StagedRelease
    [IO.File]::WriteAllText($StagedSidecar, $expectedSidecar, [Text.Encoding]::ASCII)
    if (
      (Get-FileHash -LiteralPath $StagedRelease -Algorithm SHA256).Hash.ToLower() -cne
        $ExpectedHash -or
      [IO.File]::ReadAllText($StagedSidecar, [Text.Encoding]::ASCII) -cne
        $expectedSidecar
    ) { throw "staged v0.6 package pair differs" }

    try {
      if ($releaseExists) {
        Move-Item -LiteralPath $Release -Destination $BackupRelease
        $releaseBackedUp = $true
        Move-Item -LiteralPath $Sidecar -Destination $BackupSidecar
        $sidecarBackedUp = $true
      }
      Move-Item -LiteralPath $StagedRelease -Destination $Release
      $releasePublished = $true
      if ($TestOnlyFault -cne "None") {
        throw "injected v0.6 package publication failure"
      }
      Move-Item -LiteralPath $StagedSidecar -Destination $Sidecar
      $sidecarPublished = $true
      if (
        (Get-FileHash -LiteralPath $Release -Algorithm SHA256).Hash.ToLower() -cne
          $ExpectedHash -or
        [IO.File]::ReadAllText($Sidecar, [Text.Encoding]::ASCII) -cne
          $expectedSidecar
      ) { throw "published v0.6 package pair failed final verification" }
    }
    catch {
      $publicationFailure = $_
      $rollbackErrors = [Collections.Generic.List[string]]::new()
      if ($releasePublished -and (Test-Path -LiteralPath $Release -PathType Leaf)) {
        try {
          Remove-Item -LiteralPath $Release -Force
          $releasePublished = $false
        }
        catch { $rollbackErrors.Add("published archive cleanup failed") }
      }
      if ($sidecarPublished -and (Test-Path -LiteralPath $Sidecar -PathType Leaf)) {
        try {
          Remove-Item -LiteralPath $Sidecar -Force
          $sidecarPublished = $false
        }
        catch { $rollbackErrors.Add("published sidecar cleanup failed") }
      }
      if ($releaseBackedUp) {
        try {
          Move-Item -LiteralPath $BackupRelease -Destination $Release
          $releaseBackedUp = $false
        }
        catch { $rollbackErrors.Add("archive restore failed") }
      }
      if ($sidecarBackedUp) {
        try {
          Move-Item -LiteralPath $BackupSidecar -Destination $Sidecar
          $sidecarBackedUp = $false
        }
        catch { $rollbackErrors.Add("sidecar restore failed") }
      }
      if ($rollbackErrors.Count -ne 0) {
        throw "v0.6 package publication failed and rollback was incomplete; recovery files retained"
      }
      throw $publicationFailure
    }
    if ($releaseBackedUp) {
      Remove-Item -LiteralPath $BackupRelease -Force
      $releaseBackedUp = $false
    }
    if ($sidecarBackedUp) {
      Remove-Item -LiteralPath $BackupSidecar -Force
      $sidecarBackedUp = $false
    }
  }
  finally {
    foreach ($path in @($StagedRelease, $StagedSidecar)) {
      if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force
      }
    }
  }
}

$artifactFull = [IO.Path]::GetFullPath($artifactRoot)
$qualificationFull = [IO.Path]::GetFullPath($qualificationRoot)
$scratchFull = [IO.Path]::GetFullPath($scratchRoot)
$pathComparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  [StringComparison]::OrdinalIgnoreCase
} else {
  [StringComparison]::Ordinal
}
if (
  -not [string]::Equals(
    [IO.Path]::GetDirectoryName($qualificationFull), $artifactFull, $pathComparison
  ) -or
  -not [string]::Equals(
    [IO.Path]::GetDirectoryName($scratchFull), $qualificationFull, $pathComparison
  )
) { throw "v0.6 package scratch path escapes its owned artifact directory" }

$scratchOwned = $false
$worktreeAOwned = $false
$worktreeBOwned = $false
try {
  Assert-V05ArtifactsUnchanged
  $releaseCommit = (@(& git -C $root rev-parse --verify "HEAD^{commit}") -join "`n").Trim()
  if ($LASTEXITCODE -ne 0 -or $releaseCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw "cannot freeze the explicit v0.6 package source commit"
  }
  foreach ($path in @($artifactRoot, $qualificationRoot)) {
    if (-not (Test-Path -LiteralPath $path)) {
      New-Item -ItemType Directory -Path $path | Out-Null
    }
    $item = Get-Item -Force -LiteralPath $path
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "refusing unsafe v0.6 package scratch parent: $path"
    }
  }
  if (Test-Path -LiteralPath $scratchRoot) {
    throw "v0.6 package scratch path already exists"
  }
  New-Item -ItemType Directory -Path $scratchRoot | Out-Null
  $scratchOwned = $true
  $scratchItem = Get-Item -Force -LiteralPath $scratchRoot
  if (
    -not $scratchItem.PSIsContainer -or
    ($scratchItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    -not [string]::Equals(
      [IO.Path]::GetFullPath($scratchItem.FullName), $scratchFull, $pathComparison
    )
  ) { throw "v0.6 package scratch directory is unsafe" }

  $exportFull = [IO.Path]::GetFullPath($exportRoot)
  $tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if (-not $exportFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "v0.6 package export path escapes the temporary root"
  }
  if (Test-Path -LiteralPath $exportRoot) { throw "v0.6 package export path already exists" }
  New-Item -ItemType Directory -Path $exportRoot | Out-Null
  & git -C $root worktree add --detach $exportA $releaseCommit | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "first independent source export failed" }
  $worktreeAOwned = $true
  & git -C $root worktree add --detach $exportB $releaseCommit | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "second independent source export failed" }
  $worktreeBOwned = $true
  foreach ($export in @($exportA, $exportB)) {
    $exportCommit = (@(& git -C $export rev-parse --verify HEAD) -join "`n").Trim()
    if ($LASTEXITCODE -ne 0 -or $exportCommit -cne $releaseCommit) {
      throw "independent package export commit differs from the explicit source freeze"
    }
    Stage-AcceptedV05ExternalRelease $export
  }

  $a = Invoke-PackageBuild $exportA $exportFirst
  $b = Invoke-PackageBuild $exportB $exportSecond
  foreach ($export in @($exportA, $exportB)) {
    & (Join-Path $PSScriptRoot "assert_accepted_v05_release_v06.ps1") -Root $export | Out-Null
  }
  $firstHash = (Get-FileHash -LiteralPath $exportFirst -Algorithm SHA256).Hash.ToLower()
  $secondHash = (Get-FileHash -LiteralPath $exportSecond -Algorithm SHA256).Hash.ToLower()
  if (
    $firstHash -cne $secondHash -or
    $a.final_archive_sha256 -cne $firstHash -or
    $b.final_archive_sha256 -cne $secondHash -or
    $a.release_commit -cne $releaseCommit -or
    $a.release_commit -cne $b.release_commit -or
    $a.source_fingerprint_sha256 -cne $b.source_fingerprint_sha256 -or
    $a.evidence_fingerprint_sha256 -cne $b.evidence_fingerprint_sha256 -or
    $a.product_package_sha256 -cne $b.product_package_sha256 -or
    $a.accepted_v05_release.archive_sha256 -cne "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241" -or
    $a.accepted_v05_release.sidecar_sha256 -cne "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279" -or
    $a.accepted_v05_release.tag_object -cne "a1b277d74d2fb19062ca3e4388e9104d45c50ec4" -or
    $a.accepted_v05_release.tag_archive_claim -cne "Final archive SHA-256: cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241" -or
    ($a.accepted_v05_release | ConvertTo-Json -Compress) -cne
      ($b.accepted_v05_release | ConvertTo-Json -Compress)
  ) { throw "independent v0.6 package processes produced different results" }

  Copy-Item -LiteralPath $exportFirst -Destination $first
  Copy-Item -LiteralPath $exportSecond -Destination $second

  Publish-V06PackagePair -SourceRelease $first -StagedRelease $stagedRelease `
    -StagedSidecar $stagedSidecar -Release $release -Sidecar $sidecar `
    -BackupRelease $backupRelease -BackupSidecar $backupSidecar `
    -ExpectedHash $firstHash

  [ordered]@{
    schema_version = "spell.v06.package-publication/1"
    product_version = "0.6.0"
    release_commit = $a.release_commit
    source_fingerprint_sha256 = $a.source_fingerprint_sha256
    evidence_fingerprint_sha256 = $a.evidence_fingerprint_sha256
    product_package_sha256 = $a.product_package_sha256
    final_archive_sha256 = $firstHash
    package_build_count = 4
    independent_process_count = 2
    independent_export_count = 2
    package_byte_identical = $true
    accepted_v05_release = [ordered]@{
      archive_sha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
      sidecar_sha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
      tag_object = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
      tag_archive_claim = "Final archive SHA-256: cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
    }
    output = "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz"
  } | ConvertTo-Json -Depth 5 -Compress | Write-Output
  Assert-V05ArtifactsUnchanged
}
finally {
  if ($worktreeBOwned) {
    & git -C $root worktree remove --force $exportB | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "second package source export cleanup failed" }
    $worktreeBOwned = $false
  }
  if ($worktreeAOwned) {
    & git -C $root worktree remove --force $exportA | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "first package source export cleanup failed" }
    $worktreeAOwned = $false
  }
  if (Test-Path -LiteralPath $exportRoot) {
    $unsafeExport = Get-ChildItem -Force -Recurse -LiteralPath $exportRoot |
      Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
      Select-Object -First 1
    if ($null -ne $unsafeExport) { throw "refusing unsafe package export cleanup" }
    Remove-Item -LiteralPath $exportRoot -Recurse -Force
  }
  # A failed rollback keeps its uniquely named backup files for manual recovery.
  if ($scratchOwned -and (Test-Path -LiteralPath $scratchRoot)) {
    $scratchItem = Get-Item -Force -LiteralPath $scratchRoot
    if (
      -not $scratchItem.PSIsContainer -or
      ($scratchItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      -not [string]::Equals(
        [IO.Path]::GetFullPath($scratchItem.FullName), $scratchFull, $pathComparison
      )
    ) { throw "refusing unsafe v0.6 package scratch cleanup" }
    $unsafeChild = Get-ChildItem -Force -Recurse -LiteralPath $scratchRoot |
      Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
      Select-Object -First 1
    if ($null -ne $unsafeChild) {
      throw "refusing v0.6 package scratch cleanup containing a reparse point"
    }
    Remove-Item -LiteralPath $scratchRoot -Recurse -Force
    $scratchOwned = $false
  }
}
