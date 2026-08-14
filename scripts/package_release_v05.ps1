$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts/v0.5"
$release = Join-Path $artifactRoot "openbexi-spell-v0.5.0.tar.gz"
$sidecar = "$release.sha256"
$runId = [guid]::NewGuid().ToString("N")
$first = Join-Path $artifactRoot ".package-a-$runId.tar.gz"
$second = Join-Path $artifactRoot ".package-b-$runId.tar.gz"
$stagedRelease = Join-Path $artifactRoot ".openbexi-spell-v0.5.0.tar.gz.staging-$runId"
$stagedSidecar = "$stagedRelease.sha256"

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Invoke-PackageBuild([string]$OutputPath) {
  $lines = @(& $PythonExe (Join-Path $PSScriptRoot "build_reproducible_v05.py") `
    --root $root --output $OutputPath)
  if ($LASTEXITCODE -ne 0) { throw "v0.5 deterministic package build failed" }
  $jsonLine = $lines | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
  if (-not $jsonLine) { throw "v0.5 deterministic package build emitted no JSON" }
  return $jsonLine | ConvertFrom-Json
}

New-Item -ItemType Directory -Force $artifactRoot | Out-Null
try {
  $a = Invoke-PackageBuild $first
  $b = Invoke-PackageBuild $second
  $firstHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash.ToLower()
  $secondHash = (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash.ToLower()
  if (
    $firstHash -cne $secondHash -or
    $a.final_archive_sha256 -cne $firstHash -or
    $b.final_archive_sha256 -cne $secondHash -or
    $a.release_commit -cne $b.release_commit -or
    $a.source_fingerprint_sha256 -cne $b.source_fingerprint_sha256 -or
    $a.evidence_fingerprint_sha256 -cne $b.evidence_fingerprint_sha256 -or
    $a.product_package_sha256 -cne $b.product_package_sha256
  ) { throw "independent v0.5 package processes produced different results" }

  Copy-Item -LiteralPath $first -Destination $stagedRelease
  [IO.File]::WriteAllText(
    $stagedSidecar,
    "$firstHash  openbexi-spell-v0.5.0.tar.gz`n",
    [Text.Encoding]::ASCII
  )
  if ((Get-FileHash -LiteralPath $stagedRelease -Algorithm SHA256).Hash.ToLower() -cne $firstHash) {
    throw "staged v0.5 package hash differs"
  }
  Move-Item -Force -LiteralPath $stagedRelease -Destination $release
  Move-Item -Force -LiteralPath $stagedSidecar -Destination $sidecar
  if (
    (Get-FileHash -LiteralPath $release -Algorithm SHA256).Hash.ToLower() -cne $firstHash -or
    [IO.File]::ReadAllText($sidecar, [Text.Encoding]::ASCII) -cne
      "$firstHash  openbexi-spell-v0.5.0.tar.gz`n"
  ) { throw "published v0.5 package pair failed verification" }

  [ordered]@{
    schema_version = "spell.v05.package-publication/1"
    product_version = "0.5.0"
    release_commit = $a.release_commit
    source_fingerprint_sha256 = $a.source_fingerprint_sha256
    evidence_fingerprint_sha256 = $a.evidence_fingerprint_sha256
    product_package_sha256 = $a.product_package_sha256
    final_archive_sha256 = $firstHash
    package_build_count = 4
    independent_process_count = 2
    package_byte_identical = $true
    output = "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz"
  } | ConvertTo-Json -Depth 5 -Compress | Write-Output
}
finally {
  foreach ($path in @(
    $first, "$first.sha256", $second, "$second.sha256", $stagedRelease, $stagedSidecar
  )) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      Remove-Item -LiteralPath $path -Force
    }
  }
}
