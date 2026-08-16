[CmdletBinding()]
param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$archiveRelative = "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz"
$sidecarRelative = "$archiveRelative.sha256"
$archiveSha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
$sidecarSha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
$tagObject = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
$tagCommit = "e7b6bb9428833437e0160040541eb840deee7cca"
$tagClaim = "Final archive SHA-256: $archiveSha256"
$sidecarText = "$archiveSha256  openbexi-spell-v0.5.0.tar.gz`n"

foreach ($relative in @($archiveRelative, $sidecarRelative)) {
  $path = Join-Path $rootFull $relative
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "accepted v0.5 external release input is missing: $relative"
  }
  $cursor = Get-Item -LiteralPath $path -Force
  while ($true) {
    if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "accepted v0.5 external release input contains a reparse point: $relative"
    }
    if ([string]::Equals(
      [IO.Path]::GetFullPath($cursor.FullName).TrimEnd('\', '/'),
      $rootFull,
      [StringComparison]::OrdinalIgnoreCase
    )) { break }
    $parent = Split-Path -Parent $cursor.FullName
    if (-not $parent) { throw "accepted v0.5 external release input escapes its root: $relative" }
    $cursor = Get-Item -LiteralPath $parent -Force
  }
}

$archive = Join-Path $rootFull $archiveRelative
$sidecar = Join-Path $rootFull $sidecarRelative
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $archiveSha256) {
  throw "accepted v0.5 archive SHA-256 differs"
}
if ((Get-FileHash -LiteralPath $sidecar -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sidecarSha256) {
  throw "accepted v0.5 sidecar SHA-256 differs"
}
$sidecarBytes = [IO.File]::ReadAllBytes($sidecar)
$expectedSidecarBytes = [Text.Encoding]::ASCII.GetBytes($sidecarText)
if (
  [Convert]::ToBase64String($sidecarBytes) -cne
  [Convert]::ToBase64String($expectedSidecarBytes)
) {
  throw "accepted v0.5 sidecar bytes differ"
}

$observedTagObject = (@(& git -C $rootFull show-ref --verify --hash refs/tags/v0.5.0) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $observedTagObject -cne $tagObject) {
  throw "accepted v0.5 tag object differs"
}
$observedTagType = (@(& git -C $rootFull cat-file -t $tagObject) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $observedTagType -cne "tag") {
  throw "accepted v0.5 tag is not annotated"
}
$observedTagCommit = (@(& git -C $rootFull rev-parse "refs/tags/v0.5.0^{commit}") -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $observedTagCommit -cne $tagCommit) {
  throw "accepted v0.5 tag target differs"
}
$tagLines = @(& git -C $rootFull cat-file tag $tagObject)
if ($LASTEXITCODE -ne 0) { throw "accepted v0.5 tag cannot be read" }
$archiveClaims = @($tagLines | Where-Object { $_.StartsWith("Final archive SHA-256:", [StringComparison]::Ordinal) })
if ($archiveClaims.Count -ne 1 -or $archiveClaims[0] -cne $tagClaim) {
  throw "accepted v0.5 tag final-archive claim differs"
}

[ordered]@{
  archive_path = $archiveRelative
  archive_sha256 = $archiveSha256
  sidecar_path = $sidecarRelative
  sidecar_sha256 = $sidecarSha256
  tag_object = $tagObject
  tag_commit = $tagCommit
  tag_archive_claim = $tagClaim
} | ConvertTo-Json -Compress
