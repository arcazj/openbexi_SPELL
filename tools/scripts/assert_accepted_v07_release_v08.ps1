[CmdletBinding()]
param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$tagRef = "refs/tags/v0.7.0"
$tagObject = "70e4d46a46d158dee3c63ec37a5d1922b3b61668"
$rawTagSha256 = "dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae"
$tagCommit = "cf18e9d887ba0476cbcc3d8194e321332a3ae864"
$archiveSha256 = "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
$sidecarSha256 = "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
$validator = Join-Path $PSScriptRoot "accepted_v07_release_v08.py"

if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
  throw "accepted v0.7 canonical validator is missing"
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "accepted v0.7 canonical validation requires the locked release toolchain"
}
$pythonPath = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)

$output = @(
  & $pythonPath -I $validator --root ([IO.Path]::GetFullPath($Root))
)
if ($LASTEXITCODE -ne 0) {
  throw "accepted v0.7 canonical validation failed"
}
if ($output.Count -ne 1) {
  throw "accepted v0.7 canonical validator returned an ambiguous result"
}
try {
  $binding = $output[0] | ConvertFrom-Json -ErrorAction Stop
} catch {
  throw "accepted v0.7 canonical validator returned invalid JSON"
}

if (
  [string]$binding.tag_ref -cne $tagRef -or
  [string]$binding.tag_object -cne $tagObject -or
  [string]$binding.raw_tag_object_sha256 -cne $rawTagSha256 -or
  [string]$binding.tag_commit -cne $tagCommit -or
  [string]$binding.archive_sha256 -cne $archiveSha256 -or
  [string]$binding.sidecar_sha256 -cne $sidecarSha256
) {
  throw "accepted v0.7 canonical validator returned a different binding"
}

$output[0]
