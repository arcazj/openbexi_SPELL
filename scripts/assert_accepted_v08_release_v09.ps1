[CmdletBinding()]
param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$tagRef = "refs/tags/v0.8.0"
$tagObject = "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae"
$rawTagSha256 = "c609c25cb8987222df0b143f71aa792140171acffd454e31a760c16fb263eede"
$tagCommit = "d6e01222de3bf52013279e48a099b6ae7ded121d"
$artifactTree = "899dd791fbfd5aa8720c3ce836d5cc2208bac6b9"
$archiveSha256 = "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
$sidecarSha256 = "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
$validator = Join-Path $PSScriptRoot "accepted_v08_release_v09.py"

if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
  throw "accepted v0.8 canonical validator is missing"
}

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "accepted v0.8 canonical validation requires the locked release toolchain"
}
$pythonPath = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)

$output = @(
  & $pythonPath -I $validator --root ([IO.Path]::GetFullPath($Root))
)
if ($LASTEXITCODE -ne 0) {
  throw "accepted v0.8 canonical validation failed"
}
if ($output.Count -ne 1) {
  throw "accepted v0.8 canonical validator returned an ambiguous result"
}
try {
  $binding = $output[0] | ConvertFrom-Json -ErrorAction Stop
} catch {
  throw "accepted v0.8 canonical validator returned invalid JSON"
}

if (
  [string]$binding.tag_ref -cne $tagRef -or
  [string]$binding.tag_object -cne $tagObject -or
  [string]$binding.raw_tag_object_sha256 -cne $rawTagSha256 -or
  [string]$binding.tag_commit -cne $tagCommit -or
  [string]$binding.artifact_tree -cne $artifactTree -or
  [string]$binding.archive_sha256 -cne $archiveSha256 -or
  [string]$binding.sidecar_sha256 -cne $sidecarSha256
) {
  throw "accepted v0.8 canonical validator returned a different binding"
}

$output[0]
