[CmdletBinding()]
param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$tagRef = "refs/tags/v0.6.0"
$tagObject = "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919"
$rawTagSha256 = "b08b3e66b0018a6f559b696cdd478b639f5ecbabc750b9049c85a8f8a17dd8a4"
$tagCommit = "05ec783a6e54a76e0548bdd536c18538f6bff51b"
$archiveSha256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
$sidecarSha256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
$validator = Join-Path $PSScriptRoot "accepted_v06_release_v07.py"

if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
  throw "accepted v0.6 canonical validator is missing"
}
$pythonPath = $null
[string[]]$pythonPrefix = @()
foreach ($candidate in @(
  [pscustomobject]@{ Name = "py"; Prefix = @("-3") },
  [pscustomobject]@{ Name = "python3"; Prefix = @() },
  [pscustomobject]@{ Name = "python"; Prefix = @() }
)) {
  $command = Get-Command $candidate.Name -CommandType Application `
    -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $command) { continue }
  $probe = @(& $command.Source @($candidate.Prefix) -c "import sys; print(sys.version_info[0])" 2>&1)
  if ($LASTEXITCODE -eq 0 -and $probe.Count -eq 1 -and $probe[0] -eq "3") {
    $pythonPath = $command.Source
    [string[]]$pythonPrefix = @($candidate.Prefix)
    break
  }
}
if (-not $pythonPath) {
  throw "accepted v0.6 canonical validation requires Python 3"
}

$output = @(
  & $pythonPath @pythonPrefix $validator --root ([IO.Path]::GetFullPath($Root))
)
if ($LASTEXITCODE -ne 0) {
  throw "accepted v0.6 canonical validation failed"
}
if ($output.Count -ne 1) {
  throw "accepted v0.6 canonical validator returned an ambiguous result"
}
try {
  $binding = $output[0] | ConvertFrom-Json -ErrorAction Stop
} catch {
  throw "accepted v0.6 canonical validator returned invalid JSON"
}

if (
  [string]$binding.tag_ref -cne $tagRef -or
  [string]$binding.tag_object -cne $tagObject -or
  [string]$binding.raw_tag_object_sha256 -cne $rawTagSha256 -or
  [string]$binding.tag_commit -cne $tagCommit -or
  [string]$binding.archive_sha256 -cne $archiveSha256 -or
  [string]$binding.sidecar_sha256 -cne $sidecarSha256
) {
  throw "accepted v0.6 canonical validator returned a different binding"
}

$output[0]
