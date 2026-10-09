param(
  [Parameter(Mandatory=$true)][string]$Module,
  [string[]]$Arguments = @()
)
$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot 'run_release_next.ps1') -Module $Module -Arguments $Arguments
if ($LASTEXITCODE -ne 0) { throw "v0.19.1 command failed: $Module" }
