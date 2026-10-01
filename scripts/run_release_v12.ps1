param(
  [Parameter(Mandatory=$true)][string]$Module,
  [string[]]$Arguments = @()
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$lock = Get-Content (Join-Path $root 'scripts/release-toolchain-v12.json') -Raw | ConvertFrom-Json
$python = $null
foreach ($tool in $lock.tools) {
  $base = [Environment]::GetEnvironmentVariable($tool.base_directory)
  $path = Join-Path $base $tool.relative_path
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $tool.sha256) {
    throw "v0.12 tool hash differs: $($tool.name)"
  }
  if ($tool.name -ceq 'python') { $python = $path }
}
if (-not $python) { throw 'Pinned Python is missing' }
& $python -I -c 'import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module(sys.argv.pop(1),run_name=sys.argv.pop(1))' $root $Module __main__ @Arguments
if ($LASTEXITCODE -ne 0) { throw "v0.12 command failed: $Module" }
