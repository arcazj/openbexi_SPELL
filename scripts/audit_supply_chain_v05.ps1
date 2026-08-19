$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Get-V05Fingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v05.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "v0.5 source fingerprint failed" }
  return $value
}

function Get-V04EngineFingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v04.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "inherited audit-engine fingerprint failed" }
  return $value
}

$sourceBefore = Get-V05Fingerprint
$engineFingerprint = Get-V04EngineFingerprint
$v04DiffBefore = @(git diff --name-only -- artifacts/v0.4)
if ($LASTEXITCODE -ne 0 -or $v04DiffBefore.Count -ne 0) {
  throw "accepted v0.4 evidence was modified before the v0.5 audit"
}

$lines = @(& (Join-Path $PSScriptRoot "audit_supply_chain_v04.ps1"))
if ($LASTEXITCODE -ne 0) { throw "current-source dependency/image audit failed" }
$jsonLine = $lines | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
if (-not $jsonLine) { throw "current-source dependency/image audit emitted no JSON" }
$engineResult = $jsonLine | ConvertFrom-Json
if (
  $engineResult.test_id -cne "V04-SC-001" -or
  $engineResult.source_fingerprint_sha256 -cne $engineFingerprint -or
  [int]$engineResult.metrics.critical_finding_count -ne 0 -or
  [int]$engineResult.metrics.high_finding_count -ne 0 -or
  [int]$engineResult.metrics.unlocked_input_count -ne 0 -or
  [int]$engineResult.metrics.audited_image_count -ne 4 -or
  [int]$engineResult.metrics.compose_dependency_audited_image_count -ne 2
) { throw "current-source dependency/image audit result failed the v0.5 contract" }
if (@($engineResult.assertions | Where-Object { $_.passed -ne $true }).Count -ne 0) {
  throw "current-source dependency/image audit contains a failed assertion"
}

$sourceAfter = Get-V05Fingerprint
$v04DiffAfter = @(git diff --name-only -- artifacts/v0.4)
if ($sourceAfter -cne $sourceBefore) { throw "v0.5 source changed during supply-chain audit" }
if ($v04DiffAfter.Count -ne 0) { throw "v0.5 audit modified accepted v0.4 evidence" }

$result = [ordered]@{
  schema_version = "spell.v05.supply-chain/1"
  product_version = "0.5.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
  test_id = "V05-SC-001"
  passed = $true
  source_fingerprint_sha256 = $sourceBefore
  inherited_audit_engine = [ordered]@{
    command = "scripts/audit_supply_chain_v04.ps1"
    test_id = "V04-SC-001"
    source_fingerprint_sha256 = $engineFingerprint
    result_sha256 = (
      [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash(
          [Text.Encoding]::UTF8.GetBytes($jsonLine)
        )
      ).Replace("-", "").ToLower()
    )
  }
  assertions = @($engineResult.assertions)
  metrics = $engineResult.metrics
  accepted_v04_artifacts_unchanged = $true
}
$result | ConvertTo-Json -Depth 20 -Compress | Write-Output
