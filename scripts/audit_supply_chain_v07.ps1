$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Get-V07Fingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v07.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "v0.7 source fingerprint failed" }
  return $value
}

function Get-V04EngineFingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v04.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "inherited audit-engine fingerprint failed" }
  return $value
}

$sourceBefore = Get-V07Fingerprint
$engineFingerprint = Get-V04EngineFingerprint
$v06Tree = @(& git rev-parse "HEAD:artifacts/v0.6") -join "`n"
$v06DiffBefore = @(git diff --name-only -- artifacts/v0.6)
$v06StatusBefore = @(git status --porcelain --untracked-files=all -- artifacts/v0.6)
if (
  $LASTEXITCODE -ne 0 -or $v06DiffBefore.Count -ne 0 -or $v06StatusBefore.Count -ne 0 -or
  $v06Tree.Trim() -cne "18cb672a45c538539f78278962ea5822b9f52441"
) {
  throw "accepted v0.6 evidence was modified before the v0.7 audit"
}
& git diff --quiet v0.6.0 HEAD -- artifacts/v0.6
if ($LASTEXITCODE -ne 0) { throw "accepted v0.6 evidence differs from v0.6.0" }
& (Join-Path $PSScriptRoot "assert_accepted_v06_release_v07.ps1") -Root $root | Out-Null

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
) { throw "current-source dependency/image audit result failed the v0.7 contract" }
if (@($engineResult.assertions | Where-Object { $_.passed -ne $true }).Count -ne 0) {
  throw "current-source dependency/image audit contains a failed assertion"
}

$sourceAfter = Get-V07Fingerprint
$v06DiffAfter = @(git diff --name-only -- artifacts/v0.6)
$v06StatusAfter = @(git status --porcelain --untracked-files=all -- artifacts/v0.6)
if ($sourceAfter -cne $sourceBefore) { throw "v0.7 source changed during supply-chain audit" }
if ($v06DiffAfter.Count -ne 0 -or $v06StatusAfter.Count -ne 0) { throw "v0.7 audit modified accepted v0.6 evidence" }
& (Join-Path $PSScriptRoot "assert_accepted_v06_release_v07.ps1") -Root $root | Out-Null

$result = [ordered]@{
  schema_version = "spell.v07.supply-chain/1"
  product_version = "0.7.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
  test_id = "V07-SC-001"
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
  accepted_v06_artifacts_unchanged = $true
  accepted_v06_release = [ordered]@{
    archive_sha256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
    sidecar_sha256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
    tag_object = "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919"
    tag_archive_claim = "Final archive SHA-256: b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
  }
}
$result | ConvertTo-Json -Depth 20 -Compress | Write-Output
