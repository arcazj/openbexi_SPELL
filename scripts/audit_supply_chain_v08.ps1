$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Get-V08Fingerprint {
  $value = @(& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v08.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "v0.8 source fingerprint failed" }
  return $value
}

function Get-V04EngineFingerprint {
  $value = @(& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v04.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "inherited audit-engine fingerprint failed" }
  return $value
}

$sourceBefore = Get-V08Fingerprint
$engineFingerprint = Get-V04EngineFingerprint
$v07Tree = @(& git rev-parse "HEAD:artifacts/v0.7") -join "`n"
$v07DiffBefore = @(git diff --name-only -- artifacts/v0.7)
$v07StatusBefore = @(git status --porcelain --untracked-files=all -- artifacts/v0.7)
if (
  $LASTEXITCODE -ne 0 -or $v07DiffBefore.Count -ne 0 -or $v07StatusBefore.Count -ne 0 -or
  $v07Tree.Trim() -cne "b6b4a9239e36eaea61da8e7d87cc5bffecfd064f"
) {
  throw "accepted v0.7 evidence was modified before the v0.8 audit"
}
& git diff --quiet v0.7.0 HEAD -- artifacts/v0.7
if ($LASTEXITCODE -ne 0) { throw "accepted v0.7 evidence differs from v0.7.0" }
& (Join-Path $PSScriptRoot "assert_accepted_v07_release_v08.ps1") -Root $root | Out-Null

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
) { throw "current-source dependency/image audit result failed the v0.8 contract" }
if (@($engineResult.assertions | Where-Object { $_.passed -ne $true }).Count -ne 0) {
  throw "current-source dependency/image audit contains a failed assertion"
}

$sourceAfter = Get-V08Fingerprint
$v07DiffAfter = @(git diff --name-only -- artifacts/v0.7)
$v07StatusAfter = @(git status --porcelain --untracked-files=all -- artifacts/v0.7)
if ($sourceAfter -cne $sourceBefore) { throw "v0.8 source changed during supply-chain audit" }
if ($v07DiffAfter.Count -ne 0 -or $v07StatusAfter.Count -ne 0) { throw "v0.8 audit modified accepted v0.7 evidence" }
& (Join-Path $PSScriptRoot "assert_accepted_v07_release_v08.ps1") -Root $root | Out-Null

$result = [ordered]@{
  schema_version = "spell.v08.supply-chain/1"
  product_version = "0.8.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE"
  test_id = "V08-SC-001"
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
  accepted_v07_artifacts_unchanged = $true
  accepted_v07_release = [ordered]@{
    archive_sha256 = "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
    sidecar_sha256 = "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
    tag_object = "70e4d46a46d158dee3c63ec37a5d1922b3b61668"
    tag_archive_claim = "Final archive SHA-256: 90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
  }
}
$result | ConvertTo-Json -Depth 20 -Compress | Write-Output
