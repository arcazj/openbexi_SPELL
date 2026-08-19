$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Get-V09Fingerprint {
  $value = @(& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v09.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "v0.9 source fingerprint failed" }
  return $value
}

function Get-V04EngineFingerprint {
  $value = @(& $PythonExe -I (Join-Path $PSScriptRoot "source_fingerprint_v04.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "inherited audit-engine fingerprint failed" }
  return $value
}

$sourceBefore = Get-V09Fingerprint
$engineFingerprint = Get-V04EngineFingerprint
$v08Tree = @(& git rev-parse "HEAD:artifacts/v0.8") -join "`n"
$v08DiffBefore = @(git diff --name-only -- artifacts/v0.8)
$v08StatusBefore = @(git status --porcelain --untracked-files=all -- artifacts/v0.8)
if (
  $LASTEXITCODE -ne 0 -or $v08DiffBefore.Count -ne 0 -or $v08StatusBefore.Count -ne 0 -or
  $v08Tree.Trim() -cne "899dd791fbfd5aa8720c3ce836d5cc2208bac6b9"
) {
  throw "accepted v0.8 evidence was modified before the v0.9 audit"
}
& git diff --quiet v0.8.0 HEAD -- artifacts/v0.8
if ($LASTEXITCODE -ne 0) { throw "accepted v0.8 evidence differs from v0.8.0" }
& (Join-Path $PSScriptRoot "assert_accepted_v08_release_v09.ps1") -Root $root | Out-Null

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
) { throw "current-source dependency/image audit result failed the v0.9 contract" }
if (@($engineResult.assertions | Where-Object { $_.passed -ne $true }).Count -ne 0) {
  throw "current-source dependency/image audit contains a failed assertion"
}

$sourceAfter = Get-V09Fingerprint
$v08DiffAfter = @(git diff --name-only -- artifacts/v0.8)
$v08StatusAfter = @(git status --porcelain --untracked-files=all -- artifacts/v0.8)
if ($sourceAfter -cne $sourceBefore) { throw "v0.9 source changed during supply-chain audit" }
if ($v08DiffAfter.Count -ne 0 -or $v08StatusAfter.Count -ne 0) { throw "v0.9 audit modified accepted v0.8 evidence" }
& (Join-Path $PSScriptRoot "assert_accepted_v08_release_v09.ps1") -Root $root | Out-Null

$result = [ordered]@{
  schema_version = "spell.v09.supply-chain/1"
  product_version = "0.9.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
  test_id = "V09-SC-001"
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
  accepted_v08_artifacts_unchanged = $true
  accepted_v08_release = [ordered]@{
    archive_sha256 = "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
    sidecar_sha256 = "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
    tag_object = "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae"
    tag_archive_claim = "Final archive SHA-256: 87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
  }
}
$result | ConvertTo-Json -Depth 20 -Compress | Write-Output
