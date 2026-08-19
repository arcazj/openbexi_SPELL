$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1")
if ($LASTEXITCODE -ne 0) { throw "inherited release toolchain validation failed" }
$PythonExe = $env:SPELL_RELEASE_PYTHON_EXE

function Get-V06Fingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v06.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "v0.6 source fingerprint failed" }
  return $value
}

function Get-V04EngineFingerprint {
  $value = @(& $PythonExe (Join-Path $PSScriptRoot "source_fingerprint_v04.py") --root $root) |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } | Select-Object -Last 1
  if (-not $value -or $LASTEXITCODE -ne 0) { throw "inherited audit-engine fingerprint failed" }
  return $value
}

$sourceBefore = Get-V06Fingerprint
$engineFingerprint = Get-V04EngineFingerprint
$v05Tree = @(& git rev-parse "HEAD:artifacts/v0.5") -join "`n"
$v05DiffBefore = @(git diff --name-only -- artifacts/v0.5)
$v05StatusBefore = @(git status --porcelain --untracked-files=all -- artifacts/v0.5)
if (
  $LASTEXITCODE -ne 0 -or $v05DiffBefore.Count -ne 0 -or $v05StatusBefore.Count -ne 0 -or
  $v05Tree.Trim() -cne "27542ec5db41ff29ba2af62824c8d39f442b95e8"
) {
  throw "accepted v0.5 evidence was modified before the v0.6 audit"
}
& git diff --quiet v0.5.0 HEAD -- artifacts/v0.5
if ($LASTEXITCODE -ne 0) { throw "accepted v0.5 evidence differs from v0.5.0" }
& (Join-Path $PSScriptRoot "assert_accepted_v05_release_v06.ps1") -Root $root | Out-Null

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
) { throw "current-source dependency/image audit result failed the v0.6 contract" }
if (@($engineResult.assertions | Where-Object { $_.passed -ne $true }).Count -ne 0) {
  throw "current-source dependency/image audit contains a failed assertion"
}

$sourceAfter = Get-V06Fingerprint
$v05DiffAfter = @(git diff --name-only -- artifacts/v0.5)
$v05StatusAfter = @(git status --porcelain --untracked-files=all -- artifacts/v0.5)
if ($sourceAfter -cne $sourceBefore) { throw "v0.6 source changed during supply-chain audit" }
if ($v05DiffAfter.Count -ne 0 -or $v05StatusAfter.Count -ne 0) { throw "v0.6 audit modified accepted v0.5 evidence" }
& (Join-Path $PSScriptRoot "assert_accepted_v05_release_v06.ps1") -Root $root | Out-Null

$result = [ordered]@{
  schema_version = "spell.v06.supply-chain/1"
  product_version = "0.6.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
  test_id = "V06-SC-001"
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
  accepted_v05_artifacts_unchanged = $true
  accepted_v05_release = [ordered]@{
    archive_sha256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
    sidecar_sha256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
    tag_object = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
    tag_archive_claim = "Final archive SHA-256: cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
  }
}
$result | ConvertTo-Json -Depth 20 -Compress | Write-Output
