$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$auditNonce = [guid]::NewGuid().ToString("N")
$auditImageTag = "openbexi_spell-supply-chain-audit:$auditNonce"
$currentInputImageTag = "openbexi_spell-supply-chain-current-input:$auditNonce"

Push-Location $root
try {
  docker build --pull=false --build-arg "AUDIT_NONCE=$auditNonce" `
    -f scripts/supply-chain.Dockerfile -t $auditImageTag .
  if ($LASTEXITCODE -ne 0) { throw "Supply-chain audit failed" }
  $auditImage = (docker image inspect $auditImageTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $auditImage) {
    throw "Supply-chain audit image ID lookup failed"
  }

  $fingerprintOutput = @(
    docker run --rm --network none $auditImage
  )
  if ($LASTEXITCODE -ne 0) { throw "Supply-chain audit fingerprint failed" }
  $sourceFingerprint = $fingerprintOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $sourceFingerprint) { throw "Supply-chain audit fingerprint was invalid" }

  docker build --pull=false -f scripts/package.Dockerfile `
    -t $currentInputImageTag . | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Current supply-chain input image build failed" }
  $currentInputImage = (
    docker image inspect $currentInputImageTag --format "{{.Id}}"
  ).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $currentInputImage) {
    throw "Current supply-chain input image ID lookup failed"
  }
  $currentFingerprintOutput = @(
    docker run --rm --network none --entrypoint python $currentInputImage `
      scripts/source_fingerprint.py --root /workspace
  )
  if ($LASTEXITCODE -ne 0) { throw "Current supply-chain fingerprint failed" }
  $currentFingerprint = $currentFingerprintOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $currentFingerprint -or $currentFingerprint -cne $sourceFingerprint) {
    throw "Source changed while supply-chain audits were running"
  }
  Write-Output $sourceFingerprint
}
finally {
  Pop-Location
}
