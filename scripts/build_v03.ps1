param(
  [switch]$RunQualification
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactDirectory = Join-Path $root "artifacts"
$releasePackage = Join-Path $artifactDirectory "openbexi-spell-v0.3.tar.gz"
$releaseSidecar = "${releasePackage}.sha256"
$postgresTestDatabaseCreated = $false
$originalCi = [Environment]::GetEnvironmentVariable("CI", "Process")
$originalRealBackend = [Environment]::GetEnvironmentVariable("SPELL_REAL_BACKEND", "Process")
$originalE2eToken = [Environment]::GetEnvironmentVariable("SPELL_E2E_TOKEN", "Process")
$packageRunId = "$PID-$([guid]::NewGuid().ToString('N'))"
$temporaryPackages = @()
$temporarySidecar = $null
$releasePublished = $false

function Remove-CanonicalReleaseOutputs {
  $artifactDirectoryFull = [IO.Path]::GetFullPath($artifactDirectory)
  foreach ($canonicalOutput in @($releaseSidecar, $releasePackage)) {
    $canonicalOutputFull = [IO.Path]::GetFullPath($canonicalOutput)
    if ([IO.Path]::GetDirectoryName($canonicalOutputFull) -cne $artifactDirectoryFull) {
      throw "Refusing to invalidate a release output outside artifacts: $canonicalOutputFull"
    }
    if (Test-Path -LiteralPath $canonicalOutput) {
      if ((Get-Item -LiteralPath $canonicalOutput).PSIsContainer) {
        throw "Canonical release output is not a file: $canonicalOutputFull"
      }
      Remove-Item -LiteralPath $canonicalOutput -Force
    }
  }
}

Remove-CanonicalReleaseOutputs

foreach ($command in @("docker", "node", "npm", "npx")) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "The v0.3 release gate requires '$command' on PATH"
  }
}

Push-Location $root
try {
  docker compose build --pull=false
  if ($LASTEXITCODE -ne 0) { throw "Container build failed" }

  docker run --rm --network none -e PYTHONDONTWRITEBYTECODE=1 `
    openbexi_spell-backend:latest python -m pytest backend/tests -q
  if ($LASTEXITCODE -ne 0) { throw "SQLite backend tests failed" }

  docker compose up -d --wait postgres
  if ($LASTEXITCODE -ne 0) { throw "PostgreSQL test service failed to become healthy" }
  docker compose exec -T postgres sh -ec `
    'dropdb --if-exists --force -U "$POSTGRES_USER" spell_migration_test && createdb -U "$POSTGRES_USER" spell_migration_test'
  if ($LASTEXITCODE -ne 0) { throw "Dedicated PostgreSQL test database setup failed" }
  $postgresTestDatabaseCreated = $true
  docker compose run --rm --no-deps backend sh -ec `
    'export SPELL_TEST_DATABASE_URL="${DATABASE_URL%/*}/spell_migration_test"; export SPELL_MIGRATION_TEST_DATABASE_URL="$SPELL_TEST_DATABASE_URL"; python -m pytest backend/tests -q'
  if ($LASTEXITCODE -ne 0) { throw "PostgreSQL backend and migration tests failed" }

  docker run --rm --network none --add-host backend:127.0.0.1 --entrypoint sh `
    openbexi_spell-proxy:latest -lc "test -s /usr/share/nginx/html/index.html && nginx -t"
  if ($LASTEXITCODE -ne 0) { throw "Proxy artifact validation failed" }

  Push-Location (Join-Path $root "frontend")
  try {
    npm ci --ignore-scripts --no-audit
    if ($LASTEXITCODE -ne 0) { throw "Frontend dependency installation failed" }
    npm test
    if ($LASTEXITCODE -ne 0) { throw "Frontend unit tests failed" }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "Frontend production build failed" }
    $chromiumExecutable = node -p "require('playwright').chromium.executablePath()"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $chromiumExecutable)) {
      throw "Frontend E2E requires the Playwright Chromium browser (run 'npx playwright install chromium')"
    }

    $env:CI = "true"
    Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
    Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
    npx playwright test e2e/auth.spec.ts e2e/console.spec.ts
    if ($LASTEXITCODE -ne 0) { throw "Mocked frontend E2E tests failed" }
  }
  finally {
    Pop-Location
  }

  docker compose up -d --wait backend proxy
  if ($LASTEXITCODE -ne 0) { throw "Real E2E stack failed to become healthy" }
  $tokenOutput = @(
    docker compose run --rm --no-deps -e SPELL_ALLOW_LOCAL_DEV_TOKEN=true backend `
      python /app/scripts/issue_dev_token.py --subject v03-release-e2e --role admin --lifetime 900
  )
  if ($LASTEXITCODE -ne 0) { throw "Could not issue the short-lived real E2E token" }
  $e2eToken = $tokenOutput |
    Where-Object { $_ -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' } |
    Select-Object -Last 1
  if (-not $e2eToken) { throw "Real E2E token output was not a JWT" }

  Push-Location (Join-Path $root "frontend")
  try {
    $env:SPELL_REAL_BACKEND = "true"
    $env:SPELL_E2E_TOKEN = $e2eToken
    npx playwright test e2e/integration.spec.ts
    if ($LASTEXITCODE -ne 0) { throw "Real backend/frontend E2E tests failed" }
  }
  finally {
    Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
    $e2eToken = $null
    $tokenOutput = $null
    Pop-Location
  }

  if ($RunQualification) {
    & (Join-Path $PSScriptRoot "qualify_release.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Release qualification failed" }
  }

  $auditOutput = @(& (Join-Path $PSScriptRoot "audit_supply_chain.ps1"))
  if ($LASTEXITCODE -ne 0) { throw "Supply-chain audit failed" }
  $auditFingerprint = $auditOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $auditFingerprint) { throw "Supply-chain audit fingerprint was invalid" }
  & (Join-Path $PSScriptRoot "generate_sbom.ps1")
  if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed" }
  $firstSbomManifest = Get-Content -Raw (Join-Path $root "artifacts/sbom/SHA256SUMS")
  & (Join-Path $PSScriptRoot "generate_sbom.ps1")
  if ($LASTEXITCODE -ne 0) { throw "Second SBOM generation failed" }
  $secondSbomManifest = Get-Content -Raw (Join-Path $root "artifacts/sbom/SHA256SUMS")
  if ($firstSbomManifest -cne $secondSbomManifest) {
    throw "Normalized SBOM generation is not reproducible"
  }

  New-Item -ItemType Directory -Force $artifactDirectory | Out-Null
  $packageInputTag = "openbexi_spell-package-input:$packageRunId"
  docker build --pull=false -f scripts/package.Dockerfile -t $packageInputTag .
  if ($LASTEXITCODE -ne 0) { throw "Package input image build failed" }
  $packageInputImage = (docker image inspect $packageInputTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $packageInputImage) {
    throw "Package input image ID lookup failed"
  }

  docker run --rm --network none --entrypoint python $packageInputImage `
    -m unittest discover -s scripts/tests -p "test_*.py"
  if ($LASTEXITCODE -ne 0) { throw "Release packaging tool tests failed" }

  $validationOutput = @(
    docker run --rm --network none --entrypoint python $packageInputImage `
      scripts/build_reproducible.py --root /workspace --validate-only
  )
  if ($LASTEXITCODE -ne 0) {
    if (-not $RunQualification) {
      throw "Qualification evidence is missing, stale, failed, or inconsistent. Run this gate again with -RunQualification."
    }
    throw "New qualification evidence does not match the immutable package input"
  }
  $packageFingerprint = $validationOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $packageFingerprint -or $packageFingerprint -cne $auditFingerprint) {
    throw "Supply-chain audit input does not match the validated package input"
  }

  $packageHashes = @()
  foreach ($suffix in @("a", "b")) {
    $packageContainer = "openbexi-spell-package-$PID-$suffix"
    $temporaryPackage = Join-Path $artifactDirectory `
      "openbexi-spell-v0.3-$packageRunId-$suffix.tar.gz"
    $temporaryPackages += $temporaryPackage
    try {
      docker create --name $packageContainer --network none $packageInputImage | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Packaging container creation failed" }
      docker start -a $packageContainer
      if ($LASTEXITCODE -ne 0) { throw "Reproducible packaging failed" }
      docker cp "${packageContainer}:/tmp/openbexi-spell-v0.3.tar.gz" $temporaryPackage
      if ($LASTEXITCODE -ne 0) { throw "Release artifact copy failed" }
      $packageHashes += (Get-FileHash $temporaryPackage -Algorithm SHA256).Hash.ToLower()
    }
    finally {
      docker rm -f $packageContainer 2>$null | Out-Null
    }
  }
  if ($packageHashes[0] -ne $packageHashes[1]) {
    throw "Reproducible package hashes differ"
  }

  $currentPackageInputTag = "openbexi_spell-package-current-input:$packageRunId"
  docker build --pull=false -f scripts/package.Dockerfile -t $currentPackageInputTag .
  if ($LASTEXITCODE -ne 0) { throw "Current package input image build failed" }
  $currentPackageInputImage = (
    docker image inspect $currentPackageInputTag --format "{{.Id}}"
  ).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $currentPackageInputImage) {
    throw "Current package input image ID lookup failed"
  }
  $currentPackageContainer = "openbexi-spell-package-$PID-current"
  $currentTemporaryPackage = Join-Path $artifactDirectory `
    "openbexi-spell-v0.3-$packageRunId-current.tar.gz"
  $temporaryPackages += $currentTemporaryPackage
  try {
    docker create --name $currentPackageContainer --network none `
      $currentPackageInputImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Current packaging container creation failed" }
    docker start -a $currentPackageContainer
    if ($LASTEXITCODE -ne 0) { throw "Current-context packaging failed" }
    docker cp "${currentPackageContainer}:/tmp/openbexi-spell-v0.3.tar.gz" `
      $currentTemporaryPackage
    if ($LASTEXITCODE -ne 0) { throw "Current release artifact copy failed" }
    $currentPackageHash = (
      Get-FileHash $currentTemporaryPackage -Algorithm SHA256
    ).Hash.ToLower()
  }
  finally {
    docker rm -f $currentPackageContainer 2>$null | Out-Null
  }
  if ($currentPackageHash -ne $packageHashes[0]) {
    throw "Package input changed while release artifacts were being built"
  }

  Move-Item -Force $temporaryPackages[0] $releasePackage
  Remove-Item -Force $temporaryPackages[1]
  Remove-Item -Force $temporaryPackages[2]
  $temporarySidecar = "${releasePackage}.sha256.tmp-$packageRunId"
  "$($packageHashes[0])  openbexi-spell-v0.3.tar.gz" |
    Set-Content -Encoding ascii $temporarySidecar
  Move-Item -Force $temporarySidecar $releaseSidecar
  $temporarySidecar = $null
  $releasePublished = $true
}
finally {
  if (-not $releasePublished) {
    Remove-CanonicalReleaseOutputs
  }
  foreach ($temporaryPackage in $temporaryPackages) {
    if (Test-Path -LiteralPath $temporaryPackage) {
      Remove-Item -LiteralPath $temporaryPackage -Force
    }
  }
  if ($temporarySidecar -and (Test-Path -LiteralPath $temporarySidecar)) {
    Remove-Item -LiteralPath $temporarySidecar -Force
  }
  if ($postgresTestDatabaseCreated) {
    docker compose exec -T postgres sh -ec `
      'dropdb --if-exists --force -U "$POSTGRES_USER" spell_migration_test' 2>$null
  }
  if ($null -eq $originalCi) {
    Remove-Item Env:CI -ErrorAction SilentlyContinue
  }
  else {
    $env:CI = $originalCi
  }
  if ($null -eq $originalRealBackend) {
    Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
  }
  else {
    $env:SPELL_REAL_BACKEND = $originalRealBackend
  }
  if ($null -eq $originalE2eToken) {
    Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
  }
  else {
    $env:SPELL_E2E_TOKEN = $originalE2eToken
  }
  Pop-Location
}
