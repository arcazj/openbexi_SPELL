param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$LocalConfirmation,
  [switch]$Replace,
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$QualificationImageId
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runId = [guid]::NewGuid().ToString("N")
$project = "spell-v04-reg-$runId"
$qualificationTag = "openbexi-spell-v04-regression:$runId"
$containers = [Collections.Generic.List[string]]::new()
$outputVolumes = [Collections.Generic.List[string]]::new()
$containerVolumes = @{}
$commands = [ordered]@{}
$failure = $null
$composeStarted = $false
$resourcesTornDown = $false
$qualificationImageOwned = $false

if ($LocalConfirmation -cne "LOCAL_SYNTHETIC_NON_CUI_ONLY") {
  throw "V04-REG-001 requires the exact local synthetic non-CUI confirmation"
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
  $pythonExe = $py.Source
  $pythonPrefix = @("-3.9")
}
elseif (Test-Path -LiteralPath (Join-Path $root ".venv/Scripts/python.exe")) {
  $pythonExe = Join-Path $root ".venv/Scripts/python.exe"
  $pythonPrefix = @()
}
else {
  throw "V04-REG-001 requires a local Python interpreter for the standard-library collector"
}
$collectorScript = Join-Path $root "scripts/collect_regression_v04.py"
$fingerprintScript = Join-Path $root "scripts/source_fingerprint_v04.py"

function Invoke-CollectorPython {
  param([Parameter(Mandatory = $true)][string[]]$PythonArguments)
  & $pythonExe @pythonPrefix @PythonArguments
}

function Get-SourceFingerprint {
  $lines = @(
    Invoke-CollectorPython @($fingerprintScript, "--root", $root)
  )
  if ($LASTEXITCODE -ne 0) { throw "v0.4 source fingerprint failed" }
  $value = $lines |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $value) { throw "v0.4 source fingerprint output is invalid" }
  return $value
}

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  }
  finally {
    $listener.Stop()
  }
}

function Get-LowerSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Invoke-RecordedCommand {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][scriptblock]$Action
  )
  if ($commands.Contains($Id)) { throw "duplicate regression command id: $Id" }
  $stdoutRelative = "logs/$Id.stdout.log"
  $stderrRelative = "logs/$Id.stderr.log"
  $stdoutPath = Join-Path $captureRoot $stdoutRelative
  $stderrPath = Join-Path $captureRoot $stderrRelative
  [IO.File]::WriteAllBytes($stdoutPath, [byte[]]@())
  [IO.File]::WriteAllBytes($stderrPath, [byte[]]@())
  $code = 0
  $savedPreference = $ErrorActionPreference
  try {
    $global:LASTEXITCODE = 0
    $ErrorActionPreference = "Continue"
    & $Action 1> $stdoutPath 2> $stderrPath
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
  }
  catch {
    $code = 1
    [IO.File]::AppendAllText(
      $stderrPath,
      "$($_.Exception.GetType().FullName): $($_.Exception.Message)`n",
      [Text.UTF8Encoding]::new($false)
    )
  }
  finally {
    $ErrorActionPreference = $savedPreference
  }
  $commands[$Id] = [ordered]@{
    return_code = [int]$code
    stdout_path = $stdoutRelative
    stdout_sha256 = Get-LowerSha256 $stdoutPath
    stderr_path = $stderrRelative
    stderr_sha256 = Get-LowerSha256 $stderrPath
  }
  if ($code -ne 0) {
    Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue | Write-Host
    Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue | Write-Host
    throw "V04-REG-001 command failed: $Id"
  }
}

function New-QualificationContainer {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Network,
    [Parameter(Mandatory = $true)][string[]]$Environment,
    [Parameter(Mandatory = $true)][string[]]$Command
  )
  $arguments = @(
    "create", "--name", $Name,
    "--label", "com.docker.compose.project=$project", "--network", $Network,
    "--read-only", "--tmpfs", "/tmp:size=512m,noexec,nosuid"
  )
  $outputVolume = "$Name-output"
  docker volume create --label "com.docker.compose.project=$project" `
    $outputVolume | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "could not create qualification output volume: $outputVolume"
  }
  $outputVolumes.Add($outputVolume)
  $containerVolumes[$Name] = $outputVolume
  $arguments += @(
    "--mount", "type=volume,source=$outputVolume,target=/qualification-output"
  )
  foreach ($entry in $Environment) { $arguments += @("-e", $entry) }
  $arguments += @($qualificationImage)
  $arguments += $Command
  docker @arguments | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not create qualification container: $Name" }
  $containers.Add($Name)
}

function Invoke-DockerCleanupCommand {
  param([Parameter(Mandatory = $true)][string[]]$DockerArguments)
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(docker @DockerArguments 2>$null)
    $exitCode = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $savedPreference
  }
  return [pscustomobject]@{
    ExitCode = [int]$exitCode
    Lines = [string[]]@($lines | ForEach-Object { [string]$_ })
  }
}

function Copy-ContainerCapture {
  param(
    [Parameter(Mandatory = $true)][string]$Container,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $outputVolume = $containerVolumes[$Container]
  if (-not $outputVolume) { throw "qualification output volume is missing: $Container" }
  $copyContainer = "$Container-copy"
  docker create --name $copyContainer `
    --label "com.docker.compose.project=$project" --network none --read-only `
    --mount "type=volume,source=$outputVolume,target=/qualification-output,readonly" `
    --entrypoint sleep $qualificationImage 60 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not create capture copy container: $Name" }
  $containers.Add($copyContainer)
  try {
    docker start $copyContainer | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not start capture copy container: $Name" }
    docker cp "${copyContainer}:/qualification-output/$Name" `
      (Join-Path $captureRoot $Name) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not copy regression capture: $Name" }
  }
  finally {
    Invoke-DockerCleanupCommand @("rm", "-f", $copyContainer) | Out-Null
  }
}

function Restore-EnvironmentVariable {
  param([string]$Name, [AllowNull()][string]$Value)
  if ($null -eq $Value) {
    Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
  }
  else {
    Set-Item "Env:$Name" $Value
  }
}

foreach ($command in @("docker", "node", "npm", "npx")) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "V04-REG-001 requires '$command' on PATH"
  }
}

Push-Location $root
try {
  $sourceBefore = Get-SourceFingerprint
  $captureRoot = Join-Path $root `
    "artifacts/v0.4/.qualification/runtime-captures/$sourceBefore/regression"
  $expectedParent = [IO.Path]::GetFullPath(
    (Join-Path $root "artifacts/v0.4/.qualification/runtime-captures/$sourceBefore")
  ).TrimEnd('\', '/')
  $captureFull = [IO.Path]::GetFullPath($captureRoot)
  if (
    [IO.Path]::GetDirectoryName($captureFull).TrimEnd('\', '/') -cne $expectedParent -or
    [IO.Path]::GetFileName($captureFull) -cne "regression"
  ) { throw "refusing unsafe regression capture root: $captureFull" }
  if (Test-Path -LiteralPath $captureRoot) {
    if (-not $Replace) { throw "regression capture already exists; pass -Replace to rerun" }
    $item = Get-Item -LiteralPath $captureRoot -Force
    if (-not $item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "regression capture root is not a regular directory"
    }
    Remove-Item -LiteralPath $captureRoot -Recurse -Force
  }
  New-Item -ItemType Directory -Path (Join-Path $captureRoot "logs") | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $captureRoot "screenshots") | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $captureRoot "playwright-mocked") | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $captureRoot "playwright-real") | Out-Null

  $inventoryPath = Join-Path $captureRoot ".accepted-inventory.json"
  Invoke-CollectorPython @(
    $collectorScript, "--root", $root,
    "--inventory-output", $inventoryPath
  )
  if ($LASTEXITCODE -ne 0) { throw "accepted v0.3 test inventory failed" }
  $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
  Remove-Item -LiteralPath $inventoryPath -Force
  $backendPaths = @(
    $inventory.python.PSObject.Properties |
      Where-Object { $_.Name.StartsWith("backend/tests/") } |
      ForEach-Object { $_.Name }
  )
  $toolingPaths = @(
    $inventory.python.PSObject.Properties |
      Where-Object { $_.Name.StartsWith("scripts/tests/") } |
      ForEach-Object { $_.Name }
  )
  $frontendUnitPaths = @(
    $inventory.frontend_unit.PSObject.Properties |
      ForEach-Object { $_.Name.Substring("frontend/".Length) }
  )
  if ($backendPaths.Count -eq 0 -or $toolingPaths.Count -eq 0 -or $frontendUnitPaths.Count -eq 0) {
    throw "accepted v0.3 inventory did not yield every executable suite"
  }

  Invoke-RecordedCommand "qualification-image-build" {
    if ($QualificationImageId) {
      $resolvedQualificationImage = (
        docker image inspect $QualificationImageId --format "{{.Id}}"
      ).Trim()
      if (
        $LASTEXITCODE -ne 0 -or
        $resolvedQualificationImage -cne $QualificationImageId
      ) { throw "external qualification image identity differs" }
    }
    else {
      docker build --pull=false --provenance=false `
        --label "com.docker.compose.project=$project" `
        -f scripts/qualification.Dockerfile -t $qualificationTag .
    }
  }
  if ($QualificationImageId) {
    $qualificationImage = $QualificationImageId
  }
  else {
    $qualificationImageOwned = $true
    $qualificationImage = (
      docker image inspect $qualificationTag --format "{{.Id}}"
    ).Trim()
  }
  if ($LASTEXITCODE -ne 0 -or $qualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "qualification image identity is invalid"
  }
  Invoke-RecordedCommand "qualification-runtime" {
    docker run --rm --network none --read-only --entrypoint python `
      $qualificationImage --version
  }
  $qualificationPython = (
    Get-Content -LiteralPath (Join-Path $captureRoot "logs/qualification-runtime.stdout.log") -Raw
  ).Trim()
  if ($qualificationPython -cnotmatch '^Python 3\.13\.\d+$') {
    throw "qualification image does not use Python 3.13.x"
  }

  $sqliteContainer = "spell-v04-reg-sqlite-$runId"
  $sqliteCommand = @(
    "python", "-m", "pytest"
  ) + $backendPaths + @(
    "-q", "--junitxml=/qualification-output/backend-sqlite.xml"
  )
  New-QualificationContainer -Name $sqliteContainer -Network "none" `
    -Environment @("PYTHONDONTWRITEBYTECODE=1") -Command $sqliteCommand
  Invoke-RecordedCommand "backend-sqlite" { docker start -a $sqliteContainer }
  Copy-ContainerCapture $sqliteContainer "backend-sqlite.xml"

  $priorDbPassword = $env:SPELL_DB_PASSWORD
  $priorJwtSecret = $env:SPELL_JWT_HS256_SECRET
  $priorDriverEnabled = $env:SPELL_DRIVER_ENABLED
  $priorProxyPort = $env:SPELL_PROXY_PORT
  $env:SPELL_DB_PASSWORD = "synthetic-regression-database-$runId"
  $env:SPELL_JWT_HS256_SECRET = "synthetic-regression-jwt-secret-$runId-material"
  $env:SPELL_DRIVER_ENABLED = "false"
  $env:SPELL_PROXY_PORT = [string](Get-FreeLoopbackPort)

  $composeStarted = $true
  Invoke-RecordedCommand "postgres-prepare" {
    docker compose -p $project -f compose.yaml up -d --wait postgres
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL did not become healthy" }
    docker compose -p $project -f compose.yaml exec -T postgres sh -ec `
      'dropdb --if-exists --force -U "$POSTGRES_USER" spell_migration_test && createdb -U "$POSTGRES_USER" spell_migration_test'
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL regression database setup failed" }
  }
  $postgresUrl = "postgresql+psycopg://spell:$($env:SPELL_DB_PASSWORD)@postgres:5432/spell_migration_test"
  $postgresContainer = "spell-v04-reg-postgres-$runId"
  $postgresCommand = @(
    "python", "-m", "pytest"
  ) + $backendPaths + @(
    "-q", "--junitxml=/qualification-output/backend-postgresql.xml"
  )
  New-QualificationContainer -Name $postgresContainer `
    -Network "${project}_spell-internal" -Environment @(
      "PYTHONDONTWRITEBYTECODE=1",
      "SPELL_TEST_DATABASE_URL=$postgresUrl",
      "SPELL_MIGRATION_TEST_DATABASE_URL=$postgresUrl"
    ) -Command $postgresCommand
  Invoke-RecordedCommand "backend-postgresql" { docker start -a $postgresContainer }
  Copy-ContainerCapture $postgresContainer "backend-postgresql.xml"

  $toolingContainer = "spell-v04-reg-tooling-$runId"
  $toolingCommand = @(
    "python", "-m", "pytest"
  ) + $toolingPaths + @(
    "-q", "--junitxml=/qualification-output/tooling.xml"
  )
  New-QualificationContainer -Name $toolingContainer -Network "none" `
    -Environment @("PYTHONDONTWRITEBYTECODE=1") -Command $toolingCommand
  Invoke-RecordedCommand "tooling" { docker start -a $toolingContainer }
  Copy-ContainerCapture $toolingContainer "tooling.xml"

  Push-Location (Join-Path $root "frontend")
  try {
    Invoke-RecordedCommand "frontend-install" {
      npm ci --ignore-scripts --no-audit
    }
    $frontendUnitOutput = Join-Path $captureRoot "frontend-unit.json"
    Invoke-RecordedCommand "frontend-unit" {
      npx vitest run @frontendUnitPaths --reporter=json --outputFile=$frontendUnitOutput
    }
    Invoke-RecordedCommand "frontend-build" { npm run build }
    Copy-Item -LiteralPath (Join-Path $root "frontend/dist") `
      -Destination (Join-Path $captureRoot "frontend-dist") -Recurse

    $chromiumExecutable = node -p "require('playwright').chromium.executablePath()"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $chromiumExecutable)) {
      throw "Playwright Chromium is unavailable"
    }
    $nodeVersion = (node --version).Trim()
    $playwrightVersion = (node -p "require('@playwright/test/package.json').version").Trim()
    $chromiumVersion = (
      node -e "const {chromium}=require('playwright');(async()=>{const b=await chromium.launch({headless:true});console.log(b.version());await b.close();})().catch(e=>{console.error(e);process.exit(1)})"
    ).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $chromiumVersion) {
      throw "could not identify the Playwright Chromium runtime"
    }

    $savedCi = $env:CI
    $savedReal = $env:SPELL_REAL_BACKEND
    $savedToken = $env:SPELL_E2E_TOKEN
    $savedBase = $env:SPELL_E2E_BASE_URL
    $savedPreview = $env:SPELL_E2E_PREVIEW_PORT
    $savedJunit = $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE
    $savedArtifact = $env:SPELL_E2E_ARTIFACT_DIRECTORY
    $savedOutput = $env:SPELL_E2E_OUTPUT_DIRECTORY
    try {
      $mockPort = Get-FreeLoopbackPort
      $env:CI = "true"
      Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
      Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
      $env:SPELL_E2E_PREVIEW_PORT = [string]$mockPort
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:$mockPort"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = Join-Path $captureRoot "browser-mocked.xml"
      $env:SPELL_E2E_ARTIFACT_DIRECTORY = Join-Path $captureRoot "screenshots"
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "playwright-mocked"
      Invoke-RecordedCommand "browser-mocked" {
        npx playwright test e2e/auth.spec.ts e2e/console.spec.ts `
          --reporter=junit --retries=0
      }

      Pop-Location
      Invoke-RecordedCommand "compose-runtime" {
        docker compose -p $project -f compose.yaml up -d --build --wait backend proxy
      }
      Push-Location (Join-Path $root "frontend")
      $tokenOutput = @(
        docker compose -p $project -f (Join-Path $root "compose.yaml") run --rm --no-deps `
          -e SPELL_ALLOW_LOCAL_DEV_TOKEN=true backend `
          python /app/scripts/issue_dev_token.py `
          --subject v04-regression-browser --role admin --lifetime 900
      )
      if ($LASTEXITCODE -ne 0) { throw "could not issue the short-lived browser token" }
      $e2eToken = $tokenOutput |
        Where-Object { $_ -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' } |
        Select-Object -Last 1
      $tokenOutput = $null
      if (-not $e2eToken) { throw "browser token output was not a JWT" }
      $env:SPELL_REAL_BACKEND = "true"
      $env:SPELL_E2E_TOKEN = $e2eToken
      $env:SPELL_E2E_BASE_URL = "http://127.0.0.1:$($env:SPELL_PROXY_PORT)"
      $env:PLAYWRIGHT_JUNIT_OUTPUT_FILE = Join-Path $captureRoot "browser-real.xml"
      $env:SPELL_E2E_OUTPUT_DIRECTORY = Join-Path $captureRoot "playwright-real"
      Invoke-RecordedCommand "browser-real" {
        npx playwright test e2e/integration.spec.ts --reporter=junit --retries=0
      }
      $e2eToken = $null
    }
    finally {
      Restore-EnvironmentVariable "CI" $savedCi
      Restore-EnvironmentVariable "SPELL_REAL_BACKEND" $savedReal
      Restore-EnvironmentVariable "SPELL_E2E_TOKEN" $savedToken
      Restore-EnvironmentVariable "SPELL_E2E_BASE_URL" $savedBase
      Restore-EnvironmentVariable "SPELL_E2E_PREVIEW_PORT" $savedPreview
      Restore-EnvironmentVariable "PLAYWRIGHT_JUNIT_OUTPUT_FILE" $savedJunit
      Restore-EnvironmentVariable "SPELL_E2E_ARTIFACT_DIRECTORY" $savedArtifact
      Restore-EnvironmentVariable "SPELL_E2E_OUTPUT_DIRECTORY" $savedOutput
    }
  }
  finally {
    if ((Get-Location).Path -cne $root) { Pop-Location }
  }

  Invoke-RecordedCommand "proxy-artifact" {
    docker compose -p $project -f compose.yaml exec -T proxy sh -ec `
      'test -s /usr/share/nginx/html/index.html && nginx -t'
  }

  foreach ($profile in @("quick", "soak")) {
    $container = "spell-v04-reg-legacy-$profile-$runId"
    $name = "legacy-$profile.json"
    New-QualificationContainer -Name $container -Network "none" `
      -Environment @("PYTHONDONTWRITEBYTECODE=1") -Command @(
        "python", "/qualification-source/scripts/qualify_v03.py", "--$profile",
        "--output", "/qualification-output/$name"
      )
    Invoke-RecordedCommand "legacy-$profile" { docker start -a $container }
    Copy-ContainerCapture $container $name
  }

  Invoke-RecordedCommand "legacy-browser-stream" {
    & (Join-Path $PSScriptRoot "qualify_browser_stream.ps1") `
      -Image $qualificationImage `
      -OutputPath (Join-Path $captureRoot "legacy-browser-stream.json")
    if ($LASTEXITCODE -ne 0) { throw "legacy browser stream qualification failed" }
  }

  $sourceAfter = Get-SourceFingerprint
  if ($sourceAfter -cne $sourceBefore) {
    throw "source changed while V04-REG-001 was running"
  }
}
catch {
  $failure = $_
}
finally {
  $cleanupFailures = [Collections.Generic.List[string]]::new()
  foreach ($name in $containers) {
    Invoke-DockerCleanupCommand @("rm", "-f", $name) | Out-Null
    $inspection = Invoke-DockerCleanupCommand @("inspect", $name)
    if ($inspection.ExitCode -eq 0) {
      $cleanupFailures.Add("tracked container remains: $name")
    }
  }
  foreach ($name in $outputVolumes) {
    Invoke-DockerCleanupCommand @("volume", "rm", "-f", $name) | Out-Null
    $inspection = Invoke-DockerCleanupCommand @("volume", "inspect", $name)
    if ($inspection.ExitCode -eq 0) {
      $cleanupFailures.Add("qualification output volume remains: $name")
    }
  }
  if ($composeStarted) {
    $down = Invoke-DockerCleanupCommand @(
      "compose", "-p", $project, "-f", (Join-Path $root "compose.yaml"),
      "down", "--rmi", "local", "-v", "--remove-orphans"
    )
    if ($down.ExitCode -ne 0) {
      $cleanupFailures.Add("docker compose down failed")
    }
  }
  if ($qualificationImageOwned) {
    Invoke-DockerCleanupCommand @("image", "rm", $qualificationTag) | Out-Null
    $inspection = Invoke-DockerCleanupCommand @("image", "inspect", $qualificationTag)
    if ($inspection.ExitCode -eq 0) {
      $cleanupFailures.Add("qualification image tag remains")
    }
  }
  $resourceQueries = [ordered]@{
    containers = @("ps", "-aq", "--filter", "label=com.docker.compose.project=$project")
    networks = @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
    volumes = @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
    images = @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
  }
  foreach ($entry in $resourceQueries.GetEnumerator()) {
    $queryArguments = [string[]]$entry.Value
    $query = Invoke-DockerCleanupCommand $queryArguments
    $remaining = @($query.Lines | Where-Object { $_ })
    if ($query.ExitCode -ne 0) {
      $cleanupFailures.Add("could not verify remaining project $($entry.Key)")
    }
    elseif ($remaining.Count -ne 0) {
      $cleanupFailures.Add("project $($entry.Key) remain after teardown")
    }
  }
  $resourcesTornDown = $cleanupFailures.Count -eq 0
  if (-not $resourcesTornDown) {
    $cleanupMessage = "V04-REG-001 teardown verification failed: $($cleanupFailures -join '; ')"
    if ($failure) {
      $failure = [InvalidOperationException]::new("$($failure.Exception.Message); $cleanupMessage")
    }
    else {
      $failure = [InvalidOperationException]::new($cleanupMessage)
    }
  }
  if (Get-Variable priorDbPassword -ErrorAction SilentlyContinue) {
    Restore-EnvironmentVariable "SPELL_DB_PASSWORD" $priorDbPassword
    Restore-EnvironmentVariable "SPELL_JWT_HS256_SECRET" $priorJwtSecret
    Restore-EnvironmentVariable "SPELL_DRIVER_ENABLED" $priorDriverEnabled
    Restore-EnvironmentVariable "SPELL_PROXY_PORT" $priorProxyPort
  }
  Pop-Location
}

if ($failure) { throw $failure }

$captureNames = @(
  "backend-sqlite.xml",
  "backend-postgresql.xml",
  "tooling.xml",
  "frontend-unit.json",
  "browser-mocked.xml",
  "browser-real.xml",
  "legacy-quick.json",
  "legacy-soak.json",
  "legacy-browser-stream.json"
)
$captureHashes = [ordered]@{}
foreach ($name in $captureNames) {
  $path = Join-Path $captureRoot $name
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "required regression capture is missing: $name"
  }
  $captureHashes[$name] = Get-LowerSha256 $path
}

$screenshotNames = @(
  "desktop-as-run-report.png",
  "desktop-v03-validation.png",
  "mobile-recovered-prompt.png",
  "session-access.png"
)
$screenshotHashes = [ordered]@{}
foreach ($name in $screenshotNames) {
  $path = Join-Path $captureRoot "screenshots/$name"
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "required regression screenshot is missing: $name"
  }
  $screenshotHashes[$name] = Get-LowerSha256 $path
}

$buildLines = @(
  Invoke-CollectorPython @(
    $collectorScript, "--root", $root,
    "--tree-root", (Join-Path $captureRoot "frontend-dist")
  )
)
if ($LASTEXITCODE -ne 0) { throw "frontend build capture hashing failed" }
$frontendBuild = $buildLines[-1] | ConvertFrom-Json
$dockerServerPlatform = (docker version --format "{{.Server.Os}}/{{.Server.Arch}}").Trim()
if ($LASTEXITCODE -ne 0 -or -not $dockerServerPlatform) {
  throw "Docker server platform lookup failed"
}

$manifest = [ordered]@{
  schema_version = "spell.v04.regression-run/1"
  product_version = "0.4.0"
  scope_profile = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
  source_fingerprint_before_sha256 = $sourceBefore
  source_fingerprint_after_sha256 = $sourceAfter
  qualification_image_id = $qualificationImage
  accepted_baseline = [ordered]@{
    tag = "v0.3.0"
    commit = "7bccbb4eb096b22d0d1f2f765d5172f6dde244f1"
    inventory_sha256 = $inventory.sha256
  }
  runtime = [ordered]@{
    qualification_python = $qualificationPython
    node = $nodeVersion
    playwright = $playwrightVersion
    chromium = $chromiumVersion
    docker_server_platform = $dockerServerPlatform
    short_lived_browser_token_discarded = $true
    isolated_runtime_resources_torn_down = $resourcesTornDown
  }
  commands = $commands
  captures = $captureHashes
  screenshots = $screenshotHashes
  frontend_build = [ordered]@{
    file_count = [int]$frontendBuild.file_count
    sha256 = [string]$frontendBuild.sha256
  }
  proxy_artifact_validated = $true
}
$manifestJson = $manifest | ConvertTo-Json -Compress -Depth 100
[IO.File]::WriteAllText(
  (Join-Path $captureRoot "run.json"),
  $manifestJson,
  [Text.UTF8Encoding]::new($false)
)

$resultLines = @(
  Invoke-CollectorPython @(
    $collectorScript, "--root", $root,
    "--capture-root", $captureRoot
  )
)
if ($LASTEXITCODE -ne 0 -or $resultLines.Count -eq 0) {
  throw "V04-REG-001 collector rejected the live regression captures"
}
Write-Output $resultLines[-1]
