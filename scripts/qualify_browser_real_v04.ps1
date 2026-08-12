param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("LOCAL_SYNTHETIC_NON_CUI_ONLY")]
  [string]$Confirm,
  [string]$PythonExecutable,
  [ValidatePattern('^sha256:[0-9a-f]{64}$')]
  [string]$QualificationImageId
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runId = [guid]::NewGuid().ToString("N")
$runStartedAtUtc = [DateTime]::UtcNow.ToString(
  "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
  [Globalization.CultureInfo]::InvariantCulture
)
$project = "spell-v04-browser-$PID-$($runId.Substring(0, 8))"
$qualificationTag = "openbexi-spell-v04-browser-qualification:$runId"
$failure = $null
$resultJson = $null
$priorEnvironment = @{}
$environmentNames = @(
  "CI", "SPELL_ALLOW_LOCAL_DEV_TOKEN", "SPELL_BACKEND_IMAGE_ID",
  "SPELL_BROWSER_CAPTURE_DIRECTORY", "SPELL_BROWSER_RUN_ID",
  "SPELL_BROWSER_SECRET_CANARY", "SPELL_DB_PASSWORD", "SPELL_DRIVER_ENABLED",
  "SPELL_DRIVER_IMAGE_ID", "SPELL_E2E_BASE_URL", "SPELL_E2E_TOKEN",
  "SPELL_JWT_HS256_SECRET", "SPELL_PKI_IMAGE_ID", "SPELL_POSTGRES_IMAGE_ID",
  "SPELL_PROXY_IMAGE_ID", "SPELL_PROXY_PORT", "SPELL_QUALIFICATION_IMAGE_ID",
  "SPELL_NPM_VERSION",
  "SPELL_REAL_BACKEND", "SPELL_RELEASE_BUILDX_EXE", "SPELL_RELEASE_COMPOSE_EXE",
  "SPELL_RELEASE_DOCKER_EXE", "SPELL_RELEASE_PYTHON_EXE", "SPELL_RELEASE_SBOM_EXE",
  "SPELL_RELEASE_SCOUT_EXE", "SPELL_SOURCE_FINGERPRINT"
)
foreach ($name in $environmentNames) {
  $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Assert-NativeSuccess([string]$message) {
  if ($LASTEXITCODE -ne 0) { throw $message }
}

function Invoke-DockerCleanupCommand {
  param([Parameter(Mandatory = $true)][string[]]$DockerArguments)
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:BrowserDockerExecutable @DockerArguments 2>$null)
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

function Invoke-ComposeCleanupCommand {
  param([Parameter(Mandatory = $true)][string[]]$ComposeArguments)
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $script:BrowserComposeExecutable @ComposeArguments 2>$null)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  return [pscustomobject]@{
    ExitCode = [int]$exitCode
    Lines = [string[]]@($lines | ForEach-Object { [string]$_ })
  }
}

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  }
  finally { $listener.Stop() }
}

function Get-ComposeImageId([string]$service) {
  $container = @(
    & $script:BrowserComposeExecutable -p $project --profile driver -f compose.yaml `
      ps -a -q $service
  ) | Where-Object { $_.Trim() } | Select-Object -Last 1
  Assert-NativeSuccess "cannot resolve the $service qualification container"
  if (-not $container) { throw "the $service qualification container is missing" }
  $image = (& $script:BrowserDockerExecutable inspect --format "{{.Image}}" $container).Trim()
  Assert-NativeSuccess "cannot resolve the $service image identity"
  if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "the $service image identity is invalid"
  }
  return $image
}

function Assert-NoProjectResources {
  $queries = [ordered]@{
    containers = @("ps", "-aq", "--filter", "label=com.docker.compose.project=$project")
    networks = @("network", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
    volumes = @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
    images = @("image", "ls", "-q", "--filter", "label=com.docker.compose.project=$project")
  }
  foreach ($entry in $queries.GetEnumerator()) {
    $query = Invoke-DockerCleanupCommand ([string[]]$entry.Value)
    if ($query.ExitCode -ne 0) {
      throw "cannot inspect residual browser qualification $($entry.Key)"
    }
    if (@($query.Lines | Where-Object { $_.Trim() }).Count -ne 0) {
      throw "browser qualification left Compose project $($entry.Key)"
    }
  }
}

foreach ($command in @("node", "npm", "npx")) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "browser qualification requires $command on PATH"
  }
}
$composeTouched = $false
$runtimeCleanupComplete = $false
$qualificationImageOwned = $false
$script:BrowserDockerExecutable = $null
$script:BrowserComposeExecutable = $null
Push-Location $root
try {
  & (Join-Path $PSScriptRoot "assert_release_toolchain_v04.ps1") | Out-Null
  $script:BrowserDockerExecutable = [IO.Path]::GetFullPath($env:SPELL_RELEASE_DOCKER_EXE)
  $script:BrowserComposeExecutable = [IO.Path]::GetFullPath($env:SPELL_RELEASE_COMPOSE_EXE)
  $lockedPythonExecutable = [IO.Path]::GetFullPath($env:SPELL_RELEASE_PYTHON_EXE)
  if ($PythonExecutable) {
    $declaredPythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)
    if ($declaredPythonExecutable -cne $lockedPythonExecutable) {
      throw "browser qualification Python executable differs from the release lock"
    }
  }
  $PythonExecutable = $lockedPythonExecutable

  $npmVersion = @(& npm --version) -join "`n"
  Assert-NativeSuccess "cannot read the browser qualification npm version"
  if ($npmVersion -cne "11.6.2") {
    throw "browser qualification npm version differs from the approved environment"
  }

  $captureDirectory = [IO.Path]::GetFullPath(
    (Join-Path $root "artifacts/v0.4/browser")
  )
  if (Test-Path -LiteralPath $captureDirectory) {
    $captureItem = Get-Item -LiteralPath $captureDirectory -Force
    if (
      -not $captureItem.PSIsContainer -or
      ($captureItem.Attributes -band [IO.FileAttributes]::ReparsePoint)
    ) { throw "browser capture directory is unsafe" }
    Get-ChildItem -LiteralPath $captureDirectory -Force | ForEach-Object {
      if ($_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "browser capture directory contains an unsafe entry"
      }
      Remove-Item -LiteralPath $_.FullName -Force
    }
  }
  else { New-Item -ItemType Directory -Path $captureDirectory | Out-Null }

  $fingerprintLines = @(& $PythonExecutable scripts/source_fingerprint_v04.py --root $root)
  Assert-NativeSuccess "cannot compute the v0.4 source fingerprint"
  $source = $fingerprintLines |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if (-not $source) { throw "v0.4 source fingerprint output is invalid" }

  $env:SPELL_DB_PASSWORD = "v04-browser-db-$runId"
  $env:SPELL_JWT_HS256_SECRET = "spell-v04-service-secret-$source"
  $env:SPELL_BROWSER_SECRET_CANARY = $env:SPELL_JWT_HS256_SECRET
  $env:SPELL_DRIVER_ENABLED = "true"
  $env:SPELL_ALLOW_LOCAL_DEV_TOKEN = "true"
  $env:SPELL_PROXY_PORT = [string](Get-FreeLoopbackPort)
  $env:SPELL_BROWSER_CAPTURE_DIRECTORY = $captureDirectory
  $env:SPELL_BROWSER_RUN_ID = $runId
  $env:SPELL_NPM_VERSION = $npmVersion
  $env:SPELL_SOURCE_FINGERPRINT = $source
  $env:CI = "true"

  if ($QualificationImageId) {
    $qualificationImage = (
      & $script:BrowserDockerExecutable image inspect $QualificationImageId --format "{{.Id}}"
    ).Trim()
    Assert-NativeSuccess "external browser qualification image lookup failed"
    if ($qualificationImage -cne $QualificationImageId) {
      throw "external browser qualification image identity differs"
    }
  }
  else {
    & $script:BrowserDockerExecutable build --pull=false --provenance=false `
      --label "com.docker.compose.project=$project" `
      -f scripts/qualification.Dockerfile -t $qualificationTag .
    Assert-NativeSuccess "browser qualification image build failed"
    $qualificationImageOwned = $true
    $qualificationImage = (
      & $script:BrowserDockerExecutable image inspect $qualificationTag --format "{{.Id}}"
    ).Trim()
    Assert-NativeSuccess "browser qualification image lookup failed"
  }
  if ($qualificationImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "browser qualification image identity is invalid"
  }

  $composeTouched = $true
  & $script:BrowserComposeExecutable -p $project --profile driver -f compose.yaml `
    up -d --build --wait
  Assert-NativeSuccess "browser qualification Compose stack failed to become healthy"

  $env:SPELL_BACKEND_IMAGE_ID = Get-ComposeImageId "backend"
  $env:SPELL_DRIVER_IMAGE_ID = Get-ComposeImageId "spell-driver"
  $env:SPELL_PKI_IMAGE_ID = Get-ComposeImageId "pki-init"
  $env:SPELL_POSTGRES_IMAGE_ID = Get-ComposeImageId "postgres"
  $env:SPELL_PROXY_IMAGE_ID = Get-ComposeImageId "proxy"
  $env:SPELL_QUALIFICATION_IMAGE_ID = $qualificationImage

  $tokenLines = @(
    & $script:BrowserComposeExecutable -p $project --profile driver -f compose.yaml `
      exec -T backend `
      python /app/scripts/issue_dev_token.py `
      --subject v04-browser-viewer --role viewer --lifetime 600
  )
  Assert-NativeSuccess "browser qualification viewer token issuance failed"
  $token = $tokenLines |
    Where-Object { $_ -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' } |
    Select-Object -Last 1
  if (-not $token) { throw "viewer token output is invalid" }

  $headers = @{ Authorization = "Bearer $token" }
  $baseUrl = "http://127.0.0.1:$($env:SPELL_PROXY_PORT)"
  $ready = $false
  $deadline = (Get-Date).AddSeconds(45)
  do {
    try {
      $projection = Invoke-RestMethod -Headers $headers -Uri "$baseUrl/api/v1/drivers"
      $ready = @($projection.items | Where-Object { $_.ready -eq $true }).Count -eq 1
    }
    catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Milliseconds 250 }
  } until ($ready -or (Get-Date) -ge $deadline)
  if (-not $ready) { throw "the simulator driver did not become ready for browser qualification" }

  $backendContainer = @(
    & $script:BrowserComposeExecutable -p $project --profile driver -f compose.yaml `
      ps -q backend
  ) | Where-Object { $_.Trim() } | Select-Object -Last 1
  Assert-NativeSuccess "cannot resolve the browser backend container"
  $backendInspection = & $script:BrowserDockerExecutable inspect $backendContainer | ConvertFrom-Json
  Assert-NativeSuccess "cannot inspect the browser backend container"
  $databaseNetwork = @($backendInspection[0].NetworkSettings.Networks.PSObject.Properties.Name) |
    Where-Object { $_ -like '*spell-internal' } |
    Select-Object -First 1
  if (-not $databaseNetwork) { throw "cannot resolve the internal database network" }
  $databaseUrl = "postgresql+psycopg://spell:$($env:SPELL_DB_PASSWORD)@postgres:5432/spell"
  & $script:BrowserDockerExecutable run --rm --network $databaseNetwork --read-only `
    --tmpfs /tmp:size=256m,noexec,nosuid `
    -e "DATABASE_URL=$databaseUrl" `
    $qualificationImage python scripts/seed_driver_projection_v04.py `
    --confirm $Confirm
  Assert-NativeSuccess "canonical browser projection seed failed"

  Push-Location (Join-Path $root "frontend")
  try {
    npm run build
    Assert-NativeSuccess "browser qualification frontend build failed"
    $env:SPELL_REAL_BACKEND = "true"
    $env:SPELL_E2E_BASE_URL = $baseUrl
    $env:SPELL_E2E_TOKEN = $token
    npx playwright test e2e/driver-projection-real.spec.ts `
      --project=chromium --project=mobile
    Assert-NativeSuccess "real backend driver projection browser qualification failed"

    Remove-Item Env:SPELL_REAL_BACKEND -ErrorAction SilentlyContinue
    Remove-Item Env:SPELL_E2E_BASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:SPELL_E2E_TOKEN -ErrorAction SilentlyContinue
    $token = $null
    $tokenLines = $null
    npx playwright test e2e/driver-projection.spec.ts `
      --project=chromium --project=mobile
    Assert-NativeSuccess "driver projection fault-state browser qualification failed"
  }
  finally { Pop-Location }

  $afterLines = @(& $PythonExecutable scripts/source_fingerprint_v04.py --root $root)
  Assert-NativeSuccess "cannot recompute the v0.4 source fingerprint"
  $after = $afterLines |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  if ($after -cne $source) { throw "source changed during browser qualification" }

  $down = Invoke-ComposeCleanupCommand @(
    "-p", $project, "--profile", "driver", "-f", "compose.yaml",
    "down", "--rmi", "local", "-v", "--remove-orphans"
  )
  if ($down.ExitCode -ne 0) {
    throw "browser qualification Compose teardown failed"
  }
  if ($qualificationImageOwned) {
    Invoke-DockerCleanupCommand @("image", "rm", $qualificationTag) | Out-Null
    $qualificationInspection = Invoke-DockerCleanupCommand @(
      "image", "inspect", $qualificationTag
    )
    if ($qualificationInspection.ExitCode -eq 0) {
      throw "browser qualification image tag remains"
    }
  }
  Assert-NoProjectResources
  $composeTouched = $false
  $runtimeCleanupComplete = $true

  $runFinishedAtUtc = [DateTime]::UtcNow.ToString(
    "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
    [Globalization.CultureInfo]::InvariantCulture
  )
  $publicationLines = @(
    & $PythonExecutable scripts/qualify_browser_v04.py `
      --root $root `
      --observation-dir $captureDirectory `
      --publish-provenance `
      --run-id $runId `
      --started-at-utc $runStartedAtUtc `
      --finished-at-utc $runFinishedAtUtc `
      --docker-executable $script:BrowserDockerExecutable `
      --compose-executable $script:BrowserComposeExecutable `
      --python-executable $PythonExecutable `
      --replace
  )
  Assert-NativeSuccess "browser provenance publication failed"
  $publicationJson = $publicationLines |
    Where-Object { $_ -cmatch '^\{.*\}$' } |
    Select-Object -Last 1
  if (-not $publicationJson) { throw "browser provenance publication output is invalid" }
  $publication = $publicationJson | ConvertFrom-Json
  if (
    $publication.browser_provenance_schema_version -cne "spell.v04.browser-provenance/1" -or
    $publication.browser_run_id -cne $runId -or
    [string]$publication.browser_qualification_image_id -cne $qualificationImage
  ) { throw "browser provenance publication binding differs" }

  $resultJson = [ordered]@{
    schema_version = "spell.v04.browser-run/2"
    run_id = $runId
    source_fingerprint_sha256 = $source
    started_at_utc = $runStartedAtUtc
    finished_at_utc = $runFinishedAtUtc
    passed = $true
    real_browser_project_count = 2
    fault_browser_project_count = 2
    stack_image_ids = [ordered]@{
      backend = $env:SPELL_BACKEND_IMAGE_ID
      driver = $env:SPELL_DRIVER_IMAGE_ID
      pki_init = $env:SPELL_PKI_IMAGE_ID
      postgres = $env:SPELL_POSTGRES_IMAGE_ID
      proxy = $env:SPELL_PROXY_IMAGE_ID
      qualification = $env:SPELL_QUALIFICATION_IMAGE_ID
    }
    provenance = $publication
    release_tools = [ordered]@{
      docker_cli_path = $script:BrowserDockerExecutable
      docker_compose_path = $script:BrowserComposeExecutable
      python_path = $PythonExecutable
    }
  } | ConvertTo-Json -Compress -Depth 8
}
catch {
  $failure = $_
}
finally {
  $token = $null
  $tokenLines = $null
  $cleanupFailures = @()
  if (-not $runtimeCleanupComplete -and $composeTouched -and $script:BrowserComposeExecutable) {
    $down = Invoke-ComposeCleanupCommand @(
      "-p", $project, "--profile", "driver", "-f", "compose.yaml",
      "down", "--rmi", "local", "-v", "--remove-orphans"
    )
    if ($down.ExitCode -ne 0) {
      $cleanupFailures += "browser qualification Compose teardown failed"
    }
  }
  if (-not $runtimeCleanupComplete -and $script:BrowserDockerExecutable) {
    if ($qualificationImageOwned) {
      Invoke-DockerCleanupCommand @("image", "rm", $qualificationTag) | Out-Null
      $qualificationInspection = Invoke-DockerCleanupCommand @(
        "image", "inspect", $qualificationTag
      )
      if ($qualificationInspection.ExitCode -eq 0) {
        $cleanupFailures += "browser qualification image tag remains"
      }
    }
    try { Assert-NoProjectResources }
    catch { $cleanupFailures += $_.Exception.Message }
  }
  try {
    foreach ($name in $environmentNames) {
      if ($null -eq $priorEnvironment[$name]) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
      }
      else {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], "Process")
      }
    }
  }
  catch { $cleanupFailures += "browser qualification environment restoration failed: $($_.Exception.Message)" }
  try { Pop-Location }
  catch { $cleanupFailures += "browser qualification location restoration failed: $($_.Exception.Message)" }
  if ($cleanupFailures.Count -ne 0) {
    $cleanupMessage = $cleanupFailures -join "; "
    if ($failure) {
      $failure = [InvalidOperationException]::new(
        "$($failure.Exception.Message); $cleanupMessage",
        $failure.Exception
      )
    }
    else {
      $failure = [InvalidOperationException]::new($cleanupMessage)
    }
  }
}

if ($failure) { throw $failure }
Write-Output $resultJson
