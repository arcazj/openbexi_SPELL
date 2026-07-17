$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root "artifacts"
$artifactDirectory = Join-Path $artifactRoot "v0.3"
$stageId = [guid]::NewGuid().ToString("N")
$staging = Join-Path $artifactRoot ".qualification-staging-$stageId"
$backup = Join-Path $artifactRoot ".qualification-backup-$stageId"
$imageTag = "openbexi_spell-qualification-input:$stageId"
$fingerprintImageTag = "openbexi_spell-qualification-fingerprint-input:$stageId"
$backupComplete = $false
$publicationStarted = $false
$publicationComplete = $false
$reportNames = @(
  "qualification-quick.json",
  "qualification-soak.json",
  "qualification-browser-stream.json",
  "qualification.json"
)

$artifactRootFull = [IO.Path]::GetFullPath($artifactRoot)
foreach ($temporaryPath in @($staging, $backup)) {
  $temporaryFull = [IO.Path]::GetFullPath($temporaryPath)
  if (-not $temporaryFull.StartsWith("$artifactRootFull$([IO.Path]::DirectorySeparatorChar)")) {
    throw "Refusing to use qualification temporary path outside artifacts: $temporaryFull"
  }
}

function Restore-PreviousEvidence {
  foreach ($name in $reportNames) {
    $published = Join-Path $artifactDirectory $name
    if (Test-Path -LiteralPath $published) {
      if ((Get-Item -LiteralPath $published).PSIsContainer) {
        throw "Qualification evidence path is not a file: $published"
      }
      Remove-Item -LiteralPath $published -Force
    }
    $previous = Join-Path $backup $name
    if (Test-Path -LiteralPath $previous) {
      Move-Item -LiteralPath $previous -Destination $published
    }
  }
}

function Invoke-IsolatedQualification {
  param(
    [Parameter(Mandatory = $true)][string]$Profile,
    [Parameter(Mandatory = $true)][string]$OutputName
  )
  $container = "openbexi-spell-qualification-$Profile-$PID"
  try {
    docker create --name $container --network none --tmpfs /tmp:size=512m,noexec,nosuid $image `
      python /qualification-source/scripts/qualify_v03.py "--$Profile" `
      --output "/qualification-output/$OutputName" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create $Profile qualification container" }
    docker start -a $container
    $qualificationExitCode = $LASTEXITCODE
    docker cp "${container}:/qualification-output/$OutputName" (Join-Path $staging $OutputName)
    if ($LASTEXITCODE -ne 0) { throw "Could not copy $Profile qualification evidence" }
    if ($qualificationExitCode -ne 0) { throw "$Profile qualification failed" }
  }
  finally {
    docker rm -f $container 2>$null | Out-Null
  }
}

New-Item -ItemType Directory -Force $artifactRoot | Out-Null
New-Item -ItemType Directory $staging | Out-Null

Push-Location $root
try {
  docker build --pull=false -f scripts/qualification.Dockerfile -t $imageTag .
  if ($LASTEXITCODE -ne 0) { throw "Qualification input image build failed" }
  $image = (docker image inspect $imageTag --format "{{.Id}}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $image) { throw "Qualification image ID lookup failed" }

  Invoke-IsolatedQualification -Profile "quick" -OutputName "qualification-quick.json"
  Invoke-IsolatedQualification -Profile "soak" -OutputName "qualification-soak.json"
  & (Join-Path $PSScriptRoot "qualify_browser_stream.ps1") -Image $image `
    -OutputPath (Join-Path $staging "qualification-browser-stream.json")
  if ($LASTEXITCODE -ne 0) { throw "Browser qualification failed" }

  $composeContainer = "openbexi-spell-qualification-compose-$PID"
  try {
    docker create --name $composeContainer --network none $image `
      python /qualification-source/scripts/compose_qualification.py `
      --quick /tmp/qualification-quick.json `
      --soak /tmp/qualification-soak.json `
      --browser /tmp/qualification-browser-stream.json `
      --output /tmp/qualification.json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create evidence composition container" }
    foreach ($name in $reportNames[0..2]) {
      docker cp (Join-Path $staging $name) "${composeContainer}:/tmp/$name"
      if ($LASTEXITCODE -ne 0) { throw "Could not stage $name for evidence composition" }
    }
    docker start -a $composeContainer
    if ($LASTEXITCODE -ne 0) { throw "Qualification evidence composition failed" }
    docker cp "${composeContainer}:/tmp/qualification.json" `
      (Join-Path $staging "qualification.json")
    if ($LASTEXITCODE -ne 0) { throw "Could not copy composed qualification evidence" }
  }
  finally {
    docker rm -f $composeContainer 2>$null | Out-Null
  }

  $stagedNames = @(Get-ChildItem -LiteralPath $staging -File | ForEach-Object { $_.Name })
  if (@(Compare-Object $reportNames $stagedNames).Count -ne 0) {
    throw "Qualification staging directory does not contain the exact report set"
  }

  docker build --pull=false -f scripts/package.Dockerfile -t $fingerprintImageTag . | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Qualification fingerprint input image build failed" }
  $fingerprintImage = (
    docker image inspect $fingerprintImageTag --format "{{.Id}}"
  ).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $fingerprintImage) {
    throw "Qualification fingerprint image ID lookup failed"
  }
  $fingerprintOutput = @(
    docker run --rm --network none --entrypoint python $fingerprintImage `
      scripts/source_fingerprint.py --root /workspace
  )
  if ($LASTEXITCODE -ne 0) { throw "Current qualification fingerprint failed" }
  $currentFingerprint = $fingerprintOutput |
    Where-Object { $_ -cmatch '^[0-9a-f]{64}$' } |
    Select-Object -Last 1
  $evidenceFingerprint = (
    Get-Content -Raw (Join-Path $staging "qualification.json") | ConvertFrom-Json
  ).source.fingerprint_sha256
  if (-not $currentFingerprint -or $currentFingerprint -cne $evidenceFingerprint) {
    throw "Source changed while qualification evidence was being measured"
  }

  New-Item -ItemType Directory -Force $artifactDirectory | Out-Null
  New-Item -ItemType Directory $backup | Out-Null
  foreach ($name in $reportNames) {
    $published = Join-Path $artifactDirectory $name
    if (Test-Path -LiteralPath $published) {
      if ((Get-Item -LiteralPath $published).PSIsContainer) {
        throw "Qualification evidence path is not a file: $published"
      }
      Copy-Item -LiteralPath $published -Destination (Join-Path $backup $name)
    }
  }
  $backupComplete = $true
  $publicationStarted = $true
  foreach ($name in $reportNames) {
    Move-Item -LiteralPath (Join-Path $staging $name) `
      -Destination (Join-Path $artifactDirectory $name) -Force
  }
  $publicationComplete = $true
  Remove-Item -LiteralPath $backup -Recurse -Force
}
finally {
  if (Test-Path -LiteralPath $backup) {
    if ($backupComplete -and $publicationStarted -and -not $publicationComplete) {
      Restore-PreviousEvidence
    }
    Remove-Item -LiteralPath $backup -Recurse -Force
  }
  if (Test-Path -LiteralPath $staging) {
    Remove-Item -LiteralPath $staging -Recurse -Force
  }
  Pop-Location
}
