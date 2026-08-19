param([string]$LockPath)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $LockPath) { $LockPath = Join-Path $root "scripts/release-toolchain-v04.json" }
$LockPath = [IO.Path]::GetFullPath($LockPath)
$bootstrapPythonRelative = "OpenBEXI/release-toolchain/python-3.13.14-embed-amd64/python.exe"
$bootstrapPythonSha256 = "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1"
$bootstrapArchiveRelative = "OpenBEXI/release-toolchain/python-3.13.14-embed-amd64.zip"
$bootstrapArchiveSha256 = "90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907"
$bootstrapArchiveUrl = "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embeddable-amd64.zip"
$expectedTools = [ordered]@{
  "docker-cli" = [ordered]@{
    BaseDirectory = "ProgramFiles"
    RelativePath = "Docker/Docker/resources/bin/docker.exe"
  }
  "docker-buildx" = [ordered]@{
    BaseDirectory = "ProgramFiles"
    RelativePath = "Docker/Docker/resources/cli-plugins/docker-buildx.exe"
  }
  "docker-compose" = [ordered]@{
    BaseDirectory = "ProgramFiles"
    RelativePath = "Docker/Docker/resources/cli-plugins/docker-compose.exe"
  }
  "docker-sbom" = [ordered]@{
    BaseDirectory = "LocalAppData"
    RelativePath = "OpenBEXI/release-toolchain/docker-sbom-0.6.0-windows-amd64/docker-sbom.exe"
  }
  "docker-scout" = [ordered]@{
    BaseDirectory = "ProgramFiles"
    RelativePath = "Docker/Docker/resources/cli-plugins/docker-scout.exe"
  }
  "python" = [ordered]@{
    BaseDirectory = "LocalAppData"
    RelativePath = $bootstrapPythonRelative
    ArchiveRelativePath = $bootstrapArchiveRelative
    ArchiveUrl = $bootstrapArchiveUrl
  }
}

function Get-LockedBaseDirectory([string]$name) {
  switch -CaseSensitive ($name) {
    "ProgramFiles" { return $env:ProgramFiles }
    "LocalAppData" { return $env:LOCALAPPDATA }
    default { throw "unsupported locked release tool base directory: $name" }
  }
}

function Get-StreamSha256([IO.Stream]$stream) {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace("-", "").ToLower()
  }
  finally { $hasher.Dispose() }
}

function Assert-PythonRuntimeArchive(
  [string]$archivePath,
  [string]$archiveSha256,
  [string]$pythonPath
) {
  if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "locked Python runtime archive is missing"
  }
  $archiveDigest = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLower()
  if ($archiveDigest -cne $archiveSha256) {
    throw "locked Python runtime archive hash differs"
  }

  $runtimeRoot = [IO.Path]::GetFullPath((Split-Path -Parent $pythonPath)).TrimEnd('\', '/')
  $runtimePrefix = $runtimeRoot + [IO.Path]::DirectorySeparatorChar
  $runtimeItems = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Force)
  $runtimeRootItem = Get-Item -LiteralPath $runtimeRoot -Force
  if (
    ($runtimeRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    @($runtimeItems | Where-Object {
      $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -gt 0
  ) { throw "locked Python runtime contains a reparse point" }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
  $archiveFiles = @{}
  try {
    foreach ($entry in $archive.Entries) {
      if ($entry.FullName.EndsWith("/")) { continue }
      $relative = $entry.FullName.Replace('\', '/')
      if (
        [string]::IsNullOrWhiteSpace($relative) -or
        [IO.Path]::IsPathRooted($relative) -or
        $relative -match '(^|/)\.\.(/|$)' -or
        $relative.Contains(":") -or
        $archiveFiles.ContainsKey($relative)
      ) { throw "locked Python runtime archive has an unsafe or duplicate entry" }
      $candidate = [IO.Path]::GetFullPath(
        (Join-Path $runtimeRoot $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
      )
      if (-not $candidate.StartsWith($runtimePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "locked Python runtime archive entry escapes its target"
      }
      if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "locked Python runtime extraction is incomplete: $relative"
      }
      $entryStream = $entry.Open()
      try { $expectedDigest = Get-StreamSha256 $entryStream }
      finally { $entryStream.Dispose() }
      $observedDigest = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLower()
      if ($observedDigest -cne $expectedDigest) {
        throw "locked Python runtime extraction differs: $relative"
      }
      $archiveFiles[$relative] = $true
    }
  }
  finally { $archive.Dispose() }

  $runtimeFiles = @($runtimeItems | Where-Object { -not $_.PSIsContainer })
  foreach ($file in $runtimeFiles) {
    $relative = $file.FullName.Substring($runtimePrefix.Length).Replace('\', '/')
    if (-not $archiveFiles.ContainsKey($relative)) {
      throw "locked Python runtime contains an unverified file: $relative"
    }
  }
  if ($runtimeFiles.Count -ne $archiveFiles.Count) {
    throw "locked Python runtime file set differs from its archive"
  }
}

if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
  throw "v0.4 release toolchain lock is missing"
}
$lockItem = Get-Item -LiteralPath $LockPath -Force
if ($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw "v0.4 release toolchain lock cannot be a reparse point"
}
$bootstrapPython = Join-Path $env:LOCALAPPDATA $bootstrapPythonRelative
$bootstrapArchive = Join-Path $env:LOCALAPPDATA $bootstrapArchiveRelative
if (-not (Test-Path -LiteralPath $bootstrapPython -PathType Leaf)) {
  throw "hardcoded release-toolchain Python executable is missing"
}
$bootstrapPythonDigest = (Get-FileHash -LiteralPath $bootstrapPython -Algorithm SHA256).Hash.ToLower()
if ($bootstrapPythonDigest -cne $bootstrapPythonSha256) {
  throw "hardcoded release-toolchain Python executable hash differs"
}
Assert-PythonRuntimeArchive $bootstrapArchive $bootstrapArchiveSha256 $bootstrapPython

$strictJsonParser = @'
import json
import pathlib
import sys

def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = item
    return value

def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")

data = pathlib.Path(sys.argv[1]).read_bytes()
if not 0 < len(data) <= 262144:
    raise ValueError("release toolchain lock has an invalid size")
value = json.loads(
    data.decode("utf-8"),
    object_pairs_hook=unique_object,
    parse_constant=reject_constant,
)
sys.stdout.write(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
'@
$savedPreference = $ErrorActionPreference
try {
  $ErrorActionPreference = "Continue"
  $normalizedLock = @($strictJsonParser | & $bootstrapPython -I - $LockPath 2>$null)
  $strictParseExitCode = $LASTEXITCODE
}
finally { $ErrorActionPreference = $savedPreference }
if ($strictParseExitCode -ne 0 -or $normalizedLock.Count -ne 1) {
  throw "v0.4 release toolchain lock is invalid strict JSON"
}
$lock = $normalizedLock[0] | ConvertFrom-Json
$lockProperties = @($lock.PSObject.Properties.Name | Sort-Object)
if (($lockProperties -join "`0") -cne "host_platform`0schema_version`0tools`0versions") {
  throw "v0.4 release toolchain lock fields differ"
}
if ($lock.schema_version -cne "spell.v04.release-toolchain/1") {
  throw "v0.4 release toolchain lock schema differs"
}
if (
  $lock.host_platform -cne "windows-amd64-docker-desktop" -or
  @($lock.tools).Count -ne $expectedTools.Count
) { throw "v0.4 release toolchain platform/set differs" }
$versionProperties = @($lock.versions.PSObject.Properties.Name | Sort-Object)
$expectedVersionProperties = @(
  "docker_buildx", "docker_cli", "docker_compose", "docker_sbom", "docker_scout",
  "host_python", "syft_provider"
) | Sort-Object
if (($versionProperties -join "`0") -cne ($expectedVersionProperties -join "`0")) {
  throw "v0.4 release toolchain version fields differ"
}

$lockedPaths = @{}
foreach ($tool in $lock.tools) {
  $definition = $expectedTools[$tool.name]
  $expectedProperties = @("base_directory", "name", "relative_path", "sha256")
  if ($tool.name -ceq "python") {
    $expectedProperties += @("archive_relative_path", "archive_sha256", "archive_url")
  }
  $observedProperties = @($tool.PSObject.Properties.Name | Sort-Object)
  $expectedProperties = @($expectedProperties | Sort-Object)
  if (
    -not $expectedTools.Contains($tool.name) -or
    ($observedProperties -join "`0") -cne ($expectedProperties -join "`0") -or
    [string]$tool.base_directory -cne $definition.BaseDirectory -or
    [string]$tool.relative_path -cne $definition.RelativePath -or
    $lockedPaths.Contains($tool.name)
  ) { throw "v0.4 release toolchain entry differs: $($tool.name)" }
  if (
    $tool.name -ceq "python" -and (
      [string]$tool.archive_relative_path -cne $definition.ArchiveRelativePath -or
      [string]$tool.archive_url -cne $definition.ArchiveUrl -or
      [string]$tool.archive_sha256 -cne $bootstrapArchiveSha256
    )
  ) { throw "v0.4 release toolchain archive entry differs: $($tool.name)" }
  $base = Get-LockedBaseDirectory $tool.base_directory
  $path = Join-Path $base $tool.relative_path
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "locked release tool is missing: $($tool.name)"
  }
  $observed = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
  if ($observed -cne $tool.sha256) {
    throw "locked release tool hash differs: $($tool.name)"
  }
  if ($tool.name -ceq "python" -and $observed -cne $bootstrapPythonSha256) {
    throw "locked Python executable differs from the hardcoded bootstrap identity"
  }
  $lockedPaths[$tool.name] = [IO.Path]::GetFullPath($path)
}

$pythonExe = $lockedPaths["python"]
if ($pythonExe -cne [IO.Path]::GetFullPath($bootstrapPython)) {
  throw "locked Python path differs from the hardcoded bootstrap path"
}

$dockerExe = $lockedPaths["docker-cli"]
$buildxExe = $lockedPaths["docker-buildx"]
$composeExe = $lockedPaths["docker-compose"]
$sbomExe = $lockedPaths["docker-sbom"]
$scoutExe = $lockedPaths["docker-scout"]
$dockerVersion = @(& $dockerExe --version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Docker CLI version" }
$buildxVersion = @(& $buildxExe version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Docker Buildx version" }
$composeVersion = @(& $composeExe version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Docker Compose version" }
$sbomVersion = @(& $sbomExe sbom version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Docker SBOM version" }
$scoutVersion = @(& $scoutExe version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Docker Scout version" }
$pythonVersion = @(& $pythonExe --version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "cannot read the locked Python version" }
if ($dockerVersion -notmatch [regex]::Escape("Docker version $($lock.versions.docker_cli),")) {
  throw "Docker CLI version differs from the v0.4 lock"
}
if ($buildxVersion -notmatch [regex]::Escape($lock.versions.docker_buildx)) {
  throw "Docker Buildx version differs from the v0.4 lock"
}
if ($composeVersion -notmatch [regex]::Escape($lock.versions.docker_compose)) {
  throw "Docker Compose version differs from the v0.4 lock"
}
if (
  $sbomVersion -notmatch "Application:\s+docker-sbom \($([regex]::Escape($lock.versions.docker_sbom))\)" -or
  $sbomVersion -notmatch "Provider:\s+syft \($([regex]::Escape($lock.versions.syft_provider))\)"
) { throw "Docker SBOM/Syft version differs from the v0.4 lock" }
if ($scoutVersion -notmatch [regex]::Escape($lock.versions.docker_scout)) {
  throw "Docker Scout version differs from the v0.4 lock"
}
if ($pythonVersion -cne "Python $($lock.versions.host_python)") {
  throw "Python version differs from the v0.4 lock"
}
$env:SPELL_RELEASE_DOCKER_EXE = $dockerExe
$env:SPELL_RELEASE_BUILDX_EXE = $buildxExe
$env:SPELL_RELEASE_COMPOSE_EXE = $composeExe
$env:SPELL_RELEASE_SBOM_EXE = $sbomExe
$env:SPELL_RELEASE_SCOUT_EXE = $scoutExe
$env:SPELL_RELEASE_PYTHON_EXE = $pythonExe
Write-Output "v0.4 release toolchain lock passed"
