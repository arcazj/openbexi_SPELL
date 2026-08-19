param(
  [string]$Image = "openbexi_spell-qualification-input:0.3",
  [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$container = "openbexi-spell-browser-qualification-$PID"
$portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$port = ([Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()
$ready = $null
$originalBrowserOutput = [Environment]::GetEnvironmentVariable(
  "SPELL_BROWSER_STREAM_OUTPUT", "Process"
)
if (-not $OutputPath) {
  $OutputPath = Join-Path $root "artifacts/v0.3/qualification-browser-stream.json"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

Push-Location $root
try {
  docker run -d --name $container --tmpfs /tmp:size=512m,noexec,nosuid `
    -p "127.0.0.1:${port}:8765" `
    --entrypoint python $Image `
    /qualification-source/scripts/qualify_browser_stream_server.py | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Browser qualification server failed to start" }

  $deadline = (Get-Date).AddSeconds(30)
  do {
    try {
      $ready = Invoke-RestMethod "http://127.0.0.1:${port}/qualification/config"
    }
    catch {
      Start-Sleep -Milliseconds 250
    }
  } until ($ready -or (Get-Date) -ge $deadline)
  if (-not $ready) {
    docker logs $container
    throw "Browser qualification server did not become ready"
  }

  Push-Location (Join-Path $root "frontend")
  try {
    $env:SPELL_BROWSER_STREAM_URL = "http://127.0.0.1:${port}"
    $env:SPELL_BROWSER_STREAM_OUTPUT = $OutputPath
    node scripts/qualify-browser-stream.mjs
    if ($LASTEXITCODE -ne 0) { throw "Browser stream qualification failed" }
  }
  finally {
    Remove-Item Env:SPELL_BROWSER_STREAM_URL -ErrorAction SilentlyContinue
    if ($null -eq $originalBrowserOutput) {
      Remove-Item Env:SPELL_BROWSER_STREAM_OUTPUT -ErrorAction SilentlyContinue
    }
    else {
      $env:SPELL_BROWSER_STREAM_OUTPUT = $originalBrowserOutput
    }
    Pop-Location
  }
}
finally {
  docker rm -f $container 2>$null | Out-Null
  Pop-Location
}
