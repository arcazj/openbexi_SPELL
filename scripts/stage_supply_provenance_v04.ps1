$ErrorActionPreference = "Stop"

function Add-V04SupplyProvenanceMetrics {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [Parameter(Mandatory = $true)][string]$TestId,
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$SourceFingerprint,
    [Parameter(Mandatory = $true)][string]$RawDirectory,
    [Parameter(Mandatory = $true)]$Result,
    [Parameter(Mandatory = $true)]$ExecutionImages
  )

  if ($TestId -cnotmatch '^V04-SC-00(?:1|3|4|6)$') {
    throw "unsupported v0.4 supply provenance test ID"
  }
  if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
    throw "v0.4 supply provenance run ID is invalid"
  }
  if ($SourceFingerprint -cnotmatch '^[0-9a-f]{64}$') {
    throw "v0.4 supply provenance source fingerprint is invalid"
  }
  if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "locked v0.4 provenance Python executable is missing"
  }
  if (-not (Test-Path -LiteralPath $RawDirectory -PathType Container)) {
    throw "v0.4 raw supply provenance directory is missing"
  }

  $temporary = Join-Path $env:TEMP "spell-v04-supply-provenance-$RunId-$($TestId.ToLower())"
  $temporaryFull = [IO.Path]::GetFullPath($temporary)
  $tempRootFull = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
  if (-not $temporaryFull.StartsWith("$tempRootFull$([IO.Path]::DirectorySeparatorChar)")) {
    throw "refusing a provenance metadata path outside the temporary root"
  }
  if (Test-Path -LiteralPath $temporary) {
    throw "v0.4 provenance metadata staging path already exists"
  }

  New-Item -ItemType Directory -Path $temporary | Out-Null
  try {
    $resultPath = Join-Path $temporary "result.json"
    $imagesPath = Join-Path $temporary "execution-images.json"
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText(
      $resultPath,
      "$(($Result | ConvertTo-Json -Depth 100 -Compress))`n",
      $utf8
    )
    [IO.File]::WriteAllText(
      $imagesPath,
      "$(($ExecutionImages | ConvertTo-Json -Depth 20 -Compress))`n",
      $utf8
    )

    $output = @(
      & $PythonExe -I (Join-Path $Root "scripts/supply_provenance_v04.py") stage `
        --root $Root --test-id $TestId --run-id $RunId `
        --source $SourceFingerprint --input-directory $RawDirectory `
        --result-json $resultPath --execution-images-json $imagesPath
    )
    if ($LASTEXITCODE -ne 0) {
      throw "v0.4 $TestId supply provenance staging failed"
    }
    $line = $output | Where-Object { $_ -cmatch '^\{.+\}$' } | Select-Object -Last 1
    if (-not $line) { throw "v0.4 $TestId supply provenance staging emitted no JSON" }
    $metrics = $line | ConvertFrom-Json
    $expected = @(
      "supply_provenance_corpus_sha256",
      "supply_provenance_file_count",
      "supply_provenance_manifest_sha256",
      "supply_provenance_run_id",
      "supply_provenance_schema_version"
    )
    if ((@($metrics.PSObject.Properties.Name | Sort-Object) -join "`0") -cne ($expected -join "`0")) {
      throw "v0.4 $TestId supply provenance metrics differ"
    }
    foreach ($property in $metrics.PSObject.Properties) {
      $Result.metrics | Add-Member -NotePropertyName $property.Name `
        -NotePropertyValue $property.Value -Force
    }
    return $Result
  }
  finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
      Remove-Item -LiteralPath $temporary -Recurse -Force
    }
  }
}
