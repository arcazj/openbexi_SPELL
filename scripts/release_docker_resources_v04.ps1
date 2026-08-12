function Invoke-V04DockerCleanupCommand {
  param(
    [Parameter(Mandatory = $true)][string]$DockerExe,
    [Parameter(Mandatory = $true)][string[]]$DockerArguments
  )
  $savedPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $lines = @(& $DockerExe @DockerArguments 2>$null)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $savedPreference }
  return [pscustomobject]@{
    ExitCode = [int]$exitCode
    Lines = [string[]]@($lines | ForEach-Object { [string]$_ })
  }
}

function Remove-V04RunDockerResources {
  param(
    [Parameter(Mandatory = $true)][string]$DockerExe,
    [string[]]$Tags = @(),
    [string[]]$Containers = @(),
    [string[]]$ImageIds = @()
  )

  $failures = [Collections.Generic.List[string]]::new()
  $allImageIds = [Collections.Generic.List[string]]::new()
  foreach ($imageId in @($ImageIds | Where-Object { $_ } | Select-Object -Unique)) {
    $allImageIds.Add($imageId)
  }

  foreach ($container in @($Containers | Where-Object { $_ } | Select-Object -Unique)) {
    $inspection = Invoke-V04DockerCleanupCommand $DockerExe @("container", "inspect", $container)
    if ($inspection.ExitCode -eq 0) {
      $removal = Invoke-V04DockerCleanupCommand $DockerExe `
        @("container", "rm", "--force", $container)
      if ($removal.ExitCode -ne 0) { $failures.Add("cannot remove run container $container") }
    }
    $verification = Invoke-V04DockerCleanupCommand $DockerExe @("container", "inspect", $container)
    if ($verification.ExitCode -eq 0) { $failures.Add("run container remains: $container") }
  }

  $ownedTags = @($Tags | Where-Object { $_ } | Select-Object -Unique)
  foreach ($tag in $ownedTags) {
    $inspection = Invoke-V04DockerCleanupCommand $DockerExe `
      @("image", "inspect", $tag, "--format", "{{.Id}}")
    if ($inspection.ExitCode -eq 0) {
      $imageId = @($inspection.Lines | Where-Object { $_ -cmatch '^sha256:[0-9a-f]{64}$' }) |
        Select-Object -Last 1
      if ($imageId) { $allImageIds.Add([string]$imageId) }
      $removal = Invoke-V04DockerCleanupCommand $DockerExe @("image", "rm", $tag)
      if ($removal.ExitCode -ne 0) { $failures.Add("cannot remove run image tag $tag") }
    }
    $verification = Invoke-V04DockerCleanupCommand $DockerExe @("image", "inspect", $tag)
    if ($verification.ExitCode -eq 0) { $failures.Add("run image tag remains: $tag") }
  }

  $retainedShared = [Collections.Generic.List[string]]::new()
  $uniqueIds = @($allImageIds | Select-Object -Unique)
  [array]::Reverse($uniqueIds)
  foreach ($imageId in $uniqueIds) {
    $inspection = Invoke-V04DockerCleanupCommand $DockerExe `
      @("image", "inspect", $imageId, "--format", "{{json .RepoTags}}")
    if ($inspection.ExitCode -ne 0) { continue }
    $repoTagsJson = @($inspection.Lines) -join ""
    try { $repoTags = @($repoTagsJson | ConvertFrom-Json) }
    catch {
      $failures.Add("cannot read retained tags for run image $imageId")
      continue
    }
    $meaningfulTags = @($repoTags | Where-Object { $_ -and $_ -cne "<none>:<none>" })
    if (@($meaningfulTags | Where-Object { $_ -cin $ownedTags }).Count -gt 0) {
      $failures.Add("run image retains an owned tag: $imageId")
      continue
    }
    if ($meaningfulTags.Count -gt 0) {
      $retainedShared.Add($imageId)
      continue
    }
    $removal = Invoke-V04DockerCleanupCommand $DockerExe @("image", "rm", $imageId)
    if ($removal.ExitCode -ne 0) { $failures.Add("cannot remove untagged run image $imageId") }
    $verification = Invoke-V04DockerCleanupCommand $DockerExe @("image", "inspect", $imageId)
    if ($verification.ExitCode -eq 0) { $failures.Add("untagged run image remains: $imageId") }
  }

  if ($failures.Count -gt 0) { throw ($failures -join "; ") }
  return [pscustomobject]@{
    retained_shared_image_ids = @($retainedShared | Select-Object -Unique)
  }
}
