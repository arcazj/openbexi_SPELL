$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$container = "spell-lock-$([Guid]::NewGuid().ToString('N'))"

try {
  docker create --name $container `
    "python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280" `
    sh -lc "python -m pip install --quiet pip==25.3 pip-tools==7.5.2 && pip-compile --generate-hashes --resolver=backtracking --strip-extras --output-file=/tmp/requirements.hashes.lock /tmp/requirements.txt" |
    Out-Null
  docker cp "${root}/backend/requirements.txt" "${container}:/tmp/requirements.txt"
  docker start -a $container
  if ($LASTEXITCODE -ne 0) { throw "Python dependency locking failed" }
  docker cp "${container}:/tmp/requirements.hashes.lock" "${root}/backend/requirements.hashes.lock"
}
finally {
  docker rm -f $container 2>$null | Out-Null
}
