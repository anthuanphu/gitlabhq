# Generates Dockerfile from repo source files using base64 encoding.
# This is immune to .dockerignore exclusions AND CRLF line-ending corruption.
# Run: powershell -ExecutionPolicy Bypass -File scripts/generate-dockerfile.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Get-B64 {
  param([string]$path)
  $content = [IO.File]::ReadAllText($path) -replace "`r`n", "`n"
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
}

$b64Initializer = Get-B64 (Join-Path $root 'config/initializers/gitlab_security_addon.rb')
$b64Model      = Get-B64 (Join-Path $root 'app/models/project_security_setting.rb')
$b64Patch      = Get-B64 (Join-Path $root 'scripts/patch-gitlab.rb')

$dockerfile = @'
FROM gitlab/gitlab-ce:latest

# Bump this line to bust Docker build cache when deploying changes
ARG CACHE_BUST=13
RUN echo "cache_bust=${CACHE_BUST}"

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    GITLAB_OMNIBUS_CONFIG="external_url 'http://192.168.1.168:8228'; nginx['listen_port'] = 80; nginx['listen_https'] = false; puma['worker_processes'] = 1; sidekiq['max_concurrency'] = 5; postgresql['shared_buffers'] = '128MB'; prometheus_monitoring['enable'] = false"

# Source Code Protection - base64 inline (immune to .dockerignore and line-ending issues)
RUN echo '__B64_INITIALIZER__' | base64 -d > ${GITLAB_RAILS_DIR}/config/initializers/gitlab_security_addon.rb
RUN echo '__B64_MODEL__' | base64 -d > ${GITLAB_RAILS_DIR}/app/models/project_security_setting.rb
RUN echo '__B64_PATCH__' | base64 -d > /tmp/patch-gitlab.rb
RUN /opt/gitlab/embedded/bin/ruby /tmp/patch-gitlab.rb && rm /tmp/patch-gitlab.rb
RUN mkdir -p /workspace && chmod 777 /workspace
'@

$dockerfile = $dockerfile.Replace('__B64_INITIALIZER__', $b64Initializer)
$dockerfile = $dockerfile.Replace('__B64_MODEL__', $b64Model)
$dockerfile = $dockerfile.Replace('__B64_PATCH__', $b64Patch)
$dockerfile = $dockerfile -replace "`r`n", "`n"

[IO.File]::WriteAllText((Join-Path $root 'Dockerfile'), $dockerfile)
Write-Host "Dockerfile generated OK."
