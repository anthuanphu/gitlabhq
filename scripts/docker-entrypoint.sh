#!/bin/bash
# Auto-run security migration on container start
echo "[SourceProtection] Running pending migrations..."
/opt/gitlab/bin/gitlab-rake db:migrate 2>/dev/null || true
echo "[SourceProtection] Done. Starting GitLab..."

# Hand off to the original GitLab entrypoint
exec /assets/wrapper "$@"
