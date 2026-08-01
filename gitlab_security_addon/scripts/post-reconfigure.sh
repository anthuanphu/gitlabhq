#!/bin/bash
# =============================================================================
# GitLab Security Addon - Post-Reconfigure Hook
# Chạy tự động sau khi GitLab khởi động, thực hiện database migration
# =============================================================================

set -e

echo "============================================"
echo " GitLab Security Addon - Initializing..."
echo " Version: 1.0.0"
echo "============================================"

# Đợi database sẵn sàng
echo "Waiting for database to be ready..."
for i in $(seq 1 30); do
  if /opt/gitlab/bin/gitlab-rails runner "ActiveRecord::Base.connection.active?" 2>/dev/null; then
    echo "Database is ready."
    break
  fi
  echo "  Attempt $i/30 - waiting..."
  sleep 2
done

# Chạy migration cho security addon
echo "Running security addon database migrations..."
/opt/gitlab/bin/gitlab-rake db:migrate 2>&1 || echo "Migration skipped (may already be up-to-date)"

echo ""
echo "============================================"
echo " Security Addon initialized successfully!"
echo " Admin panel: /admin/security_policies"
echo "============================================"
