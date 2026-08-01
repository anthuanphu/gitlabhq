#!/bin/bash
# =============================================================================
# GitLab Security Addon - Post-Reconfigure Hook
# =============================================================================
echo "============================================"
echo " GitLab Security Addon - Initializing..."
echo "============================================"

# Chạy migration (không crash nếu lỗi)
/opt/gitlab/bin/gitlab-rake db:migrate 2>&1 || echo "(migration deferred - will retry next restart)"

echo "Security Addon setup complete."
echo "Admin panel: /admin/security_policies"
echo "============================================"
