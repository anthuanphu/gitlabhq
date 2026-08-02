# Định nghĩa các method cần thiết cho middleware (trước khi load toàn bộ module)
module GitlabSecurity
  class << self
    def feature_enabled?(feature) = false
    def device_whitelisted?(*args) = true
    def policy_for(project) = nil
  end
end

# =============================================================================
# GITLAB SECURITY ADDON - Final Initializer
# =============================================================================

root = Rails.root.join('gitlab_security_addon/lib')
if root.exist?
  # --- Middleware (phải load + insert ngay, trước khi stack freeze) ---
  require root.join('gitlab_security/version').to_s
  begin
    require root.join('gitlab_security/middleware/security_blocker').to_s
    require root.join('gitlab_security/middleware/vs_code_detector').to_s
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly,
      GitlabSecurity::Middleware::SecurityBlocker
    ) rescue nil
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly,
      GitlabSecurity::Middleware::VsCodeDetector
    ) rescue nil
  rescue => e
    Rails.logger.warn('[GitlabSecurity] mw: %s' % e.message)
  end
end

# --- Overrides + Models (sau khi Rails fully initialized) ---
Rails.application.config.after_initialize do
  begin
    root = Rails.root.join('gitlab_security_addon/lib')
    next unless root.exist?
    require root.join('gitlab_security/models/security_policy').to_s
    require root.join('gitlab_security/models/security_audit_log').to_s
    require root.join('gitlab_security/models/security_access_grant').to_s
    require root.join('gitlab_security/models/device_whitelist').to_s
    require root.join('gitlab_security/overrides/git_access').to_s
    Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
    require root.join('gitlab_security/overrides/project_policy').to_s
    ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
    require root.join('gitlab_security/overrides/project').to_s
    Project.prepend(GitlabSecurity::Overrides::Project)
    Rails.logger.info('[GitlabSecurity] v%s OK' % GitlabSecurity::VERSION)
  rescue => e
    Rails.logger.warn('[GitlabSecurity] %s' % e.message)
  end
end
