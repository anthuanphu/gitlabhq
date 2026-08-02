# GitLab Source Protection - Middleware (IDE blocking)
# Core enforcement: git_access.rb, repositories_controller.rb, etc.
root = Rails.root.join('gitlab_security_addon/lib')
if root.exist?
  begin
    require root.join('gitlab_security').to_s
    require root.join('gitlab_security/middleware/security_blocker').to_s
    require root.join('gitlab_security/middleware/vs_code_detector').to_s
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::SecurityBlocker
    ) rescue nil
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::VsCodeDetector
    ) rescue nil
  rescue => e
    Rails.logger.warn('[SourceProtection] %s' % e.message)
  end
end
