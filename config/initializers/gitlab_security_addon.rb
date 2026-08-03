# GitLab Source Protection - Middleware (IDE blocking)
# Core enforcement: git_access.rb, repositories_controller.rb, etc.
#
# NOTE: The project_security_settings table is NOT auto-created here.
# Run ONCE after container is fully up:
#   docker exec <container> gitlab-rails db:migrate
# Model uses attribute declarations so the app works even before the table exists.

# Stub GitlabSecurity module — provides the minimal API the middleware needs.
# All real enforcement is in core (git_access.rb, fork_service.rb, controllers).
module GitlabSecurity
  class << self
    def feature_enabled?(_feature); false; end
    def device_whitelisted?(_ip, _ua = nil); true; end
  end
  module SecurityAuditLog
    def self.log!(**); end
  end
end

root = Rails.root.join('gitlab_security_addon/lib')
if root.exist?
  begin
    $LOAD_PATH.unshift(root.to_s) unless $LOAD_PATH.include?(root.to_s)
    require 'gitlab_security/middleware/security_blocker'
    require 'gitlab_security/middleware/vs_code_detector'
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
