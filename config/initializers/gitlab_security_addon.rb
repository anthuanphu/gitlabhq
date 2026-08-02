Rails.application.config.after_initialize do
  begin
    root = Rails.root.join('gitlab_security_addon')
    next unless root.exist?
    lib = root.join('lib')
    $LOAD_PATH.unshift(lib.to_s)

    # Load models
    require 'gitlab_security/version'
    require 'gitlab_security/models/security_policy'
    require 'gitlab_security/models/security_audit_log'
    require 'gitlab_security/models/security_access_grant'
    require 'gitlab_security/models/device_whitelist'

    # Overrides
    require 'gitlab_security/overrides/git_access'
    Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)

    require 'gitlab_security/overrides/project_policy'
    ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)

    require 'gitlab_security/overrides/project'
    Project.prepend(GitlabSecurity::Overrides::Project)

    # Middleware
    require 'gitlab_security/middleware/security_blocker'
    require 'gitlab_security/middleware/vs_code_detector'
    if defined?(Gitlab::Middleware::ReadOnly)
      Rails.application.config.middleware.insert_before(Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::SecurityBlocker)
      Rails.application.config.middleware.insert_before(Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::VsCodeDetector)
    end

    Rails.logger.info('[GitlabSecurity] v%s FULL' % GitlabSecurity::VERSION)
  rescue => e
    Rails.logger.warn('[GitlabSecurity] %s' % e.message)
  end
end
