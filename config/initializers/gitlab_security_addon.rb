Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  next unless root.exist?

  lib = root.join('lib')
  $LOAD_PATH.unshift(lib.to_s)

  require 'gitlab_security/version'
  require 'gitlab_security/models/security_policy'
  require 'gitlab_security/models/security_audit_log'
  require 'gitlab_security/models/security_access_grant'
  require 'gitlab_security/models/device_whitelist'
  require 'gitlab_security/overrides/git_access'
  require 'gitlab_security/overrides/project_policy'
  require 'gitlab_security/overrides/project'
  require 'gitlab_security/middleware/security_blocker'
  require 'gitlab_security/middleware/vs_code_detector'

  Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
  ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
  Project.prepend(GitlabSecurity::Overrides::Project)

  if defined?(Gitlab::Middleware::ReadOnly)
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly,
      GitlabSecurity::Middleware::SecurityBlocker
    )
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly,
      GitlabSecurity::Middleware::VsCodeDetector
    )
  end

  Rails.logger.info('[GitlabSecurity] v%s FULL' % GitlabSecurity::VERSION)
rescue => e
  Rails.logger.warn('[GitlabSecurity] %s' % e.message)
end

