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

  Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
  ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
  Project.prepend(GitlabSecurity::Overrides::Project)
  Rails.logger.info('[GitlabSecurity] v%s all overrides OK' % GitlabSecurity::VERSION)
rescue => e
  Rails.logger.warn('[GitlabSecurity] FAIL: %s' % e.message)
end

