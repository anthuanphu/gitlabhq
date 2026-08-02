Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  next unless root.exist?
  $LOAD_PATH.unshift(root.join('lib').to_s)
  require 'gitlab_security/version'
  require 'gitlab_security/models/security_policy'
  require 'gitlab_security/models/security_audit_log'
  require 'gitlab_security/models/security_access_grant'
  require 'gitlab_security/models/device_whitelist'
  require 'gitlab_security/overrides/git_access'
  Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
  Rails.logger.info('[GitlabSecurity] +GitAccess')
rescue => e
  Rails.logger.warn('[GitlabSecurity] %s' % e.message)
end
