Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  next unless root.exist?
  $LOAD_PATH.unshift(root.join('lib').to_s)
  require 'gitlab_security/version'
  require 'gitlab_security/models/security_policy'
  require 'gitlab_security/models/security_audit_log'
  require 'gitlab_security/models/security_access_grant'
  require 'gitlab_security/models/device_whitelist'
  Rails.logger.info('[GitlabSecurity] models loaded')
rescue => e
  Rails.logger.warn('[GitlabSecurity] %s' % e.message)
end
