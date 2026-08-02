Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  next unless root.exist?
  lib = root.join('lib')
  $LOAD_PATH.unshift(lib.to_s)

  require 'gitlab_security/version'
  require 'gitlab_security/overrides/git_access'
  Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
  Rails.logger.info('[GitlabSecurity] +GitAccess only')
rescue => e
  Rails.logger.warn('[GitlabSecurity] %s' % e.message)
end

