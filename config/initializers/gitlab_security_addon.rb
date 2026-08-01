Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  if root.exist?
    $LOAD_PATH.unshift(root.join('lib').to_s)
    require 'gitlab_security/version'
    Rails.logger.info('[GitlabSecurity] v%s OK' % GitlabSecurity::VERSION)
  end
rescue => e
  Rails.logger.warn('[GitlabSecurity] FAIL: %s' % e.message)
end

