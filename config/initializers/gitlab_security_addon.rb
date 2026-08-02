Rails.application.config.after_initialize do
  root = Rails.root.join('gitlab_security_addon')
  if root.exist?
    $LOAD_PATH.unshift(root.join('lib').to_s)
  end
  Rails.logger.info('[GitlabSecurity] load path only')
rescue => e
  Rails.logger.warn('[GitlabSecurity] %s' % e.message)
end
