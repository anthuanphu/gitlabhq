# frozen_string_literal: true

Rails.application.config.after_initialize do
  begin
    root = Rails.root.join('gitlab_security_addon')
    next unless root.exist?

    $LOAD_PATH.unshift(root.join('lib').to_s)
    require 'gitlab_security/version'
    Rails.logger.info('[GitlabSecurity] v%s OK' % GitlabSecurity::VERSION)
  rescue => e
    Rails.logger.warn('[GitlabSecurity] %s' % e.message)
  end
end

