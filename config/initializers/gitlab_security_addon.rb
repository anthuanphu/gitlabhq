# frozen_string_literal: true

Rails.application.config.after_initialize do
  begin
    root = Rails.root.join('gitlab_security_addon')
    next unless root.exist?

    $LOAD_PATH.unshift(root.join('lib').to_s)
    %w[controllers models services helpers].each do |d|
      p = root.join('app', d)
      next unless p.exist?
      ActiveSupport::Dependencies.autoload_paths << p.to_s
      Rails.application.config.eager_load_paths << p.to_s
    end

    require 'gitlab_security/version'
    Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess) if defined?(Gitlab::GitAccess)
    ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy) if defined?(ProjectPolicy)
    Project.prepend(GitlabSecurity::Overrides::Project) if defined?(Project)

    Rails.logger.info('[GitlabSecurity] v%s loaded' % GitlabSecurity::VERSION)
  rescue => e
    Rails.logger.warn('[GitlabSecurity] %s' % e.message)
  end
end

