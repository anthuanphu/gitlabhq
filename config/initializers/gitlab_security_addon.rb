# frozen_string_literal: true

# =============================================================================
# GITLAB SECURITY ADDON - Core Initializer (Robust Version)
# =============================================================================

Rails.application.config.after_initialize do
  begin
    addon_root = Rails.root.join('gitlab_security_addon')
    next unless addon_root.exist?

    # Thiết lập autoload paths
    lib = addon_root.join('lib')
    $LOAD_PATH.unshift(lib.to_s) unless $LOAD_PATH.include?(lib.to_s)
    %w[controllers models services helpers].each do |d|
      p = addon_root.join('app', d)
      next unless p.exist?
      ActiveSupport::Dependencies.autoload_paths << p.to_s
      Rails.application.config.eager_load_paths << p.to_s
    end

    require 'gitlab_security/version'

    # Ghi đè GitLab core - mỗi override load độc lập, không kéo theo dependency
    if defined?(Gitlab::GitAccess)
      require 'gitlab_security/overrides/git_access'
      Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
    end

    if defined?(ProjectPolicy)
      require 'gitlab_security/overrides/project_policy'
      ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
    end

    if defined?(Project)
      require 'gitlab_security/overrides/project'
      Project.prepend(GitlabSecurity::Overrides::Project)
    end

    if defined?(Admin::ApplicationSettingsController)
      require 'gitlab_security/admin_settings_extension'
      Admin::ApplicationSettingsController.prepend(GitlabSecurity::AdminSettingsExtension)
    end

    # Middleware
    if defined?(GitlabSecurity::Middleware::SecurityBlocker)
      Rails.application.config.middleware.insert_before(
        Gitlab::Middleware::ReadOnly,
        GitlabSecurity::Middleware::SecurityBlocker
      )
    end

    Rails.logger.info('[GitlabSecurity] v%s loaded' % GitlabSecurity::VERSION)
  rescue => e
    Rails.logger.warn('[GitlabSecurity] Init skipped: %s' % e.message)
  end
end
