# frozen_string_literal: true

# =============================================================================
# GITLAB SECURITY ADDON - Initializer
# =============================================================================
# This is the ONLY file that needs to be added to the core GitLab codebase.
# It loads the security addon engine and hooks it into GitLab's lifecycle.
#
# When updating GitLab from upstream, only this file needs to be preserved.
# All security addon code resides in the /gitlab_security_addon/ directory.
#
# Installation:
#   1. Copy this file to: config/initializers/gitlab_security_addon.rb
#   2. Ensure gitlab_security_addon/ directory exists at Rails root
#   3. Run: bundle exec rake gitlab_security:install
#   4. Run: bundle exec rake db:migrate
# =============================================================================

# Only load in Rails server context (not in rake tasks or console unless specified)
if defined?(Rails::Server) || ENV['GITLAB_SECURITY_LOAD'] == 'true' || Rails.env.test?
  Rails.application.reloader.to_prepare do
    begin
      # Add security addon paths to Rails autoload paths
      security_addon_root = Rails.root.join('gitlab_security_addon')

      if security_addon_root.exist?
        # Add lib path for Ruby files
        lib_path = security_addon_root.join('lib')
        $LOAD_PATH.unshift(lib_path.to_s) unless $LOAD_PATH.include?(lib_path.to_s)

        # Add app paths
        %w[controllers models services helpers].each do |app_dir|
          dir = security_addon_root.join('app', app_dir)
          if dir.exist?
            ActiveSupport::Dependencies.autoload_paths << dir.to_s
            Rails.application.config.eager_load_paths << dir.to_s
          end
        end

        # Load the main module
        require 'gitlab_security'

        # Apply overrides using GitLab's prepend_mod_with pattern
        # These override core GitLab behavior without modifying core files

        # Override git access control
        if defined?(Gitlab::GitAccess)
          Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
          Rails.logger.info('[GitlabSecurity] GitAccess override applied')
        end

        # Override project policy
        if defined?(ProjectPolicy)
          ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
          Rails.logger.info('[GitlabSecurity] ProjectPolicy override applied')
        end

        # Override project model
        if defined?(Project)
          Project.prepend(GitlabSecurity::Overrides::Project)
          Rails.logger.info('[GitlabSecurity] Project model override applied')
        end

        # Register middleware
        if defined?(Rails.application)
          Rails.application.config.middleware.insert_before(
            Gitlab::Middleware::ReadOnly,
            GitlabSecurity::Middleware::SecurityBlocker
          ) rescue nil

          Rails.application.config.middleware.insert_before(
            Gitlab::Middleware::ReadOnly,
            GitlabSecurity::Middleware::VsCodeDetector
          ) rescue nil

          Rails.logger.info('[GitlabSecurity] Middleware registered')
        end

        # Inject admin settings panel
        if defined?(Admin::ApplicationSettingsController)
          Admin::ApplicationSettingsController.prepend(GitlabSecurity::AdminSettingsExtension)
          Rails.logger.info('[GitlabSecurity] Admin settings extension applied')
        end

        # Mount API endpoints
        if defined?(Grape::API)
          # API endpoints are mounted via the routes configuration
          Rails.logger.info('[GitlabSecurity] API endpoints ready')
        end

        Rails.logger.info('[GitlabSecurity] Security Addon v%s loaded successfully' % GitlabSecurity::VERSION)
      else
        Rails.logger.warn('[GitlabSecurity] Addon directory not found at: %s' % security_addon_root)
      end

    rescue StandardError => e
      Rails.logger.error('[GitlabSecurity] Failed to initialize: %s' % e.message)
      Rails.logger.error('[GitlabSecurity] Backtrace: %s' % e.backtrace&.first(5)&.join("\n"))
    end
  end
end
