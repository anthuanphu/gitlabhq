# frozen_string_literal: true

require 'gitlab_security/version'

module GitlabSecurity
  class Engine < ::Rails::Engine
    isolate_namespace GitlabSecurity
    engine_name 'gitlab_security'

    # Load security overrides using GitLab's prepend_mod_with pattern
    initializer 'gitlab_security.load_overrides', before: :load_config_initializers do |app|
      require_dependency 'gitlab_security/overrides/git_access'
      require_dependency 'gitlab_security/overrides/project_policy'
      require_dependency 'gitlab_security/overrides/auth'
      require_dependency 'gitlab_security/overrides/project'
    end

    # Register middleware for connection security
    initializer 'gitlab_security.middleware', after: :load_config_initializers do |app|
      app.config.middleware.insert_before(
        Gitlab::Middleware::ReadOnly,
        GitlabSecurity::Middleware::SecurityBlocker
      )
      app.config.middleware.insert_before(
        Gitlab::Middleware::ReadOnly,
        GitlabSecurity::Middleware::VsCodeDetector
      )
    end

    # Add security routes to admin namespace
    initializer 'gitlab_security.routes', after: :add_routing_paths do |app|
      app.routes.prepend do
        scope path: '/admin', as: :admin do
          resources :security_policies, controller: 'gitlab_security/admin/security_policies' do
            member do
              post :toggle
            end
            collection do
              get :audit_log
            end
          end
          resources :device_whitelists, controller: 'gitlab_security/admin/device_whitelists'
        end
      end
    end

    # Load helpers
    initializer 'gitlab_security.helpers' do
      ActiveSupport.on_load(:action_view) do
        include GitlabSecurity::ApplicationHelper
      end
    end

    config.after_initialize do
      # Inject security panel into admin settings
      Admin::ApplicationSettingsController.prepend(GitlabSecurity::AdminSettingsExtension)
    end
  end
end
