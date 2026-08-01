# frozen_string_literal: true

# Routes for GitLab Security Addon
# Admin namespace routes are mounted under /admin
Rails.application.routes.draw do
  # API routes for security management
  mount GitlabSecurity::API::SecurityPolicies => '/'

  # Admin panel routes for security
  namespace :admin do
    resources :security_policies, controller: 'gitlab_security/admin/security_policies' do
      member do
        post :toggle
      end
      collection do
        get :audit_log
        post :bulk_update
      end
    end

    resources :device_whitelists, controller: 'gitlab_security/admin/device_whitelists' do
      member do
        post :renew
        post :revoke
      end
      collection do
        post :bulk_whitelist
      end
    end

    # Security access grants management
    resources :security_access_grants, controller: 'gitlab_security/admin/security_access_grants' do
      member do
        post :revoke
        post :extend
      end
    end

    # Add security panel to admin settings
    scope path: 'application_settings', as: :application_settings do
      get 'security', to: 'application_settings#security'
      patch 'security', to: 'application_settings#update_security'
    end
  end
end
