# frozen_string_literal: true

require 'gitlab_security/version'
require 'gitlab_security/engine'

# Main module for GitLab Security Addon
# Provides enterprise-grade security features:
# - Block download/clone/fork of source code
# - Block sharing of repositories
# - Block external IDE connections (VS Code, etc.)
# - Device/IP whitelisting
# - Comprehensive audit logging
module GitlabSecurity
  # Feature flags for granular control
  FEATURES = %i[
    block_download
    block_clone
    block_fork
    block_share
    block_vscode_connection
    block_ssh_connection
    block_http_connection
    device_whitelist
    ip_whitelist
    audit_logging
  ].freeze

  class << self
    # Get current security configuration
    def config
      @config ||= SecurityConfiguration.new
    end

    # Check if a specific security feature is globally enabled
    def feature_enabled?(feature)
      config.global_setting(feature)
    end

    # Check security policy for a given project
    def policy_for(project)
      SecurityPolicy.find_by(project: project) || SecurityPolicy.global_default
    end

    # Check if a user action is allowed
    def allowed?(user, action, project)
      Security::AccessChecker.new(user, action, project).allowed?
    end

    # Log a security event
    def log_event(event_type, details = {})
      SecurityAuditLog.create!(
        event_type: event_type,
        details: details,
        ip_address: details[:ip_address],
        user_agent: details[:user_agent]
      )
    rescue StandardError => e
      Rails.logger.error("[GitlabSecurity] Failed to log event: #{e.message}")
    end

    # Check if device/IP is whitelisted
    def device_whitelisted?(ip_address, user_agent = nil)
      DeviceWhitelist.whitelisted?(ip_address, user_agent)
    end
  end

  # Configuration container for security settings
  class SecurityConfiguration
    attr_accessor :global_settings

    def initialize
      @global_settings = default_settings
      load_from_database
    end

    def global_setting(key)
      @global_settings[key.to_sym]
    end

    def update_setting(key, value)
      @global_settings[key.to_sym] = value
      save_to_database(key, value)
    end

    private

    def default_settings
      {
        block_download: false,
        block_clone: false,
        block_fork: true,
        block_share: true,
        block_vscode_connection: false,
        block_ssh_connection: false,
        block_http_connection: false,
        device_whitelist_enabled: false,
        ip_whitelist_enabled: false,
        audit_logging: true,
        block_all_external_connections: false,
        admin_approval_required: true
      }
    end

    def load_from_database
      # Load from application_settings or dedicated table
      settings = ApplicationSetting.current_without_cache
      return unless settings.respond_to?(:security_addon_settings)

      stored = settings.security_addon_settings
      @global_settings.merge!(stored.deep_symbolize_keys) if stored.present?
    rescue StandardError => e
      Rails.logger.warn("[GitlabSecurity] Could not load settings: #{e.message}")
    end

    def save_to_database(key, value)
      settings = ApplicationSetting.current_without_cache
      return unless settings.respond_to?(:security_addon_settings=)

      current = settings.security_addon_settings || {}
      current[key.to_s] = value
      settings.update!(security_addon_settings: current)
    rescue StandardError => e
      Rails.logger.error("[GitlabSecurity] Failed to save settings: #{e.message}")
    end
  end
end
