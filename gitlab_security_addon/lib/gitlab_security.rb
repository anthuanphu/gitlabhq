# frozen_string_literal: true

require 'gitlab_security/version'

# Main module for GitLab Security Addon
# Provides enterprise-grade security features:
# - Block download/clone/fork of source code
# - Block sharing of repositories
# - Block external IDE connections (VS Code, etc.)
# - Device/IP whitelisting
# - Comprehensive audit logging
module GitlabSecurity
  FEATURES = %i[
    block_download block_clone block_fork block_share
    block_vscode_connection block_ssh_connection block_http_connection
    device_whitelist ip_whitelist audit_logging
  ].freeze

  class << self
    def config
      @config ||= SecurityConfiguration.new
    end

    def feature_enabled?(feature)
      config.global_setting(feature)
    end

    def policy_for(project)
      SecurityPolicy.find_by(project: project) || SecurityPolicy.global_default
    rescue => e
      Rails.logger.warn("[GitlabSecurity] policy_for error: #{e.message}")
      nil
    end

    def allowed?(user, action, project)
      Security::AccessChecker.new(user, action, project).allowed?
    rescue => e
      Rails.logger.warn("[GitlabSecurity] allowed? error: #{e.message}")
      true
    end

    def log_event(event_type, details = {})
      SecurityAuditLog.create!(
        event_type: event_type, details: details,
        ip_address: details[:ip_address], user_agent: details[:user_agent]
      )
    rescue => e
      Rails.logger.error("[GitlabSecurity] log_event error: #{e.message}")
    end

    def device_whitelisted?(ip_address, user_agent = nil)
      DeviceWhitelist.whitelisted?(ip_address, user_agent)
    rescue => e
      Rails.logger.warn("[GitlabSecurity] device_whitelisted? error: #{e.message}")
      true
    end
  end

  # Configuration - fully lazy, no DB access on init
  class SecurityConfiguration
    DEFAULTS = {
      block_download: false, block_clone: false,
      block_fork: true, block_share: true,
      block_vscode_connection: false, block_ssh_connection: false,
      block_http_connection: false, device_whitelist_enabled: false,
      ip_whitelist_enabled: false, audit_logging: true,
      block_all_external_connections: false, admin_approval_required: true
    }.freeze

    def global_setting(key)
      from_db(key) || DEFAULTS[key.to_sym]
    end

    private

    def from_db(key)
      return unless defined?(ApplicationSetting)
      settings = ApplicationSetting.current_without_cache
      return unless settings.respond_to?(:security_addon_settings)
      stored = settings.security_addon_settings
      stored&.dig(key.to_s)
    rescue => e
      Rails.logger.warn("[GitlabSecurity] Config read error: #{e.message}")
      nil
    end
  end
end
