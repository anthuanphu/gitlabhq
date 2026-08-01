# frozen_string_literal: true

# Extension to Admin::ApplicationSettingsController
# Adds "Security" panel to admin settings page
module GitlabSecurity
  module AdminSettingsExtension
    extend ActiveSupport::Concern

    prepended do
      # Add "security" to valid setting panels
      def valid_setting_panels_with_security
        panels = valid_setting_panels_without_security
        panels + %w[security]
      end

      alias_method :valid_setting_panels_without_security, :valid_setting_panels
      alias_method :valid_setting_panels, :valid_setting_panels_with_security
    end

    # GET /admin/application_settings/security
    def security
      @security_config = GitlabSecurity.config
      @recent_blocks = GitlabSecurity::SecurityAuditLog
        .blocked_events
        .recent
        .limit(20)

      render 'admin/application_settings/security'
    end

    # PATCH /admin/application_settings/security
    def update_security
      if update_security_settings
        redirect_to admin_application_settings_security_path,
          notice: _('Security settings saved successfully.')
      else
        render 'admin/application_settings/security'
      end
    end

    private

    # Update security addon specific settings
    def update_security_settings
      settings = ApplicationSetting.current_without_cache

      security_params = params.require(:application_setting).permit(
        security_addon_settings: [
          :block_download,
          :block_clone,
          :block_fork,
          :block_share,
          :block_vscode_connection,
          :block_ssh_connection,
          :block_http_connection,
          :device_whitelist_enabled,
          :ip_whitelist_enabled,
          :audit_logging,
          :block_all_external_connections,
          :admin_approval_required
        ]
      )

      current_settings = settings.security_addon_settings || {}
      new_settings = current_settings.merge(security_params[:security_addon_settings] || {})

      settings.update!(security_addon_settings: new_settings)

      # Clear config cache
      GitlabSecurity.instance_variable_set(:@config, nil)

      true
    rescue StandardError => e
      Rails.logger.error("[GitlabSecurity] Failed to update security settings: #{e.message}")
      false
    end
  end
end
