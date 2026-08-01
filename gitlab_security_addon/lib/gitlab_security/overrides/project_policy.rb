# frozen_string_literal: true

# Override for ProjectPolicy (app/policies/project_policy.rb)
# Adds security-specific permission rules to GitLab's declarative policy framework.
# Controls: clone_code, download_code, fork_project, share_project, use_vscode
module GitlabSecurity
  module Overrides
    module ProjectPolicy
      extend ActiveSupport::Concern

      prepended do
        # Security policy conditions
        condition(:security_clone_blocked) { security_policy_blocks?(:clone) }
        condition(:security_download_blocked) { security_policy_blocks?(:download) }
        condition(:security_fork_blocked) { security_policy_blocks?(:fork) }
        condition(:security_share_blocked) { security_policy_blocks?(:share) }
        condition(:security_vscode_blocked) { security_policy_blocks?(:vscode_access) }
        condition(:security_http_blocked) { security_policy_blocks?(:http_access) }
        condition(:security_ssh_blocked) { security_policy_blocks?(:ssh_access) }

        # Admin-granted exception conditions
        condition(:has_admin_clone_grant) { admin_grant_for?(:clone) }
        condition(:has_admin_download_grant) { admin_grant_for?(:download) }
        condition(:has_admin_fork_grant) { admin_grant_for?(:fork) }
        condition(:has_admin_share_grant) { admin_grant_for?(:share) }
        condition(:has_admin_vscode_grant) { admin_grant_for?(:vscode) }
        condition(:has_admin_http_grant) { admin_grant_for?(:http_access) }
        condition(:has_admin_ssh_grant) { admin_grant_for?(:ssh_access) }
        condition(:has_full_access_grant) { admin_grant_for?(:full_access) }

        # Device/IP whitelist conditions
        condition(:device_whitelisted) { device_or_ip_whitelisted? }
        condition(:vscode_device_approved) { vscode_specifically_approved? }

        # Admin bypass condition
        condition(:security_admin_override) { @user&.admin? && !security_policy_blocks_admin? }

        # =====================================================================
        # PERMISSION RULES
        # =====================================================================

        # Download code - blocked if security policy forbids it
        # Admins can always download unless explicitly blocked
        # Users with explicit admin grants can download
        rule { security_download_blocked & ~security_admin_override & ~has_admin_download_grant & ~has_full_access_grant }
          .prevent :download_code

        rule { security_download_blocked & (has_admin_download_grant | has_full_access_grant) }
          .enable :download_code

        # Clone code - blocked if security policy forbids it
        rule { security_clone_blocked & ~security_admin_override & ~has_admin_clone_grant & ~has_full_access_grant }
          .prevent :download_code

        # Fork project - blocked if security policy forbids it
        rule { security_fork_blocked & ~security_admin_override & ~has_admin_fork_grant & ~has_full_access_grant }
          .prevent :fork_project

        rule { security_fork_blocked & (has_admin_fork_grant | has_full_access_grant) }
          .enable :fork_project

        # Share project - blocked if security policy forbids it
        rule { security_share_blocked & ~security_admin_override & ~has_admin_share_grant & ~has_full_access_grant }
          .prevent :share_project

        # HTTP access - blocked if security policy forbids it
        rule { security_http_blocked & ~security_admin_override & ~has_admin_http_grant & ~has_full_access_grant }
          .prevent :download_code

        # SSH access - blocked if security policy forbids it
        rule { security_ssh_blocked & ~security_admin_override & ~has_admin_ssh_grant & ~has_full_access_grant }
          .prevent :download_code

        # VS Code access - blocked if security policy forbids it
        rule { security_vscode_blocked & ~security_admin_override & ~has_admin_vscode_grant & ~has_full_access_grant }
          .prevent :use_vscode

        rule { security_vscode_blocked & (has_admin_vscode_grant | has_full_access_grant) }
          .enable :use_vscode

        # Device whitelist enforcement
        rule { ~device_whitelisted & ~security_admin_override & ~has_full_access_grant }
          .prevent :download_code

        # VS Code device-specific approval
        rule { vscode_device_approved }
          .enable :use_vscode
      end

      private

      # Check if a security policy blocks a specific operation
      def security_policy_blocks?(operation)
        return false unless @subject.is_a?(Project)

        policy = GitlabSecurity.policy_for(@subject)
        return false unless policy&.enabled?

        policy.operation_blocked?(operation) &&
          policy.enforcement_level != 'audit_only'
      end

      # Check if admin operations are also blocked by policy
      def security_policy_blocks_admin?
        return false unless @subject.is_a?(Project)

        policy = GitlabSecurity.policy_for(@subject)
        return false unless policy&.enabled?

        policy.enforcement_level == 'hard_block'
      end

      # Check if user has an admin-granted exception for a specific operation
      def admin_grant_for?(grant_type)
        return false unless @user && @subject.is_a?(Project)

        GitlabSecurity::SecurityAccessGrant.user_has_grant?(
          user: @user,
          project: @subject,
          grant_type: grant_type.to_s
        )
      end

      # Check if the current device/IP is whitelisted
      def device_or_ip_whitelisted?
        return true unless GitlabSecurity.feature_enabled?(:device_whitelist_enabled)

        # Get current request IP from SafeRequestStore
        ip = Gitlab::SafeRequestStore[:client_ip]
        return true if ip.blank?

        user_agent = Gitlab::SafeRequestStore[:client_user_agent]

        GitlabSecurity.device_whitelisted?(ip, user_agent)
      end

      # Check if VS Code specifically is approved for this user/device
      def vscode_specifically_approved?
        return false unless @user

        ip = Gitlab::SafeRequestStore[:client_ip]
        return false if ip.blank?

        # Check device whitelist for VS Code type entries
        GitlabSecurity::DeviceWhitelist.active
          .for_user(@user)
          .where(device_type: 'vscode')
          .for_ip(ip)
          .exists?
      end
    end
  end
end
