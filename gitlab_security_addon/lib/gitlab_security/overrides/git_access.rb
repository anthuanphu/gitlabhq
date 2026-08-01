# frozen_string_literal: true

# Override for Gitlab::GitAccess
# Injects security checks into GitLab's git access control flow.
# Uses the same prepend pattern that GitLab EE uses for extending CE.
#
# This override hooks into:
#   - check_download_access!  → Block unauthorized clone/download
#   - check_push_access!      → Block unauthorized push
#   - check_additional_conditions! → Additional security checks (EE hook point)
#   - check_custom_ssh_action! → Block SSH access per policy
module GitlabSecurity
  module Overrides
    module GitAccess
      extend ActiveSupport::Concern

      prepended do
        # No additional setup needed - we override methods below
      end

      # Override: Add security policy check before download
      def check_download_access!
        # First, check security policy
        security_check_result = check_security_policy_for_download
        return security_check_result if security_check_result

        # Then proceed with normal download access check
        super
      end

      # Override: Add security policy check before push
      def check_push_access!
        # Check security policy for push operations
        security_check_result = check_security_policy_for_push
        return security_check_result if security_check_result

        # Then proceed with normal push access check
        super
      end

      # Hook into EE extension point for additional security checks
      def check_additional_conditions!
        # Security policy check for any additional conditions
        security_result = check_security_policy_conditions
        return security_result if security_result

        # Call original (EE override) if exists
        super if defined?(super)
      end

      # Hook into EE extension point for custom SSH actions
      def check_custom_ssh_action!
        # Security check for SSH operations
        ssh_check_result = check_security_policy_for_ssh
        return ssh_check_result if ssh_check_result

        # Call original (EE override) if exists
        super if defined?(super)
      end

      private

      # Check security policy for download (clone/pull) operations
      def check_security_policy_for_download
        return unless project

        policy = GitlabSecurity.policy_for(project)
        return unless policy&.enabled?

        # Check if clone/download is blocked
        if policy.operation_blocked?(:clone) || policy.operation_blocked?(:download)
          if policy.enforcement_level == 'hard_block'
            # Check if user has explicit admin-granted access
            user = try(:user)
            if user && GitlabSecurity::SecurityAccessGrant.user_has_grant?(
              user: user, project: project, grant_type: 'clone'
            )
              # Admin has granted this user explicit clone access
              log_security_event('clone_allowed_admin_override', 'allowed')
              return nil
            end

            log_security_event('clone_blocked', 'blocked')
            return ::Gitlab::GitAccessResult::Failure.new(
              'Clone/download access denied by security policy. ' \
              'Contact your administrator to request access.',
              status: 403
            )
          elsif policy.enforcement_level == 'soft_block'
            log_security_event('clone_soft_blocked', 'blocked')
            # Soft block - still block but with different message
            return ::Gitlab::GitAccessResult::Failure.new(
              'Clone/download access restricted. An access request has been logged.',
              status: 403
            )
          elsif policy.enforcement_level == 'audit_only'
            # Just audit, don't block
            log_security_event('clone_audit', 'allowed')
            return nil
          end
        end

        # Check IP restrictions
        if policy.blocked_ip_ranges.present?
          client_ip = try(:request)&.ip
          if client_ip && policy.ip_blocked?(client_ip)
            log_security_event('clone_blocked_ip', 'blocked')
            return ::Gitlab::GitAccessResult::Failure.new(
              'Access denied from your IP address by security policy.',
              status: 403
            )
          end
        end

        # Check allowed IPs (if whitelist is configured)
        if policy.allowed_ip_ranges.present?
          client_ip = try(:request)&.ip
          if client_ip && !policy.ip_allowed?(client_ip)
            log_security_event('clone_blocked_ip_not_allowed', 'blocked')
            return ::Gitlab::GitAccessResult::Failure.new(
              'Your IP is not in the allowed list for this project.',
              status: 403
            )
          end
        end

        # Check time-based restrictions
        unless policy.within_allowed_time?
          log_security_event('clone_blocked_time', 'blocked')
          return ::Gitlab::GitAccessResult::Failure.new(
            'Access is restricted during this time period.',
            status: 403
          )
        end

        nil  # All security checks passed
      end

      # Check security policy for push operations
      def check_security_policy_for_push
        # For now, push operations are less commonly blocked
        # But we can add push-specific checks here
        nil
      end

      # Check security policy for additional conditions (EE hook)
      def check_security_policy_conditions
        return unless project

        policy = GitlabSecurity.policy_for(project)
        return unless policy&.enabled?

        # Block sharing checks
        if policy.operation_blocked?(:share)
          log_security_event('share_blocked', 'blocked')
          return ::Gitlab::GitAccessResult::Failure.new(
            'Project sharing is disabled by security policy.',
            status: 403
          )
        end

        nil
      end

      # Check security policy for SSH access
      def check_security_policy_for_ssh
        return unless project

        policy = GitlabSecurity.policy_for(project)
        return unless policy&.enabled?

        if policy.operation_blocked?(:ssh_access) && protocol == 'ssh'
          log_security_event('ssh_blocked', 'blocked')
          return ::Gitlab::GitAccessResult::Failure.new(
            'SSH access is disabled by security policy. Please use HTTPS.',
            status: 403
          )
        end

        if policy.operation_blocked?(:http_access) && protocol == 'http'
          log_security_event('http_blocked', 'blocked')
          return ::Gitlab::GitAccessResult::Failure.new(
            'HTTP access is disabled by security policy. Please use SSH.',
            status: 403
          )
        end

        nil
      end

      # Log security events for auditing
      def log_security_event(event_type, result)
        user_identifier = nil
        user_identifier = user.id if respond_to?(:user) && user.present?
        user_identifier = actor.id if !user_identifier && respond_to?(:actor) && actor.present?

        client_ip = nil
        client_ip = request.ip if respond_to?(:request) && request.present?

        GitlabSecurity::SecurityAuditLog.log!(
          event_type: event_type,
          result: result,
          user_id: user_identifier,
          project: project,
          security_policy: GitlabSecurity.policy_for(project),
          ip_address: client_ip,
          protocol: respond_to?(:protocol) ? protocol : nil,
          details: {
            access_type: self.class.name,
            project_path: project&.full_path,
            enforcement_level: GitlabSecurity.policy_for(project)&.enforcement_level
          }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::GitAccess] Audit log error: #{e.message}")
      end
    end
  end
end
