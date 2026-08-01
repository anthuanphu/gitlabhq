# frozen_string_literal: true

module GitlabSecurity
  module Security
    # AccessChecker: Central service for checking if a user action is allowed
    # under the current security policies.
    #
    # Usage:
    #   checker = GitlabSecurity::Security::AccessChecker.new(user, :clone, project)
    #   if checker.allowed?
    #     # proceed
    #   else
    #     # blocked: checker.block_reason
    #   end
    class AccessChecker
      attr_reader :user, :action, :project, :block_reason, :policy

      def initialize(user, action, project, request: nil)
        @user = user
        @action = action.to_sym
        @project = project
        @request = request
        @block_reason = nil
        @policy = nil
      end

      # Main check: returns true if action is allowed
      def allowed?
        return true if bypass_security?

        @policy = GitlabSecurity.policy_for(@project)
        return true unless @policy&.enabled?

        # Check each layer of security
        return false if blocked_by_policy?
        return false if blocked_by_ip?
        return false if blocked_by_device?
        return false if blocked_by_time?
        return false if blocked_by_user_agent?

        # Log allowed access
        log_access('allowed')
        true
      end

      # Get detailed reason why access was blocked
      def denial_reason
        return nil if allowed?

        {
          action: @action,
          project: @project&.full_path,
          policy_name: @policy&.name,
          enforcement_level: @policy&.enforcement_level,
          reason: @block_reason,
          timestamp: Time.current.iso8601,
          help: 'Contact your administrator to request access.',
          request_access_path: '/admin/security_policies'
        }
      end

      private

      # Check if user can bypass all security (admin override)
      def bypass_security?
        return false unless @user&.admin?

        # Admin can always bypass unless hard_block level
        return true unless @policy&.enabled? && @policy.enforcement_level == 'hard_block'

        false
      end

      # Check policy-level blocks
      def blocked_by_policy?
        return false unless @policy

        case @action
        when :clone, :download
          if @policy.operation_blocked?(:clone) || @policy.operation_blocked?(:download)
            unless admin_grant?(:clone) || admin_grant?(:download) || admin_grant?(:full_access)
              @block_reason = "Clone/download blocked by policy '#{@policy.name}'"
              log_block('policy_block')
              return true
            end
          end
        when :fork
          if @policy.operation_blocked?(:fork)
            unless admin_grant?(:fork) || admin_grant?(:full_access)
              @block_reason = "Fork blocked by policy '#{@policy.name}'"
              log_block('policy_block_fork')
              return true
            end
          end
        when :share
          if @policy.operation_blocked?(:share)
            unless admin_grant?(:share) || admin_grant?(:full_access)
              @block_reason = "Share blocked by policy '#{@policy.name}'"
              log_block('policy_block_share')
              return true
            end
          end
        when :vscode
          if @policy.operation_blocked?(:vscode_access)
            unless admin_grant?(:vscode) || admin_grant?(:full_access)
              @block_reason = "VS Code access blocked by policy '#{@policy.name}'"
              log_block('policy_block_vscode')
              return true
            end
          end
        when :http_access
          if @policy.operation_blocked?(:http_access)
            unless admin_grant?(:http_access) || admin_grant?(:full_access)
              @block_reason = "HTTP access blocked by policy '#{@policy.name}'"
              log_block('policy_block_http')
              return true
            end
          end
        when :ssh_access
          if @policy.operation_blocked?(:ssh_access)
            unless admin_grant?(:ssh_access) || admin_grant?(:full_access)
              @block_reason = "SSH access blocked by policy '#{@policy.name}'"
              log_block('policy_block_ssh')
              return true
            end
          end
        end

        false
      end

      # Check IP-based blocks
      def blocked_by_ip?
        return false unless @policy && @request

        client_ip = @request.ip

        # Check blocked IPs
        if @policy.ip_blocked?(client_ip)
          @block_reason = "IP #{client_ip} is blocked by security policy"
          log_block('ip_blocked')
          return true
        end

        # Check allowed IPs whitelist
        if @policy.allowed_ip_ranges.present? && !@policy.ip_allowed?(client_ip)
          @block_reason = "IP #{client_ip} is not in the allowed list"
          log_block('ip_not_allowed')
          return true
        end

        # Check global IP whitelist
        if GitlabSecurity.feature_enabled?(:ip_whitelist_enabled)
          unless GitlabSecurity.device_whitelisted?(client_ip)
            @block_reason = 'IP not in global whitelist'
            log_block('ip_not_global_whitelist')
            return true
          end
        end

        false
      end

      # Check device-based blocks
      def blocked_by_device?
        return false unless @request
        return false unless GitlabSecurity.feature_enabled?(:device_whitelist_enabled)

        client_ip = @request.ip
        user_agent = @request.user_agent

        unless GitlabSecurity.device_whitelisted?(client_ip, user_agent)
          @block_reason = 'Device not in approved whitelist'
          log_block('device_not_whitelisted')
          return true
        end

        false
      end

      # Check time-based restrictions
      def blocked_by_time?
        return false unless @policy

        unless @policy.within_allowed_time?
          @block_reason = 'Access outside allowed time window'
          log_block('time_restriction')
          return true
        end

        false
      end

      # Check user-agent based blocks
      def blocked_by_user_agent?
        return false unless @policy && @request

        user_agent = @request.user_agent || ''

        if @policy.user_agent_blocked?(user_agent)
          @block_reason = 'User agent is blocked by security policy'
          log_block('user_agent_blocked')
          return true
        end

        if @policy.allowed_user_agents.present? && !@policy.user_agent_allowed?(user_agent)
          @block_reason = 'User agent is not in allowed list'
          log_block('user_agent_not_allowed')
          return true
        end

        false
      end

      # Check if user has admin-granted exception
      def admin_grant?(grant_type)
        return false unless @user && @project

        GitlabSecurity::SecurityAccessGrant.user_has_grant?(
          user: @user,
          project: @project,
          grant_type: grant_type.to_s
        )
      end

      # Log a blocked access attempt
      def log_block(reason)
        GitlabSecurity::SecurityAuditLog.log!(
          event_type: "#{@action}_blocked",
          result: 'blocked',
          user: @user,
          project: @project,
          security_policy: @policy,
          ip_address: @request&.ip,
          user_agent: @request&.user_agent,
          block_reason: reason,
          details: {
            checker: 'AccessChecker',
            action: @action,
            policy_name: @policy&.name,
            enforcement_level: @policy&.enforcement_level
          }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::AccessChecker] Log error: #{e.message}")
      end

      # Log an allowed access
      def log_access(result)
        GitlabSecurity::SecurityAuditLog.log!(
          event_type: "#{@action}_allowed",
          result: result,
          user: @user,
          project: @project,
          security_policy: @policy,
          ip_address: @request&.ip,
          user_agent: @request&.user_agent,
          details: {
            checker: 'AccessChecker',
            action: @action,
            policy_name: @policy&.name
          }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::AccessChecker] Log error: #{e.message}")
      end
    end
  end
end
