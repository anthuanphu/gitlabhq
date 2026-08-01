# frozen_string_literal: true

# Override for Gitlab::Auth
# Adds security addon authentication checks including:
#   - VS Code connection authentication
#   - Device/IP whitelist validation during auth
#   - Security policy enforcement at authentication level
module GitlabSecurity
  module Overrides
    module Auth
      extend ActiveSupport::Concern

      class_methods do
        # Override: find_for_git_client with security addon checks
        def find_for_git_client_with_security(login, password, project:, request:)
          # First, do the normal auth
          result = find_for_git_client_without_security(login, password, project: project, request: request)

          # If auth was successful, apply security checks
          if result.success?
            security_result = apply_security_checks(result, project, request)
            return security_result if security_result
          end

          result
        end

        private

        # Apply security addon checks after successful authentication
        def apply_security_checks(auth_result, project, request)
          return unless project && request

          policy = GitlabSecurity.policy_for(project)
          return unless policy&.enabled?

          user = auth_result.actor
          client_ip = request.ip
          user_agent = request.user_agent || ''

          # Store client info for policy checks
          Gitlab::SafeRequestStore[:client_ip] = client_ip
          Gitlab::SafeRequestStore[:client_user_agent] = user_agent

          # Check VS Code connections
          if vs_code_user_agent?(user_agent)
            unless vscode_access_allowed?(user, project, client_ip)
              log_blocked_auth('vscode_blocked', user, project, client_ip, user_agent)
              return ::Gitlab::Auth::Result.new(
                actor: nil,
                project: project,
                type: :none,
                authentication_abilities: []
              )
            end
          end

          # Check device whitelist
          if GitlabSecurity.feature_enabled?(:device_whitelist_enabled)
            unless GitlabSecurity.device_whitelisted?(client_ip, user_agent)
              log_blocked_auth('device_not_whitelisted', user, project, client_ip, user_agent)
              return ::Gitlab::Auth::Result.new(
                actor: nil,
                project: project,
                type: :none,
                authentication_abilities: []
              )
            end
          end

          # If policy blocks certain operations, strip those abilities
          if policy.operation_blocked?(:clone) || policy.operation_blocked?(:download)
            unless admin_grant_for?(user, project, :clone) || admin_grant_for?(user, project, :download)
              # Remove download ability from auth result
              abilities = auth_result.authentication_abilities - [:download_code]
              auth_result.instance_variable_set(:@authentication_abilities, abilities)
            end
          end

          nil  # No blocking, auth continues
        end

        def vs_code_user_agent?(user_agent)
          return false if user_agent.blank?
          user_agent.match?(/vscode|Visual Studio Code|Code\/[\d.]+/i)
        end

        def vscode_access_allowed?(user, project, client_ip)
          # Check global VS Code block
          return false if GitlabSecurity.feature_enabled?(:block_vscode_connection)

          # Check project-specific policy
          policy = GitlabSecurity.policy_for(project)
          return false if policy&.operation_blocked?(:vscode_access)

          # Check admin grant
          return true if user&.admin?
          return true if admin_grant_for?(user, project, :vscode)

          # Check device whitelist
          if GitlabSecurity.feature_enabled?(:device_whitelist_enabled)
            return GitlabSecurity.device_whitelisted?(client_ip, 'vscode')
          end

          true
        end

        def admin_grant_for?(user, project, grant_type)
          return false unless user && project

          GitlabSecurity::SecurityAccessGrant.user_has_grant?(
            user: user,
            project: project,
            grant_type: grant_type.to_s
          )
        end

        def log_blocked_auth(reason, user, project, client_ip, user_agent)
          GitlabSecurity::SecurityAuditLog.log!(
            event_type: 'http_connection_blocked',
            result: 'blocked',
            user: user,
            project: project,
            ip_address: client_ip,
            user_agent: user_agent,
            block_reason: reason,
            details: {
              component: 'GitlabSecurity::Auth',
              block_reason: reason
            }
          )
        rescue StandardError => e
          Rails.logger.error("[GitlabSecurity::Auth] Log error: #{e.message}")
        end
      end
    end
  end
end
