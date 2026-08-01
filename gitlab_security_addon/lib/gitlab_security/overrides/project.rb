# frozen_string_literal: true

# Override for Project model
# Adds security-related methods to the Project model:
#   - security_policy association
#   - Fork prevention
#   - Share prevention
#   - Clone/download prevention checks
module GitlabSecurity
  module Overrides
    module Project
      extend ActiveSupport::Concern

      prepended do
        # Association with security policies
        has_many :security_policies,
          class_name: 'GitlabSecurity::SecurityPolicy',
          foreign_key: :project_id,
          dependent: :destroy

        has_many :security_access_grants,
          class_name: 'GitlabSecurity::SecurityAccessGrant',
          foreign_key: :project_id,
          dependent: :destroy

        # Security-related validations/callbacks
        before_destroy :check_security_policy_before_destroy, prepend: true
      end

      # =========================================================================
      # Security Checks
      # =========================================================================

      # Check if clone/download is currently allowed for this project
      def clone_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?

        if policy.operation_blocked?(:clone) || policy.operation_blocked?(:download)
          return false if policy.enforcement_level == 'hard_block'
          return false if policy.enforcement_level == 'soft_block'

          # Check user-specific grants
          if user && GitlabSecurity::SecurityAccessGrant.user_has_grant?(
            user: user, project: self, grant_type: 'clone'
          )
            return true
          end

          return false unless policy.enforcement_level == 'audit_only'
        end

        true
      end

      # Check if forking is currently allowed for this project
      def fork_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?

        if policy.operation_blocked?(:fork)
          return false if user.nil? || !user.admin?

          # Check admin grant
          return true if GitlabSecurity::SecurityAccessGrant.user_has_grant?(
            user: user, project: self, grant_type: 'fork'
          )

          return false
        end

        true
      end

      # Check if sharing is currently allowed for this project
      def share_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?

        if policy.operation_blocked?(:share)
          return true if user&.admin?
          return false
        end

        true
      end

      # Check if VS Code access is allowed for this project
      def vscode_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?

        if policy.operation_blocked?(:vscode_access)
          return true if user&.admin?

          return true if user && GitlabSecurity::SecurityAccessGrant.user_has_grant?(
            user: user, project: self, grant_type: 'vscode'
          )

          return false
        end

        true
      end

      # Get effective security policy for this project
      def effective_security_policy
        GitlabSecurity.policy_for(self)
      end

      # Check if project is under any active security restrictions
      def security_restricted?
        policy = effective_security_policy
        return false unless policy&.enabled?

        policy.blocked_operations.any?
      end

      # Get list of blocked operations for this project
      def blocked_operations
        policy = effective_security_policy
        return [] unless policy&.enabled?

        policy.blocked_operations
      end

      private

      # Prevent deletion if security policy requires it
      def check_security_policy_before_destroy
        policy = effective_security_policy
        if policy&.enabled? && policy.enforcement_level == 'hard_block'
          errors.add(:base, 'Cannot delete project: protected by security policy')
          throw :abort
        end
      end
    end
  end
end
