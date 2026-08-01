# frozen_string_literal: true

module GitlabSecurity
  module Overrides
    module Project
      extend ActiveSupport::Concern

      def clone_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?
        return true if policy.enforcement_level == 'audit_only'
        return false if policy.operation_blocked?(:clone) || policy.operation_blocked?(:download)
        true
      rescue => e
        Rails.logger.warn("[GitlabSecurity] clone_allowed? error: #{e.message}")
        true
      end

      def fork_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?
        return false if policy.operation_blocked?(:fork)
        true
      rescue => e
        Rails.logger.warn("[GitlabSecurity] fork_allowed? error: #{e.message}")
        true
      end

      def share_allowed?(user = nil)
        policy = GitlabSecurity.policy_for(self)
        return true unless policy&.enabled?
        return false if policy.operation_blocked?(:share)
        true
      rescue => e
        Rails.logger.warn("[GitlabSecurity] share_allowed? error: #{e.message}")
        true
      end
    end
  end
end
