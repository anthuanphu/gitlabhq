# frozen_string_literal: true

# SecurityPolicy model - defines what security restrictions apply to a project/group
# Can be:
#   - Global default (applies to all projects without specific policy)
#   - Project-specific
#   - Group-specific
#   - Namespace-specific
module GitlabSecurity
  class SecurityPolicy < ApplicationRecord
    self.table_name = 'security_policies'

    AUDIT_ONLY  = 0
    SOFT_BLOCK  = 1
    HARD_BLOCK  = 2

    def enforcement_level_audit_only?
      enforcement_level == AUDIT_ONLY
    end

    # Associations
    belongs_to :project, optional: true
    belongs_to :group, optional: true
    belongs_to :namespace, optional: true
    belongs_to :created_by, class_name: 'User', optional: true
    belongs_to :updated_by, class_name: 'User', optional: true

    # Validations
    validates :name, presence: true, length: { maximum: 255 }
    validates :policy_type, presence: true,
              inclusion: { in: %w[global project group namespace] }
    validates :enforcement_level, presence: true

    # Scopes
    scope :enabled, -> { where(enabled: true) }
    scope :global_defaults, -> { where(is_global_default: true, enabled: true) }
    scope :for_project, ->(project) { where(project: project, enabled: true) }
    scope :for_group, ->(group) { where(group: group, enabled: true) }
    scope :active, -> { enabled.where('deleted_at IS NULL') }

    # Class methods
    class << self
      # Get the effective policy for a given project
      # Priority: Project-specific > Group > Namespace > Global default
      def effective_policy_for(project)
        # 1. Check project-specific policy
        policy = for_project(project).first
        return policy if policy

        # 2. Check group policy
        if project.group
          policy = for_group(project.group).first
          return policy if policy
        end

        # 3. Check global default
        global_defaults.first
      end

      # Get global default policy or create one
      def global_default
        policy = global_defaults.first
        return policy if policy

        create!(
          name: 'Global Default Security Policy',
          policy_type: 'global',
          is_global_default: true,
          enforcement_level: :audit_only,
          block_download: false,
          block_clone: false,
          block_fork: true,
          block_share: true,
          block_http_access: false,
          block_ssh_access: false,
          block_vscode_access: false,
          block_all_ide_access: false,
          require_admin_approval: true
        )
      end
    end

    # Instance methods

    # Check if a specific operation is blocked
    def operation_blocked?(operation)
      case operation.to_sym
      when :download then block_download?
      when :clone then block_clone?
      when :fork then block_fork?
      when :share then block_share?
      when :http_access then block_http_access?
      when :ssh_access then block_ssh_access?
      when :vscode_access then block_vscode_access?
      when :all_ide_access then block_all_ide_access?
      else false
      end
    end

    # Get all blocked operations
    def blocked_operations
      ops = []
      ops << :download if block_download?
      ops << :clone if block_clone?
      ops << :fork if block_fork?
      ops << :share if block_share?
      ops << :http_access if block_http_access?
      ops << :ssh_access if block_ssh_access?
      ops << :vscode_access if block_vscode_access?
      ops << :all_ide_access if block_all_ide_access?
      ops
    end

    # Check if an IP is in the allowed list
    def ip_allowed?(ip)
      return true if allowed_ip_ranges.blank?

      allowed_ip_ranges.any? do |range|
        IPAddr.new(range).include?(ip)
      end
    rescue IPAddr::InvalidAddressError
      false
    end

    # Check if an IP is in the blocked list
    def ip_blocked?(ip)
      return false if blocked_ip_ranges.blank?

      blocked_ip_ranges.any? do |range|
        IPAddr.new(range).include?(ip)
      end
    rescue IPAddr::InvalidAddressError
      false
    end

    # Check if user agent matches blocked patterns
    def user_agent_blocked?(user_agent)
      return false if user_agent.blank? || blocked_user_agents.blank?

      blocked_user_agents.any? do |pattern|
        user_agent.match?(Regexp.new(pattern, Regexp::IGNORECASE))
      end
    rescue RegexpError
      false
    end

    # Check if user agent matches allowed patterns
    def user_agent_allowed?(user_agent)
      return true if allowed_user_agents.blank?

      allowed_user_agents.any? do |pattern|
        user_agent.match?(Regexp.new(pattern, Regexp::IGNORECASE))
      end
    rescue RegexpError
      false
    end

    # Check time-based access restrictions
    def within_allowed_time?
      return true if time_restrictions.blank?

      now = Time.current
      current_day = now.wday  # 0=Sunday, 1=Monday, ..., 6=Saturday

      time_restrictions.any? do |restriction|
        restriction = restriction.symbolize_keys
        days = Array(restriction[:day_of_week] || restriction['day_of_week'])
        next false unless days.include?(current_day)

        start_time = restriction[:start_time] || restriction['start_time']
        end_time = restriction[:end_time] || restriction['end_time']
        next true if start_time.blank? || end_time.blank?

        start_parts = start_time.split(':').map(&:to_i)
        end_parts = end_time.split(':').map(&:to_i)
        start_minutes = start_parts[0] * 60 + start_parts[1]
        end_minutes = end_parts[0] * 60 + end_parts[1]
        current_minutes = now.hour * 60 + now.min

        current_minutes >= start_minutes && current_minutes <= end_minutes
      end
    end

    # Soft delete
    def soft_delete!
      update!(deleted_at: Time.current, enabled: false)
    end

    # Reactivate a soft-deleted policy
    def reactivate!
      update!(deleted_at: nil, enabled: true)
    end
  end
end
