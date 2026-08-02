# frozen_string_literal: true

# SecurityAccessGrant model - tracks admin-granted access overrides
# Allows admins to grant temporary or permanent exceptions to security policies
module GitlabSecurity
  class SecurityAccessGrant < ApplicationRecord
    self.table_name = 'security_access_grants'

    # Grant types
    GRANT_TYPES = %w[
      clone download fork share vscode all_ide
      http_access ssh_access full_access
    ].freeze

    # Associations
    belongs_to :user
    belongs_to :project, optional: true
    belongs_to :group, optional: true
    belongs_to :security_policy, optional: true
    belongs_to :granted_by, class_name: 'User', optional: true
    belongs_to :revoked_by, class_name: 'User', optional: true

    # Validations
    validates :grant_type, presence: true, inclusion: { in: GRANT_TYPES }
    validates :user_id, presence: true

    # Scopes
    scope :active, -> { where(active: true).where('expires_at IS NULL OR expires_at > ?', Time.current) }
    scope :permanent, -> { where(permanent: true) }
    scope :temporary, -> { where(permanent: false) }
    scope :expired, -> { where('expires_at <= ?', Time.current).where(active: true) }
    scope :for_user, ->(user) { where(user: user) }
    scope :for_project, ->(project) { where(project: project) }
    scope :for_grant_type, ->(type) { where(grant_type: type) }

    # Class methods
    class << self
      # Check if a user has an active grant for a specific operation
      def user_has_grant?(user:, project:, grant_type:)
        active.for_user(user)
              .for_project(project)
              .for_grant_type(grant_type)
              .exists?
      rescue
        false
      end

      # Check if user has any active grant for a project
      def user_has_any_grant?(user:, project:)
        active.for_user(user).for_project(project).exists?
      rescue
        false
      end

      # Get all active grants for a user
      def user_grants(user, project: nil)
        grants = active.for_user(user)
        grants = grants.for_project(project) if project
        grants
      end

      # Revoke expired grants
      def revoke_expired!
        expired.find_each do |grant|
          grant.revoke!(reason: 'Automatically expired')
        end
      end
    end

    # Instance methods
    def active?
      return false unless self[:active]
      return false if expired?
      true
    end

    def expired?
      expires_at.present? && expires_at <= Time.current
    end

    def permanent?
      self[:permanent]
    end

    def revoke!(revoked_by: nil, reason: nil)
      update!(
        active: false,
        revoked_at: Time.current,
        revoked_by: revoked_by,
        reason: [reason, self.reason].compact.join('; ')
      )

      GitlabSecurity::SecurityAuditLog.log!(
        event_type: 'access_revoked',
        result: 'allowed',
        user: user,
        project: project,
        details: {
          grant_type: grant_type,
          revoked_by: revoked_by&.id,
          reason: reason
        }
      )
    end

    def extend!(new_expiry:, extended_by: nil)
      update!(
        expires_at: new_expiry,
        permanent: new_expiry.nil?
      )

      GitlabSecurity::SecurityAuditLog.log!(
        event_type: 'access_granted',
        result: 'allowed',
        user: user,
        project: project,
        details: {
          grant_type: grant_type,
          extended_by: extended_by&.id,
          new_expiry: new_expiry
        }
      )
    end

    # Scope check: does this grant cover the requested operation?
    def covers?(operation)
      return true if grant_type == 'full_access'

      case operation.to_sym
      when :clone, :download
        %w[clone download full_access].include?(grant_type)
      when :fork
        %w[fork full_access].include?(grant_type)
      when :share
        %w[share full_access].include?(grant_type)
      when :vscode
        %w[vscode all_ide full_access].include?(grant_type)
      when :http_access
        %w[http_access full_access].include?(grant_type)
      when :ssh_access
        %w[ssh_access full_access].include?(grant_type)
      else
        grant_type == 'full_access'
      end
    end
  end
end
