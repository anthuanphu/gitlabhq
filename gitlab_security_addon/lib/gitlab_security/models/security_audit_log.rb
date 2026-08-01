# frozen_string_literal: true

# SecurityAuditLog model - comprehensive audit trail for security events
module GitlabSecurity
  class SecurityAuditLog < ApplicationRecord
    self.table_name = 'security_audit_logs'

    # Event types
    EVENT_TYPES = %w[
      clone_attempt clone_blocked clone_allowed
      download_attempt download_blocked download_allowed
      fork_attempt fork_blocked fork_allowed
      share_attempt share_blocked share_allowed
      vscode_connection_attempt vscode_connection_blocked vscode_connection_allowed
      ssh_connection_attempt ssh_connection_blocked ssh_connection_allowed
      http_connection_attempt http_connection_blocked http_connection_allowed
      device_blocked device_allowed
      policy_created policy_updated policy_deleted
      access_granted access_revoked
      admin_override
      security_policy_violation
      suspicious_activity_detected
    ].freeze

    # Results
    RESULTS = %w[allowed blocked error unknown].freeze

    # Associations
    belongs_to :user, optional: true
    belongs_to :project, optional: true
    belongs_to :security_policy, optional: true
    belongs_to :actor, class_name: 'User', optional: true

    # Validations
    validates :event_type, presence: true, inclusion: { in: EVENT_TYPES }
    validates :result, presence: true, inclusion: { in: RESULTS }
    validates :created_at, presence: true

    # Scopes
    scope :recent, -> { order(created_at: :desc) }
    scope :blocked_events, -> { where(result: 'blocked') }
    scope :allowed_events, -> { where(result: 'allowed') }
    scope :for_user, ->(user) { where(user: user) }
    scope :for_project, ->(project) { where(project: project) }
    scope :for_ip, ->(ip) { where(ip_address: ip) }
    scope :today, -> { where('created_at >= ?', Time.current.beginning_of_day) }
    scope :this_week, -> { where('created_at >= ?', 1.week.ago) }
    scope :this_month, -> { where('created_at >= ?', 1.month.ago) }
    scope :by_type, ->(type) { where(event_type: type) }

    # Class methods
    class << self
      # Log a security event
      def log!(event_type:, result: 'unknown', **options)
        create!(
          event_type: event_type,
          result: result,
          user: options[:user],
          project: options[:project],
          security_policy: options[:security_policy],
          ip_address: options[:ip_address],
          user_agent: options[:user_agent],
          http_method: options[:http_method],
          request_path: options[:request_path],
          protocol: options[:protocol],
          block_reason: options[:block_reason],
          details: options[:details] || {},
          actor: options[:actor],
          created_at: Time.current
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::AuditLog] Failed to log: #{e.message}")
        nil
      end

      # Get statistics for a time period
      def statistics(since: 1.day.ago, upto: Time.current)
        base = where(created_at: since..upto)

        {
          total_events: base.count,
          blocked_events: base.where(result: 'blocked').count,
          allowed_events: base.where(result: 'allowed').count,
          unique_ips: base.distinct.count(:ip_address),
          unique_users: base.distinct.count(:user_id),
          top_blocked_ips: base.where(result: 'blocked')
                             .group(:ip_address)
                             .order('count_id DESC')
                             .limit(10)
                             .count(:id),
          top_event_types: base.group(:event_type)
                              .order('count_id DESC')
                              .limit(10)
                              .count(:id),
          events_by_day: base.group("DATE(created_at)")
                            .order('date_created_at DESC')
                            .limit(30)
                            .count(:id)
        }
      end

      # Detect suspicious activity patterns
      def detect_suspicious_activity(user:, threshold: 50, window: 5.minutes)
        recent_count = where(user: user)
                        .where('created_at > ?', window.ago)
                        .where(result: 'blocked')
                        .count

        if recent_count >= threshold
          log!(
            event_type: 'suspicious_activity_detected',
            result: 'blocked',
            user: user,
            details: {
              blocked_count: recent_count,
              time_window_seconds: window.to_i,
              threshold: threshold
            }
          )
          true
        else
          false
        end
      end

      # Clean up old logs (retention policy)
      def cleanup_old_logs!(retention_days: 90)
        where('created_at < ?', retention_days.days.ago).delete_all
      end
    end
  end
end
