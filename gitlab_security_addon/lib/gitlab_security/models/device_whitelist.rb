# frozen_string_literal: true

# DeviceWhitelist model - controls which devices/IPs are explicitly allowed
# Used for BYOD (Bring Your Own Device) scenarios where employees use personal
# computers that need explicit admin approval to connect.
module GitlabSecurity
  class DeviceWhitelist < ApplicationRecord
    self.table_name = 'device_whitelists'

    # Access levels
    READ_ONLY  = 0
    READ_WRITE = 1
    FULL_ACCESS = 2

    # Device types
    DEVICE_TYPES = %w[
      workstation laptop server vscode jetbrains eclipse terminal
      mobile tablet other
    ].freeze

    # Associations
    belongs_to :user, optional: true
    belongs_to :project, optional: true
    belongs_to :group, optional: true
    belongs_to :approved_by, class_name: 'User', optional: true

    # Validations
    validates :device_name, length: { maximum: 255 }
    validates :device_type, inclusion: { in: DEVICE_TYPES, allow_blank: true }
    validates :ip_address, presence: true, unless: :user_agent_pattern_present?
    validates :ip_address, format: { with: Resolv::IPv4::Regex }, allow_blank: true

    # Scopes
    scope :enabled, -> { where(enabled: true) }
    scope :active, -> { enabled.where('expires_at IS NULL OR expires_at > ?', Time.current) }
    scope :for_ip, ->(ip) { where(ip_address: ip) }
    scope :for_user, ->(user) { where(user: user) }
    scope :not_expired, -> { where('expires_at IS NULL OR expires_at > ?', Time.current) }

    # Class methods
    class << self
      # Check if a device/IP is whitelisted for access
      def whitelisted?(ip_address, user_agent = nil, user = nil)
        return false if ip_address.blank?

        # Check for exact IP match
        whitelist = active.for_ip(ip_address)
        whitelist = whitelist.for_user(user) if user.present?
        return true if whitelist.exists?

        # Check for IP range match
        active.find_each do |entry|
          next if entry.ip_range.blank?
          begin
            return true if IPAddr.new(entry.ip_range).include?(ip_address)
          rescue IPAddr::InvalidAddressError
            next
          end
        end

        # Check for user agent pattern match
        if user_agent.present?
          active.where.not(user_agent_pattern: nil).find_each do |entry|
            begin
              return true if user_agent.match?(Regexp.new(entry.user_agent_pattern, Regexp::IGNORECASE))
            rescue RegexpError
              next
            end
          end
        end

        false
      end

      # Find or create a whitelist entry for VS Code
      def whitelist_vscode!(user:, ip_address:, approved_by:)
        create!(
          user: user,
          ip_address: ip_address,
          device_type: 'vscode',
          device_name: "VS Code - #{user.name}",
          user_agent_pattern: 'vscode|Visual Studio Code|Code',
          approved_by: approved_by,
          access_level: READ_WRITE
        )
      end

      # Clean up expired entries
      def cleanup_expired!
        where('expires_at <= ?', Time.current).update_all(enabled: false)
      end
    end

    # Instance methods
    def active?
      enabled? && !expired?
    end

    def expired?
      expires_at.present? && expires_at <= Time.current
    end

    def expire!
      update!(enabled: false, expires_at: Time.current)
    end

    def renew!(duration = 30.days)
      update!(enabled: true, expires_at: duration.from_now)
    end

    def touch_last_used!
      update_column(:last_used_at, Time.current)
    end

    private

    def user_agent_pattern_present?
      user_agent_pattern.present?
    end
  end
end
