# frozen_string_literal: true

# Migration: Create core security tables for GitLab Security Addon
# Tables:
#   security_policies      - Per-project/global security policies
#   device_whitelists      - Whitelisted devices and IPs
#   security_audit_logs    - Audit trail for security events
#   security_access_grants - Admin-granted access permissions
class CreateGitlabSecurityTables < Gitlab::Database::Migration[2.3]
  def up
    # =========================================================================
    # Security Policies Table
    # Defines what operations are blocked/allowed for projects and groups
    # =========================================================================
    create_table :security_policies, if_not_exists: true do |t|
      t.references :project, null: true, foreign_key: { on_delete: :cascade }
      t.references :group, null: true, foreign_key: { on_delete: :cascade }
      t.references :namespace, null: true, foreign_key: { on_delete: :cascade }

      # Policy type: 'global', 'project', 'group'
      t.string :policy_type, null: false, default: 'project', limit: 50

      # Policy name and description
      t.string :name, null: false, limit: 255
      t.text :description

      # Access control booleans
      t.boolean :block_download, default: false, null: false
      t.boolean :block_clone, default: false, null: false
      t.boolean :block_fork, default: false, null: false
      t.boolean :block_share, default: false, null: false
      t.boolean :block_http_access, default: false, null: false
      t.boolean :block_ssh_access, default: false, null: false
      t.boolean :block_vscode_access, default: false, null: false
      t.boolean :block_all_ide_access, default: false, null: false
      t.boolean :require_admin_approval, default: true, null: false
      t.boolean :block_all_external_tools, default: false, null: false

      # Enforcement level
      t.integer :enforcement_level, default: 0, null: false
      # 0 = audit_only (log but don't block)
      # 1 = soft_block (block with override capability)
      # 2 = hard_block (absolute block, no override)

      # Status
      t.boolean :enabled, default: true, null: false
      t.boolean :is_global_default, default: false, null: false

      # Allowed IP ranges (JSON array)
      t.jsonb :allowed_ip_ranges, default: []

      # Allowed User-Agent patterns (JSON array)
      t.jsonb :allowed_user_agents, default: []

      # Blocked IP ranges
      t.jsonb :blocked_ip_ranges, default: []

      # Blocked User-Agent patterns
      t.jsonb :blocked_user_agents, default: []

      # Time-based restrictions
      t.jsonb :time_restrictions, default: []
      # Format: [{ day_of_week: 1..7, start_time: '09:00', end_time: '18:00' }]

      t.timestamps_with_timezone
      t.datetime_with_timezone :deleted_at

      t.references :created_by, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
      t.references :updated_by, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
    end

    add_index :security_policies, :policy_type, name: 'idx_security_policies_on_policy_type'
    add_index :security_policies, [:project_id, :enabled], name: 'idx_security_policies_on_project_enabled'
    add_index :security_policies, [:group_id, :enabled], name: 'idx_security_policies_on_group_enabled'
    add_index :security_policies, :is_global_default, name: 'idx_security_policies_on_global_default'

    # =========================================================================
    # Device Whitelists Table
    # Controls which devices/IPs are explicitly allowed to connect
    # =========================================================================
    create_table :device_whitelists, if_not_exists: true do |t|
      t.references :user, null: true, foreign_key: { on_delete: :cascade }
      t.references :project, null: true, foreign_key: { on_delete: :cascade }
      t.references :group, null: true, foreign_key: { on_delete: :cascade }

      # Device identification
      t.string :device_name, limit: 255
      t.string :device_type, limit: 100
      # device_type: 'workstation', 'laptop', 'server', 'vscode', 'jetbrains', etc.

      # IP-based identification
      t.string :ip_address, limit: 45       # IPv4/IPv6
      t.string :ip_range, limit: 45         # CIDR notation
      t.string :mac_address, limit: 17

      # Agent-based identification
      t.string :user_agent_pattern, limit: 500
      t.string :user_agent_hash, limit: 64

      # Device fingerprint (for advanced identification)
      t.string :device_fingerprint, limit: 255

      # Access scope
      t.integer :access_level, default: 0, null: false
      # 0 = read_only, 1 = read_write, 2 = full_access

      # Status
      t.boolean :enabled, default: true, null: false
      t.datetime_with_timezone :expires_at
      t.datetime_with_timezone :last_used_at

      t.timestamps_with_timezone
      t.datetime_with_timezone :deleted_at

      t.references :approved_by, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
    end

    add_index :device_whitelists, :ip_address, name: 'idx_device_whitelists_on_ip'
    add_index :device_whitelists, [:user_id, :enabled], name: 'idx_device_whitelists_on_user_enabled'
    add_index :device_whitelists, :device_fingerprint, name: 'idx_device_whitelists_on_fingerprint'

    # =========================================================================
    # Security Audit Logs Table
    # Comprehensive audit trail for all security events
    # =========================================================================
    create_table :security_audit_logs, if_not_exists: true do |t|
      t.references :user, null: true, foreign_key: { on_delete: :nullify }
      t.references :project, null: true, foreign_key: { on_delete: :nullify }
      t.references :security_policy, null: true, foreign_key: { on_delete: :nullify }

      # Event classification
      t.string :event_type, null: false, limit: 100
      # event_type values:
      #   'clone_attempt', 'clone_blocked', 'clone_allowed'
      #   'download_attempt', 'download_blocked', 'download_allowed'
      #   'fork_attempt', 'fork_blocked', 'fork_allowed'
      #   'share_attempt', 'share_blocked', 'share_allowed'
      #   'vscode_connection_attempt', 'vscode_connection_blocked'
      #   'ssh_connection_attempt', 'ssh_connection_blocked'
      #   'http_connection_attempt', 'http_connection_blocked'
      #   'device_blocked', 'device_allowed'
      #   'policy_created', 'policy_updated', 'policy_deleted'
      #   'access_granted', 'access_revoked'

      # Action result
      t.string :result, null: false, default: 'unknown', limit: 50
      # 'allowed', 'blocked', 'error', 'unknown'

      # Block reason (if blocked)
      t.string :block_reason, limit: 500

      # Request details
      t.string :ip_address, limit: 45
      t.string :user_agent, limit: 1000
      t.string :http_method, limit: 10
      t.string :request_path, limit: 2000
      t.string :protocol, limit: 10  # 'http', 'https', 'ssh'

      # Additional metadata (JSON)
      t.jsonb :details, default: {}

      t.datetime_with_timezone :created_at, null: false

      t.references :actor, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
    end

    add_index :security_audit_logs, :event_type, name: 'idx_security_audit_logs_on_event_type'
    add_index :security_audit_logs, :created_at, name: 'idx_security_audit_logs_on_created_at'
    add_index :security_audit_logs, [:user_id, :event_type], name: 'idx_security_audit_logs_on_user_event'
    add_index :security_audit_logs, [:ip_address, :created_at], name: 'idx_security_audit_logs_on_ip_created'
    add_index :security_audit_logs, :result, name: 'idx_security_audit_logs_on_result'

    # =========================================================================
    # Security Access Grants Table
    # Tracks admin-granted temporary/permanent access overrides
    # =========================================================================
    create_table :security_access_grants, if_not_exists: true do |t|
      t.references :user, null: false, foreign_key: { on_delete: :cascade }
      t.references :project, null: true, foreign_key: { on_delete: :cascade }
      t.references :group, null: true, foreign_key: { on_delete: :cascade }
      t.references :security_policy, null: true, foreign_key: { on_delete: :nullify }

      # Grant type
      t.string :grant_type, null: false, limit: 100
      # 'clone', 'download', 'fork', 'share', 'vscode', 'full_access'

      # Duration
      t.datetime_with_timezone :expires_at
      t.boolean :permanent, default: false, null: false

      # Status
      t.boolean :active, default: true, null: false
      t.datetime_with_timezone :revoked_at

      # Reason for grant
      t.text :reason

      t.timestamps_with_timezone

      t.references :granted_by, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
      t.references :revoked_by, null: true, foreign_key: { to_table: :users, on_delete: :nullify }
    end

    add_index :security_access_grants, [:user_id, :project_id, :grant_type],
      name: 'idx_security_access_grants_on_user_project_type'
    add_index :security_access_grants, [:active, :expires_at],
      name: 'idx_security_access_grants_on_active_expires'

    # =========================================================================
    # Add security settings column to application_settings
    # =========================================================================
    unless column_exists?(:application_settings, :security_addon_settings)
      add_column :application_settings, :security_addon_settings, :jsonb, default: {}
    end
  end

  def down
    remove_column :application_settings, :security_addon_settings if column_exists?(:application_settings, :security_addon_settings)
    drop_table :security_access_grants, if_exists: true
    drop_table :security_audit_logs, if_exists: true
    drop_table :device_whitelists, if_exists: true
    drop_table :security_policies, if_exists: true
  end
end
