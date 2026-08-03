# frozen_string_literal: true

class ProjectSecuritySetting < ApplicationRecord
  belongs_to :project, inverse_of: :security_setting

  validates :project_id, presence: true, uniqueness: true

  # Define attributes explicitly so they work even before the DB table exists.
  # Once the table is created, the DB-backed attributes take precedence.
  attribute :enabled, :boolean, default: true
  attribute :allow_clone, :boolean, default: false
  attribute :allow_download, :boolean, default: false
  attribute :allow_fork, :boolean, default: false
  attribute :allow_export, :boolean, default: false
  attribute :allow_ide_access, :boolean, default: false

  scope :with_protection_enabled, -> { where(enabled: true) }

  # Auto-create the table on first access (lazy, no boot delay).
  # Called by admin controller; idempotent via if_not_exists.
  def self.ensure_table!
    return if @table_checked
    @table_checked = true
    return if connection.table_exists?(:project_security_settings)

    connection.create_table :project_security_settings, if_not_exists: true do |t|
      t.bigint :project_id, null: false
      t.index :project_id, unique: true
      t.boolean :allow_clone, default: false, null: false
      t.boolean :allow_download, default: false, null: false
      t.boolean :allow_fork, default: false, null: false
      t.boolean :allow_export, default: false, null: false
      t.boolean :allow_ide_access, default: false, null: false
      t.boolean :enabled, default: true, null: false
      t.timestamps_with_timezone null: false
    end
    Rails.logger.info('[SourceProtection] Table created')
  rescue => e
    @table_checked = false
    Rails.logger.warn('[SourceProtection] %s' % e.message)
  end

  # Check if a specific action is blocked for this project
  def block?(action)
    return false unless enabled?

    case action.to_sym
    when :clone then !allow_clone?
    when :download then !allow_download?
    when :fork then !allow_fork?
    when :export then !allow_export?
    when :ide_access then !allow_ide_access?
    else false
    end
  end

  # Convenience - all operations allowed?
  def all_allowed?
    allow_clone? && allow_download? && allow_fork? && allow_export? && allow_ide_access?
  end
end
