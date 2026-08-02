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
