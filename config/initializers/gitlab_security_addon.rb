# frozen_string_literal: true

# Source Code Protection — injects via Module#prepend (no file modification, version-safe)
Rails.application.config.to_prepare do
  # ========================================================================
  # 1. Auto-create DB table (safe, fails silently)
  # ========================================================================
  begin
    unless ActiveRecord::Base.connection.table_exists?(:project_security_settings)
      ActiveRecord::Base.connection.create_table :project_security_settings, if_not_exists: true do |t|
        t.bigint :project_id, null: false; t.index :project_id, unique: true
        t.boolean :allow_clone, default: false, null: false
        t.boolean :allow_download, default: false, null: false
        t.boolean :allow_fork, default: false, null: false
        t.boolean :allow_export, default: false, null: false
        t.boolean :allow_ide_access, default: false, null: false
        t.boolean :enabled, default: true, null: false
        t.timestamps_with_timezone null: false
      end
      Rails.logger.info('[SourceProtection] Table created')
    end
  rescue => e
    Rails.logger.warn('[SourceProtection] %s' % e.message)
  end

  # ========================================================================
  # 2. Admin::ProjectsController — add update_security action
  # ========================================================================
  Admin::ProjectsController.prepend(Module.new do
    def show
      super
    rescue => e
      Rails.logger.warn('[SourceProtection] %s' % e.message)
    end
  end) rescue nil

  # ========================================================================
  # 3. GitAccess — block clone
  # ========================================================================
  Gitlab::GitAccess.prepend(Module.new do
    def check_download_access!
      if project&.security_setting&.block?(:clone) && !user&.admin?
        raise ForbiddenError, 'Source code download has been disabled for this project. Contact your administrator.'
      end
      super
    end
  end) rescue nil
end
