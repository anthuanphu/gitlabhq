# GitLab Source Protection - Middleware (IDE blocking)
# Core enforcement: git_access.rb, repositories_controller.rb, etc.

# Auto-migrate: ensure project_security_settings table exists on boot
# Runs in after_initialize because PostgreSQL is ready at that point
Rails.application.config.after_initialize do
  next if ActiveRecord::Base.connection.table_exists?(:project_security_settings)

  ActiveRecord::Base.connection.create_table :project_security_settings, if_not_exists: true do |t|
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
  Rails.logger.info('[SourceProtection] Auto-created table: project_security_settings')
rescue => e
  Rails.logger.warn('[SourceProtection] Auto-migrate failed: %s' % e.message)
end

# Stub GitlabSecurity module — provides the minimal API the middleware needs.
# All real enforcement is in core (git_access.rb, fork_service.rb, controllers).
module GitlabSecurity
  class << self
    def feature_enabled?(_feature); false; end
    def device_whitelisted?(_ip, _ua = nil); true; end
  end
  module SecurityAuditLog
    def self.log!(**); end
  end
end

root = Rails.root.join('gitlab_security_addon/lib')
if root.exist?
  begin
    $LOAD_PATH.unshift(root.to_s) unless $LOAD_PATH.include?(root.to_s)
    require 'gitlab_security/middleware/security_blocker'
    require 'gitlab_security/middleware/vs_code_detector'
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::SecurityBlocker
    ) rescue nil
    Rails.application.config.middleware.insert_before(
      Gitlab::Middleware::ReadOnly, GitlabSecurity::Middleware::VsCodeDetector
    ) rescue nil
  rescue => e
    Rails.logger.warn('[SourceProtection] %s' % e.message)
  end
end
