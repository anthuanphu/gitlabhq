# frozen_string_literal: true

# Auto-create table + inject admin security UI
Rails.application.config.to_prepare do
  # 1. Create table
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

  # 2. Inject @security_setting into Admin::ProjectsController#show
  Admin::ProjectsController.prepend(Module.new do
    def show
      @security_setting = begin
        ProjectSecuritySetting.ensure_table!
        if ActiveRecord::Base.connection.table_exists?(:project_security_settings)
          @project.security_setting || @project.build_security_setting
        else
          @project.build_security_setting
        end
      rescue => e
        Rails.logger.warn('[SourceProtection] %s' % e.message)
        @project.build_security_setting
      end
      super
    end

    def update_security
      ProjectSecuritySetting.ensure_table!
      setting = begin
        if ActiveRecord::Base.connection.table_exists?(:project_security_settings)
          @project.security_setting || @project.build_security_setting
        else
          @project.build_security_setting
        end
      end
      setting.assign_attributes(
        params.require(:project_security_setting).permit(:allow_clone, :allow_download, :allow_fork, :allow_export, :allow_ide_access, :enabled)
      )
      if setting.save
        redirect_to admin_project_path(@project), notice: 'Security settings updated.'
      else
        redirect_to admin_project_path(@project), alert: setting.errors.full_messages.join(', ')
      end
    end
  end) rescue nil
end
