# frozen_string_literal: true

class CreateProjectSecuritySettings < Gitlab::Database::Migration[2.3]
  milestone '19.2'

  def up
    create_table :project_security_settings, if_not_exists: true do |t|
      t.references :project, null: false, index: { unique: true }
      t.boolean :allow_clone, default: false, null: false
      t.boolean :allow_download, default: false, null: false
      t.boolean :allow_fork, default: false, null: false
      t.boolean :allow_export, default: false, null: false
      t.boolean :allow_ide_access, default: false, null: false
      t.boolean :enabled, default: true, null: false
      t.timestamps_with_timezone null: false
    end
  end

  def down
    drop_table :project_security_settings, if_exists: true
  end
end
