FROM gitlab/gitlab-ce:latest

# Bump this line to bust Docker build cache when deploying changes
ARG CACHE_BUST=11

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    GITLAB_OMNIBUS_CONFIG="external_url 'https://git.aurixsystems.vn'; nginx['listen_port'] = 80; nginx['listen_https'] = false; nginx['proxy_set_headers'] = { 'X-Forwarded-Proto' => 'https', 'X-Forwarded-Ssl' => 'on' }; puma['worker_processes'] = 2; sidekiq['max_concurrency'] = 10; postgresql['shared_buffers'] = '256MB'; prometheus_monitoring['enable'] = false"

# Source Code Protection — create files inline (bypass .dockerignore)
RUN cat <<'RUBY' > ${GITLAB_RAILS_DIR}/config/initializers/gitlab_security_addon.rb
# frozen_string_literal: true
Rails.application.config.after_initialize do
  Thread.new do
    sleep 5
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
  end
  Admin::ProjectsController.prepend(Module.new do
    def show
      @security_setting = begin
        ProjectSecuritySetting.ensure_table!
        if ActiveRecord::Base.connection.table_exists?(:project_security_settings)
          @project.security_setting || @project.build_security_setting
        else
          @project.build_security_setting
        end
      rescue
        @project.build_security_setting
      end
      super
    end
    def update_security
      ProjectSecuritySetting.ensure_table!
      s = begin
        if ActiveRecord::Base.connection.table_exists?(:project_security_settings)
          @project.security_setting || @project.build_security_setting
        else
          @project.build_security_setting
        end
      end
      s.assign_attributes(params.require(:project_security_setting).permit(
        :allow_clone, :allow_download, :allow_fork, :allow_export, :allow_ide_access, :enabled))
      if s.save
        redirect_to admin_project_path(@project), notice: 'Security settings updated.'
      else
        redirect_to admin_project_path(@project), alert: s.errors.full_messages.join(', ')
      end
    end
  end) rescue nil
end
RUBY

RUN cat <<'RUBY' > ${GITLAB_RAILS_DIR}/app/models/project_security_setting.rb
# frozen_string_literal: true
class ProjectSecuritySetting < ApplicationRecord
  belongs_to :project, inverse_of: :security_setting
  validates :project_id, presence: true, uniqueness: true
  attribute :enabled, :boolean, default: true
  attribute :allow_clone, :boolean, default: false
  attribute :allow_download, :boolean, default: false
  attribute :allow_fork, :boolean, default: false
  attribute :allow_export, :boolean, default: false
  attribute :allow_ide_access, :boolean, default: false
  scope :with_protection_enabled, -> { where(enabled: true) }

  def self.ensure_table!
    return if @table_ensured
    begin
      unless ActiveRecord::Base.connection.table_exists?(:project_security_settings)
        ActiveRecord::Base.connection.create_table :project_security_settings, if_not_exists: true do |t|
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
      @table_ensured = true
    rescue => e
      Rails.logger.warn('[ProjectSecuritySetting] ensure_table! %s' % e.message)
    end
  end

  def block?(action)
    enabled? && !public_send("allow_#{action}?")
  end
end
RUBY

# Patch existing GitLab files (version-safe injection)
RUN cat <<'ENDOFPATCH' > /tmp/patch-gitlab.rb
#!/opt/gitlab/embedded/bin/ruby
RAILS_DIR = '/opt/gitlab/embedded/service/gitlab-rails'
def inject_after(file, pattern, code)
  content = File.read(file)
  unless content.include?(code.strip)
    content.sub!(pattern) { |m| "#{m}\n#{code}" }
    File.write(file, content)
    puts "  PATCHED: #{file}"
  end
end
def inject_before(file, pattern, code)
  content = File.read(file)
  unless content.include?(code.strip)
    content.sub!(pattern) { |m| "#{code}\n#{m}" }
    File.write(file, content)
    puts "  PATCHED: #{file}"
  end
end

# ---- git_access.rb: add security check before can_download? in check_download_access! ----
inject_before("#{RAILS_DIR}/lib/gitlab/git_access.rb",
  /^\s+return if can_download\?/,
  <<~RUBY
      # [SourceProtection] Auto-create table + block clone per project
      ProjectSecuritySetting.ensure_table! if defined?(ProjectSecuritySetting)
      if project&.security_setting&.block?(:clone) && !user&.admin?
        raise ForbiddenError, 'Source code download has been disabled for this project. Contact your administrator.'
      end
  RUBY
)

# ---- repositories_controller.rb: add check at top of archive method ----
inject_after("#{RAILS_DIR}/app/controllers/projects/repositories_controller.rb",
  /def archive/,
  <<~RUBY
    if @project.security_setting&.block?(:download) && !current_user&.can_admin_all_resources?
      render plain: 'Download disabled by administrator.', status: :forbidden
      return
    end
  RUBY
)

# ---- raw_controller.rb: add check at top of show method ----
inject_after("#{RAILS_DIR}/app/controllers/projects/raw_controller.rb",
  /def show/,
  <<~RUBY
    if @project.security_setting&.block?(:download) && !current_user&.can_admin_all_resources?
      render plain: 'Raw file access disabled by administrator.', status: :forbidden
      return
    end
  RUBY
)

# ---- fork_service.rb: add check at top of execute method ----
inject_after("#{RAILS_DIR}/app/services/projects/fork_service.rb",
  /def execute\(fork_to_project = nil\)/,
  <<~RUBY
      if @project.security_setting&.block?(:fork) && !current_user&.admin?
        return ServiceResponse.error(message: 'Forking has been disabled for this project.', reason: :forbidden)
      end
  RUBY
)

# ---- project.rb: add has_one :security_setting after another has_one ----
inject_after("#{RAILS_DIR}/app/models/project.rb",
  /has_one :project_setting.*$/,
  "  has_one :security_setting, class_name: 'ProjectSecuritySetting'"
)

# ---- admin/projects_controller.rb: add :update_security to before_action + feature_category ----
controller = "#{RAILS_DIR}/app/controllers/admin/projects_controller.rb"
content = File.read(controller)
unless content.include?(':update_security')
  content.sub!(/before_action :project, only:.*$/) { |m| m.sub(']', ', :update_security]') }
  content.sub!(/feature_category :groups_and_projects,.*$/) { |m| m.sub(']', ', :update_security]') }
  File.write(controller, content)
  puts "  PATCHED: #{controller}"
end

# ---- admin/routes.rb: add update_security route ----
routes = "#{RAILS_DIR}/config/routes/admin.rb"
routes_content = File.read(routes)
unless routes_content.include?(':update_security')
  routes_content.sub!(/post :repository_check/) { |m| "#{m}\n        post :update_security" }
  File.write(routes, routes_content)
  puts "  PATCHED: #{routes}"
end

# ---- admin/projects/show.html.haml: add security form ----
view = "#{RAILS_DIR}/app/views/admin/projects/show.html.haml"
view_content = File.read(view)
unless view_content.include?('Source Code Protection')
  form = <<~HAML

  = render ::Layouts::CrudComponent.new(_('Source Code Protection')) do |c|
    - c.with_body do
      = form_for @security_setting, url: update_security_admin_project_path(@project), method: :post, html: { class: 'gl-form' } do |f|
        .gl-form-group
          = f.check_box :enabled
          = f.label :enabled, _('Enable source code protection for this project')
        .gl-form-group
          = f.check_box :allow_clone
          = f.label :allow_clone, _('Allow git clone/pull')
        .gl-form-group
          = f.check_box :allow_download
          = f.label :allow_download, _('Allow download ZIP/TAR')
        .gl-form-group
          = f.check_box :allow_fork
          = f.label :allow_fork, _('Allow fork project')
        .gl-form-group
          = f.check_box :allow_export
          = f.label :allow_export, _('Allow export project')
        .gl-form-group
          = f.check_box :allow_ide_access
          = f.label :allow_ide_access, _('Allow IDE connections (VS Code, JetBrains...)')
        = f.submit _('Save'), class: 'btn btn-primary'
  HAML
  view_content += form
  File.write(view, view_content)
  puts "  PATCHED: #{view}"
end

# ---- ide_controller.rb: redirect to code-server ----
ide = "#{RAILS_DIR}/app/controllers/ide_controller.rb"
ide_content = File.read(ide)
unless ide_content.include?('192.168.1.168')
  new_index = <<~'RUBY'
  def index
    if project.present?
      folder = "/workspace/#{project.full_path}"
      unless Dir.exist?(folder)
        token = ENV['GITLAB_WORKSPACE_TOKEN']
        url = token ? "http://oauth2:#{token}@localhost:80/#{project.full_path}.git" : "http://localhost:80/#{project.full_path}.git"
        system("git", "clone", "--depth", "1", url, folder)
        system("chmod", "-R", "777", folder)
      end
      redirect_to "http://192.168.1.168:8443/?folder=#{folder}", allow_other_host: true
    else
      redirect_to "http://192.168.1.168:8443/", allow_other_host: true
    end
  end
  RUBY
  ide_content.sub!(/def index.*?^  end/m, new_index.strip)
  File.write(ide, ide_content)
  puts "  PATCHED: #{ide}"
end

puts "[SourceProtection] All patches applied."

# Validate syntax on patched files
PATCHED = [
  "#{RAILS_DIR}/lib/gitlab/git_access.rb",
  "#{RAILS_DIR}/app/controllers/projects/repositories_controller.rb",
  "#{RAILS_DIR}/app/controllers/projects/raw_controller.rb",
  "#{RAILS_DIR}/app/services/projects/fork_service.rb",
  "#{RAILS_DIR}/app/models/project.rb",
  "#{RAILS_DIR}/app/controllers/admin/projects_controller.rb",
  "#{RAILS_DIR}/config/routes/admin.rb",
  "#{RAILS_DIR}/app/controllers/ide_controller.rb",
]
errors = PATCHED.select { |f| !system("/opt/gitlab/embedded/bin/ruby -c #{f} 2>/dev/null") }
if errors.any?
  puts "[SourceProtection] FAILED: #{errors.join(', ')}"
  exit 1
end
puts "[SourceProtection] Syntax OK."
ENDOFPATCH
RUN /opt/gitlab/embedded/bin/ruby /tmp/patch-gitlab.rb && rm /tmp/patch-gitlab.rb
RUN mkdir -p /workspace && chmod 777 /workspace