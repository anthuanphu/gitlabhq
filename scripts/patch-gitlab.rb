#!/opt/gitlab/embedded/bin/ruby
# Inject Source Code Protection into GitLab CE files.
# Uses the EXISTING files in the image (version-compatible), adds our code only.

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

# ---- admin/projects_controller.rb: add update_security action + load_security_setting ----
controller = "#{RAILS_DIR}/app/controllers/admin/projects_controller.rb"
content = File.read(controller)

# add before_action
unless content.include?(':update_security')
  content.sub!(/before_action :project, only:.*$/) { |m| m.sub(']', ', :update_security]') }
end

# add feature_category
unless content.include?(':update_security')
  content.sub!(/feature_category :groups_and_projects,.*$/) { |m| m.sub(']', ', :update_security]') }
end

# add load_security_setting + update_security + security_params after show method
unless content.include?('def update_security')
  patch = <<~RUBY

  def update_security
    ProjectSecuritySetting.ensure_table!
    setting = load_security_setting
    setting.assign_attributes(security_params)
    if setting.save
      redirect_to admin_project_path(@project), notice: _('Security settings updated.')
    else
      redirect_to admin_project_path(@project), alert: setting.errors.full_messages.join(', ')
    end
  end

  private

  def load_security_setting
    if ActiveRecord::Base.connection.table_exists?(:project_security_settings)
      @project.security_setting || @project.build_security_setting
    else
      @project.build_security_setting
    end
  end

  def security_params
    params.require(:project_security_setting).permit(:allow_clone, :allow_download, :allow_fork, :allow_export, :allow_ide_access, :enabled)
  end
  RUBY
  content.sub!(/^\s+def destroy$/, "#{patch}\n  def destroy")
end

# add @security_setting to show action
unless content.include?('load_security_setting')
  content.sub!(/AccessRequestsFinder.*$\n/) { |m| "#{m}    ProjectSecuritySetting.ensure_table!\n    @security_setting = load_security_setting\n" }
end

File.write(controller, content)
puts "  PATCHED: #{controller}"

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
unless ide_content.include?('code.aurixsystems.vn')
  new_index = <<~RUBY
  def index
    if project.present?
      redirect_to "https://code.aurixsystems.vn/?folder=/workspace/\#{project.full_path}", allow_other_host: true
    else
      redirect_to "https://code.aurixsystems.vn/", allow_other_host: true
    end
  end
  RUBY
  ide_content.sub!(/def index.*?^  end/m, new_index.strip)
  File.write(ide, ide_content)
  puts "  PATCHED: #{ide}"
end

puts "[SourceProtection] All patches applied."

# ---- Validate: check Ruby syntax on all patched files ----
puts "[SourceProtection] Validating syntax..."
PATCHED_FILES = [
  "#{RAILS_DIR}/lib/gitlab/git_access.rb",
  "#{RAILS_DIR}/app/controllers/projects/repositories_controller.rb",
  "#{RAILS_DIR}/app/controllers/projects/raw_controller.rb",
  "#{RAILS_DIR}/app/services/projects/fork_service.rb",
  "#{RAILS_DIR}/app/models/project.rb",
  "#{RAILS_DIR}/app/controllers/admin/projects_controller.rb",
  "#{RAILS_DIR}/config/routes/admin.rb",
  "#{RAILS_DIR}/app/controllers/ide_controller.rb",
]

errors = []
PATCHED_FILES.each do |f|
  result = system("/opt/gitlab/embedded/bin/ruby -c #{f} 2>&1")
  unless result
    errors << f
    puts "  SYNTAX ERROR in: #{f}"
  end
end

if errors.any?
  puts "[SourceProtection] FAILED — #{errors.size} file(s) have syntax errors. Build aborted."
  exit 1
else
  puts "[SourceProtection] Syntax check passed. All good."
end
