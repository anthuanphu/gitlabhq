# frozen_string_literal: true

class Admin::ProjectsController < Admin::ApplicationController
  include MembersPresentation

  before_action :project, only: [:show, :transfer, :repository_check, :destroy, :edit, :update, :update_security]
  before_action :group, only: [:show, :transfer]

  feature_category :groups_and_projects, [:index, :show, :transfer, :destroy, :edit, :update, :update_security]
  feature_category :source_code_management, [:repository_check]

  # rubocop: disable CodeReuse/ActiveRecord
  def show
    if @group
      @group_members = present_members(
        @group.members.order("access_level DESC").page(page_params[:group_members_page]))
    end

    @project_members = present_members(
      @project.members.page(page_params[:project_members_page]))
    @requesters = present_members(
      AccessRequestsFinder.new(@project).execute(current_user))
    ProjectSecuritySetting.ensure_table!
    @security_setting = load_security_setting
  end

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
  # rubocop: enable CodeReuse/ActiveRecord

  def destroy
    ::Projects::DestroyService.new(@project, current_user, {}).async_execute # rubocop:disable Gitlab/HardDeleteCalls -- hard delete by admin is intentional
    flash[:toast] = format(_("Project '%{project_name}' is being deleted."), project_name: @project.full_name)

    redirect_to admin_projects_path, status: :found
  rescue Projects::DestroyService::DestroyError => e
    redirect_to admin_projects_path, status: :found, alert: e.message
  end

  # rubocop: disable CodeReuse/ActiveRecord
  def transfer
    namespace = Namespace.find_by(id: transfer_params[:new_namespace_id])
    ::Projects::TransferService.new(@project, current_user).execute(namespace)

    flash[:alert] = @project.errors[:new_namespace].first if @project.errors[:new_namespace].present?

    @project.reset
    redirect_to admin_project_path(@project)
  end
  # rubocop: enable CodeReuse/ActiveRecord

  def edit; end

  def update
    result = ::Projects::UpdateService.new(@project, current_user, project_params).execute

    if result[:status] == :success
      unless Gitlab::Utils.to_boolean(project_params['runner_registration_enabled'])
        Ci::Runners::ResetRegistrationTokenService.new(@project, current_user).execute
      end

      redirect_to [:admin, @project],
        notice: format(_("Project '%{project_name}' was successfully updated."), project_name: @project.name)
    else
      render "edit"
    end
  end

  def repository_check
    RepositoryCheck::SingleRepositoryWorker.perform_async(@project.id) # rubocop:disable CodeReuse/Worker

    redirect_to(
      admin_project_path(@project),
      notice: _('Repository check was triggered.')
    )
  end

  protected

  def project
    @project = Project.find_by_full_path(
      [project_identifier_params[:namespace_id], '/', project_identifier_params[:id]].join('')
    )
    @project || render_404
  end

  def group
    @group ||= @project.group
  end

  def project_params
    params.require(:project).permit(allowed_project_params)
  end

  def allowed_project_params
    [
      :description,
      :name,
      :runner_registration_enabled
    ]
  end

  private

  def project_identifier_params
    params.permit(:namespace_id, :id)
  end

  def transfer_params
    params.permit(:new_namespace_id)
  end

  def page_params
    params.permit(:group_members_page, :project_members_page)
  end
end

Admin::ProjectsController.prepend_mod_with('Admin::ProjectsController')
