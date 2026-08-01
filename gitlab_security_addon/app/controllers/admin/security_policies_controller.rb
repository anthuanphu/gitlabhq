# frozen_string_literal: true

# Admin controller for managing security policies
# Provides full CRUD for security policies with audit logging
module GitlabSecurity
  module Admin
    class SecurityPoliciesController < ::Admin::ApplicationController
      before_action :set_security_policy, only: [:show, :edit, :update, :destroy, :toggle]
      before_action :check_admin_access

      feature_category :system_access

      # GET /admin/security_policies
      def index
        @policies = GitlabSecurity::SecurityPolicy.order(created_at: :desc).page(params[:page])
        @global_policy = GitlabSecurity::SecurityPolicy.global_default
        @stats = load_statistics

        respond_to do |format|
          format.html
          format.json { render json: serialize_policies(@policies) }
        end
      end

      # GET /admin/security_policies/audit_log
      def audit_log
        @logs = GitlabSecurity::SecurityAuditLog
          .recent
          .includes(:user, :project)
          .page(params[:page])

        # Filter options
        @logs = @logs.by_type(params[:event_type]) if params[:event_type].present?
        @logs = @logs.for_user(User.find(params[:user_id])) if params[:user_id].present?
        @logs = @logs.for_ip(params[:ip_address]) if params[:ip_address].present?
        @logs = @logs.where(result: params[:result]) if params[:result].present?

        # Date range filter
        if params[:date_from].present?
          @logs = @logs.where('created_at >= ?', Date.parse(params[:date_from]).beginning_of_day)
        end
        if params[:date_to].present?
          @logs = @logs.where('created_at <= ?', Date.parse(params[:date_to]).end_of_day)
        end

        @log_stats = GitlabSecurity::SecurityAuditLog.statistics(
          since: 7.days.ago,
          upto: Time.current
        )
      end

      # GET /admin/security_policies/new
      def new
        @policy = GitlabSecurity::SecurityPolicy.new
        @projects = Project.order(:name).limit(100)
        @groups = Group.order(:name).limit(50)
      end

      # POST /admin/security_policies
      def create
        @policy = GitlabSecurity::SecurityPolicy.new(security_policy_params)
        @policy.created_by = current_user

        if @policy.save
          GitlabSecurity::SecurityAuditLog.log!(
            event_type: 'policy_created',
            result: 'allowed',
            user: current_user,
            details: {
              policy_id: @policy.id,
              policy_name: @policy.name,
              policy_type: @policy.policy_type,
              enforcement_level: @policy.enforcement_level
            }
          )

          redirect_to admin_security_policies_path,
            notice: _('Security policy was successfully created.')
        else
          @projects = Project.order(:name).limit(100)
          @groups = Group.order(:name).limit(50)
          render :new, status: :unprocessable_entity
        end
      end

      # GET /admin/security_policies/:id
      def show
        @audit_logs = GitlabSecurity::SecurityAuditLog
          .where(security_policy: @policy)
          .recent
          .limit(50)

        @affected_projects = if @policy.project
          [@policy.project]
        elsif @policy.group
          @policy.group.all_projects.limit(100)
        else
          Project.limit(100)  # Global policy
        end
      end

      # GET /admin/security_policies/:id/edit
      def edit
        @projects = Project.order(:name).limit(100)
        @groups = Group.order(:name).limit(50)
      end

      # PATCH/PUT /admin/security_policies/:id
      def update
        @policy.updated_by = current_user

        if @policy.update(security_policy_params)
          GitlabSecurity::SecurityAuditLog.log!(
            event_type: 'policy_updated',
            result: 'allowed',
            user: current_user,
            details: {
              policy_id: @policy.id,
              policy_name: @policy.name,
              changes: @policy.previous_changes.keys
            }
          )

          redirect_to admin_security_policy_path(@policy),
            notice: _('Security policy was successfully updated.')
        else
          @projects = Project.order(:name).limit(100)
          @groups = Group.order(:name).limit(50)
          render :edit, status: :unprocessable_entity
        end
      end

      # DELETE /admin/security_policies/:id
      def destroy
        policy_name = @policy.name
        @policy.soft_delete!

        GitlabSecurity::SecurityAuditLog.log!(
          event_type: 'policy_deleted',
          result: 'allowed',
          user: current_user,
          details: {
            policy_id: @policy.id,
            policy_name: policy_name
          }
        )

        redirect_to admin_security_policies_path,
          notice: _('Security policy was successfully deleted.')
      end

      # POST /admin/security_policies/:id/toggle
      def toggle
        if @policy.enabled?
          @policy.update!(enabled: false)
          message = _('Policy disabled')
        else
          @policy.update!(enabled: true)
          message = _('Policy enabled')
        end

        respond_to do |format|
          format.html { redirect_to admin_security_policies_path, notice: message }
          format.json { render json: { status: 'ok', enabled: @policy.enabled? } }
        end
      end

      # POST /admin/security_policies/bulk_update
      def bulk_update
        action = params[:bulk_action]
        policy_ids = params[:policy_ids] || []

        case action
        when 'enable'
          GitlabSecurity::SecurityPolicy.where(id: policy_ids).update_all(enabled: true)
          message = _('%{count} policies enabled') % { count: policy_ids.size }
        when 'disable'
          GitlabSecurity::SecurityPolicy.where(id: policy_ids).update_all(enabled: false)
          message = _('%{count} policies disabled') % { count: policy_ids.size }
        when 'delete'
          GitlabSecurity::SecurityPolicy.where(id: policy_ids).find_each(&:soft_delete!)
          message = _('%{count} policies deleted') % { count: policy_ids.size }
        else
          message = _('No action specified')
        end

        redirect_to admin_security_policies_path, notice: message
      end

      private

      def set_security_policy
        @policy = GitlabSecurity::SecurityPolicy.find(params[:id])
      rescue ActiveRecord::RecordNotFound
        redirect_to admin_security_policies_path, alert: _('Policy not found.')
      end

      def check_admin_access
        render_404 unless current_user&.admin?
      end

      def security_policy_params
        params.require(:gitlab_security_security_policy).permit(
          :name,
          :description,
          :policy_type,
          :project_id,
          :group_id,
          :namespace_id,
          :enforcement_level,
          :block_download,
          :block_clone,
          :block_fork,
          :block_share,
          :block_http_access,
          :block_ssh_access,
          :block_vscode_access,
          :block_all_ide_access,
          :require_admin_approval,
          :block_all_external_tools,
          :enabled,
          :is_global_default,
          allowed_ip_ranges: [],
          allowed_user_agents: [],
          blocked_ip_ranges: [],
          blocked_user_agents: [],
          time_restrictions: []
        )
      end

      def load_statistics
        {
          total_policies: GitlabSecurity::SecurityPolicy.count,
          active_policies: GitlabSecurity::SecurityPolicy.enabled.count,
          total_blocks_today: GitlabSecurity::SecurityAuditLog.today.blocked_events.count,
          total_blocks_this_week: GitlabSecurity::SecurityAuditLog.this_week.blocked_events.count,
          unique_blocked_ips: GitlabSecurity::SecurityAuditLog.today.blocked_events.distinct.count(:ip_address),
          top_blocked_actions: GitlabSecurity::SecurityAuditLog.today.blocked_events
            .group(:event_type)
            .order('count_id DESC')
            .limit(5)
            .count(:id)
        }
      end

      def serialize_policies(policies)
        policies.map do |policy|
          {
            id: policy.id,
            name: policy.name,
            policy_type: policy.policy_type,
            enabled: policy.enabled?,
            enforcement_level: policy.enforcement_level,
            blocked_operations: policy.blocked_operations,
            created_at: policy.created_at.iso8601
          }
        end
      end
    end
  end
end
