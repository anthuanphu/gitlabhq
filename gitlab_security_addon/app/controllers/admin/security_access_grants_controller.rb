# frozen_string_literal: true

# Admin controller for managing security access grants
# Allows admins to grant temporary/permanent access exceptions to users
module GitlabSecurity
  module Admin
    class SecurityAccessGrantsController < ::Admin::ApplicationController
      before_action :set_access_grant, only: [:show, :revoke, :extend]

      feature_category :system_access

      # GET /admin/security_access_grants
      def index
        @grants = GitlabSecurity::SecurityAccessGrant
          .includes(:user, :project, :granted_by)
          .order(created_at: :desc)
          .page(params[:page])

        # Filters
        @grants = @grants.where(active: params[:active]) unless params[:active].nil?
        @grants = @grants.where(grant_type: params[:grant_type]) if params[:grant_type].present?
        @grants = @grants.for_user(User.find(params[:user_id])) if params[:user_id].present?
        @grants = @grants.for_project(Project.find(params[:project_id])) if params[:project_id].present?

        @stats = grant_statistics
      end

      # GET /admin/security_access_grants/new
      def new
        @grant = GitlabSecurity::SecurityAccessGrant.new
        @users = User.order(:username).limit(100)
        @projects = Project.order(:name).limit(100)
      end

      # POST /admin/security_access_grants
      def create
        @grant = GitlabSecurity::SecurityAccessGrant.new(access_grant_params)
        @grant.granted_by = current_user
        @grant.active = true

        if @grant.save
          GitlabSecurity::SecurityAuditLog.log!(
            event_type: 'access_granted',
            result: 'allowed',
            user: @grant.user,
            project: @grant.project,
            actor: current_user,
            details: {
              grant_type: @grant.grant_type,
              grant_id: @grant.id,
              permanent: @grant.permanent?,
              expires_at: @grant.expires_at
            }
          )

          redirect_to admin_security_access_grants_path,
            notice: _('Access grant was successfully created.')
        else
          @users = User.order(:username).limit(100)
          @projects = Project.order(:name).limit(100)
          render :new, status: :unprocessable_entity
        end
      end

      # GET /admin/security_access_grants/:id
      def show; end

      # POST /admin/security_access_grants/:id/revoke
      def revoke
        @grant.revoke!(
          revoked_by: current_user,
          reason: params[:reason] || 'Manually revoked by admin'
        )

        redirect_to admin_security_access_grants_path,
          notice: _('Access grant has been revoked.')
      end

      # POST /admin/security_access_grants/:id/extend
      def extend
        new_expiry = if params[:permanent] == 'true'
          nil
        else
          Time.current + params[:days].to_i.days
        end

        @grant.extend!(
          new_expiry: new_expiry,
          extended_by: current_user
        )

        redirect_to admin_security_access_grants_path,
          notice: _('Access grant has been extended.')
      end

      # POST /admin/security_access_grants/bulk_revoke
      def bulk_revoke
        grant_ids = params[:grant_ids] || []
        count = 0

        GitlabSecurity::SecurityAccessGrant.where(id: grant_ids).find_each do |grant|
          grant.revoke!(revoked_by: current_user, reason: 'Bulk revoked')
          count += 1
        end

        redirect_to admin_security_access_grants_path,
          notice: _('%{count} access grants revoked.') % { count: count }
      end

      private

      def set_access_grant
        @grant = GitlabSecurity::SecurityAccessGrant.find(params[:id])
      rescue ActiveRecord::RecordNotFound
        redirect_to admin_security_access_grants_path, alert: _('Access grant not found.')
      end

      def access_grant_params
        params.require(:gitlab_security_security_access_grant).permit(
          :user_id,
          :project_id,
          :group_id,
          :security_policy_id,
          :grant_type,
          :expires_at,
          :permanent,
          :reason
        )
      end

      def grant_statistics
        {
          total_grants: GitlabSecurity::SecurityAccessGrant.count,
          active_grants: GitlabSecurity::SecurityAccessGrant.active.count,
          permanent_grants: GitlabSecurity::SecurityAccessGrant.permanent.count,
          temporary_grants: GitlabSecurity::SecurityAccessGrant.temporary.count,
          expiring_soon: GitlabSecurity::SecurityAccessGrant.active
            .where('expires_at <= ?', 7.days.from_now)
            .where(permanent: false)
            .count,
          by_type: GitlabSecurity::SecurityAccessGrant.active.group(:grant_type).count
        }
      end
    end
  end
end
