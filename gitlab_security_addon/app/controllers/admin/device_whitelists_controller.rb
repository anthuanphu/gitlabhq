# frozen_string_literal: true

# Admin controller for managing device whitelists
# Controls which devices/IPs are authorized to connect
module GitlabSecurity
  module Admin
    class DeviceWhitelistsController < ::Admin::ApplicationController
      before_action :set_device_whitelist, only: [:show, :edit, :update, :destroy, :renew, :revoke]

      feature_category :system_access

      # GET /admin/device_whitelists
      def index
        @devices = GitlabSecurity::DeviceWhitelist
          .includes(:user, :approved_by)
          .order(created_at: :desc)
          .page(params[:page])

        # Filters
        @devices = @devices.where(device_type: params[:device_type]) if params[:device_type].present?
        @devices = @devices.where(enabled: params[:enabled]) if params[:enabled].present?
        @devices = @devices.for_user(User.find(params[:user_id])) if params[:user_id].present?

        @stats = device_statistics
      end

      # GET /admin/device_whitelists/new
      def new
        @device = GitlabSecurity::DeviceWhitelist.new
        @users = User.order(:username).limit(100)
      end

      # POST /admin/device_whitelists
      def create
        @device = GitlabSecurity::DeviceWhitelist.new(device_whitelist_params)
        @device.approved_by = current_user

        if @device.save
          redirect_to admin_device_whitelists_path,
            notice: _('Device was successfully whitelisted.')
        else
          @users = User.order(:username).limit(100)
          render :new, status: :unprocessable_entity
        end
      end

      # GET /admin/device_whitelists/:id
      def show; end

      # GET /admin/device_whitelists/:id/edit
      def edit
        @users = User.order(:username).limit(100)
      end

      # PATCH/PUT /admin/device_whitelists/:id
      def update
        if @device.update(device_whitelist_params)
          redirect_to admin_device_whitelists_path,
            notice: _('Device whitelist was successfully updated.')
        else
          @users = User.order(:username).limit(100)
          render :edit, status: :unprocessable_entity
        end
      end

      # DELETE /admin/device_whitelists/:id
      def destroy
        @device.expire!
        redirect_to admin_device_whitelists_path,
          notice: _('Device whitelist entry was revoked.')
      end

      # POST /admin/device_whitelists/:id/renew
      def renew
        @device.renew!(30.days)
        redirect_to admin_device_whitelists_path,
          notice: _('Device whitelist renewed for 30 days.')
      end

      # POST /admin/device_whitelists/:id/revoke
      def revoke
        @device.expire!
        redirect_to admin_device_whitelists_path,
          notice: _('Device access has been revoked.')
      end

      # POST /admin/device_whitelists/bulk_whitelist
      def bulk_whitelist
        ip_list = params[:ip_list].to_s.split(/[\r\n,;\s]+/).map(&:strip).reject(&:blank?)
        device_type = params[:device_type] || 'workstation'
        user_id = params[:user_id]

        created = 0
        failed = 0

        ip_list.each do |ip|
          device = GitlabSecurity::DeviceWhitelist.new(
            ip_address: ip,
            device_type: device_type,
            user_id: user_id,
            approved_by: current_user
          )
          if device.save
            created += 1
          else
            failed += 1
          end
        end

        redirect_to admin_device_whitelists_path,
          notice: _('%{created} devices whitelisted, %{failed} failed.') % { created: created, failed: failed }
      end

      private

      def set_device_whitelist
        @device = GitlabSecurity::DeviceWhitelist.find(params[:id])
      rescue ActiveRecord::RecordNotFound
        redirect_to admin_device_whitelists_path, alert: _('Device not found.')
      end

      def device_whitelist_params
        params.require(:gitlab_security_device_whitelist).permit(
          :user_id,
          :project_id,
          :group_id,
          :device_name,
          :device_type,
          :ip_address,
          :ip_range,
          :mac_address,
          :user_agent_pattern,
          :device_fingerprint,
          :access_level,
          :enabled,
          :expires_at
        )
      end

      def device_statistics
        {
          total_devices: GitlabSecurity::DeviceWhitelist.count,
          active_devices: GitlabSecurity::DeviceWhitelist.active.count,
          vs_code_devices: GitlabSecurity::DeviceWhitelist.where(device_type: 'vscode').count,
          expiring_soon: GitlabSecurity::DeviceWhitelist.active
            .where('expires_at <= ?', 7.days.from_now).count,
          by_type: GitlabSecurity::DeviceWhitelist.group(:device_type).count
        }
      end
    end
  end
end
