# frozen_string_literal: true

# API endpoints for GitLab Security Addon
# Provides REST API for managing security policies, access grants, and audit logs
module GitlabSecurity
  module API
    class SecurityPolicies < ::Grape::API
      prefix :api
      version 'v4', using: :path

      resource :security_policies do
        # GET /api/v4/security_policies
        desc 'List all security policies' do
          success ::API::Entities::BasicSuccess
        end
        params do
          optional :project_id, type: Integer, desc: 'Filter by project ID'
          optional :group_id, type: Integer, desc: 'Filter by group ID'
          optional :enabled, type: Boolean, desc: 'Filter by enabled status'
          optional :page, type: Integer, default: 1
          optional :per_page, type: Integer, default: 20
        end
        get do
          authenticate!
          authorize! :admin_all_resources

          policies = SecurityPolicy.all
          policies = policies.where(project_id: params[:project_id]) if params[:project_id]
          policies = policies.where(group_id: params[:group_id]) if params[:group_id]
          policies = policies.where(enabled: params[:enabled]) unless params[:enabled].nil?
          policies = policies.order(created_at: :desc)
          policies = policies.page(params[:page]).per(params[:per_page])

          present policies, with: ::API::Entities::SecurityPolicy
        end

        # GET /api/v4/security_policies/:id
        desc 'Get a single security policy'
        params do
          requires :id, type: Integer, desc: 'Security policy ID'
        end
        get ':id' do
          authenticate!
          authorize! :admin_all_resources

          policy = SecurityPolicy.find(params[:id])
          present policy, with: ::API::Entities::SecurityPolicy
        end

        # POST /api/v4/security_policies
        desc 'Create a new security policy'
        params do
          requires :name, type: String, desc: 'Policy name'
          optional :description, type: String, desc: 'Policy description'
          optional :policy_type, type: String, default: 'project', values: %w[global project group namespace]
          optional :project_id, type: Integer, desc: 'Project ID'
          optional :group_id, type: Integer, desc: 'Group ID'
          optional :enforcement_level, type: Integer, default: 0, values: [0, 1, 2]
          optional :block_download, type: Boolean, default: false
          optional :block_clone, type: Boolean, default: false
          optional :block_fork, type: Boolean, default: false
          optional :block_share, type: Boolean, default: false
          optional :block_http_access, type: Boolean, default: false
          optional :block_ssh_access, type: Boolean, default: false
          optional :block_vscode_access, type: Boolean, default: false
          optional :block_all_ide_access, type: Boolean, default: false
          optional :enabled, type: Boolean, default: true
          optional :allowed_ip_ranges, type: Array[String], default: []
          optional :blocked_ip_ranges, type: Array[String], default: []
          optional :blocked_user_agents, type: Array[String], default: []
          optional :time_restrictions, type: Array, default: []
        end
        post do
          authenticate!
          authorize! :admin_all_resources

          policy = SecurityPolicy.new(declared(params, include_missing: false))
          policy.created_by = current_user

          if policy.save
            present policy, with: ::API::Entities::SecurityPolicy
          else
            render_validation_error!(policy)
          end
        end

        # PUT /api/v4/security_policies/:id
        desc 'Update a security policy'
        params do
          requires :id, type: Integer, desc: 'Security policy ID'
          optional :name, type: String
          optional :description, type: String
          optional :enforcement_level, type: Integer, values: [0, 1, 2]
          optional :block_download, type: Boolean
          optional :block_clone, type: Boolean
          optional :block_fork, type: Boolean
          optional :block_share, type: Boolean
          optional :block_http_access, type: Boolean
          optional :block_ssh_access, type: Boolean
          optional :block_vscode_access, type: Boolean
          optional :block_all_ide_access, type: Boolean
          optional :enabled, type: Boolean
          optional :allowed_ip_ranges, type: Array[String]
          optional :blocked_ip_ranges, type: Array[String]
          optional :blocked_user_agents, type: Array[String]
          optional :time_restrictions, type: Array
        end
        put ':id' do
          authenticate!
          authorize! :admin_all_resources

          policy = SecurityPolicy.find(params[:id])
          policy.updated_by = current_user

          if policy.update(declared(params, include_missing: false))
            present policy, with: ::API::Entities::SecurityPolicy
          else
            render_validation_error!(policy)
          end
        end

        # DELETE /api/v4/security_policies/:id
        desc 'Delete a security policy'
        params do
          requires :id, type: Integer, desc: 'Security policy ID'
        end
        delete ':id' do
          authenticate!
          authorize! :admin_all_resources

          policy = SecurityPolicy.find(params[:id])
          policy.soft_delete!

          { message: 'Policy deleted successfully' }
        end
      end

      # =========================================================================
      # Security Access Grants API
      # =========================================================================
      resource :security_access_grants do
        # GET /api/v4/security_access_grants
        desc 'List all access grants'
        params do
          optional :user_id, type: Integer, desc: 'Filter by user ID'
          optional :project_id, type: Integer, desc: 'Filter by project ID'
          optional :grant_type, type: String, desc: 'Filter by grant type'
          optional :active, type: Boolean, default: true
          optional :page, type: Integer, default: 1
          optional :per_page, type: Integer, default: 20
        end
        get do
          authenticate!
          authorize! :admin_all_resources

          grants = SecurityAccessGrant.all
          grants = grants.where(user_id: params[:user_id]) if params[:user_id]
          grants = grants.where(project_id: params[:project_id]) if params[:project_id]
          grants = grants.where(grant_type: params[:grant_type]) if params[:grant_type]
          grants = grants.where(active: params[:active]) unless params[:active].nil?
          grants = grants.order(created_at: :desc)
          grants = grants.page(params[:page]).per(params[:per_page])

          present grants
        end

        # POST /api/v4/security_access_grants
        desc 'Grant access to a user'
        params do
          requires :user_id, type: Integer, desc: 'User ID'
          requires :grant_type, type: String, values: SecurityAccessGrant::GRANT_TYPES, desc: 'Type of access to grant'
          optional :project_id, type: Integer, desc: 'Project ID (for project-specific grants)'
          optional :group_id, type: Integer, desc: 'Group ID (for group-specific grants)'
          optional :expires_at, type: DateTime, desc: 'Expiration date'
          optional :permanent, type: Boolean, default: false
          optional :reason, type: String, desc: 'Reason for granting access'
        end
        post do
          authenticate!
          authorize! :admin_all_resources

          grant = SecurityAccessGrant.new(
            user_id: params[:user_id],
            grant_type: params[:grant_type],
            project_id: params[:project_id],
            group_id: params[:group_id],
            expires_at: params[:expires_at],
            permanent: params[:permanent],
            reason: params[:reason],
            granted_by: current_user
          )

          if grant.save
            present grant
          else
            render_validation_error!(grant)
          end
        end

        # DELETE /api/v4/security_access_grants/:id
        desc 'Revoke an access grant'
        params do
          requires :id, type: Integer, desc: 'Access grant ID'
        end
        delete ':id' do
          authenticate!
          authorize! :admin_all_resources

          grant = SecurityAccessGrant.find(params[:id])
          grant.revoke!(revoked_by: current_user, reason: 'Revoked via API')

          { message: 'Access grant revoked' }
        end
      end

      # =========================================================================
      # Device Whitelist API
      # =========================================================================
      resource :device_whitelists do
        # GET /api/v4/device_whitelists
        desc 'List all device whitelists'
        params do
          optional :user_id, type: Integer, desc: 'Filter by user'
          optional :device_type, type: String, desc: 'Filter by device type'
          optional :enabled, type: Boolean, default: true
          optional :page, type: Integer, default: 1
          optional :per_page, type: Integer, default: 20
        end
        get do
          authenticate!
          authorize! :admin_all_resources

          devices = DeviceWhitelist.all
          devices = devices.where(user_id: params[:user_id]) if params[:user_id]
          devices = devices.where(device_type: params[:device_type]) if params[:device_type]
          devices = devices.where(enabled: params[:enabled]) unless params[:enabled].nil?
          devices = devices.order(created_at: :desc)
          devices = devices.page(params[:page]).per(params[:per_page])

          present devices
        end

        # POST /api/v4/device_whitelists
        desc 'Add a device to whitelist'
        params do
          optional :user_id, type: Integer, desc: 'User ID'
          requires :ip_address, type: String, desc: 'IP address to whitelist'
          optional :device_name, type: String, desc: 'Device name'
          optional :device_type, type: String, values: DeviceWhitelist::DEVICE_TYPES, default: 'workstation'
          optional :expires_at, type: DateTime, desc: 'Expiration'
          optional :access_level, type: Integer, default: 1, values: [0, 1, 2]
        end
        post do
          authenticate!
          authorize! :admin_all_resources

          device = DeviceWhitelist.new(
            user_id: params[:user_id],
            ip_address: params[:ip_address],
            device_name: params[:device_name],
            device_type: params[:device_type],
            expires_at: params[:expires_at],
            access_level: params[:access_level],
            approved_by: current_user
          )

          if device.save
            present device
          else
            render_validation_error!(device)
          end
        end

        # DELETE /api/v4/device_whitelists/:id
        desc 'Remove a device from whitelist'
        params do
          requires :id, type: Integer, desc: 'Device whitelist ID'
        end
        delete ':id' do
          authenticate!
          authorize! :admin_all_resources

          device = DeviceWhitelist.find(params[:id])
          device.expire!

          { message: 'Device removed from whitelist' }
        end
      end

      # =========================================================================
      # Security Audit Log API
      # =========================================================================
      resource :security_audit_logs do
        # GET /api/v4/security_audit_logs
        desc 'Query security audit logs'
        params do
          optional :user_id, type: Integer, desc: 'Filter by user'
          optional :project_id, type: Integer, desc: 'Filter by project'
          optional :event_type, type: String, desc: 'Filter by event type'
          optional :result, type: String, values: %w[allowed blocked error], desc: 'Filter by result'
          optional :ip_address, type: String, desc: 'Filter by IP'
          optional :date_from, type: Date, desc: 'Start date'
          optional :date_to, type: Date, desc: 'End date'
          optional :page, type: Integer, default: 1
          optional :per_page, type: Integer, default: 50
        end
        get do
          authenticate!
          authorize! :admin_all_resources

          logs = SecurityAuditLog.recent
          logs = logs.for_user(User.find(params[:user_id])) if params[:user_id]
          logs = logs.for_project(Project.find(params[:project_id])) if params[:project_id]
          logs = logs.by_type(params[:event_type]) if params[:event_type]
          logs = logs.where(result: params[:result]) if params[:result]
          logs = logs.for_ip(params[:ip_address]) if params[:ip_address]
          logs = logs.where('created_at >= ?', params[:date_from].beginning_of_day) if params[:date_from]
          logs = logs.where('created_at <= ?', params[:date_to].end_of_day) if params[:date_to]
          logs = logs.page(params[:page]).per(params[:per_page])

          present logs
        end

        # GET /api/v4/security_audit_logs/statistics
        desc 'Get security audit statistics'
        params do
          optional :since, type: DateTime, default: 7.days.ago.iso8601
          optional :upto, type: DateTime, default: Time.current.iso8601
        end
        get 'statistics' do
          authenticate!
          authorize! :admin_all_resources

          SecurityAuditLog.statistics(since: params[:since], upto: params[:upto])
        end
      end
    end
  end
end
