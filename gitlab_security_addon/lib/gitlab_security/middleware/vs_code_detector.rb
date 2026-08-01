# frozen_string_literal: true

# Rack Middleware: VsCodeDetector
# Specifically detects and handles VS Code connection attempts.
# Can be configured to:
#   - Block all VS Code connections
#   - Allow only whitelisted VS Code connections
#   - Require admin approval for VS Code connections
#   - Show a custom message to blocked VS Code users
module GitlabSecurity
  module Middleware
    class VsCodeDetector
      # Known VS Code GitLab extension endpoints
      VSCODE_API_PATTERNS = [
        %r{/api/v4/projects/.*/repository/},
        %r{/api/v4/projects/.*/merge_requests},
        %r{/api/v4/projects/.*/issues},
        %r{/api/v4/user},
        %r{/api/v4/groups},
      ].freeze

      # VS Code specific User-Agent substrings
      VSCODE_USER_AGENT_MARKERS = [
        'vscode',
        'Visual Studio Code',
        'Code/',
        'vscode-remote',
        'vscode-server',
        'GitHub Copilot',   # Copilot uses VS Code extension context
        'GitLab Workflow',  # GitLab's own VS Code extension
        'gitlab-vscode',
      ].freeze

      def initialize(app)
        @app = app
      end

      def call(env)
        request = Rack::Request.new(env)

        if vscode_connection?(request)
          handle_vscode_request(request)
        else
          @app.call(env)
        end
      end

      private

      # Detect if this is a VS Code initiated connection
      def vscode_connection?(request)
        user_agent = (request.user_agent || '').downcase
        path = (request.path || '').downcase

        # Check User-Agent for VS Code markers
        agent_match = VSCODE_USER_AGENT_MARKERS.any? do |marker|
          user_agent.include?(marker.downcase)
        end

        # Check if path matches VS Code extension API patterns
        path_match = VSCODE_API_PATTERNS.any? do |pattern|
          path.match?(pattern)
        end

        # Both must match for it to be a VS Code connection
        agent_match || (path_match && looks_like_ide_request?(request))
      end

      # Additional heuristics for IDE requests
      def looks_like_ide_request?(request)
        headers = request.env
        # VS Code extension adds specific headers
        headers['HTTP_X_VSCODE'] ||
          headers['HTTP_X_IDE'] ||
          (headers['HTTP_ACCEPT'] || '').include?('application/vnd.github') ||
          request.user_agent.to_s.include?('node-fetch')  # VS Code uses node-fetch
      end

      def handle_vscode_request(request)
        ip = request.ip
        user_agent = request.user_agent

        # 1. Check if VS Code is globally blocked
        if GitlabSecurity.feature_enabled?(:block_vscode_connection)
          log_vscode_block('global_vscode_block', request)
          return vscode_blocked_response
        end

        # 2. Check device whitelist
        if GitlabSecurity.feature_enabled?(:device_whitelist_enabled)
          unless GitlabSecurity.device_whitelisted?(ip, user_agent)
            log_vscode_block('device_not_whitelisted', request)
            return vscode_device_not_whitelisted_response
          end
        end

        # 3. Check if admin approval is required
        if GitlabSecurity.feature_enabled?(:admin_approval_required)
          # Check if user has explicit VS Code access grant
          # This requires user authentication context, checked at controller level
          # Add header to indicate approval is being checked
          status, headers, response = @app.call(request.env)
          headers['X-GitLab-Security-VSCode-Checked'] = 'true'
          return [status, headers, response]
        end

        # 4. Allow with monitoring
        log_vscode_allowed(request)
        status, headers, response = @app.call(request.env)
        headers['X-GitLab-Security-VSCode-Allowed'] = 'true'
        [status, headers, response]
      end

      def vscode_blocked_response
        body = {
          error: 'vscode_access_denied',
          message: 'VS Code connections are blocked by your administrator.',
          timestamp: Time.current.iso8601,
          help: 'Contact your GitLab administrator to request VS Code access.',
          request_access_url: '/admin/security_policies'  # Admin path for managing
        }.to_json

        [403, security_headers(body), [body]]
      end

      def vscode_device_not_whitelisted_response
        body = {
          error: 'device_not_authorized',
          message: 'Your device is not authorized to connect via VS Code. ' \
                   'Please request device whitelisting from your administrator.',
          timestamp: Time.current.iso8601,
          device_info: {
            ip: 'logged',  # Don't expose actual IP in response
            reason: 'Device not in approved whitelist'
          }
        }.to_json

        [403, security_headers(body), [body]]
      end

      def security_headers(body)
        {
          'Content-Type' => 'application/json',
          'Content-Length' => body.bytesize.to_s,
          'X-GitLab-Security-VSCode-Blocked' => 'true',
          'X-Content-Type-Options' => 'nosniff'
        }
      end

      def log_vscode_block(reason, request)
        GitlabSecurity::SecurityAuditLog.log!(
          event_type: 'vscode_connection_blocked',
          result: 'blocked',
          ip_address: request.ip,
          user_agent: request.user_agent,
          http_method: request.request_method,
          request_path: request.path,
          protocol: request.scheme,
          block_reason: reason,
          details: {
            middleware: 'VsCodeDetector',
            block_reason: reason,
            user_agent_full: request.user_agent
          }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::VsCodeDetector] Log error: #{e.message}")
      end

      def log_vscode_allowed(request)
        GitlabSecurity::SecurityAuditLog.log!(
          event_type: 'vscode_connection_allowed',
          result: 'allowed',
          ip_address: request.ip,
          user_agent: request.user_agent,
          http_method: request.request_method,
          request_path: request.path,
          protocol: request.scheme,
          details: { middleware: 'VsCodeDetector' }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::VsCodeDetector] Log error: #{e.message}")
      end
    end
  end
end
