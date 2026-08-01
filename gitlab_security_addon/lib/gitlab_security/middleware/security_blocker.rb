# frozen_string_literal: true

# Rack Middleware: SecurityBlocker
# Intercepts ALL incoming HTTP requests and checks against security policies.
# Blocks unauthorized access at the HTTP level before it reaches Rails controllers.
#
# Placement in middleware stack: Before Gitlab::Middleware::ReadOnly
# This ensures security checks run before any business logic.
module GitlabSecurity
  module Middleware
    class SecurityBlocker
      # Patterns for blocking IDE connections
      BLOCKED_USER_AGENT_PATTERNS = [
        /vscode/i,                    # VS Code
        /Visual Studio Code/i,        # VS Code (full name)
        /Code\/[\d.]+/i,              # VS Code versioned
        /JetBrains/i,                 # JetBrains IDEs (IntelliJ, etc.)
        /IntelliJ IDEA/i,
        /PyCharm/i,
        /WebStorm/i,
        /PhpStorm/i,
        /RubyMine/i,
        /GoLand/i,
        /CLion/i,
        /Eclipse/i,                   # Eclipse IDE
        /NetBeans/i,
        /Sublime Text/i,              # Sublime Text
        /Atom\//i,                    # Atom editor
        /Brackets/i,                  # Brackets editor
        /git\//i,                     # Git CLI (can be blocked separately)
        /libgit2/i,                   # libgit2 based tools
        /SourceTree/i,                # Sourcetree
        /GitKraken/i,                 # GitKraken
        /TortoiseGit/i,               # TortoiseGit
        /Fork\//i,                   # Fork (Git client)
      ].freeze

      # Git operations that indicate clone/download attempts
      GIT_OPERATIONS_PATTERN = %r{/(git-upload-pack|git-receive-pack|git-upload-archive|info/refs)}i

      # Project path pattern in URL
      PROJECT_PATH_PATTERN = %r{/([^/]+(?:/[^/]+)*?)\.git/}

      def initialize(app)
        @app = app
      end

      def call(env)
        request = Rack::Request.new(env)
        status, headers, response = check_request(request)

        if status
          # Request is blocked - return immediately
          [status, headers, response]
        else
          # Request allowed - continue the middleware chain
          @app.call(env)
        end
      end

      private

      def check_request(request)
        ip = request.ip
        user_agent = request.user_agent || ''
        path = request.path || ''
        method = request.request_method || ''

        # Skip health checks and internal endpoints
        return nil if skip_check?(path)

        # 1. Check global "block all" mode
        if GitlabSecurity.feature_enabled?(:block_all_external_connections)
          unless internal_request?(request)
            log_block('block_all_external_connections', request)
            return blocked_response('All external connections are blocked by administrator')
          end
        end

        # 2. Check IP whitelist
        if GitlabSecurity.feature_enabled?(:ip_whitelist_enabled)
          unless GitlabSecurity.device_whitelisted?(ip, user_agent)
            log_block('ip_not_whitelisted', request)
            return blocked_response('Your IP address is not authorized to access this GitLab instance')
          end
        end

        # 3. Check device whitelist for IDE connections
        if GitlabSecurity.feature_enabled?(:device_whitelist_enabled)
          if ide_user_agent?(user_agent) && !GitlabSecurity.device_whitelisted?(ip, user_agent)
            log_block('device_not_whitelisted', request)
            return blocked_response('Your device is not authorized. Please contact your administrator.')
          end
        end

        # 4. Check VS Code blocking
        if GitlabSecurity.feature_enabled?(:block_vscode_connection)
          if vscode_user_agent?(user_agent) || vscode_request?(request)
            log_block('vscode_blocked', request)
            return blocked_response('VS Code connections are blocked by administrator')
          end
        end

        # 5. Check IDE blocking
        if GitlabSecurity.feature_enabled?(:block_all_ide_access)
          if ide_user_agent?(user_agent)
            log_block('ide_blocked', request)
            return blocked_response('IDE connections are blocked by administrator')
          end
        end

        # All checks passed
        nil
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::SecurityBlocker] Error: #{e.message}")
        nil # Allow request on error (fail-open for safety)
      end

      # Detect VS Code specific requests
      def vscode_user_agent?(user_agent)
        return false if user_agent.blank?
        user_agent.match?(/vscode|Visual Studio Code/i)
      end

      # Detect VS Code-specific API calls
      def vscode_request?(request)
        path = request.path || ''
        # VS Code GitLab extension uses specific API endpoints
        path.include?('/api/v4/projects/') && path.include?('/repository/')
      end

      # Detect any IDE/tool user agent
      def ide_user_agent?(user_agent)
        return false if user_agent.blank?
        BLOCKED_USER_AGENT_PATTERNS.any? { |pattern| user_agent.match?(pattern) }
      end

      # Check if this is a git clone/download attempt
      def git_operation?(request)
        (request.path || '').match?(GIT_OPERATIONS_PATTERN)
      end

      # Extract project path from URL if it's a git operation
      def extract_project_path(request)
        match = (request.path || '').match(PROJECT_PATH_PATTERN)
        match ? match[1] : nil
      end

      # Skip security checks for certain paths
      def skip_check?(path)
        return true if path.blank?

        skip_patterns = [
          %r{^/health},
          %r{^/-/health},
          %r{^/-/liveness},
          %r{^/-/readiness},
          %r{^/-/metrics},
          %r{^/api/v4/internal/},
          %r{^/assets/},
          %r{^/admin/},          # Admin panel always accessible
          %r{^/users/sign_in},
          %r{^/oauth/},
        ]

        skip_patterns.any? { |pattern| path.match?(pattern) }
      end

      # Check if request comes from internal network
      def internal_request?(request)
        ip = request.ip
        return false if ip.blank?

        # Check private IP ranges
        private_ranges = [
          IPAddr.new('10.0.0.0/8'),
          IPAddr.new('172.16.0.0/12'),
          IPAddr.new('192.168.0.0/16'),
          IPAddr.new('127.0.0.0/8'),
        ]

        begin
          addr = IPAddr.new(ip)
          private_ranges.any? { |range| range.include?(addr) }
        rescue IPAddr::InvalidAddressError
          false
        end
      end

      # Log blocked request
      def log_block(reason, request)
        GitlabSecurity::SecurityAuditLog.log!(
          event_type: 'http_connection_blocked',
          result: 'blocked',
          ip_address: request.ip,
          user_agent: request.user_agent,
          http_method: request.request_method,
          request_path: request.path,
          protocol: request.scheme,
          block_reason: reason,
          details: {
            middleware: 'SecurityBlocker',
            block_reason: reason,
            headers: extract_relevant_headers(request)
          }
        )
      rescue StandardError => e
        Rails.logger.error("[GitlabSecurity::SecurityBlocker] Log error: #{e.message}")
      end

      # Build HTTP 403 Forbidden response
      def blocked_response(message)
        body = {
          error: 'access_denied',
          message: message,
          timestamp: Time.current.iso8601,
          help: 'Contact your GitLab administrator to request access.'
        }.to_json

        headers = {
          'Content-Type' => 'application/json',
          'Content-Length' => body.bytesize.to_s,
          'X-GitLab-Security-Blocked' => 'true'
        }

        [403, headers, [body]]
      end

      # Extract relevant headers for logging (no sensitive data)
      def extract_relevant_headers(request)
        env = request.env
        {
          'HTTP_HOST' => env['HTTP_HOST'],
          'HTTP_ORIGIN' => env['HTTP_ORIGIN'],
          'HTTP_REFERER' => env['HTTP_REFERER'],
          'REMOTE_ADDR' => env['REMOTE_ADDR'],
          'REQUEST_METHOD' => env['REQUEST_METHOD'],
          'REQUEST_URI' => env['REQUEST_URI']
        }.compact
      end
    end
  end
end
