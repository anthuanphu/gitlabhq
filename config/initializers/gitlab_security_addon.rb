# frozen_string_literal: true

# =============================================================================
# GITLAB SECURITY ADDON - Core Initializer
# =============================================================================
# FILE DUY NHẤT được thêm vào mã nguồn lõi GitLab.
# Khi upstream (gitlabhq/gitlabhq) cập nhật và bạn merge về:
#   - File này KHÔNG có trong upstream → git merge không xung đột
#   - Thư mục gitlab_security_addon/ KHÔNG có trong upstream → không xung đột
#   - Kết quả: addon tiếp tục hoạt động bình thường sau merge
# =============================================================================

if defined?(Rails::Server) || ENV['GITLAB_SECURITY_LOAD'] == 'true' || Rails.env.test?
  Rails.application.reloader.to_prepare do
    begin
      security_addon_root = Rails.root.join('gitlab_security_addon')

      if security_addon_root.exist?
        # Thêm đường dẫn autoload cho thư mục addon
        lib_path = security_addon_root.join('lib')
        $LOAD_PATH.unshift(lib_path.to_s) unless $LOAD_PATH.include?(lib_path.to_s)

        %w[controllers models services helpers].each do |dir|
          path = security_addon_root.join('app', dir)
          if path.exist?
            ActiveSupport::Dependencies.autoload_paths << path.to_s
            Rails.application.config.eager_load_paths << path.to_s
          end
        end

        # Load module chính
        require 'gitlab_security'

        # =====================================================================
        # Ghi đè GitLab core classes bằng Ruby prepend (không sửa file gốc)
        # =====================================================================

        if defined?(Gitlab::GitAccess)
          Gitlab::GitAccess.prepend(GitlabSecurity::Overrides::GitAccess)
          Rails.logger.info('[GitlabSecurity] GitAccess override applied')
        end

        if defined?(ProjectPolicy)
          ProjectPolicy.prepend(GitlabSecurity::Overrides::ProjectPolicy)
          Rails.logger.info('[GitlabSecurity] ProjectPolicy override applied')
        end

        if defined?(Project)
          Project.prepend(GitlabSecurity::Overrides::Project)
          Rails.logger.info('[GitlabSecurity] Project model override applied')
        end

        # Đăng ký middleware bảo mật
        Rails.application.config.middleware.insert_before(
          Gitlab::Middleware::ReadOnly,
          GitlabSecurity::Middleware::SecurityBlocker
        ) rescue Rails.logger.warn('[GitlabSecurity] Could not insert SecurityBlocker')

        Rails.application.config.middleware.insert_before(
          Gitlab::Middleware::ReadOnly,
          GitlabSecurity::Middleware::VsCodeDetector
        ) rescue Rails.logger.warn('[GitlabSecurity] Could not insert VsCodeDetector')

        # Gắn admin settings panel
        if defined?(Admin::ApplicationSettingsController)
          Admin::ApplicationSettingsController.prepend(GitlabSecurity::AdminSettingsExtension)
        end

        # Load rake tasks
        Dir[security_addon_root.join('lib', 'tasks', '**', '*.rake')].each { |f| load f }

        Rails.logger.info("[GitlabSecurity] v#{GitlabSecurity::VERSION} loaded - OK")
      end
    rescue StandardError => e
      Rails.logger.error("[GitlabSecurity] Init failed: #{e.message}")
    end
  end
end
