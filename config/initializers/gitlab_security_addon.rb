# frozen_string_literal: true

# GITLAB SECURITY ADDON - Minimal bootstrap
# Step 1: Chỉ log, chưa load gì cả. Nếu container boot được → vấn đề nằm ở code addon.
# Step 2: Sẽ bật từng module một để xác định chính xác nguyên nhân crash.

Rails.application.config.after_initialize do
  Rails.logger.info('[GitlabSecurity] Boot phase 1 - container alive, addon not loaded yet')
end

