# frozen_string_literal: true

Rails.application.config.after_initialize do
  Rails.logger.info('[GitlabSecurity] Loaded')
end

