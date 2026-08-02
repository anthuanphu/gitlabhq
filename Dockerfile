FROM gitlab/gitlab-ce:latest

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    GITLAB_OMNIBUS_CONFIG="gitlab_rails['nginx']['listen_port'] = 8228; gitlab_rails['nginx']['listen_https'] = false; puma['worker_processes'] = 2; sidekiq['max_concurrency'] = 10; postgresql['shared_buffers'] = '256MB'; prometheus_monitoring['enable'] = false"

# Security Addon (legacy middleware helpers)
COPY gitlab_security_addon/ ${GITLAB_RAILS_DIR}/gitlab_security_addon/
COPY config/initializers/gitlab_security_addon.rb ${GITLAB_RAILS_DIR}/config/initializers/
COPY gitlab_security_addon/scripts/run_migration.sh /usr/local/bin/gitlab-security-migrate
RUN chmod +x /usr/local/bin/gitlab-security-migrate

# Security: core modifications (migration + model + enforcement)
COPY db/migrate/20240803000001_create_project_security_settings.rb ${GITLAB_RAILS_DIR}/db/migrate/
COPY app/models/project_security_setting.rb ${GITLAB_RAILS_DIR}/app/models/
COPY app/models/project.rb ${GITLAB_RAILS_DIR}/app/models/
COPY lib/gitlab/git_access.rb ${GITLAB_RAILS_DIR}/lib/gitlab/
COPY app/controllers/projects/repositories_controller.rb ${GITLAB_RAILS_DIR}/app/controllers/projects/
COPY app/controllers/projects/raw_controller.rb ${GITLAB_RAILS_DIR}/app/controllers/projects/
COPY app/services/projects/fork_service.rb ${GITLAB_RAILS_DIR}/app/services/projects/
COPY app/controllers/admin/projects_controller.rb ${GITLAB_RAILS_DIR}/app/controllers/admin/
COPY config/routes/admin.rb ${GITLAB_RAILS_DIR}/config/routes/
COPY app/views/admin/projects/show.html.haml ${GITLAB_RAILS_DIR}/app/views/admin/projects/
