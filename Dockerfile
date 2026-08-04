FROM gitlab/gitlab-ce:latest

# Bump this line to bust Docker build cache when deploying changes
ARG CACHE_BUST=4

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    GITLAB_OMNIBUS_CONFIG="external_url 'http://git.aurixsystems.vn'; nginx['listen_port'] = 80; nginx['listen_https'] = false; puma['worker_processes'] = 2; sidekiq['max_concurrency'] = 10; postgresql['shared_buffers'] = '256MB'; prometheus_monitoring['enable'] = false"

# Source Code Protection — new files
COPY config/initializers/gitlab_security_addon.rb ${GITLAB_RAILS_DIR}/config/initializers/
COPY db/migrate/20240803000001_create_project_security_settings.rb ${GITLAB_RAILS_DIR}/db/migrate/
COPY app/models/project_security_setting.rb ${GITLAB_RAILS_DIR}/app/models/

# Patch existing files (version-safe injection)
COPY scripts/patch-gitlab.rb /tmp/patch-gitlab.rb
RUN /opt/gitlab/embedded/bin/ruby /tmp/patch-gitlab.rb && rm /tmp/patch-gitlab.rb
RUN mkdir -p /workspace && chmod 777 /workspace
