FROM gitlab/gitlab-ce:latest

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    GITLAB_OMNIBUS_CONFIG="nginx['listen_port'] = 8228; nginx['listen_https'] = false"

COPY gitlab_security_addon/ ${GITLAB_RAILS_DIR}/gitlab_security_addon/
COPY config/initializers/gitlab_security_addon.rb ${GITLAB_RAILS_DIR}/config/initializers/
