FROM gitlab/gitlab-ce:latest

ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails \
    EXTERNAL_URL=http://localhost

COPY gitlab_security_addon/ ${GITLAB_RAILS_DIR}/gitlab_security_addon/
COPY config/initializers/gitlab_security_addon.rb ${GITLAB_RAILS_DIR}/config/initializers/
