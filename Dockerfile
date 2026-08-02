FROM gitlab/gitlab-ce:latest
ENV GITLAB_OMNIBUS_CONFIG="gitlab_rails['nginx']['listen_port'] = 8228; gitlab_rails['nginx']['listen_https'] = false"
