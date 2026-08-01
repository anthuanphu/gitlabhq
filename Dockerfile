# =============================================================================
# GitLab Security Addon - Docker Image
# =============================================================================
# Build:  docker build -t gitlab-security .
# Run:    docker run -d --name gitlab -p 80:80 -p 443:443 -p 22:22 gitlab-security
# 
# Tương thích Coolify: chỉ cần trỏ đến repo GitHub là Coolify tự build & deploy
# =============================================================================

FROM gitlab/gitlab-ce:latest

# ---------------------------------------------------------------------------
# Copy Security Addon vào Rails app trong Omnibus
# ---------------------------------------------------------------------------
# Rails app nằm tại /opt/gitlab/embedded/service/gitlab-rails/ trong Omnibus
ENV GITLAB_RAILS_DIR=/opt/gitlab/embedded/service/gitlab-rails

# 1. Copy toàn bộ addon (models, controllers, views, middleware, v.v.)
COPY gitlab_security_addon/ ${GITLAB_RAILS_DIR}/gitlab_security_addon/

# 2. Copy Rails initializer (file duy nhất trong core)
COPY config/initializers/gitlab_security_addon.rb ${GITLAB_RAILS_DIR}/config/initializers/gitlab_security_addon.rb

# 3. Copy database migration vào db/migrate/ để Rails tự động pick up
COPY gitlab_security_addon/db/migrate/ ${GITLAB_RAILS_DIR}/db/migrate/

# 4. Copy post-reconfigure script (chạy migration khi container start)
COPY gitlab_security_addon/scripts/post-reconfigure.sh /assets/security-post-reconfigure.sh
RUN chmod +x /assets/security-post-reconfigure.sh

# ---------------------------------------------------------------------------
# Tự động chạy migration khi container start
# ---------------------------------------------------------------------------
# Dùng script file thay vì inline (tránh lỗi escape backslash trong Docker ENV)
ENV GITLAB_POST_RECONFIGURE_SCRIPT=/assets/security-post-reconfigure.sh

# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
LABEL maintainer="anthuanphu"
LABEL description="GitLab CE with Security Addon - enterprise source code protection"
LABEL version="1.0.0"
LABEL git.url="https://github.com/anthuanphu/gitlabhq.git"
