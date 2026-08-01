#!/bin/bash
# Copy migration, run it, then clean up
MIGRATIONS=/opt/gitlab/embedded/service/gitlab-rails/gitlab_security_addon/db/migrate
TARGET=/opt/gitlab/embedded/service/gitlab-rails/db/migrate

cp ${MIGRATIONS}/*.rb ${TARGET}/
/opt/gitlab/bin/gitlab-rake db:migrate
rm -f ${TARGET}/20240801000001_create_gitlab_security_tables.rb
echo "GitlabSecurity migration done"
