# frozen_string_literal: true

# Rake tasks for GitLab Security Addon installation and maintenance
namespace :gitlab_security do
  desc 'Install GitLab Security Addon'
  task install: :environment do
    puts '=' * 60
    puts 'GitLab Security Addon - Installation'
    puts 'Version: %s' % GitlabSecurity::VERSION
    puts '=' * 60

    # Step 1: Run database migrations
    puts "\n[1/4] Running database migrations..."
    Rake::Task['db:migrate'].invoke
    puts '  ✓ Migrations complete'

    # Step 2: Create global default policy
    puts "\n[2/4] Creating global default security policy..."
    global_policy = GitlabSecurity::SecurityPolicy.global_default
    puts '  ✓ Global policy created (ID: %d)' % global_policy.id

    # Step 3: Seed initial configuration
    puts "\n[3/4] Configuring default settings..."
    settings = ApplicationSetting.current_without_cache
    unless settings.security_addon_settings.present?
      settings.update!(security_addon_settings: {
        block_download: false,
        block_clone: false,
        block_fork: true,
        block_share: true,
        block_vscode_connection: false,
        device_whitelist_enabled: false,
        ip_whitelist_enabled: false,
        audit_logging: true
      })
    end
    puts '  ✓ Default settings configured'

    # Step 4: Verify installation
    puts "\n[4/4] Verifying installation..."
    errors = []

    unless defined?(GitlabSecurity)
      errors << 'GitlabSecurity module not loaded'
    end

    unless GitlabSecurity::SecurityPolicy.table_exists?
      errors << 'security_policies table not found'
    end

    unless GitlabSecurity::SecurityAuditLog.table_exists?
      errors << 'security_audit_logs table not found'
    end

    if errors.empty?
      puts '  ✓ All checks passed'
    else
      puts '  ✗ Errors found:'
      errors.each { |e| puts '    - %s' % e }
    end

    puts "\n" + '=' * 60
    puts 'Installation complete!'
    puts 'Access the admin panel at: /admin/security_policies'
    puts '=' * 60
  end

  desc 'Uninstall GitLab Security Addon'
  task uninstall: :environment do
    puts 'WARNING: This will remove all security addon data!'
    puts 'Are you sure? Type "YES" to confirm:'
    input = STDIN.gets.chomp

    if input == 'YES'
      puts 'Removing security addon data...'

      # Drop tables
      ActiveRecord::Migration.drop_table(:security_access_grants) rescue nil
      ActiveRecord::Migration.drop_table(:security_audit_logs) rescue nil
      ActiveRecord::Migration.drop_table(:device_whitelists) rescue nil
      ActiveRecord::Migration.drop_table(:security_policies) rescue nil

      # Remove settings column
      if ActiveRecord::Base.connection.column_exists?(:application_settings, :security_addon_settings)
        ActiveRecord::Migration.remove_column(:application_settings, :security_addon_settings)
      end

      puts 'Uninstall complete.'
    else
      puts 'Uninstall cancelled.'
    end
  end

  desc 'Show security addon status'
  task status: :environment do
    puts '=' * 60
    puts 'GitLab Security Addon Status'
    puts '=' * 60

    puts "\nVersion: %s" % GitlabSecurity::VERSION

    puts "\n--- Policies ---"
    puts 'Total policies: %d' % GitlabSecurity::SecurityPolicy.count
    puts 'Active policies: %d' % GitlabSecurity::SecurityPolicy.enabled.count
    puts 'Global default: %s' % (GitlabSecurity::SecurityPolicy.global_defaults.exists? ? '✓' : '✗')

    puts "\n--- Device Whitelist ---"
    puts 'Total devices: %d' % GitlabSecurity::DeviceWhitelist.count
    puts 'Active devices: %d' % GitlabSecurity::DeviceWhitelist.active.count

    puts "\n--- Audit Logs ---"
    puts 'Total logs: %d' % GitlabSecurity::SecurityAuditLog.count
    puts 'Blocks today: %d' % GitlabSecurity::SecurityAuditLog.today.blocked_events.count
    puts 'Blocks this week: %d' % GitlabSecurity::SecurityAuditLog.this_week.blocked_events.count

    puts "\n--- Access Grants ---"
    puts 'Active grants: %d' % GitlabSecurity::SecurityAccessGrant.active.count

    puts "\n--- Middleware ---"
    middleware = Rails.application.config.middleware
    puts 'SecurityBlocker: %s' % (middleware.include?(GitlabSecurity::Middleware::SecurityBlocker) ? '✓' : '✗')
    puts 'VsCodeDetector: %s' % (middleware.include?(GitlabSecurity::Middleware::VsCodeDetector) ? '✓' : '✗')

    puts "\n--- Configuration ---"
    GitlabSecurity::FEATURES.each do |feature|
      status = GitlabSecurity.feature_enabled?(feature) ? 'ENABLED' : 'disabled'
      puts '  %-35s %s' % [feature.to_s.humanize, status]
    end

    puts '=' * 60
  end

  desc 'Clean up old audit logs (default: > 90 days)'
  task :cleanup_logs, [:days] => :environment do |_t, args|
    days = (args[:days] || 90).to_i
    puts 'Cleaning audit logs older than %d days...' % days
    deleted = GitlabSecurity::SecurityAuditLog.cleanup_old_logs!(retention_days: days)
    puts 'Deleted %d old log entries.' % deleted
  end

  desc 'Revoke expired access grants'
  task revoke_expired_grants: :environment do
    puts 'Revoking expired access grants...'
    GitlabSecurity::SecurityAccessGrant.revoke_expired!
    puts 'Done.'
  end

  desc 'Clean up expired device whitelists'
  task cleanup_devices: :environment do
    puts 'Cleaning up expired device whitelists...'
    GitlabSecurity::DeviceWhitelist.cleanup_expired!
    puts 'Done.'
  end

  desc 'Run all maintenance tasks'
  task maintenance: [:cleanup_logs, :revoke_expired_grants, :cleanup_devices]
end
