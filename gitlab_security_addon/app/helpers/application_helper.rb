# frozen_string_literal: true

# Helper methods for Security Addon views
module GitlabSecurity
  module ApplicationHelper
    # Get CSS class for enforcement level badge
    def enforcement_level_class(level)
      case level.to_s
      when 'audit_only', '0'
        'label label-info'
      when 'soft_block', '1'
        'label label-warning'
      when 'hard_block', '2'
        'label label-danger'
      else
        'label label-default'
      end
    end

    # Get CSS class for audit log row
    def log_row_class(result)
      case result.to_s
      when 'blocked'
        'danger'
      when 'allowed'
        'success'
      when 'error'
        'warning'
      else
        ''
      end
    end

    # Human-readable operation name
    def operation_label(operation)
      case operation.to_sym
      when :download then _('Download')
      when :clone then _('Clone')
      when :fork then _('Fork')
      when :share then _('Share')
      when :http_access then _('HTTP Access')
      when :ssh_access then _('SSH Access')
      when :vscode_access then _('VS Code')
      when :all_ide_access then _('All IDEs')
      else operation.to_s.humanize
      end
    end

    # Format IP address for display (mask part of it for security)
    def masked_ip(ip)
      return '—' if ip.blank?

      parts = ip.to_s.split('.')
      if parts.length == 4
        "#{parts[0]}.#{parts[1]}.*.*"
      else
        # IPv6: show first 2 groups
        ip.to_s.split(':').first(2).join(':') + '::*'
      end
    end

    # Get security status icon
    def security_status_icon(policy)
      if !policy.enabled?
        content_tag(:span, '●', class: 'text-muted', title: _('Disabled'))
      elsif policy.enforcement_level == 'hard_block'
        content_tag(:span, '●', class: 'text-danger', title: _('Hard Block'))
      elsif policy.enforcement_level == 'soft_block'
        content_tag(:span, '●', class: 'text-warning', title: _('Soft Block'))
      else
        content_tag(:span, '●', class: 'text-info', title: _('Audit Only'))
      end
    end

    # Navigation link for admin sidebar
    def admin_security_nav_link
      link_to _('Security Policies'), admin_security_policies_path,
        class: 'nav-link',
        data: { track_action: 'click_admin_security' }
    end
  end
end
