from datetime import datetime


def format_datetime(dt):
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return ''


def format_date(dt):
    if dt:
        return dt.strftime('%Y-%m-%d')
    return ''


def format_time(dt):
    if dt:
        return dt.strftime('%H:%M:%S')
    return ''


def truncate_text(text, length=100):
    if text is None:
        return ''
    if len(text) > length:
        return text[:length] + '...'
    return text


def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def get_report_status_css(status):
    status_classes = {'Received': 'text-bg-primary', 'Triaged': 'text-bg-info', 'Investigating': 'text-bg-warning', 'Resolved': 'text-bg-success'}
    return status_classes.get(status, 'text-bg-secondary')


def get_action_css(action):
    action_classes = {'user_registration': 'text-success', 'user_login': 'text-info', 'user_logout': 'text-warning', 'report_submission': 'text-primary', 'status_update': 'text-info', 'investigator_assignment': 'text-warning', 'investigation_note': 'text-secondary', 'password_change': 'text-danger', 'user_deactivation': 'text-danger', 'login_failed': 'text-danger'}
    return action_classes.get(action, 'text-muted')


def json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def get_role_display_name(role):
    role_names = {'whistleblower': 'Whistleblower', 'investigator': 'Investigator', 'report_admin': 'Report Admin', 'system_admin': 'System Admin'}
    return role_names.get(role, role)


def get_category_display_name(category):
    category_names = {'academic_misconduct': 'Academic Misconduct', 'financial_misconduct': 'Financial Misconduct', 'harassment': 'Harassment', 'policy_violation': 'Policy Violation', 'ethical_concern': 'Ethical Concern', 'other': 'Other'}
    return category_names.get(category, category)
