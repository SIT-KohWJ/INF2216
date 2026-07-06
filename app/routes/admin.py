from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.models import User, Report
from app.services.auth_service import AuthService
from app.services.report_service import ReportService
from app.services.audit_service import AuditService, REPORT_ACTIONS, SYSTEM_ACTIONS
from app.services.crypto_service import crypto_service
from app.forms import AssignInvestigatorForm, UserManagementForm, RoleChangeForm
from datetime import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.before_request
@login_required
def check_admin():
    if current_user.role not in ['report_admin', 'system_admin']:
        abort(403)


# ── Shared ────────────────────────────────────────────────────────────────────

@admin_bp.route('/')
def dashboard():
    if current_user.role == 'report_admin':
        total_reports = Report.query.count()
        received_reports = Report.query.filter_by(status='Received').count()
        triaged_reports = Report.query.filter_by(status='Triaged').count()
        planning_reports = Report.query.filter_by(status='Planning').count()
        investigating_reports = Report.query.filter_by(status='Investigating').count()
        under_review_reports = Report.query.filter_by(status='Under Review').count()
        closed_reports = Report.query.filter_by(status='Closed').count()
        recent_activity = AuditService.get_recent_report_activity(10)
        return render_template('admin/dashboard.html',
                               total_reports=total_reports,
                               received_reports=received_reports,
                               triaged_reports=triaged_reports,
                               planning_reports=planning_reports,
                               investigating_reports=investigating_reports,
                               under_review_reports=under_review_reports,
                               closed_reports=closed_reports,
                               recent_activity=recent_activity)
    else:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        suspended_users = User.query.filter_by(is_active=False).count()
        recent_activity = AuditService.get_recent_system_activity(10)
        return render_template('admin/dashboard.html',
                               total_users=total_users,
                               active_users=active_users,
                               suspended_users=suspended_users,
                               recent_activity=recent_activity)


# ── Report Admin routes (FR-AD2 to FR-AD10) ──────────────────────────────────

@admin_bp.route('/reports')
def manage_reports():
    if current_user.role != 'report_admin':
        abort(403)
    filters = {}
    filters['category'] = request.args.get('category')
    filters['status'] = request.args.get('status')
    filters['severity'] = request.args.get('severity')
    filters['investigator_id'] = request.args.get('investigator_id')
    filters['search'] = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if date_from:
        filters['date_from'] = datetime.strptime(date_from, '%Y-%m-%d')
    if date_to:
        filters['date_to'] = datetime.strptime(date_to, '%Y-%m-%d')
    filters = {k: v for k, v in filters.items() if v}
    if filters:
        reports = ReportService.search_and_filter_reports(filters, current_user)
    else:
        reports = ReportService.get_reports_for_user(current_user)
    investigators = AuthService.get_users_by_role('investigator')
    return render_template('admin/manage_reports.html', reports=reports, investigators=investigators, filters=request.args)


@admin_bp.route('/reports/<report_id>/assign', methods=['GET', 'POST'])
def assign_investigator(report_id):
    if current_user.role != 'report_admin':
        abort(403)
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        return redirect(url_for('admin.manage_reports'))
    form = AssignInvestigatorForm()
    form.investigator.choices = [(i.id, i.full_name) for i in AuthService.get_users_by_role('investigator')]
    if form.validate_on_submit():
        investigator = AuthService.get_user_by_id(form.investigator.data)
        if investigator:
            success, message = ReportService.assign_investigator(report=report, investigator=investigator, acting_user=current_user)
            if success:
                flash(message, 'success')
                return redirect(url_for('admin.manage_reports'))
            else:
                flash(message, 'danger')
        else:
            flash('Investigator not found', 'danger')
    return render_template('admin/assign_investigator.html', form=form, report=report)


@admin_bp.route('/reports/<report_id>/severity', methods=['POST'])
def update_report_severity(report_id):
    if current_user.role != 'report_admin':
        abort(403)
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        return redirect(url_for('admin.manage_reports'))
    new_severity = request.form.get('severity')
    if new_severity in ReportService.VALID_SEVERITIES:
        success, message = ReportService.update_report_severity(report=report, new_severity=new_severity, acting_user=current_user)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')
    else:
        flash('Invalid severity', 'danger')
    return redirect(request.referrer or url_for('admin.manage_reports'))


@admin_bp.route('/reports/<report_id>/status', methods=['POST'])
def update_report_status(report_id):
    if current_user.role != 'report_admin':
        abort(403)
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        return redirect(url_for('admin.manage_reports'))
    new_status = request.form.get('status')
    if new_status != 'Triaged':
        flash('Invalid status', 'danger')
        return redirect(url_for('admin.manage_reports'))
    success, message = ReportService.update_report_status(report=report, new_status=new_status, acting_user=current_user)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('admin.manage_reports'))


@admin_bp.route('/audit')
def audit_logs():
    if current_user.role != 'report_admin':
        abort(403)
    logs = AuditService.get_report_audit_logs(limit=100)
    integrity = AuditService.verify_audit_integrity(actions=REPORT_ACTIONS)
    return render_template('admin/audit_logs.html', logs=logs, integrity=integrity)


@admin_bp.route('/audit/verify')
def verify_audit_integrity():
    if current_user.role != 'report_admin':
        abort(403)
    result = AuditService.verify_audit_integrity(actions=REPORT_ACTIONS)
    if result['integrity_ok']:
        msg = 'Audit log integrity verified successfully'
        if result.get('historical'):
            msg += f' ({result["historical"]} historical entries signed by a rotated key)'
        flash(msg, 'success')
    else:
        flash(f'Audit log integrity check failed: {result["invalid"]} invalid entries', 'danger')
    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/audit/export')
def export_audit_logs():
    if current_user.role != 'report_admin':
        abort(403)
    import json
    from flask import Response
    logs = AuditService.get_report_audit_logs(limit=10000)
    data = [{'id': log.id, 'timestamp': log.timestamp.isoformat() if log.timestamp else None, 'action': log.action, 'acting_role': log.acting_role, 'target_type': log.target_type, 'target_id': log.target_id, 'details': log.details, 'ip_address': log.ip_address} for log in logs]
    response = Response(json.dumps(data, indent=2), mimetype='application/json', headers={'Content-Disposition': 'attachment; filename=report_audit_logs.json'})
    crypto_service.log_audit_action(action='audit_log_export', acting_user=current_user, acting_role=current_user.role, details='Report audit logs exported')
    return response


@admin_bp.route('/security')
def security_monitoring():
    if current_user.role != 'report_admin':
        abort(403)
    suspicious_activity = AuditService.get_suspicious_activity()
    activity_stats = AuditService.get_activity_stats()
    return render_template('admin/security_monitoring.html', suspicious_activity=suspicious_activity, activity_stats=activity_stats)


# ── System Admin routes (FR-SA2 to FR-SA8) ───────────────────────────────────

@admin_bp.route('/system_audit')
def system_audit_logs():
    if current_user.role != 'system_admin':
        abort(403)
    logs = AuditService.get_system_audit_logs(limit=100)
    integrity = AuditService.verify_audit_integrity(actions=SYSTEM_ACTIONS)
    return render_template('admin/audit_logs.html', logs=logs, integrity=integrity)


@admin_bp.route('/users')
def manage_users():
    if current_user.role != 'system_admin':
        abort(403)
    # Anonymised accounts from an approved deletion (deleted_<id>@deleted.sitinform)
    # are kept only for report/audit integrity; they are not manageable users, so
    # exclude them from every list.
    not_deleted = ~User.email.like('%@deleted.sitinform')
    users = User.query.filter_by(is_active=True).filter(not_deleted).all()
    suspended_users = User.query.filter_by(is_active=False, deletion_requested=False).filter(not_deleted).all()
    deletion_requests = User.query.filter_by(deletion_requested=True).filter(not_deleted).all()
    return render_template('admin/manage_users.html', users=users, suspended_users=suspended_users, deletion_requests=deletion_requests)


@admin_bp.route('/users/<user_id>/deactivate', methods=['POST'])
def deactivate_user(user_id):
    if current_user.role != 'system_admin':
        abort(403)
    if str(user_id) == str(current_user.id):
        flash('Cannot deactivate your own account', 'danger')
        return redirect(url_for('admin.manage_users'))
    user = AuthService.get_user_by_id(user_id)
    if user:
        success, message = AuthService.deactivate_user(user, current_user)
        flash(message, 'success' if success else 'danger')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/approve_deletion', methods=['POST'])
def approve_deletion(user_id):
    if current_user.role != 'system_admin':
        abort(403)
    user = AuthService.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.manage_users'))
    success, message = AuthService.approve_account_deletion(user, current_user)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/deny_deletion', methods=['POST'])
def deny_deletion(user_id):
    if current_user.role != 'system_admin':
        abort(403)
    user = AuthService.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.manage_users'))
    success, message = AuthService.deny_account_deletion(user, current_user)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/reactivate', methods=['POST'])
def reactivate_user(user_id):
    if current_user.role != 'system_admin':
        abort(403)
    user = AuthService.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.manage_users'))
    # An approved deletion permanently anonymises the account (email overwritten
    # to deleted_<id>@deleted.sitinform, password wiped). Reactivating such an
    # account only flips is_active but can never restore login, so block it and
    # tell the admin to advise the user to register a new account.
    if user.email.endswith('@deleted.sitinform') or not user.password_hash:
        flash('This account has been permanently deleted and cannot be reactivated. The user must register a new account.', 'danger')
        return redirect(url_for('admin.manage_users'))
    AuthService.reactivate_user(user, current_user)
    flash('User account reactivated successfully', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/change_role', methods=['GET', 'POST'])
def change_user_role(user_id):
    if current_user.role != 'system_admin':
        abort(403)
    if str(user_id) == str(current_user.id):
        flash('Cannot modify your own role', 'danger')
        return redirect(url_for('admin.manage_users'))
    user = AuthService.get_user_by_id(user_id)
    if not user:
        abort(404)
    form = RoleChangeForm()
    if form.validate_on_submit():
        success, message = AuthService.update_user_role(user=user, new_role=form.role.data, acting_user=current_user)
        if success:
            flash(message, 'success')
            return redirect(url_for('admin.manage_users'))
        else:
            flash(message, 'danger')
    return render_template('admin/change_role.html', form=form, target_user=user)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
def create_user():
    if current_user.role != 'system_admin':
        abort(403)
    form = UserManagementForm()
    if form.validate_on_submit():
        user, message = AuthService.register_user(email=form.email.data, password=form.password.data, first_name=form.first_name.data, last_name=form.last_name.data, role=form.role.data, acting_user=current_user)
        if user:
            flash('User created successfully', 'success')
            return redirect(url_for('admin.manage_users'))
        else:
            flash(message, 'danger')
    return render_template('admin/create_user.html', form=form)


# Maps editable form fields <-> the app.config keys they override. Keeping this
# in one place ties the form, persistence and audit-log detail together.
_EDITABLE_CONFIG = {
    'max_failed_login_attempts': 'MAX_FAILED_LOGIN_ATTEMPTS',
    'lockout_duration_minutes': 'LOCKOUT_DURATION_MINUTES',
    'password_reset_expiry_minutes': 'PASSWORD_RESET_EXPIRY_MINUTES',
}


@admin_bp.route('/platform_config', methods=['GET', 'POST'])
def platform_config():
    if current_user.role != 'system_admin':
        abort(403)
    from flask import current_app
    from app import db
    from app.models import PlatformSetting
    from app.forms import PlatformConfigForm

    form = PlatformConfigForm()

    if form.validate_on_submit():
        changes = []
        for field_name, config_key in _EDITABLE_CONFIG.items():
            new_val = form[field_name].data
            old_val = current_app.config.get(config_key)
            if new_val != old_val:
                PlatformSetting.set_value(config_key, new_val)
                current_app.config[config_key] = new_val  # apply live, no restart
                changes.append(f'{config_key}: {old_val} -> {new_val}')
        if changes:
            db.session.commit()
            crypto_service.log_audit_action(
                action='platform_config_updated',
                acting_user=current_user, acting_role=current_user.role,
                target_type='platform_config',
                details='; '.join(changes), ip_address=request.remote_addr,
            )
            flash('Platform settings updated.', 'success')
        else:
            flash('No changes to save.', 'info')
        return redirect(url_for('admin.platform_config'))

    # Prefill the editable fields from live config on GET (or re-show on error).
    if request.method == 'GET':
        for field_name, config_key in _EDITABLE_CONFIG.items():
            form[field_name].data = current_app.config.get(config_key)

    # Read-only, security-critical settings shown for reference but never editable.
    readonly_config = {
        'max_content_length': current_app.config.get('MAX_CONTENT_LENGTH'),
        'allowed_extensions': list(current_app.config.get('ALLOWED_EXTENSIONS', set())),
        'session_cookie_secure': current_app.config.get('SESSION_COOKIE_SECURE'),
        'session_cookie_httponly': current_app.config.get('SESSION_COOKIE_HTTPONLY'),
        'session_cookie_samesite': current_app.config.get('SESSION_COOKIE_SAMESITE'),
    }
    return render_template('admin/platform_config.html', form=form, readonly_config=readonly_config)
