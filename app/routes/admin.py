from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.models import User, Report
from app.services.auth_service import AuthService
from app.services.report_service import ReportService
from app.services.audit_service import AuditService
from app.services.crypto_service import crypto_service
from app.forms import AssignInvestigatorForm, UserManagementForm, RoleChangeForm
from datetime import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.before_request
@login_required
def check_admin():
    if current_user.role not in ['admin', 'system_admin']:
        abort(403)


@admin_bp.route('/')
def dashboard():
    total_reports = Report.query.count()
    received_reports = Report.query.filter_by(status='Received').count()
    triaged_reports = Report.query.filter_by(status='Triaged').count()
    investigating_reports = Report.query.filter_by(status='Investigating').count()
    resolved_reports = Report.query.filter_by(status='Resolved').count()
    recent_activity = AuditService.get_recent_activity(10)
    return render_template('admin/dashboard.html', total_reports=total_reports, received_reports=received_reports, triaged_reports=triaged_reports, investigating_reports=investigating_reports, resolved_reports=resolved_reports, recent_activity=recent_activity)


@admin_bp.route('/reports')
def manage_reports():
    filters = {}
    filters['category'] = request.args.get('category')
    filters['status'] = request.args.get('status')
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


@admin_bp.route('/reports/<report_id>/status', methods=['POST'])
def update_report_status(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        return redirect(url_for('admin.manage_reports'))
    new_status = request.form.get('status')
    if new_status in ReportService.VALID_STATUSES:
        success, message = ReportService.update_report_status(report=report, new_status=new_status, acting_user=current_user)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')
    else:
        flash('Invalid status', 'danger')
    return redirect(url_for('admin.manage_reports'))


@admin_bp.route('/users')
def manage_users():
    users = User.query.filter_by(is_active=True).all()
    suspended_users = User.query.filter_by(is_active=False).all()
    return render_template('admin/manage_users.html', users=users, suspended_users=suspended_users)


@admin_bp.route('/users/<user_id>/deactivate', methods=['POST'])
def deactivate_user(user_id):
    if str(user_id) == str(current_user.id):
        flash('Cannot deactivate your own account', 'danger')
        return redirect(url_for('admin.manage_users'))
    user = AuthService.get_user_by_id(user_id)
    if user and AuthService.check_user_permission(current_user, 'system_admin'):
        AuthService.deactivate_user(user, current_user)
        flash('User account suspended successfully', 'success')
    else:
        flash('Failed to deactivate user. Insufficient permissions.', 'danger')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/reactivate', methods=['POST'])
def reactivate_user(user_id):
    if not AuthService.check_user_permission(current_user, 'system_admin'):
        abort(403)
    user = AuthService.get_user_by_id(user_id)
    if user:
        AuthService.reactivate_user(user, current_user)
        flash('User account reactivated successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/change_role', methods=['GET', 'POST'])
def change_user_role(user_id):
    if str(user_id) == str(current_user.id):
        flash('Cannot modify your own role', 'danger')
        return redirect(url_for('admin.manage_users'))
    if not AuthService.check_user_permission(current_user, 'system_admin'):
        abort(403)
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
    if not AuthService.check_user_permission(current_user, 'system_admin'):
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


@admin_bp.route('/audit')
def audit_logs():
    logs = AuditService.get_audit_logs(limit=100)
    integrity = AuditService.verify_audit_integrity()
    return render_template('admin/audit_logs.html', logs=logs, integrity=integrity)


@admin_bp.route('/audit/verify')
def verify_audit_integrity():
    result = AuditService.verify_audit_integrity()
    if result['integrity_ok']:
        flash('Audit log integrity verified successfully', 'success')
    else:
        flash(f'Audit log integrity check failed: {result["invalid"]} invalid entries', 'danger')
    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/audit/export')
def export_audit_logs():
    import json
    from flask import Response
    logs = AuditService.export_audit_logs()
    response = Response(json.dumps(logs, indent=2), mimetype='application/json', headers={'Content-Disposition': 'attachment; filename=audit_logs.json'})
    crypto_service.log_audit_action(action='audit_log_export', acting_user=current_user, acting_role=current_user.role, details='Audit logs exported')
    return response


@admin_bp.route('/security')
def security_monitoring():
    suspicious_activity = AuditService.get_suspicious_activity()
    activity_stats = AuditService.get_activity_stats()
    return render_template('admin/security_monitoring.html', suspicious_activity=suspicious_activity, activity_stats=activity_stats)


@admin_bp.route('/platform_config')
def platform_config():
    if not AuthService.check_user_permission(current_user, 'system_admin'):
        abort(403)
    from flask import current_app
    config = {
        'max_content_length': current_app.config.get('MAX_CONTENT_LENGTH'),
        'allowed_extensions': list(current_app.config.get('ALLOWED_EXTENSIONS', set())),
        'session_cookie_secure': current_app.config.get('SESSION_COOKIE_SECURE'),
        'session_cookie_httponly': current_app.config.get('SESSION_COOKIE_HTTPONLY'),
        'session_cookie_samesite': current_app.config.get('SESSION_COOKIE_SAMESITE'),
        'ratelimit_default': current_app.config.get('RATELIMIT_DEFAULT'),
        'max_failed_login_attempts': current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS'),
        'lockout_duration_minutes': current_app.config.get('LOCKOUT_DURATION_MINUTES'),
        'password_reset_expiry_minutes': current_app.config.get('PASSWORD_RESET_EXPIRY_MINUTES'),
        'jwt_access_token_expires': current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES'),
    }
    return render_template('admin/platform_config.html', config=config)
