from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, g, Response
from flask_login import login_required, current_user

from app.forms import AssignInvestigatorForm, UserManagementForm, RoleChangeForm
from app.models import User, Report
from app.securityfeature import (
    AccessControlService, require_permission,
    load_report_from_url, load_user_from_url,
    AuditService,
)
from app.services.auth_service import AuthService
from app.services.audit_service import _LegacyAuditService
from app.services.report_service import ReportService
from datetime import datetime
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.before_request
@login_required
def check_admin():
    """Coarse first filter: only report_admin / system_admin may enter /admin/*.

    Fine-grained per-route authorisation is enforced by @require_permission
    on each individual endpoint below.
    """
    if current_user.role not in ['report_admin', 'system_admin']:
        abort(403)


# ── Shared dashboard ────────────────────────────────────────────────────────

@admin_bp.route('/')
@require_permission('admin.view_dashboard')
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


# ── Report Admin routes ─────────────────────────────────────────────────────

@admin_bp.route('/reports')
@require_permission('admin.manage_reports')
def manage_reports():
    filters = {}
    filters['category'] = request.args.get('category')
    filters['status'] = request.args.get('status')
    filters['severity'] = request.args.get('severity')
    filters['investigator_id'] = request.args.get('investigator_id')
    filters['search'] = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if date_from:
        try:
            filters['date_from'] = datetime.strptime(date_from, '%Y-%m-%d')
        except ValueError:
            flash('Invalid "from" date format', 'danger')
            return redirect(url_for('admin.manage_reports'))
    if date_to:
        try:
            filters['date_to'] = datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            flash('Invalid "to" date format', 'danger')
            return redirect(url_for('admin.manage_reports'))
    filters = {k: v for k, v in filters.items() if v}
    if filters:
        reports = ReportService.search_and_filter_reports(filters, current_user)
    else:
        reports = ReportService.get_reports_for_user(current_user)
    investigators = AuthService.get_users_by_role('investigator')
    return render_template('admin/manage_reports.html', reports=reports, investigators=investigators, filters=request.args)


@admin_bp.route('/reports/<report_id>/assign', methods=['GET', 'POST'])
@require_permission('report.assign_investigator', resource_loader=load_report_from_url)
def assign_investigator(report_id, resource=None):
    report = resource
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
@require_permission('report.update_severity', resource_loader=load_report_from_url)
def update_report_severity(report_id, resource=None):
    report = resource
    new_severity = request.form.get('severity')
    # Server-side whitelist (defence against POST-body tampering via Burp).
    if new_severity not in ReportService.VALID_SEVERITIES:
        flash('Invalid severity', 'danger')
        return redirect(request.referrer or url_for('admin.manage_reports'))
    success, message = ReportService.update_report_severity(report=report, new_severity=new_severity, acting_user=current_user)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(request.referrer or url_for('admin.manage_reports'))


@admin_bp.route('/reports/<report_id>/status', methods=['POST'])
@require_permission('report.update_status', resource_loader=load_report_from_url)
def update_report_status(report_id, resource=None):
    report = resource
    new_status = request.form.get('status')
    # Server-side whitelist: report_admins may only triage from this endpoint
    # (other transitions are driven by investigator actions on the report page).
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
@require_permission('admin.view_report_audit')
def audit_logs():
    logs = AuditService.get_report_audit_logs(limit=100)
    integrity = AuditService.verify_audit_integrity()
    return render_template('admin/audit_logs.html', logs=logs, integrity=integrity)


@admin_bp.route('/audit/verify')
@require_permission('admin.view_report_audit')
def verify_audit_integrity():
    result = AuditService.verify_audit_integrity()
    if result['integrity_ok']:
        flash('Audit log integrity verified successfully', 'success')
        AuditService.log(
            action='audit_integrity_check',
            acting_user=current_user,
            acting_role=current_user.role,
            details='Integrity check passed',
            ip_address=request.remote_addr,
            request_id=g.get('request_id'),
        )
    else:
        flash(f'Audit log integrity check failed: {result["invalid"]} invalid entries', 'danger')
        AuditService.log(
            action='audit_integrity_check',
            acting_user=current_user,
            acting_role=current_user.role,
            details=f'Integrity check FAILED: {result["invalid"]} invalid entries',
            ip_address=request.remote_addr,
            request_id=g.get('request_id'),
        )
    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/audit/export')
@require_permission('admin.export_audit')
def export_audit_logs():
    logs = AuditService.get_report_audit_logs(limit=10000)
    data = [{
        'id': log.id,
        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
        'action': log.action,
        'acting_role': log.acting_role,
        'target_type': log.target_type,
        'target_id': log.target_id,
        'details': log.details,
        'ip_address': log.ip_address,
    } for log in logs]
    AuditService.log(
        action='audit_log_export',
        acting_user=current_user,
        acting_role=current_user.role,
        details='Report audit logs exported',
        ip_address=request.remote_addr,
        request_id=g.get('request_id'),
    )
    response = Response(json.dumps(data, indent=2), mimetype='application/json',
                        headers={'Content-Disposition': 'attachment; filename=report_audit_logs.json'})
    return response


@admin_bp.route('/security')
@require_permission('admin.view_security')
def security_monitoring():
    suspicious_activity = AuditService.get_suspicious_activity()
    activity_stats = AuditService.get_activity_stats()
    return render_template('admin/security_monitoring.html', suspicious_activity=suspicious_activity, activity_stats=activity_stats)


# ── System Admin routes ─────────────────────────────────────────────────────

@admin_bp.route('/system_audit')
@require_permission('admin.view_system_audit')
def system_audit_logs():
    logs = AuditService.get_system_audit_logs(limit=100)
    return render_template('admin/audit_logs.html', logs=logs, integrity=None)


@admin_bp.route('/users')
@require_permission('admin.manage_users')
def manage_users():
    users = User.query.filter_by(is_active=True).all()
    suspended_users = User.query.filter_by(is_active=False).all()
    return render_template('admin/manage_users.html', users=users, suspended_users=suspended_users)


@admin_bp.route('/users/<user_id>/deactivate', methods=['POST'])
@require_permission('admin.deactivate_user', resource_loader=load_user_from_url)
def deactivate_user(user_id, resource=None):
    target = resource
    if str(target.id) == str(current_user.id):
        flash('Cannot deactivate your own account', 'danger')
        return redirect(url_for('admin.manage_users'))
    AuthService.deactivate_user(target, current_user)
    flash('User account suspended successfully', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/reactivate', methods=['POST'])
@require_permission('admin.reactivate_user', resource_loader=load_user_from_url)
def reactivate_user(user_id, resource=None):
    target = resource
    AuthService.reactivate_user(target, current_user)
    flash('User account reactivated successfully', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<user_id>/change_role', methods=['GET', 'POST'])
@require_permission('admin.change_role', resource_loader=load_user_from_url)
def change_user_role(user_id, resource=None):
    target = resource
    if str(target.id) == str(current_user.id):
        flash('Cannot modify your own role', 'danger')
        return redirect(url_for('admin.manage_users'))
    form = RoleChangeForm()
    if form.validate_on_submit():
        new_role = form.role.data
        # Server-side whitelist + privilege-escalation guard (Burp resistance:
        # a forged POST with role='system_admin' from a report_admin is blocked
        # here, even if the WTForms choices list was bypassed).
        if not AccessControlService.is_valid_role(new_role):
            flash('Invalid role', 'danger')
            return redirect(url_for('admin.manage_users'))
        if not AccessControlService.can_assign_role(current_user, new_role):
            flash('Cannot assign a role equal to or higher than your own.', 'danger')
            return redirect(url_for('admin.manage_users'))
        success, message = AuthService.update_user_role(user=target, new_role=new_role, acting_user=current_user)
        if success:
            flash(message, 'success')
            return redirect(url_for('admin.manage_users'))
        else:
            flash(message, 'danger')
    return render_template('admin/change_role.html', form=form, target_user=target)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@require_permission('admin.create_user')
def create_user():
    form = UserManagementForm()
    if form.validate_on_submit():
        # Server-side role whitelist (defence against POST-body tampering).
        if not AccessControlService.is_valid_role(form.role.data):
            flash('Invalid role', 'danger')
            return redirect(url_for('admin.create_user'))
        if not AccessControlService.can_assign_role(current_user, form.role.data):
            flash('Cannot create a user with a role equal to or higher than your own.', 'danger')
            return redirect(url_for('admin.create_user'))
        user, message = AuthService.register_user(
            email=form.email.data,
            password=form.password.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            role=form.role.data,
            acting_user=current_user,
        )
        if user:
            flash('User created successfully', 'success')
            return redirect(url_for('admin.manage_users'))
        else:
            flash(message, 'danger')
    return render_template('admin/create_user.html', form=form)


@admin_bp.route('/platform_config')
@require_permission('admin.view_platform_config')
def platform_config():
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
    }
    return render_template('admin/platform_config.html', config=config)
