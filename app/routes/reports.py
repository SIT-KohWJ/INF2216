from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file
from flask_login import login_required, current_user
from app.services.report_service import ReportService
from app.services.auth_service import AuthService
from app import limiter
from app.services.crypto_service import crypto_service
from app.forms import ReportForm, InvestigationNoteForm, InvestigationPlanForm, OutcomeForm
from app.models import Evidence
from app.securityfeature import require_permission, load_report_from_url
from datetime import date, datetime
import io

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/')
@login_required
def dashboard():
    if current_user.role in ['report_admin', 'system_admin']:
        return redirect(url_for('admin.dashboard'))
    if current_user.role != 'whistleblower':
        return redirect(url_for('reports.investigator_dashboard'))
    reports = ReportService.get_reports_for_user(current_user)
    notifications = ReportService.get_notifications_for_user(current_user.id)
    return render_template('reports/dashboard.html', reports=reports, notifications=notifications)


@reports_bp.route('/investigator')
@login_required
def investigator_dashboard():
    if current_user.role != 'investigator':
        abort(403)
    all_reports = ReportService.get_all_reports_for_investigator_dashboard()
    my_reports = ReportService.get_reports_for_user(current_user)
    my_report_ids = [r.id for r in my_reports]
    investigators = AuthService.get_users_by_role('investigator')
    investigator_map = {i.id: i.full_name for i in investigators}
    return render_template('reports/investigator_dashboard.html', all_reports=all_reports, my_reports=my_reports, my_report_ids=my_report_ids, investigator_map=investigator_map)


@reports_bp.route('/submit', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")
def submit_report():
    if current_user.role != 'whistleblower':
        abort(403)
    form = ReportForm()
    if form.validate_on_submit():
        MAX_EVIDENCE_FILES = 5
        evidence_files = []
        if 'evidence' in request.files:
            all_files = [f for f in request.files.getlist('evidence') if f.filename != '']
            if len(all_files) > MAX_EVIDENCE_FILES:
                flash(f'Maximum {MAX_EVIDENCE_FILES} files allowed per submission.', 'danger')
                return redirect(request.url)
            for file in all_files:
                if ReportService._is_allowed_file(file.filename):
                    evidence_files.append(file)
                else:
                    flash(f'File {file.filename} is not allowed. Allowed types: PDF, DOCX, PNG, JPG', 'danger')
                    return redirect(request.url)
        report, message = ReportService.create_report(user=current_user, title=form.title.data, description=form.description.data, category=form.category.data, evidence_files=evidence_files)
        if report:
            flash(message, 'success')
            return redirect(url_for('reports.dashboard'))
        else:
            flash(message, 'danger')
    return render_template('reports/submit.html', form=form)


@reports_bp.route('/<report_id>')
@login_required
@require_permission('report.view', resource_loader=load_report_from_url)
def view_report(report_id, resource=None):
    report = resource
    decrypted_data = ReportService.decrypt_report_data(report)
    evidence = ReportService.get_evidence_for_report(report_id)
    notes = ReportService.get_investigation_notes(report_id)
    history = ReportService.get_report_audit_history(report_id)
    investigation_action_block_reason = ReportService.get_investigation_action_block_reason(report)
    close_block_reason = ReportService.get_close_block_reason(report)
    can_recommend_outcome = current_user.role == 'investigator' and investigation_action_block_reason is None
    can_close_report = current_user.role == 'report_admin' and close_block_reason is None
    crypto_service.log_audit_action(action='report_viewed', acting_user=current_user, acting_role=current_user.role, target_type='report', target_id=report.id, details=f'Report {report.reference_number} viewed')
    return render_template('reports/view.html', report=report, decrypted_data=decrypted_data, evidence=evidence, notes=notes, history=history, can_manage_investigation_actions=investigation_action_block_reason is None, can_recommend_outcome=can_recommend_outcome, investigation_action_block_reason=investigation_action_block_reason, can_close_report=can_close_report, close_block_reason=close_block_reason)


@reports_bp.route('/<report_id>/investigation-plan', methods=['GET', 'POST'])
@login_required
def investigation_plan(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        if current_user.role == 'investigator':
            return redirect(url_for('reports.investigator_dashboard'))
        return redirect(url_for('admin.manage_reports'))

    if current_user.role not in ['investigator', 'report_admin']:
        abort(403)

    plan = ReportService.get_investigation_plan(report.id)

    def populate_incident_fields(form, plan_record):
        if not plan_record or not plan_record.incident_when:
            return

        incident_when = plan_record.incident_when
        if isinstance(incident_when, str):
            try:
                incident_when = datetime.fromisoformat(incident_when.strip())
            except ValueError:
                return

        if isinstance(incident_when, datetime):
            form.incident_date.data = incident_when.date()
            form.incident_time.data = incident_when.time().replace(second=0, microsecond=0)

    if current_user.role == 'report_admin':
        if request.method == 'POST':
            abort(403)
        if plan is None:
            abort(404)
        form = InvestigationPlanForm(obj=plan)
        populate_incident_fields(form, plan)
        return render_template('reports/investigation_plan.html', form=form, report=report, read_only=True, page_mode='view')

    form = InvestigationPlanForm(obj=plan) if plan else InvestigationPlanForm()
    if request.method == 'GET':
        if plan is None:
            form.investigator_full_name.data = current_user.full_name
            form.planning_date.data = date.today()
        else:
            populate_incident_fields(form, plan)

    if form.validate_on_submit():
        _, message = ReportService.create_or_update_investigation_plan(report=report, investigator=current_user, form=form)
        flash(message, 'success')
        return redirect(url_for('reports.view_report', report_id=report.id))

    page_mode = 'edit' if plan else 'create'
    return render_template('reports/investigation_plan.html', form=form, report=report, read_only=False, page_mode=page_mode)


@reports_bp.route('/<report_id>/add_note', methods=['GET', 'POST'])
@login_required
def add_investigation_note(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        if current_user.role == 'investigator':
            return redirect(url_for('reports.investigator_dashboard'))
        return redirect(url_for('admin.manage_reports'))
    if current_user.role not in ['investigator', 'report_admin']:
        abort(403)
    block_reason = ReportService.get_investigation_action_block_reason(report)
    if block_reason:
        flash(block_reason, 'warning')
        return redirect(url_for('reports.view_report', report_id=report_id))
    form = InvestigationNoteForm()
    if form.validate_on_submit():
        note, message = ReportService.add_investigation_note(report=report, investigator=current_user, note=form.note.data)
        if note:
            flash(message, 'success')
            return redirect(url_for('reports.view_report', report_id=report_id))
        else:
            flash(message, 'danger')
    return render_template('reports/add_note.html', form=form, report=report)


@reports_bp.route('/<report_id>/recommend_outcome', methods=['GET', 'POST'])
@login_required
def recommend_outcome(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        if current_user.role == 'investigator':
            return redirect(url_for('reports.investigator_dashboard'))
        return redirect(url_for('admin.manage_reports'))
    if current_user.role != 'investigator':
        abort(403)
    block_reason = ReportService.get_investigation_action_block_reason(report)
    if block_reason:
        flash(block_reason, 'warning')
        return redirect(url_for('reports.view_report', report_id=report_id))
    form = OutcomeForm()
    if form.validate_on_submit():
        success, message = ReportService.recommend_outcome(report=report, outcome=form.outcome.data, outcome_details=form.outcome_details.data, acting_user=current_user)
        if success:
            flash(message, 'success')
            return redirect(url_for('reports.view_report', report_id=report_id))
        else:
            flash(message, 'danger')
    return render_template('reports/recommend_outcome.html', form=form, report=report)


@reports_bp.route('/<report_id>/close', methods=['POST'])
@login_required
def close_report(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        flash(error, 'warning')
        if current_user.role == 'investigator':
            return redirect(url_for('reports.investigator_dashboard'))
        return redirect(url_for('admin.manage_reports'))
    if current_user.role != 'report_admin':
        abort(403)
    success, message = ReportService.close_report(report, current_user)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('reports.view_report', report_id=report_id))


@reports_bp.route('/download/<evidence_id>')
@login_required
def download_evidence(evidence_id):
    evidence = Evidence.query.get(evidence_id)
    if not evidence:
        abort(404)
    report, error = ReportService.get_report_by_id(evidence.report_id, current_user)
    if error:
        flash(error, 'warning')
        abort(403)
    decrypted_data = crypto_service.decrypt_data(evidence.encrypted_file_data)
    if decrypted_data is None:
        flash('Failed to decrypt evidence file', 'danger')
        return redirect(request.referrer or url_for('reports.dashboard'))
    crypto_service.log_audit_action(action='evidence_downloaded', acting_user=current_user, acting_role=current_user.role, target_type='evidence', target_id=evidence.id, details=f'Evidence file downloaded for report {report.reference_number}')
    return send_file(io.BytesIO(decrypted_data if isinstance(decrypted_data, bytes) else decrypted_data.encode()), as_attachment=True, download_name=evidence.original_filename)


@reports_bp.route('/notifications')
@login_required
def notifications():
    notifications = ReportService.get_notifications_for_user(current_user.id)
    return render_template('reports/notifications.html', notifications=notifications)


@reports_bp.route('/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    ReportService.mark_notification_read(notification_id, current_user.id)
    return redirect(url_for('reports.notifications'))


@reports_bp.route('/notifications/read_all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    count = ReportService.mark_all_notifications_read(current_user.id)
    if count:
        flash(f'{count} notification(s) marked as read.', 'success')
    return redirect(url_for('reports.notifications'))