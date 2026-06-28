from app import db
from app.models import Report, ReportStatusHistory, Evidence, InvestigationNote, InvestigationPlan, Notification
from app.services.crypto_service import crypto_service
from app.utils.validators import FileValidator, InputValidator
from datetime import datetime
from flask import current_app
import json
import uuid
import base64
import magic
from sqlalchemy import text


class ReportService:
    VALID_CATEGORIES = ['academic_misconduct', 'financial_misconduct', 'harassment', 'policy_violation', 'ethical_concern', 'other']
    VALID_STATUSES = ['Received', 'Triaged', 'Planning', 'Investigating', 'Under Review', 'Closed']
    VALID_OUTCOMES = ['action_taken', 'dismissed', 'referred', 'insufficient_evidence']
    VALID_TRANSFERS = {
        'Received': ['Triaged'],
        'Triaged': ['Planning'],
        'Planning': ['Investigating'],
        'Investigating': ['Under Review'],
        'Under Review': ['Closed'],
        'Closed': []
    }

    VALID_SEVERITIES = ['low', 'medium', 'high', 'critical']

    @staticmethod
    def create_report(user, title, description, category, severity='medium', evidence_files=None):
        if category not in ReportService.VALID_CATEGORIES:
            return None, "Invalid report category"
        if severity not in ReportService.VALID_SEVERITIES:
            return None, "Invalid severity level"
        title = InputValidator.sanitize_html(title)
        description = InputValidator.sanitize_html(description)
        if len(title) > 255:
            return None, "Title must be 255 characters or less"
        if len(description) > 10000:
            return None, "Description must be 10000 characters or less"

        if evidence_files:
            allowed_exts = current_app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'docx', 'png', 'jpg', 'jpeg'})
            for file in evidence_files:
                file_content = file.read()
                file.seek(0)
                if not FileValidator.validate_file_type(file_content, allowed_exts):
                    from werkzeug.utils import secure_filename
                    safe_name = secure_filename(file.filename)
                    return None, f"'{safe_name}' is not a valid file. Only real PDF, DOCX, PNG, and JPG files are accepted."

        submitter_hash = crypto_service.generate_user_hash(user.id)
        report_data = {'title': title, 'description': description, 'category': category, 'submitter_email': user.email, 'submitter_name': user.full_name}
        encrypted_data = crypto_service.encrypt_data(json.dumps(report_data))

        reference_number = crypto_service.generate_reference_number()
        while Report.query.filter_by(reference_number=reference_number).first():
            reference_number = crypto_service.generate_reference_number()

        report = Report(submitter_hash=submitter_hash, title=title, description=description, category=category, severity=severity, encrypted_data=encrypted_data, user_id=user.id, reference_number=reference_number)
        db.session.add(report)
        db.session.flush()

        status_history = ReportStatusHistory(report_id=report.id, old_status='New', new_status='Received', changed_by_role=user.role)
        db.session.add(status_history)
        db.session.commit()

        if evidence_files:
            for file in evidence_files:
                result, msg = ReportService._add_evidence(report.id, file)
                if not result:
                    crypto_service.log_audit_action(action='evidence_upload_failed', acting_user=user, acting_role=user.role, target_type='report', target_id=report.id, details=f'Evidence upload failed: {msg}')

        crypto_service.log_audit_action(action='report_submission', acting_user=user, acting_role=user.role, target_type='report', target_id=report.id, details=f'New report submitted with reference: {reference_number}')
        return report, f"Report submitted successfully. Your reference number is: {reference_number}"

    @staticmethod
    def _is_allowed_file(filename):
        allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'docx', 'png', 'jpg', 'jpeg'})
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

    @staticmethod
    def _add_evidence(report_id, file):
        file_content = file.read()
        file_size = len(file_content)
        max_size = current_app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024)
        if file_size > max_size:
            return False, f"File exceeds maximum size of {max_size // (1024*1024)}MB"
        if not FileValidator.validate_file_type(file_content, current_app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'docx', 'png', 'jpg', 'jpeg'})):
            return False, "File type validation failed."
        from werkzeug.utils import secure_filename
        original_filename = secure_filename(file.filename)
        stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
        encrypted_b64 = crypto_service.encrypt_data(file_content)
        raw_encrypted = base64.b64decode(encrypted_b64)
        detected_mime = magic.from_buffer(file_content[:2048], mime=True)
        evidence = Evidence(report_id=report_id, original_filename=original_filename, stored_filename=stored_filename, file_type=detected_mime or 'application/octet-stream', file_size=file_size, encrypted_file_data=raw_encrypted)
        db.session.add(evidence)
        db.session.commit()
        return evidence, "Evidence uploaded successfully"

    @staticmethod
    def get_reports_for_user(user):
        if user.role == 'whistleblower':
            return Report.query.filter_by(user_id=user.id).all()
        elif user.role == 'investigator':
            return Report.query.filter_by(investigator_id=user.id).all()
        elif user.role == 'report_admin':
            return Report.query.all()
        return []

    @staticmethod
    def get_all_reports_for_investigator_dashboard():
        return Report.query.all()

    @staticmethod
    def get_report_by_id(report_id, user):
        report = Report.query.get(report_id)
        if not report:
            return None, "Report not found"
        if user.role == 'whistleblower':
            if not crypto_service.verify_user_hash(user.id, report.submitter_hash):
                if report.user_id != user.id:
                    return None, "Report not found"
        elif user.role == 'investigator':
            if report.investigator_id != user.id:
                return None, "Report not found"
        elif user.role != 'report_admin':
            return None, "Report not found"
        return report, None

    @staticmethod
    def update_report_severity(report, new_severity, acting_user):
        if new_severity not in ReportService.VALID_SEVERITIES:
            return False, "Invalid severity level"
        old_severity = report.severity
        report.severity = new_severity
        report.updated_at = datetime.utcnow()
        db.session.commit()
        crypto_service.log_audit_action(action='status_update', acting_user=acting_user, acting_role=acting_user.role, target_type='report', target_id=report.id, details=f'Severity changed from {old_severity} to {new_severity}')
        return True, f"Severity updated to {new_severity}"

    @staticmethod
    def update_report_status(report, new_status, acting_user):
        if new_status not in ReportService.VALID_STATUSES:
            return False, "Invalid status"
        if new_status not in ReportService.VALID_TRANSFERS.get(report.status, []):
            return False, f"Cannot transition from {report.status} to {new_status}"
        old_status = report.status
        report.status = new_status
        report.updated_at = datetime.utcnow()
        status_history = ReportStatusHistory(report_id=report.id, old_status=old_status, new_status=new_status, changed_by_role=acting_user.role)
        db.session.add(status_history)
        db.session.commit()
        crypto_service.log_audit_action(action='status_update', acting_user=acting_user, acting_role=acting_user.role, target_type='report', target_id=report.id, details=f'Status changed from {old_status} to {new_status}')
        if report.user_id:
            notification = Notification(user_id=report.user_id, message=f'Your report ({report.reference_number}) status has been updated to: {new_status}', notification_type='status_change', related_report_id=report.id)
            db.session.add(notification)
            db.session.commit()
        return True, f"Status updated to {new_status}"

    @staticmethod
    def assign_investigator(report, investigator, acting_user):
        if report.status != 'Triaged':
            return False, "Report must be triaged before assigning an investigator"
        report.investigator_id = investigator.id
        report.updated_at = datetime.utcnow()
        success, message = ReportService.update_report_status(report, 'Planning', acting_user)
        if not success:
            db.session.rollback()
            return False, message
        crypto_service.log_audit_action(action='investigator_assignment', acting_user=acting_user, acting_role=acting_user.role, target_type='report', target_id=report.id, details='Investigator assigned to report')
        if report.user_id:
            notification = Notification(user_id=report.user_id, message=f'An investigator has been assigned to your report ({report.reference_number}).', notification_type='investigator_assigned', related_report_id=report.id)
            db.session.add(notification)
            db.session.commit()
        return True, "Investigator assigned successfully"

    @staticmethod
    def recommend_outcome(report, outcome, outcome_details, acting_user):
        if outcome not in ReportService.VALID_OUTCOMES:
            return False, "Invalid outcome"
        block_reason = ReportService.get_investigation_action_block_reason(report)
        if block_reason:
            return False, block_reason
        if acting_user.role == 'investigator' and report.investigator_id != acting_user.id:
            return False, "Report not found"
        report.outcome = outcome
        report.outcome_details = InputValidator.sanitize_html(outcome_details)
        report.updated_at = datetime.utcnow()
        db.session.commit()
        if report.status == 'Investigating':
            success, message = ReportService.update_report_status(report, 'Under Review', acting_user)
            if not success:
                return False, message
        crypto_service.log_audit_action(action='outcome_recommended', acting_user=acting_user, acting_role=acting_user.role, target_type='report', target_id=report.id, details=f'Outcome recommended: {outcome}')
        return True, "Outcome recommended successfully"

    @staticmethod
    def close_report(report, acting_user):
        block_reason = ReportService.get_close_block_reason(report)
        if block_reason:
            return False, block_reason
        return ReportService.update_report_status(report, 'Closed', acting_user)

    @staticmethod
    def add_investigation_note(report, investigator, note):
        block_reason = ReportService.get_investigation_action_block_reason(report)
        if block_reason:
            return None, block_reason
        note = InputValidator.sanitize_html(note)
        investigation_note = InvestigationNote(report_id=report.id, investigator_id=investigator.id, note=note)
        db.session.add(investigation_note)
        db.session.commit()
        crypto_service.log_audit_action(action='investigation_note', acting_user=investigator, acting_role=investigator.role, target_type='report', target_id=report.id, details='Investigation note added')
        return investigation_note, "Note added successfully"

    @staticmethod
    def get_investigation_plan(report_id):
        return InvestigationPlan.query.filter_by(report_id=report_id).first()

    @staticmethod
    def has_investigation_plan(report):
        return report.investigation_plan is not None

    @staticmethod
    def get_investigation_action_block_reason(report):
        if not ReportService.has_investigation_plan(report):
            return "Complete the investigation plan before adding notes or recommending an outcome"
        if report.status == 'Closed':
            return "This report is already closed"
        if report.status not in ['Investigating', 'Under Review']:
            return f"Investigation actions are not available while the report is {report.status}"
        return None

    @staticmethod
    def can_manage_investigation_actions(report):
        return ReportService.get_investigation_action_block_reason(report) is None

    @staticmethod
    def get_close_block_reason(report):
        if report.status == 'Closed':
            return "This report is already closed"
        if report.status != 'Under Review':
            return "Report must be in Under Review status to close"
        return None

    @staticmethod
    def can_close_report(report):
        return ReportService.get_close_block_reason(report) is None

    @staticmethod
    def normalize_report_statuses():
        changed = False
        for report in Report.query.all():
            normalized_status = report.status
            if report.status == 'Resolved':
                normalized_status = 'Closed'
            elif report.status == 'Triaged' and report.investigator_id:
                normalized_status = 'Investigating' if report.investigation_plan else 'Planning'
            elif report.status == 'Investigating' and report.outcome:
                normalized_status = 'Under Review'

            if normalized_status != report.status:
                report.status = normalized_status
                report.updated_at = datetime.utcnow()
                changed = True

        if changed:
            db.session.commit()

    @staticmethod
    def migrate_investigation_plan_incident_when_column():
        if db.engine.dialect.name != 'postgresql':
            return

        column_type = db.session.execute(text("""
            SELECT data_type
            FROM information_schema.columns
            WHERE table_name = 'investigation_plans'
            AND column_name = 'incident_when'
        """)).scalar()

        if column_type != 'character varying':
            return

        try:
            db.session.execute(text("""
                ALTER TABLE investigation_plans
                ALTER COLUMN incident_when
                TYPE TIMESTAMP
                USING incident_when::timestamp
            """))
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception('Failed to migrate investigation_plans.incident_when to TIMESTAMP')

    @staticmethod
    def create_or_update_investigation_plan(report, investigator, form):
        plan = ReportService.get_investigation_plan(report.id)
        is_new_plan = plan is None
        if plan is None:
            plan = InvestigationPlan(report_id=report.id, investigator_id=investigator.id)
            db.session.add(plan)
            message = "Investigation plan created successfully"
        else:
            message = "Investigation plan updated successfully"

        plan.investigator_id = investigator.id
        plan.investigator_full_name = InputValidator.sanitize_html(form.investigator_full_name.data)
        plan.investigator_job_title = InputValidator.sanitize_html(form.investigator_job_title.data)
        plan.investigator_staff_id = InputValidator.sanitize_html(form.investigator_staff_id.data)
        plan.planning_date = form.planning_date.data
        plan.case_overview = InputValidator.sanitize_html(form.case_overview.data)
        plan.incident_when = datetime.combine(form.incident_date.data, form.incident_time.data)
        plan.incident_where = InputValidator.sanitize_html(form.incident_where.data)
        if is_new_plan and report.status == 'Planning':
            success, status_message = ReportService.update_report_status(report, 'Investigating', investigator)
            if not success:
                db.session.rollback()
                return None, status_message
        else:
            db.session.commit()
        return plan, message

    @staticmethod
    def search_and_filter_reports(filters, user):
        query = Report.query
        if user.role == 'whistleblower':
            query = query.filter_by(user_id=user.id)
        elif user.role == 'investigator':
            query = query.filter_by(investigator_id=user.id)
        if filters.get('category'):
            query = query.filter_by(category=filters['category'])
        if filters.get('status'):
            query = query.filter_by(status=filters['status'])
        if filters.get('severity'):
            query = query.filter_by(severity=filters['severity'])
        if filters.get('investigator_id'):
            query = query.filter_by(investigator_id=filters['investigator_id'])
        if filters.get('date_from'):
            query = query.filter(Report.created_at >= filters['date_from'])
        if filters.get('date_to'):
            query = query.filter(Report.created_at <= filters['date_to'])
        if filters.get('search'):
            search_term = f"%{filters['search']}%"
            query = query.filter(db.or_(Report.title.ilike(search_term), Report.description.ilike(search_term), Report.reference_number.ilike(search_term)))
        return query.order_by(Report.created_at.desc()).all()

    @staticmethod
    def get_report_audit_history(report_id):
        return ReportStatusHistory.query.filter_by(report_id=report_id).order_by(ReportStatusHistory.changed_at).all()

    @staticmethod
    def decrypt_report_data(report):
        if not report.encrypted_data:
            return None
        decrypted = crypto_service.decrypt_data(report.encrypted_data)
        if decrypted:
            return json.loads(decrypted)
        return None

    @staticmethod
    def get_evidence_for_report(report_id):
        return Evidence.query.filter_by(report_id=report_id).all()

    @staticmethod
    def get_investigation_notes(report_id):
        return InvestigationNote.query.filter_by(report_id=report_id).order_by(InvestigationNote.created_at).all()

    @staticmethod
    def get_notifications_for_user(user_id):
        return Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()

    @staticmethod
    def mark_notification_read(notification_id, user_id):
        notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
        if notification:
            notification.read = True
            db.session.commit()
            return True
        return False
