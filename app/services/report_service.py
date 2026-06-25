from app import db
from app.models import Report, ReportStatusHistory, Evidence, InvestigationNote, Notification
from app.services.crypto_service import crypto_service
from app.utils.validators import FileValidator, InputValidator
from datetime import datetime
from flask import current_app
import json
import uuid
import base64


class ReportService:
    VALID_CATEGORIES = ['academic_misconduct', 'financial_misconduct', 'harassment', 'policy_violation', 'ethical_concern', 'other']
    VALID_STATUSES = ['Received', 'Triaged', 'Investigating', 'Resolved']
    VALID_OUTCOMES = ['action_taken', 'dismissed', 'referred', 'insufficient_evidence']
    VALID_TRANSFERS = {'Received': ['Triaged'], 'Triaged': ['Investigating'], 'Investigating': ['Resolved'], 'Resolved': []}

    @staticmethod
    def create_report(user, title, description, category, evidence_files=None):
        if category not in ReportService.VALID_CATEGORIES:
            return None, "Invalid report category"
        title = InputValidator.sanitize_html(title)
        description = InputValidator.sanitize_html(description)
        if len(title) > 255:
            return None, "Title must be 255 characters or less"
        if len(description) > 10000:
            return None, "Description must be 10000 characters or less"

        submitter_hash = crypto_service.generate_user_hash(user.id)
        report_data = {'title': title, 'description': description, 'category': category, 'submitter_email': user.email, 'submitter_name': user.full_name}
        encrypted_data = crypto_service.encrypt_data(json.dumps(report_data))

        reference_number = crypto_service.generate_reference_number()
        while Report.query.filter_by(reference_number=reference_number).first():
            reference_number = crypto_service.generate_reference_number()

        report = Report(submitter_hash=submitter_hash, title=title, description=description, category=category, encrypted_data=encrypted_data, user_id=user.id, reference_number=reference_number)
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
        evidence = Evidence(report_id=report_id, original_filename=original_filename, stored_filename=stored_filename, file_type=file.content_type or 'application/octet-stream', file_size=file_size, encrypted_file_data=raw_encrypted)
        db.session.add(evidence)
        db.session.commit()
        return evidence, "Evidence uploaded successfully"

    @staticmethod
    def get_reports_for_user(user):
        if user.role == 'whistleblower':
            return Report.query.filter_by(user_id=user.id).all()
        elif user.role == 'investigator':
            return Report.query.filter_by(investigator_id=user.id).all()
        elif user.role in ['admin', 'system_admin']:
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
                    return None, "You are not authorized to view this report"
        elif user.role == 'investigator':
            if report.investigator_id != user.id:
                return None, "You are not authorized to view this report. It is assigned to another investigator."
        return report, None

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
        report.investigator_id = investigator.id
        report.updated_at = datetime.utcnow()
        db.session.commit()
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
        if acting_user.role == 'investigator' and report.investigator_id != acting_user.id:
            return False, "Not authorized to recommend outcome for this report"
        report.outcome = outcome
        report.outcome_details = InputValidator.sanitize_html(outcome_details)
        report.updated_at = datetime.utcnow()
        db.session.commit()
        crypto_service.log_audit_action(action='outcome_recommended', acting_user=acting_user, acting_role=acting_user.role, target_type='report', target_id=report.id, details=f'Outcome recommended: {outcome}')
        return True, "Outcome recommended successfully"

    @staticmethod
    def close_report(report, acting_user):
        if report.status != 'Investigating':
            return False, "Report must be in Investigating status to close"
        return ReportService.update_report_status(report, 'Resolved', acting_user)

    @staticmethod
    def add_investigation_note(report, investigator, note):
        note = InputValidator.sanitize_html(note)
        investigation_note = InvestigationNote(report_id=report.id, investigator_id=investigator.id, note=note)
        db.session.add(investigation_note)
        db.session.commit()
        crypto_service.log_audit_action(action='investigation_note', acting_user=investigator, acting_role=investigator.role, target_type='report', target_id=report.id, details='Investigation note added')
        return investigation_note, "Note added successfully"

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
