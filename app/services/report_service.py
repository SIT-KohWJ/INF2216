"""ReportService - submit, retrieve, and triage reports."""
from ..extensions import db
from ..models import Report
from ..security.anonymity import AnonymityService
from ..security.encryption import EncryptionService


class ReportService:
    @staticmethod
    def submit(user_id: str, title: str, description: str, category: str) -> Report:
        """Create an anonymous report: title/description encrypted at rest (A3),
        submitter stored only as an HMAC hash (A2)."""
        report = Report(
            submitter_hash=AnonymityService.submitter_hash(user_id),
            title_encrypted=EncryptionService.encrypt(title),
            description_encrypted=EncryptionService.encrypt(description),
            category=category,
        )
        db.session.add(report)
        db.session.commit()
        return report

    @staticmethod
    def get_by_public_id(public_id):
        # Look up by UUID public_id only (never internal id) to prevent IDOR (E2)
        return Report.query.filter_by(public_id=public_id).first()
