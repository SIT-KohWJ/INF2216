from app.models import AuditLog
from app import db
from app.services.crypto_service import crypto_service


REPORT_ACTIONS = {
    'report_submission', 'status_update', 'investigator_assignment',
    'investigation_note', 'outcome_recommended', 'evidence_downloaded',
    'report_viewed', 'audit_log_export', 'evidence_upload_failed', 'report_downloaded'
}

SYSTEM_ACTIONS = {
    'user_registration', 'user_login', 'user_logout', 'password_change',
    'role_change', 'user_deactivation', 'user_reactivation', 'account_deletion',
    'login_failed', 'login_failed_account_locked', 'password_reset_requested',
    'password_reset_completed'
}


class AuditService:
    @staticmethod
    def get_report_audit_logs(limit=100):
        return AuditLog.query.filter(AuditLog.action.in_(REPORT_ACTIONS)).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_system_audit_logs(limit=100):
        return AuditLog.query.filter(AuditLog.action.in_(SYSTEM_ACTIONS)).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_recent_report_activity(limit=10):
        return AuditLog.query.filter(AuditLog.action.in_(REPORT_ACTIONS)).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_recent_system_activity(limit=10):
        return AuditLog.query.filter(AuditLog.action.in_(SYSTEM_ACTIONS)).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def _rotation_boundary():
        """Timestamp of the most recent VALID key-rotation marker, or None.

        A rotation marker is an ordinary signed audit row (action
        'key_rotation'). It only counts if its own signature verifies under the
        current key, so an attacker who lost the old key cannot forge a
        backdated marker to launder tampered rows into the 'historical' bucket.
        Rows written before this boundary were signed by a superseded key and
        are expected not to verify; they are reported as historical, not invalid.
        """
        markers = AuditLog.query.filter(AuditLog.action == 'key_rotation').order_by(AuditLog.timestamp.desc()).all()
        for m in markers:
            data = f"{m.action}:{m.acting_role}:{m.target_type}:{m.target_id}:{m.details}"
            if m.signature and crypto_service.verify_signature(data, m.signature):
                return m.timestamp
        return None

    @staticmethod
    def verify_audit_integrity():
        logs = AuditLog.query.all()
        boundary = AuditService._rotation_boundary()
        valid = 0
        invalid = 0
        historical = 0
        for log in logs:
            log_data = f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"
            if log.signature and crypto_service.verify_signature(log_data, log.signature):
                valid += 1
            elif boundary is not None and log.timestamp is not None and log.timestamp < boundary:
                # Signed by a superseded key before the recorded rotation.
                # Cannot be re-signed (audit_logs is append-only), so it is
                # expected-invalid, not a tamper signal.
                historical += 1
            else:
                invalid += 1
        return {
            'total': len(logs), 'valid': valid, 'invalid': invalid,
            'historical': historical, 'integrity_ok': invalid == 0,
        }

    @staticmethod
    def record_key_rotation(details='ECDSA signing key rotated'):
        """Append a signed marker so pre-rotation rows are treated as historical.

        Appends only (never mutates existing rows), so it is compatible with the
        append-only DB trigger. Signed by the current key, so it verifies and
        cannot be forged after the fact. Run this once after the signing key
        changes and existing rows can no longer be verified.
        """
        return crypto_service.log_audit_action(
            action='key_rotation', acting_role='system',
            target_type='audit_log', details=details,
        )

    @staticmethod
    def get_suspicious_activity():
        from sqlalchemy import func
        failed_logins = db.session.query(AuditLog.acting_user_id, func.count(AuditLog.id).label('count')).filter(AuditLog.action == 'login_failed').group_by(AuditLog.acting_user_id).having(func.count(AuditLog.id) >= 3).all()
        return [{'user_id': r[0], 'attempts': r[1]} for r in failed_logins]

    @staticmethod
    def get_activity_stats():
        from sqlalchemy import func
        stats = db.session.query(AuditLog.action, func.count(AuditLog.id)).group_by(AuditLog.action).all()
        return {action: count for action, count in stats}
