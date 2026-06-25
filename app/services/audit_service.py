from app.models import AuditLog
from app import db
from app.services.crypto_service import crypto_service


class AuditService:
    @staticmethod
    def get_audit_logs(limit=100):
        return AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_recent_activity(limit=10):
        return AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def verify_audit_integrity():
        logs = AuditLog.query.all()
        valid = 0
        invalid = 0
        for log in logs:
            log_data = f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"
            if log.signature and crypto_service.verify_signature(log_data, log.signature):
                valid += 1
            else:
                invalid += 1
        return {'total': len(logs), 'valid': valid, 'invalid': invalid, 'integrity_ok': invalid == 0}

    @staticmethod
    def export_audit_logs():
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        return [{'id': log.id, 'timestamp': log.timestamp.isoformat() if log.timestamp else None, 'action': log.action, 'acting_user_id': log.acting_user_id, 'acting_role': log.acting_role, 'target_type': log.target_type, 'target_id': log.target_id, 'details': log.details, 'ip_address': log.ip_address} for log in logs]

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
