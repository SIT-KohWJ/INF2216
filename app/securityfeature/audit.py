"""Single entry point for all audit logging.

Why this exists (and `crypto_service.log_audit_action` is no longer called
directly from routes/services):

  1. **Action vocabulary** -- `AuditService.ACTIONS` is the canonical set of
     action names. Typos like `'status_upate'` raise at call time rather than
     silently producing an unqueryable log entry. It also splits the
     overloaded `status_update` action into `status_update` (lifecycle) and
     `severity_update` (severity changes), which were previously conflated.

  2. **Details sanitisation** -- every `details` string passes through
     `Sanitizer.redact()` before persistence. Emails, reference numbers,
     UUIDs, and JWTs are replaced with `[REDACTED:<category>]`. If `details`
     contains a forbidden keyword (otp, password, decrypted, ...) the whole
     entry is replaced with a placeholder -- the loud, testable backstop
     against developer mistakes.

  3. **Consistent signature** -- one call shape: `AuditService.log(action,
     acting_user=, acting_role=, target_type=, target_id=, details=,
     ip_address=, request_id=, allow_sensitive=)`. No more routes inventing
     their own kwarg combos.

  4. **ECDSA signing** -- delegated to `crypto_service.log_audit_action()`,
     which signs the entry before commit. Tampering with a row in the
     `audit_logs` table invalidates the signature, detectable via
     `verify_audit_integrity()`.

Append-only is enforced two ways:
  - PostgreSQL: a `BEFORE UPDATE OR DELETE` trigger (scripts/init.sql).
  - SQLite (tests): a SQLAlchemy event listener registered in the app factory.
"""
from app.securityfeature.sanitizers import Sanitizer


class AuditService:
    """Centralised, sanitised, signed audit logging."""

    # Canonical action vocabulary. Add new names here FIRST, then reference
    # them from code. Unknown actions raise ValueError at log time.
    ACTIONS = {
        # ---- Authentication / account lifecycle ----
        'user_registration',
        'user_login',
        'user_logout',
        'login_failed',
        'login_failed_account_locked',
        'password_change',
        'password_reset_requested',
        'password_reset_completed',
        'otp_verified',
        'account_deletion',
        'role_change',
        'user_deactivation',
        'user_reactivation',
        'user_created',                 # admin-created account (was previously logged as user_registration)

        # ---- Report lifecycle ----
        'report_submission',
        'report_viewed',
        'report_downloaded',
        'status_update',                # lifecycle status change (Received -> Triaged -> ...)
        'severity_update',              # severity change (split from status_update)
        'investigator_assignment',
        'investigation_note',
        'investigation_plan_created',
        'investigation_plan_updated',
        'outcome_recommended',
        'evidence_uploaded',
        'evidence_upload_failed',
        'evidence_downloaded',
        'evidence_download_failed',
        'report_closed',

        # ---- Admin / security ----
        'audit_log_export',
        'audit_integrity_check',
        'authorisation_denied',         # 403 from access_control
        'server_error',                 # unhandled 500

        # ---- SIEM-adjacent ----
        'suspicious_activity_detected',
    }

    # Actions considered "report-scoped" vs "system-scoped" -- used by the
    # admin dashboards. Report Admin sees only report-scoped; System Admin
    # sees only system-scoped.
    REPORT_ACTIONS = {
        'report_submission', 'report_viewed', 'report_downloaded',
        'status_update', 'severity_update',
        'investigator_assignment', 'investigation_note',
        'investigation_plan_created', 'investigation_plan_updated',
        'outcome_recommended', 'evidence_uploaded',
        'evidence_upload_failed', 'evidence_downloaded',
        'evidence_download_failed', 'report_closed',
        'audit_log_export',
    }

    SYSTEM_ACTIONS = {
        'user_registration', 'user_login', 'user_logout',
        'login_failed', 'login_failed_account_locked',
        'password_change', 'password_reset_requested',
        'password_reset_completed', 'otp_verified',
        'account_deletion', 'role_change',
        'user_deactivation', 'user_reactivation', 'user_created',
        'authorisation_denied', 'server_error',
        'suspicious_activity_detected', 'audit_integrity_check',
    }

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    @classmethod
    def log(cls, action, *, acting_user=None, acting_role='anonymous',
            target_type=None, target_id=None, details=None,
            ip_address=None, request_id=None, allow_sensitive=False):
        """Sanitise, validate, sign, persist. Returns the AuditLog row.

        Parameters
        ----------
        action : str
            Must be in `cls.ACTIONS`. Unknown actions raise ValueError.
        acting_user : User | None
            The user performing the action. If None, `acting_role` should
            be 'anonymous' or 'system'.
        acting_role : str
            Explicit role override (used when acting_user is None, e.g.
            failed login on a non-existent account).
        target_type / target_id : str | None
            The kind and UUID of the resource acted upon.
        details : str | None
            Free-text context. Redacted by Sanitizer before persistence.
            Must NEVER contain decrypted report content, OTPs, passwords,
            tokens, or session IDs -- the sanitiser will block these.
        ip_address : str | None
            Source IP of the request (for SIEM correlation).
        request_id : str | None
            Correlation ID from the request middleware (X-Request-ID header).
        allow_sensitive : bool
            If True, the denylist is skipped (pattern redaction still runs).
            Use only after code review -- e.g. logging that a password
            *policy* was violated, where the word "password" is unavoidable.
        """
        if action not in cls.ACTIONS:
            raise ValueError(
                f'AuditService.log: unknown action "{action}". '
                f'Add it to AuditService.ACTIONS first.'
            )

        # Extract a stable acting_role from the user if not overridden.
        if acting_user is not None and acting_role == 'anonymous':
            acting_role = getattr(acting_user, 'role', 'anonymous')

        # Sanitise details. This is the anonymity backstop.
        sanitised_details = Sanitizer.redact(details, allow_sensitive=allow_sensitive)

        # If details were blocked, the redactor returned a placeholder that
        # includes the keyword that triggered the block. Log a WARNING so
        # devs notice during development; in prod this should fire a SIEM
        # alert.
        if details and sanitised_details != details and sanitised_details.startswith('[BLOCKED:'):
            try:
                from flask import current_app
                current_app.logger.warning(
                    'Audit details blocked by sanitiser: action=%s, reason=%s',
                    action, sanitised_details,
                )
            except RuntimeError:
                # Outside an app context (rare): fall through, the entry
                # is still persisted as blocked.
                pass

        # Defer the import so this module stays free of crypto_service deps
        # at import time (lets it be unit-tested in isolation).
        from app.services.crypto_service import crypto_service
        return crypto_service.log_audit_action(
            action=action,
            acting_user=acting_user,
            acting_role=acting_role,
            target_type=target_type,
            target_id=target_id,
            details=sanitised_details,
            ip_address=ip_address,
        )

    # ------------------------------------------------------------------
    # Read path (delegated to the existing crypto_service.audit_service
    # helpers; kept here so callers have one import).
    # ------------------------------------------------------------------

    @staticmethod
    def get_audit_logs(limit=100):
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_audit_logs(limit=limit)

    @staticmethod
    def get_report_audit_logs(limit=100):
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_report_audit_logs(limit=limit)

    @staticmethod
    def get_system_audit_logs(limit=100):
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_system_audit_logs(limit=limit)

    @staticmethod
    def get_recent_report_activity(limit=10):
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_recent_report_activity(limit=limit)

    @staticmethod
    def get_recent_system_activity(limit=10):
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_recent_system_activity(limit=limit)

    @staticmethod
    def verify_audit_integrity():
        """Re-verify every audit log row's ECDSA signature."""
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.verify_audit_integrity()

    @staticmethod
    def export_audit_logs():
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.export_audit_logs()

    @staticmethod
    def get_suspicious_activity():
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_suspicious_activity()

    @staticmethod
    def get_activity_stats():
        from app.services.audit_service import _LegacyAuditService
        return _LegacyAuditService.get_activity_stats()
