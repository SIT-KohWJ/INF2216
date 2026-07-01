import json
import re
import secrets
from datetime import datetime

from app import db
from app.models import User, PasswordResetToken, Report
from app.services.crypto_service import crypto_service

# Characters accepted as "special" for the password complexity policy.
_SPECIAL_CHAR_RE = re.compile(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/\\`~]')


class AuthService:

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@(sit\.)?singaporetech\.edu\.sg$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_password(password: str) -> tuple:
        """Return (valid: bool, message: str).

        Policy:
          * At least 8 characters
          * At least one lowercase letter
          * At least one uppercase letter
          * At least one digit
          * At least one special character
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit."
        if not _SPECIAL_CHAR_RE.search(password):
            return False, "Password must contain at least one special character (!@#$%^&* etc.)."
        return True, ""

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    @staticmethod
    def register_user(email, password, first_name, last_name, role='whistleblower', acting_user=None):
        email = email.lower().strip()
        if not AuthService.validate_email(email):
            return None, "Invalid email. Must use an @singaporetech.edu.sg or @sit.singaporetech.edu.sg address."

        valid, msg = AuthService.validate_password(password)
        if not valid:
            return None, msg

        existing = User.query.filter_by(email=email).first()
        if existing:
            # Non-enumerating: same wording regardless of reason for failure.
            return None, "Unable to complete registration. Please check your details and try again."

        user = User(email=email, first_name=first_name, last_name=last_name, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        crypto_service.log_audit_action(
            action='user_registration',
            acting_user=user, acting_role=user.role,
            target_type='user', target_id=user.id,
            details=f'New user registered with role: {user.role}',
        )
        return user, "Registration successful"

    # ------------------------------------------------------------------
    # Authentication (login)
    # ------------------------------------------------------------------

    @staticmethod
    def authenticate_user(email: str, password: str, ip_address: str = None):
        """Return the User on success, None on failure.

        Timing: a dummy bcrypt check is performed whenever the real user is not
        found (or is locked) so the response latency is indistinguishable from
        a normal failed login — preventing user-enumeration via timing.

        Non-enumeration: the flash message at the call-site is always
        "Invalid email or password" regardless of the exact failure reason.
        """
        email = email.lower().strip()

        user = User.query.filter_by(email=email).first()

        if user and user.is_locked():
            # Run the password check anyway to prevent timing oracle.
            user.check_password(password)
            crypto_service.log_audit_action(
                action='login_failed_account_locked',
                acting_user=user, acting_role=user.role,
                details='Login attempt while account locked',
                ip_address=ip_address,
            )
            return None

        if user:
            if user.check_password(password):
                if user.is_active:
                    user.reset_failed_login()
                    db.session.commit()
                    crypto_service.log_audit_action(
                        action='user_login',
                        acting_user=user, acting_role=user.role,
                        details='User logged in',
                        ip_address=ip_address,
                    )
                    return user
                # Password correct but account is deactivated — do not touch
                # the lockout counter; the account is already administratively
                # disabled and incrementing serves no purpose.
            else:
                # Wrong password — increment the lockout counter.
                user.increment_failed_login()
                db.session.commit()
        else:
            # User does not exist — perform dummy bcrypt check to equalise timing.
            User.dummy_check(password)

        crypto_service.log_audit_action(
            action='login_failed',
            acting_user=user, acting_role='anonymous',
            details='Failed login attempt',
            ip_address=ip_address,
        )
        return None

    # ------------------------------------------------------------------
    # Password management
    # ------------------------------------------------------------------

    @staticmethod
    def update_user_password(user, current_password, new_password):
        if not user.check_password(current_password):
            return False, "Current password is incorrect."

        valid, msg = AuthService.validate_password(new_password)
        if not valid:
            return False, msg

        user.set_password(new_password)
        user.invalidate_all_sessions()
        db.session.commit()
        crypto_service.log_audit_action(
            action='password_change',
            acting_user=user, acting_role=user.role,
            details='User changed password; all sessions invalidated',
        )
        return True, "Password updated successfully."

    @staticmethod
    def reset_password(token: str, new_password: str):
        """Finalise a password reset using a time-limited token.

        The token is only ever created by the OTP blueprint after a successful
        OTP verification — callers cannot bypass the OTP gate.
        """
        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        if not reset_token or not reset_token.is_valid:
            return False, "Invalid or expired reset link. Please start the password reset process again."

        valid, msg = AuthService.validate_password(new_password)
        if not valid:
            return False, msg

        user = User.query.get(reset_token.user_id)
        if not user or not user.is_active:
            return False, "Invalid or expired reset link. Please start the password reset process again."

        reset_token.used = True
        user.set_password(new_password)
        # Expire every existing session so stolen cookies can't be reused.
        user.invalidate_all_sessions()
        db.session.commit()

        crypto_service.log_audit_action(
            action='password_reset_completed',
            acting_user=user, acting_role=user.role,
            details='Password reset via OTP-gated token; all sessions invalidated',
        )
        return True, "Password reset successfully."

    # ------------------------------------------------------------------
    # User management (admin operations)
    # ------------------------------------------------------------------

    @staticmethod
    def get_user_by_id(user_id):
        return User.query.get(user_id)

    @staticmethod
    def deactivate_user(user, acting_user):
        user.is_active = False
        db.session.commit()
        crypto_service.log_audit_action(
            action='user_deactivation',
            acting_user=acting_user, acting_role=acting_user.role,
            target_type='user', target_id=user.id,
            details='User account suspended',
        )
        return True

    @staticmethod
    def reactivate_user(user, acting_user):
        user.is_active = True
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        crypto_service.log_audit_action(
            action='user_reactivation',
            acting_user=acting_user, acting_role=acting_user.role,
            target_type='user', target_id=user.id,
            details='User account reactivated',
        )
        return True

    @staticmethod
    def request_account_deletion(user):
        """Whistleblower requests deletion (FR-W4).

        This does NOT delete the account. It flags the request for System Admin
        review and deactivates the account immediately so it cannot be used
        while the request is pending. Final deletion is performed by a System
        Admin via approve_account_deletion (FR-SA2).
        """
        if user.deletion_requested:
            return False, "A deletion request is already pending for this account."
        user.deletion_requested = True
        user.deletion_requested_at = datetime.utcnow()
        user.is_active = False
        db.session.commit()
        crypto_service.log_audit_action(action='account_deletion_requested', acting_user=None, acting_role=user.role, target_type='user', target_id=user.id, details='Whistleblower requested account deletion; account deactivated pending System Admin review')
        return True, "Your account deletion request has been submitted for review. Your account is now deactivated."

    @staticmethod
    def approve_account_deletion(user, acting_user):
        """System Admin approves a pending deletion request and performs the
        anonymised deletion (FR-SA2).

        Severs the reversible report->user link so the account cannot be
        correlated to its submissions after deletion. Reports remain intact and
        anonymous via submitter_hash (A6, NFR1). Reports and audit logs are
        preserved; only credentials and profile data are removed.
        """
        if not user.deletion_requested:
            return False, "This account has no pending deletion request."
        user_role = user.role
        # Scrub any submitter identity that may still live inside the encrypted
        # report payload (legacy reports stored submitter_email/name), and sever
        # the submitter_hash so reports can no longer be re-correlated to this
        # user_id. Then null user_id. After this the account is unrecoverable.
        for report in Report.query.filter_by(user_id=user.id).all():
            if report.encrypted_data:
                try:
                    data = json.loads(crypto_service.decrypt_data(report.encrypted_data))
                    data.pop('submitter_email', None)
                    data.pop('submitter_name', None)
                    report.encrypted_data = crypto_service.encrypt_data(json.dumps(data))
                except Exception:
                    # If a payload can't be read, drop it rather than risk leaking PII.
                    report.encrypted_data = None
            report.submitter_hash = secrets.token_hex(32)
            report.user_id = None
        PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
        user.email = f'deleted_{user.id}@deleted.sitinform'
        user.password_hash = ''
        user.first_name = 'Deleted'
        user.last_name = 'User'
        user.is_active = False
        user.invalidate_all_sessions()
        user.deletion_requested = False
        user.deletion_requested_at = None
        db.session.commit()
        crypto_service.log_audit_action(action='account_deletion_approved', acting_user=acting_user, acting_role=acting_user.role, target_type='user', target_id=user.id, details=f'Deletion request approved for {user_role} account; report links severed, reports and audit logs preserved')
        return True, "Account deletion approved. Reports and audit records have been preserved for integrity."

    @staticmethod
    def deny_account_deletion(user, acting_user):
        """System Admin denies a pending deletion request and reactivates the
        account (FR-SA2)."""
        if not user.deletion_requested:
            return False, "This account has no pending deletion request."
        user.deletion_requested = False
        user.deletion_requested_at = None
        user.is_active = True
        db.session.commit()
        crypto_service.log_audit_action(
            action='user_reactivation',
            acting_user=acting_user, acting_role=acting_user.role,
            target_type='user', target_id=user.id,
            details='Account deletion request denied; account reactivated',
        )
        return True, "Account deletion request denied. The account has been reactivated."

    @staticmethod
    def get_users_by_role(role):
        return User.query.filter_by(role=role, is_active=True).all()

    @staticmethod
    def check_user_permission(user, required_role):
        role_hierarchy = {'system_admin': 4, 'report_admin': 3, 'investigator': 2, 'whistleblower': 1}
        return role_hierarchy.get(user.role, 0) >= role_hierarchy.get(required_role, 0)

    @staticmethod
    def check_self_privilege_escalation(user, target_role):
        role_hierarchy = {'system_admin': 4, 'report_admin': 3, 'investigator': 2, 'whistleblower': 1}
        return role_hierarchy.get(user.role, 0) >= role_hierarchy.get(target_role, 0)

    @staticmethod
    def update_user_role(user, new_role, acting_user):
        if str(user.id) == str(acting_user.id):
            return False, "Cannot modify your own role."
        if not AuthService.check_self_privilege_escalation(acting_user, new_role):
            return False, "Cannot assign a role higher than your own."
        old_role = user.role
        user.role = new_role
        db.session.commit()
        crypto_service.log_audit_action(
            action='role_change',
            acting_user=acting_user, acting_role=acting_user.role,
            target_type='user', target_id=user.id,
            details=f'Role changed from {old_role} to {new_role}',
        )
        return True, f"Role updated to {new_role}."
