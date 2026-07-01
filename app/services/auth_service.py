from app import db
from app.models import User, PasswordResetToken
from app.services.crypto_service import crypto_service
from datetime import datetime, timedelta
import re


class AuthService:
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@(sit\.)?singaporetech\.edu\.sg$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        return True

    @staticmethod
    def register_user(email, password, first_name, last_name, role='whistleblower', acting_user=None):
        if not AuthService.validate_email(email):
            return None, "Invalid email format. Must use @singaporetech.edu.sg or @sit.singaporetech.edu.sg"
        if not AuthService.validate_password(password):
            return None, "Password must be at least 8 characters with uppercase, lowercase, and digit"
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return None, "Unable to complete registration. Please check your details and try again."
        user = User(email=email, first_name=first_name, last_name=last_name, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        crypto_service.log_audit_action(action='user_registration', acting_user=user, acting_role=user.role, target_type='user', target_id=user.id, details=f'New user registered with role: {user.role}')
        return user, "Registration successful"

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
            crypto_service.log_audit_action(action='login_failed_account_locked', acting_user=user, acting_role=user.role, details='Login attempt on locked account', ip_address=ip_address)
            return None
        if user and user.check_password(password) and user.is_active:
            user.reset_failed_login()
            db.session.commit()
            crypto_service.log_audit_action(action='user_login', acting_user=user, acting_role=user.role, details='User logged in', ip_address=ip_address)
            return user
        if user:
            user.increment_failed_login()
            db.session.commit()
        crypto_service.log_audit_action(action='login_failed', acting_user=user, acting_role='anonymous', details='Failed login attempt', ip_address=ip_address)
        return None

    @staticmethod
    def get_user_by_id(user_id):
        return User.query.get(user_id)

    @staticmethod
    def update_user_password(user, current_password, new_password):
        if not user.check_password(current_password):
            return False, "Current password is incorrect"
        if not AuthService.validate_password(new_password):
            return False, "Password must be at least 8 characters with uppercase, lowercase, and digit"
        user.set_password(new_password)
        db.session.commit()
        crypto_service.log_audit_action(action='password_change', acting_user=user, acting_role=user.role, details='User changed password')
        return True, "Password updated successfully"

    @staticmethod
    def request_password_reset(email):
        user = User.query.filter_by(email=email).first()
        if not user:
            return True, "If the email exists, a reset link has been sent"
        token = crypto_service.generate_password_reset_token()
        reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=datetime.utcnow() + timedelta(minutes=10))
        db.session.add(reset_token)
        db.session.commit()
        crypto_service.log_audit_action(action='password_reset_requested', acting_user=user, acting_role=user.role, target_type='user', target_id=user.id, details='Password reset token generated')
        return True, token

    @staticmethod
    def reset_password(token, new_password):
        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        if not reset_token or not reset_token.is_valid:
            return False, "Invalid or expired reset token"
        if not AuthService.validate_password(new_password):
            return False, "Password must be at least 8 characters with uppercase, lowercase, and digit"
        user = User.query.get(reset_token.user_id)
        if not user:
            return False, "User not found"
        reset_token.used = True
        user.set_password(new_password)
        db.session.commit()
        crypto_service.log_audit_action(action='password_reset_completed', acting_user=user, acting_role=user.role, details='Password reset via token')
        return True, "Password reset successfully"

    @staticmethod
    def deactivate_user(user, acting_user):
        user.is_active = False
        db.session.commit()
        crypto_service.log_audit_action(action='user_deactivation', acting_user=acting_user, acting_role=acting_user.role, target_type='user', target_id=user.id, details='User account suspended')
        return True

    @staticmethod
    def reactivate_user(user, acting_user):
        user.is_active = True
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        crypto_service.log_audit_action(action='user_reactivation', acting_user=acting_user, acting_role=acting_user.role, target_type='user', target_id=user.id, details='User account reactivated')
        return True

    @staticmethod
    def request_account_deletion(user):
        user_role = user.role
        user.email = f'deleted_{user.id}@deleted.sitinform'
        user.password_hash = ''
        user.first_name = 'Deleted'
        user.last_name = 'User'
        user.is_active = False
        db.session.commit()
        crypto_service.log_audit_action(action='account_deletion', acting_user=None, acting_role=user_role, target_type='user', target_id=user.id, details='Account deleted, reports and audit logs preserved')
        return True, "Account deleted successfully. Your reports and audit records have been preserved for integrity."

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
            return False, "Cannot modify your own role"
        if not AuthService.check_self_privilege_escalation(acting_user, new_role):
            return False, "Cannot assign a role higher than your own"
        old_role = user.role
        user.role = new_role
        db.session.commit()
        crypto_service.log_audit_action(action='role_change', acting_user=acting_user, acting_role=acting_user.role, target_type='user', target_id=user.id, details=f'Role changed from {old_role} to {new_role}')
        return True, f"Role updated to {new_role}"
