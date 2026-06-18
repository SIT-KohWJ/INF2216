"""AuthService - authentication, lockout, token revocation, password reset.
Requirements D1-D9. Lead: (Authentication story, 14-18 Jun)
"""
import re

import bcrypt


class AuthService:
    PASSWORD_POLICY_MESSAGE = (
        "Password must be at least 12 characters long and include uppercase, "
        "lowercase, a number, and a special character."
    )

    @staticmethod
    def validate_password_strength(plaintext: str) -> None:
        if not isinstance(plaintext, str) or len(plaintext) < 12:
            raise ValueError(AuthService.PASSWORD_POLICY_MESSAGE)
        if not re.search(r"[A-Z]", plaintext):
            raise ValueError(AuthService.PASSWORD_POLICY_MESSAGE)
        if not re.search(r"[a-z]", plaintext):
            raise ValueError(AuthService.PASSWORD_POLICY_MESSAGE)
        if not re.search(r"\d", plaintext):
            raise ValueError(AuthService.PASSWORD_POLICY_MESSAGE)
        if not re.search(r"[^A-Za-z0-9]", plaintext):
            raise ValueError(AuthService.PASSWORD_POLICY_MESSAGE)

    @staticmethod
    def hash_password(plaintext: str) -> str:
        """bcrypt hash (A1). Never store plaintext."""
        AuthService.validate_password_strength(plaintext)
        password_bytes = plaintext.encode("utf-8")
        return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(plaintext: str, password_hash: str) -> bool:
        if not plaintext or not password_hash:
            return False

        try:
            return bcrypt.checkpw(
                plaintext.encode("utf-8"),
                password_hash.encode("utf-8"),
            )
        except ValueError:
            return False

    @staticmethod
    def issue_token(user) -> str:
        """PyJWT token with exp + jti claims. Regenerate on login / privilege
        change (D2). Validate server-side on every protected request (D4)."""
        raise NotImplementedError("D2/D4: issue PyJWT token")

    @staticmethod
    def revoke_token(jti: str) -> None:
        """Add jti to token_blocklist so logout actually invalidates."""
        raise NotImplementedError("D: token revocation")

    @staticmethod
    def register_failed_attempt(user) -> None:
        """Increment login_attempt_count; lock account past threshold (account
        lockout). Use generic error messages so valid emails aren't revealed."""
        raise NotImplementedError("D: account lockout")
