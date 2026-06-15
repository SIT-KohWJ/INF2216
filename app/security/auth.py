"""AuthService - authentication, lockout, token revocation, password reset.
Requirements D1-D9. Lead: (Authentication story, 14-18 Jun)
"""


class AuthService:
    @staticmethod
    def hash_password(plaintext: str) -> str:
        """bcrypt hash (A1). Never store plaintext."""
        raise NotImplementedError("A1/D1: bcrypt hashing")

    @staticmethod
    def verify_password(plaintext: str, password_hash: str) -> bool:
        raise NotImplementedError("D1: bcrypt verify")

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
