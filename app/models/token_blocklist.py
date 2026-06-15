from ..extensions import db


class TokenBlocklist(db.Model):
    """Revoked / logged-out JWTs (D-series: session invalidation)."""
    __tablename__ = "token_blocklist"

    jti = db.Column(db.String(64), primary_key=True)   # JWT "jti" claim
    token_hash = db.Column(db.String(64), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
