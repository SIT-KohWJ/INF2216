import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True),
                        db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)  # store hash, never the token
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True))
