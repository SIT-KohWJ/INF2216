import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID, BYTEA


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    public_id = db.Column(UUID(as_uuid=True), nullable=False, unique=True,
                          default=uuid.uuid4)               # used in URLs (E2)
    submitter_hash = db.Column(db.String(64), nullable=False)  # HMAC-SHA256 (A2)
    title_encrypted = db.Column(BYTEA, nullable=False)        # AES-256-GCM (A3)
    description_encrypted = db.Column(BYTEA, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="received")
    created_at = db.Column(db.DateTime(timezone=True))
    updated_at = db.Column(db.DateTime(timezone=True))

    # NOTE: deliberately NO relationship to User. The anonymity guarantee is
    # that there is no link from a report back to its submitter (A2/NFR1).
