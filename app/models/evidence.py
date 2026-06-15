import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID, BYTEA


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = db.Column(UUID(as_uuid=True),
                          db.ForeignKey("reports.id", ondelete="CASCADE"),
                          nullable=False)
    filename_encrypted = db.Column(BYTEA, nullable=False)     # AES-256-GCM (A3)
    file_hash = db.Column(db.String(64), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    scan_status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime(timezone=True))
