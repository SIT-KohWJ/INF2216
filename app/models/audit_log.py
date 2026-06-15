import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID, JSONB


class AuditLog(db.Model):
    """Append-only audit trail (F1-F4). The DB has a trigger that blocks
    UPDATE/DELETE, so only inserts will succeed. Never store report content
    or anything that re-identifies a submitter here."""
    __tablename__ = "audit_log"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = db.Column(db.String(100), nullable=False)
    report_id = db.Column(UUID(as_uuid=True),
                          db.ForeignKey("reports.id", ondelete="SET NULL"))
    actor_role = db.Column(db.String(50))
    target_entity = db.Column(db.String(100))
    ip_address_hash = db.Column(db.String(64))
    details = db.Column(JSONB)
    occurred_at = db.Column(db.DateTime(timezone=True))
