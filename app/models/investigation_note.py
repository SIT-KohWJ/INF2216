import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID, BYTEA


class InvestigationNote(db.Model):
    __tablename__ = "investigation_notes"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = db.Column(UUID(as_uuid=True),
                          db.ForeignKey("reports.id", ondelete="CASCADE"),
                          nullable=False)
    # Investigators MUST stay attributable, so this DOES link to a real user.
    investigator_id = db.Column(UUID(as_uuid=True),
                                db.ForeignKey("users.id"), nullable=False)
    notes_encrypted = db.Column(BYTEA)
    recommendation = db.Column(db.String(30))   # recommendation_outcome enum
    assigned_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True))
    updated_at = db.Column(db.DateTime(timezone=True))
