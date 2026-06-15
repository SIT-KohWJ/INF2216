import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID


class ReportStatusHistory(db.Model):
    __tablename__ = "report_status_history"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = db.Column(UUID(as_uuid=True),
                          db.ForeignKey("reports.id", ondelete="CASCADE"),
                          nullable=False)
    actor_role = db.Column(db.String(20), nullable=False)     # role, not identity (F2)
    old_status = db.Column(db.String(20))
    new_status = db.Column(db.String(20), nullable=False)
    changed_at = db.Column(db.DateTime(timezone=True))
