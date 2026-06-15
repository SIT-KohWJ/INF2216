import uuid
from ..extensions import db
from sqlalchemy.dialects.postgresql import UUID

# Roles/statuses are native ENUM types in init.sql. We map them as plain
# strings here (create_type/checks live in the DB). Tighten to db.Enum(...,
# create_type=False) later if you want ORM-side validation too.


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.Text, nullable=False)          # bcrypt only (A1)
    role = db.Column(db.String(20), nullable=False, default="whistleblower")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    login_attempt_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True))
    updated_at = db.Column(db.DateTime(timezone=True))

    def __repr__(self):
        return f"<User {self.email} role={self.role}>"
