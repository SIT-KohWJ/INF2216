from datetime import datetime
import uuid
from app import db, login_manager
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import UUID
import bcrypt


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='whistleblower')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    reports = db.relationship('Report', backref='submitter', lazy=True, foreign_keys='Report.user_id')
    investigation_notes = db.relationship('InvestigationNote', backref='investigator', lazy=True, foreign_keys='InvestigationNote.investigator_id')
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        self.password_hash = hashed.decode('utf-8')

    def check_password(self, password):
        password_bytes = password.encode('utf-8')
        hashed_bytes = self.password_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)

    def get_id(self):
        return str(self.id)

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def increment_failed_login(self):
        from flask import current_app
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS', 5):
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(
                minutes=current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)
            )

    def reset_failed_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reference_number = db.Column(db.String(16), unique=True, nullable=False)
    submitter_hash = db.Column(db.String(64), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), nullable=False, default='Received')
    outcome = db.Column(db.String(64), nullable=True)
    outcome_details = db.Column(db.Text, nullable=True)
    encrypted_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    investigator_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    status_history = db.relationship('ReportStatusHistory', backref='report', lazy=True, cascade='all, delete-orphan')
    evidence = db.relationship('Evidence', backref='report', lazy=True, cascade='all, delete-orphan')
    investigation_notes = db.relationship('InvestigationNote', backref='report', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Report {self.reference_number} - {self.status}>'


class ReportStatusHistory(db.Model):
    __tablename__ = 'report_status_history'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('reports.id'), nullable=False)
    old_status = db.Column(db.String(32), nullable=False)
    new_status = db.Column(db.String(32), nullable=False)
    changed_by_role = db.Column(db.String(20), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)


class Evidence(db.Model):
    __tablename__ = 'evidence'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('reports.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(32), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    encrypted_file_data = db.Column(db.LargeBinary)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class InvestigationNote(db.Model):
    __tablename__ = 'investigation_notes'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('reports.id'), nullable=False)
    investigator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(128), nullable=False)
    acting_user_id = db.Column(db.String(36))
    acting_role = db.Column(db.String(20), nullable=False)
    target_type = db.Column(db.String(32))
    target_id = db.Column(db.String(36))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    signature = db.Column(db.Text)


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    @property
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self):
        return not self.used and not self.is_expired


class RevokedToken(db.Model):
    __tablename__ = 'revoked_tokens'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_jti = db.Column(db.String(36), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(64))

    @staticmethod
    def is_token_revoked(jti):
        return RevokedToken.query.filter_by(token_jti=jti).first() is not None


class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(64), nullable=False)
    related_report_id = db.Column(UUID(as_uuid=True), nullable=True)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)