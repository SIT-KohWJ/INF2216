import os
import uuid
from datetime import datetime, timedelta

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import AuditLog, PasswordResetToken, Report, User  # noqa: E402
from app.services.auth_service import AuthService  # noqa: E402
from app.services.crypto_service import crypto_service  # noqa: E402


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def create_user(email="wb@singaporetech.edu.sg", role="whistleblower"):
    user = User(email=email, first_name="Test", last_name="User", role=role)
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    return user


def create_report(submitter, status="Received"):
    report = Report(
        reference_number=f"SIT-{uuid.uuid4().hex[:10].upper()}",
        submitter_hash=crypto_service.generate_user_hash(submitter.id),
        title="Report title",
        description="Report description",
        category="other",
        status=status,
        user_id=submitter.id,
    )
    db.session.add(report)
    db.session.commit()
    return report


def test_deletion_severs_report_link_but_preserves_report(app):
    user = create_user()
    report = create_report(user)
    report_id = report.id
    original_hash = report.submitter_hash

    success, _ = AuthService.request_account_deletion(user)

    assert success is True
    refreshed = Report.query.get(report_id)
    # Report still exists and is fully preserved...
    assert refreshed is not None
    assert refreshed.title == "Report title"
    # ...but the reversible FK link to the user is gone.
    assert refreshed.user_id is None
    # Anonymous linkage (submitter_hash) is untouched.
    assert refreshed.submitter_hash == original_hash


def test_deletion_scrubs_personal_data(app):
    user = create_user()
    user_id = user.id

    AuthService.request_account_deletion(user)

    scrubbed = User.query.get(user_id)
    assert scrubbed.email == f"deleted_{user_id}@deleted.sitinform"
    assert scrubbed.password_hash == ""
    assert scrubbed.first_name == "Deleted"
    assert scrubbed.last_name == "User"
    assert scrubbed.is_active is False


def test_deletion_invalidates_pending_reset_tokens(app):
    user = create_user()
    token = PasswordResetToken(
        user_id=user.id,
        token=uuid.uuid4().hex,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.session.add(token)
    db.session.commit()

    AuthService.request_account_deletion(user)

    assert PasswordResetToken.query.get(token.id).used is True


def test_deletion_records_audit_entry(app):
    user = create_user()
    user_id = user.id

    AuthService.request_account_deletion(user)

    entry = AuditLog.query.filter_by(action="account_deletion", target_id=user_id).first()
    assert entry is not None
    # Audit entry preserves the role for accountability, not the identity.
    assert entry.acting_role == "whistleblower"


def test_deletion_only_affects_own_reports(app):
    user_a = create_user(email="a@singaporetech.edu.sg")
    user_b = create_user(email="b@singaporetech.edu.sg")
    report_a = create_report(user_a)
    report_b = create_report(user_b)

    AuthService.request_account_deletion(user_a)

    assert Report.query.get(report_a.id).user_id is None
    # Other users' reports are untouched.
    assert Report.query.get(report_b.id).user_id == user_b.id
