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


# ── Request phase (FR-W4) ────────────────────────────────────────────────────

def test_request_flags_and_deactivates_without_deleting(app):
    user = create_user()
    report = create_report(user)

    success, _ = AuthService.request_account_deletion(user)

    assert success is True
    assert user.deletion_requested is True
    assert user.deletion_requested_at is not None
    assert user.is_active is False
    # Nothing is scrubbed yet — profile and report link remain until approval.
    assert user.email == "wb@singaporetech.edu.sg"
    assert Report.query.get(report.id).user_id == user.id


def test_request_records_audit_entry_by_role(app):
    user = create_user()
    user_id = user.id

    AuthService.request_account_deletion(user)

    entry = AuditLog.query.filter_by(
        action="account_deletion_requested", target_id=user_id
    ).first()
    assert entry is not None
    assert entry.acting_role == "whistleblower"


def test_duplicate_request_is_rejected(app):
    user = create_user()
    AuthService.request_account_deletion(user)

    success, message = AuthService.request_account_deletion(user)

    assert success is False
    assert "already pending" in message


# ── Approve phase (FR-SA2) ───────────────────────────────────────────────────

def test_approve_severs_report_link_but_preserves_report(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    report = create_report(user)
    report_id = report.id
    user_id = user.id
    original_hash = report.submitter_hash

    AuthService.request_account_deletion(user)
    success, _ = AuthService.approve_account_deletion(user, admin)

    assert success is True
    refreshed = Report.query.get(report_id)
    assert refreshed is not None
    assert refreshed.title == "Report title"
    assert refreshed.user_id is None
    # The report is preserved, but its link to the deleted user is severed: the
    # submitter_hash is randomised so it can no longer be re-correlated to the
    # original user_id (was HMAC(user_id)).
    assert refreshed.submitter_hash != original_hash
    assert refreshed.submitter_hash != crypto_service.generate_user_hash(user_id)


def test_approve_scrubs_personal_data_and_clears_flag(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    user_id = user.id

    AuthService.request_account_deletion(user)
    AuthService.approve_account_deletion(user, admin)

    scrubbed = User.query.get(user_id)
    assert scrubbed.email == f"deleted_{user_id}@deleted.sitinform"
    assert scrubbed.password_hash == ""
    assert scrubbed.first_name == "Deleted"
    assert scrubbed.is_active is False
    assert scrubbed.deletion_requested is False


def test_approve_invalidates_pending_reset_tokens(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    token = PasswordResetToken(
        user_id=user.id,
        token=uuid.uuid4().hex,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.session.add(token)
    db.session.commit()

    AuthService.request_account_deletion(user)
    AuthService.approve_account_deletion(user, admin)

    assert PasswordResetToken.query.get(token.id).used is True


def test_approve_records_audit_entry_with_admin_role(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    user_id = user.id

    AuthService.request_account_deletion(user)
    AuthService.approve_account_deletion(user, admin)

    entry = AuditLog.query.filter_by(
        action="account_deletion_approved", target_id=user_id
    ).first()
    assert entry is not None
    assert entry.acting_role == "system_admin"


def test_approve_without_pending_request_is_rejected(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")

    success, message = AuthService.approve_account_deletion(user, admin)

    assert success is False
    assert "no pending deletion request" in message


def test_approve_only_affects_own_reports(app):
    user_a = create_user(email="a@singaporetech.edu.sg")
    user_b = create_user(email="b@singaporetech.edu.sg")
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    report_a = create_report(user_a)
    report_b = create_report(user_b)

    AuthService.request_account_deletion(user_a)
    AuthService.approve_account_deletion(user_a, admin)

    assert Report.query.get(report_a.id).user_id is None
    assert Report.query.get(report_b.id).user_id == user_b.id


# ── Deny phase (FR-SA2) ──────────────────────────────────────────────────────

def test_deny_reactivates_and_clears_flag(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")
    report = create_report(user)

    AuthService.request_account_deletion(user)
    success, _ = AuthService.deny_account_deletion(user, admin)

    assert success is True
    assert user.deletion_requested is False
    assert user.is_active is True
    # Data is fully intact after denial.
    assert user.email == "wb@singaporetech.edu.sg"
    assert Report.query.get(report.id).user_id == user.id


def test_deny_without_pending_request_is_rejected(app):
    user = create_user()
    admin = create_user(email="sys@singaporetech.edu.sg", role="system_admin")

    success, message = AuthService.deny_account_deletion(user, admin)

    assert success is False
    assert "no pending deletion request" in message
