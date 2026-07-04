"""Append-only audit-log tests.

Verifies that UPDATE and DELETE on `audit_logs` are blocked at the ORM layer
(the SQLAlchemy event listener registered in the app factory). This
complements the PostgreSQL trigger in scripts/init.sql, which enforces the
same guarantee at the DB layer for production.
"""
import os
import uuid

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import AuditLog, User  # noqa: E402
from app.securityfeature.audit import AuditService  # noqa: E402


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def make_user(email='append_only@sit.singaporetech.edu.sg'):
    u = User(email=email, first_name='Test', last_name='User', role='whistleblower')
    u.set_password('Password123!')
    db.session.add(u)
    db.session.commit()
    db.session.refresh(u)
    return u


def test_append_only_blocks_update(app):
    user = make_user()
    AuditService.log(action='user_login', acting_user=user, details='Login')

    log = AuditLog.query.first()
    original_details = log.details

    # Attempt to mutate -- must raise
    log.details = 'TAMPERED CONTENT'
    with pytest.raises(PermissionError, match='append-only'):
        db.session.commit()

    # Roll back and verify the row is unchanged
    db.session.rollback()
    fresh = AuditLog.query.first()
    assert fresh.details == original_details


def test_append_only_blocks_delete(app):
    user = make_user(email='delete_test@sit.singaporetech.edu.sg')
    AuditService.log(action='user_logout', acting_user=user, details='Logout')

    log = AuditLog.query.first()
    db.session.delete(log)
    with pytest.raises(PermissionError, match='append-only'):
        db.session.commit()

    db.session.rollback()
    # Row still present
    assert AuditLog.query.count() == 1


def test_append_only_allows_insert(app):
    """Sanity: inserts (the normal write path) are not blocked."""
    user = make_user(email='insert_test@sit.singaporetech.edu.sg')
    AuditService.log(action='user_login', acting_user=user, details='Login 1')
    AuditService.log(action='user_logout', acting_user=user, details='Logout 1')
    assert AuditLog.query.count() == 2


def test_ecdsa_signature_is_present_and_verifies(app):
    """Every audit entry must be ECDSA-signed and pass integrity verification."""
    user = make_user(email='sig_test@sit.singaporetech.edu.sg')
    AuditService.log(action='user_login', acting_user=user, details='Login')
    log = AuditLog.query.first()
    assert log.signature is not None
    assert len(log.signature) > 0

    result = AuditService.verify_audit_integrity()
    assert result['integrity_ok'] is True
    assert result['valid'] == 1
    assert result['invalid'] == 0
