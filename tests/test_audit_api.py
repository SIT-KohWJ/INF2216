"""Tests for /api/audit role-based filtering (SEC-007).

Uses its own literal action-name sets (rather than importing REPORT_ACTIONS /
SYSTEM_ACTIONS from app.services.audit_service) so this test doesn't become
tautological against the implementation it's checking.
"""
import os
import uuid
from datetime import datetime

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import AuditLog, User  # noqa: E402

REPORT_ACTION_NAMES = {
    "report_submission", "status_update", "investigator_assignment",
    "investigation_note", "outcome_recommended", "evidence_downloaded",
    "report_viewed", "report_downloaded",
}
SYSTEM_ACTION_NAMES = {
    "user_login", "user_logout", "login_failed", "password_change",
    "user_registration", "user_deactivation", "role_change",
}


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def create_user(email, role):
    user = User(email=email, first_name="Test", last_name="User", role=role)
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    return user


def login_as(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True
        session["_sid"] = str(uuid.uuid4())
        session["_session_created_at"] = datetime.utcnow().isoformat()


def seed_audit_logs():
    """Seed at least one AuditLog row per category so filtering regressions
    (returning everything unfiltered) would make these tests fail."""
    seeded_report_actions = ["report_submission", "outcome_recommended"]
    seeded_system_actions = ["user_login", "role_change"]
    for action in seeded_report_actions:
        db.session.add(AuditLog(action=action, acting_role="investigator", details=f"seed {action}"))
    for action in seeded_system_actions:
        db.session.add(AuditLog(action=action, acting_role="system_admin", details=f"seed {action}"))
    db.session.commit()
    return seeded_report_actions, seeded_system_actions


def test_report_admin_only_sees_report_actions(app, client):
    report_admin = create_user("ra_audit@sit.singaporetech.edu.sg", "report_admin")
    seeded_report_actions, _ = seed_audit_logs()

    login_as(client, report_admin)
    resp = client.get("/api/audit")

    assert resp.status_code == 200
    logs = resp.get_json()["logs"]
    returned_actions = {log["action"] for log in logs}
    assert returned_actions  # something came back
    assert returned_actions <= REPORT_ACTION_NAMES
    assert returned_actions.isdisjoint(SYSTEM_ACTION_NAMES)
    # What we seeded as report-actions did actually come back.
    assert set(seeded_report_actions) <= returned_actions


def test_system_admin_only_sees_system_actions(app, client):
    system_admin = create_user("sa_audit@sit.singaporetech.edu.sg", "system_admin")
    _, seeded_system_actions = seed_audit_logs()

    login_as(client, system_admin)
    resp = client.get("/api/audit")

    assert resp.status_code == 200
    logs = resp.get_json()["logs"]
    returned_actions = {log["action"] for log in logs}
    assert returned_actions  # something came back
    assert returned_actions <= SYSTEM_ACTION_NAMES
    assert returned_actions.isdisjoint(REPORT_ACTION_NAMES)
    assert set(seeded_system_actions) <= returned_actions
