"""Tests for session revocation on deactivation (SEC-006) and the peer-
protection guards on deactivate_user / update_user_role (SEC-006, SEC-009).
"""
import os
import uuid
from datetime import datetime

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import User  # noqa: E402
from app.services.auth_service import AuthService  # noqa: E402


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


def test_deactivating_user_invalidates_existing_session(app, client):
    target = create_user("staff_target@sit.singaporetech.edu.sg", "report_admin")
    admin = create_user("sysadmin_deactivate@sit.singaporetech.edu.sg", "system_admin")

    login_as(client, target)
    # Confirm the session works before deactivation.
    resp = client.get("/auth/account")
    assert resp.status_code == 200

    success, _ = AuthService.deactivate_user(target, admin)
    assert success is True

    # Same still-open session cookie, next request should be rejected.
    resp = client.get("/auth/account", follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_system_admin_cannot_deactivate_another_system_admin(app):
    sa1 = create_user("sa1_deact@sit.singaporetech.edu.sg", "system_admin")
    sa2 = create_user("sa2_deact@sit.singaporetech.edu.sg", "system_admin")

    success, message = AuthService.deactivate_user(sa2, sa1)

    assert success is False
    assert "cannot suspend each other" in message
    assert sa2.is_active is True


def test_system_admin_cannot_change_another_system_admins_role(app):
    sa1 = create_user("sa1_role@sit.singaporetech.edu.sg", "system_admin")
    sa2 = create_user("sa2_role@sit.singaporetech.edu.sg", "system_admin")

    success, message = AuthService.update_user_role(sa2, "whistleblower", sa1)

    assert success is False
    assert "cannot change each other" in message
    assert sa2.role == "system_admin"
