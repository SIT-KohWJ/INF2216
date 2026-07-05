"""Tests for the DISABLE_STAFF_OTP dev-only login-2FA bypass (app/routes/auth.py).

The flag is double-gated: it only has any effect when app.debug is also True,
and only for staff roles (system_admin, report_admin, investigator) — never
whistleblowers, and never when debug is off (as in TestingConfig/
ProductionConfig), which is the scenario that must never regress.
"""
import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import AuditLog, User  # noqa: E402


def _build_app(debug, disable_staff_otp):
    app = create_app("testing")
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["DEBUG"] = debug
    app.config["DISABLE_STAFF_OTP"] = disable_staff_otp
    return app


@pytest.fixture
def app_debug_off_flag_on():
    app = _build_app(debug=False, disable_staff_otp=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def app_debug_on_flag_on():
    app = _build_app(debug=True, disable_staff_otp=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def create_user(email, role):
    user = User(email=email, first_name="Test", last_name="User", role=role)
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    return user


def test_flag_has_no_effect_when_debug_is_off(app_debug_off_flag_on):
    assert app_debug_off_flag_on.debug is False
    client = app_debug_off_flag_on.test_client()
    with app_debug_off_flag_on.app_context():
        create_user("ra_nodebug@sit.singaporetech.edu.sg", "report_admin")

    resp = client.post(
        "/auth/login",
        data={"email": "ra_nodebug@sit.singaporetech.edu.sg", "password": "Password123!"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert "/auth/login/verify" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert sess.get("_2fa_user_id")
        assert "_user_id" not in sess


def test_whistleblower_is_not_bypassed_even_with_debug_and_flag_on(app_debug_on_flag_on):
    assert app_debug_on_flag_on.debug is True
    client = app_debug_on_flag_on.test_client()
    with app_debug_on_flag_on.app_context():
        create_user("wb_debug@sit.singaporetech.edu.sg", "whistleblower")

    resp = client.post(
        "/auth/login",
        data={"email": "wb_debug@sit.singaporetech.edu.sg", "password": "Password123!"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert "/auth/login/verify" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert sess.get("_2fa_user_id")
        assert "_user_id" not in sess


def test_staff_login_is_bypassed_with_debug_and_flag_on_and_audit_logged(app_debug_on_flag_on):
    assert app_debug_on_flag_on.debug is True
    client = app_debug_on_flag_on.test_client()
    with app_debug_on_flag_on.app_context():
        user = create_user("ra_debug@sit.singaporetech.edu.sg", "report_admin")
        user_id = user.id

    resp = client.post(
        "/auth/login",
        data={"email": "ra_debug@sit.singaporetech.edu.sg", "password": "Password123!"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert "/auth/login/verify" not in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert sess.get("_user_id") == str(user_id)
        assert "_2fa_user_id" not in sess

    with app_debug_on_flag_on.app_context():
        # AuthService.authenticate_user() also logs its own generic
        # "user_login" entry the moment the password check succeeds,
        # independent of 2FA — so this login produces two user_login rows
        # with near-identical timestamps. Filter on the DEV MODE marker
        # directly rather than assuming ordering between the two.
        entry = (
            AuditLog.query
            .filter(
                AuditLog.action == "user_login",
                AuditLog.acting_user_id == user_id,
                AuditLog.details.contains("DEV MODE"),
            )
            .first()
        )
        assert entry is not None
