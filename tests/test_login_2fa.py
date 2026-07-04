"""Tests for email 2FA at login.

Login is now a two-step flow:
  1. POST /auth/login with correct email+password -> OTP emailed, redirect to
     /auth/login/verify. NOT authenticated yet.
  2. POST /auth/login/verify with the emailed code -> authenticated session.

These tests capture the OTP by monkeypatching the email service (there is no
SMTP in the test environment) and drive the real routes end to end.
"""
import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import User  # noqa: E402
from app.services.otp_service import OtpService  # noqa: E402


@pytest.fixture
def app():
    app = create_app("testing")
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def captured_otps(monkeypatch):
    """Capture OTPs by intercepting the login-2FA initiator.

    Runs the real OTP creation (so verify_otp works against a stored hash) but
    skips the SMTP send and records the plaintext code for the test to submit.
    """
    sent = []

    def fake_initiate(user):
        otp = OtpService.create_otp_for_email(user.email)
        sent.append(otp)
        return True

    monkeypatch.setattr(OtpService, "initiate_login_2fa", staticmethod(fake_initiate))
    return sent


def create_user(email="user2fa@sit.singaporetech.edu.sg", active=True):
    user = User(email=email, first_name="Two", last_name="Factor", role="whistleblower")
    user.set_password("Password123!")
    user.is_active = active
    db.session.add(user)
    db.session.commit()
    return user


def test_correct_password_does_not_authenticate_yet(app, client, captured_otps):
    create_user()
    resp = client.post(
        "/auth/login",
        data={"email": "user2fa@sit.singaporetech.edu.sg", "password": "Password123!"},
        follow_redirects=False,
    )
    # Redirected to the verify step, not to a dashboard.
    assert resp.status_code == 302
    assert "/auth/login/verify" in resp.headers["Location"]
    # An OTP was generated/sent.
    assert len(captured_otps) == 1
    # Session holds the pending marker but no authenticated user yet.
    with client.session_transaction() as sess:
        assert sess.get("_2fa_user_id")
        assert "_user_id" not in sess


def test_full_2fa_flow_logs_in(app, client, captured_otps):
    create_user()
    client.post(
        "/auth/login",
        data={"email": "user2fa@sit.singaporetech.edu.sg", "password": "Password123!"},
    )
    otp = captured_otps[-1]
    resp = client.post("/auth/login/verify", data={"otp": otp}, follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/login/verify" not in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert sess.get("_user_id")
        assert sess.get("_sid")
        assert "_2fa_user_id" not in sess


def test_wrong_otp_does_not_log_in(app, client, captured_otps):
    create_user()
    client.post(
        "/auth/login",
        data={"email": "user2fa@sit.singaporetech.edu.sg", "password": "Password123!"},
    )
    resp = client.post("/auth/login/verify", data={"otp": "000000"}, follow_redirects=True)
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
        # Still pending — the user can retry within the attempt limit.
        assert sess.get("_2fa_user_id")


def test_wrong_password_never_sends_otp(app, client, captured_otps):
    create_user()
    resp = client.post(
        "/auth/login",
        data={"email": "user2fa@sit.singaporetech.edu.sg", "password": "WrongPass1!"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert len(captured_otps) == 0
    with client.session_transaction() as sess:
        assert "_2fa_user_id" not in sess


def test_cannot_reach_verify_without_pending_login(app, client):
    resp = client.get("/auth/login/verify", follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]
