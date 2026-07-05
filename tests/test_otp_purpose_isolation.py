"""Characterizes shared-OTP-store behavior across login-2FA and forgot-password.

app/models.py's OtpToken has no `purpose` column — a single row per email is
shared by every OTP-issuing flow (login 2FA, forgot-password, registration),
because create_otp_for_email() purges all existing OtpToken rows for the
email before creating a new one.

This test is written as the DESIRED/secure behavior (a pending login-2FA code
should be unaffected by an unrelated forgot-password request for the same
email) rather than matching current behavior. It is expected to currently
FAIL — do not weaken the assertion, and do not modify otp_service.py/
models.py to make it pass silently. See audit finding SEC-025.
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
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def create_user(email="otpshared@sit.singaporetech.edu.sg"):
    user = User(email=email, first_name="Otp", last_name="Shared", role="whistleblower")
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.mark.xfail(
    reason="OtpToken has no purpose column; forgot-password invalidates a "
           "pending login-2FA code for the same email — see audit finding SEC-025",
)
def test_forgot_password_request_does_not_invalidate_pending_login_2fa_code(app):
    user = create_user()

    # Step 1: a login-2FA flow is in progress for this user — one OtpToken row
    # now exists for their email, and the plaintext code has been "emailed".
    login_otp = OtpService.create_otp_for_email(user.email)

    # Step 2: separately (and possibly by someone else), a forgot-password
    # request comes in for the same email address.
    OtpService.initiate_for_email(user.email)

    # Desired/secure behavior: the original login-2FA code the user already
    # has in their inbox should still work — it belongs to a different
    # purpose than the forgot-password flow that just ran for the same email.
    success, _ = OtpService.verify_otp(user.email, login_otp)
    assert success is True
