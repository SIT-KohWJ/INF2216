"""OTP service — isolated from the password-reset token flow.

Responsibility boundary:
  * Generate a cryptographically random 6-digit OTP.
  * Persist only its SHA-256 hash (never the plaintext).
  * Verify a submitted OTP with constant-time comparison and attempt limiting.
  * Purge stale records so the table stays small.

This module deliberately knows nothing about PasswordResetToken. The OTP
blueprint (app/routes/otp.py) bridges the two: it calls this service to
verify the OTP, then — only on success — creates the PasswordResetToken.
That separation is the "separate process" / defence-in-depth design.
"""
import secrets
import hashlib
import hmac as _hmac
from datetime import datetime, timedelta

from flask import current_app

from app import db
from app.models import OtpToken


class OtpService:

    @staticmethod
    def _hash_otp(otp: str) -> str:
        return hashlib.sha256(otp.encode('utf-8')).hexdigest()

    @staticmethod
    def create_otp_for_email(email: str) -> str:
        """Purge any existing OTPs for *email*, then create and store a fresh one.

        Returns the plaintext OTP (to be handed to EmailService — never logged
        or stored).
        """
        email = email.lower().strip()
        OtpToken.query.filter_by(email=email).delete()
        db.session.flush()

        expiry_seconds = current_app.config.get('OTP_EXPIRY_SECONDS', 30)
        otp = str(secrets.randbelow(10 ** 6)).zfill(6)

        record = OtpToken(
            email=email,
            otp_hash=OtpService._hash_otp(otp),
            expires_at=datetime.utcnow() + timedelta(seconds=expiry_seconds),
        )
        db.session.add(record)
        db.session.commit()
        return otp

    @staticmethod
    def verify_otp(email: str, otp: str, restart_hint: str = "Please request a new password reset.") -> tuple:
        """Verify *otp* for *email*.  Returns (success: bool, message: str).

        Atomically increments the attempt counter before checking the hash so
        that concurrent requests can never exceed MAX_ATTEMPTS even without
        row-level locking.

        *restart_hint* is appended to restart-needed failures so callers other
        than password reset (e.g. registration) can point the user back to
        their own flow instead of a "request a new password reset" message
        that would make no sense there.
        """
        email = email.lower().strip()
        max_attempts = current_app.config.get('OTP_MAX_ATTEMPTS', 5)

        record = (
            OtpToken.query
            .filter_by(email=email)
            .order_by(OtpToken.created_at.desc())
            .first()
        )

        if not record:
            return False, f"No OTP request found. {restart_hint}"

        if record.is_expired:
            return False, f"OTP has expired. {restart_hint}"

        if record.verified:
            return False, "This OTP has already been used."

        if record.attempts >= max_attempts:
            return False, f"Too many failed attempts. {restart_hint}"

        # Increment BEFORE comparing — prevents race-condition bypass.
        record.attempts += 1
        db.session.commit()

        expected_hash = OtpService._hash_otp(otp)
        if _hmac.compare_digest(record.otp_hash, expected_hash):
            record.verified = True
            db.session.commit()
            return True, "OTP verified"

        remaining = max_attempts - record.attempts
        if remaining > 0:
            return False, f"Invalid OTP. {remaining} attempt(s) remaining."
        return False, f"Too many failed attempts. {restart_hint}"

    @staticmethod
    def initiate_for_email(email: str) -> None:
        """Top-level call from the forgot-password route.

        Creates an OTP record for *every* valid SIT email so the response is
        identical whether or not an account exists (non-enumeration).  The OTP
        is emailed only when an active account is found.
        """
        from app.models import User
        from app.services.email_service import EmailService

        otp = OtpService.create_otp_for_email(email)

        user = User.query.filter_by(email=email.lower(), is_active=True).first()
        if user:
            sent = EmailService.send_otp_email(email, otp, user.first_name)
            if not sent:
                current_app.logger.error(
                    "OTP email delivery failed; SMTP may be misconfigured"
                )

    @staticmethod
    def initiate_for_registration(email: str, first_name: str = '') -> None:
        """Top-level call from the registration route.

        Creates an OTP record regardless of whether the email is already
        registered, so the route's response is identical either way — the
        OTP is only actually emailed when the address is NOT already taken.
        This mirrors initiate_for_email()'s non-enumeration design (just with
        the existence check inverted), so a candidate email's registration
        status can't be inferred from the registration response.
        """
        from app.models import User
        from app.services.email_service import EmailService

        email = email.lower().strip()
        otp = OtpService.create_otp_for_email(email)

        existing = User.query.filter_by(email=email).first()
        if not existing:
            sent = EmailService.send_registration_otp_email(email, otp, first_name)
            if not sent:
                current_app.logger.error(
                    "Registration OTP email delivery failed; SMTP may be misconfigured"
                )

    @staticmethod
    def cleanup_expired() -> int:
        """Delete expired OTP records. Returns the number of rows removed."""
        deleted = OtpToken.query.filter(OtpToken.expires_at < datetime.utcnow()).delete()
        db.session.commit()
        return deleted
