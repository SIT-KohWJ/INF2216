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
    def verify_otp(email: str, otp: str) -> tuple:
        """Verify *otp* for *email*.  Returns (success: bool, message: str).

        Atomically increments the attempt counter before checking the hash so
        that concurrent requests can never exceed MAX_ATTEMPTS even without
        row-level locking.
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
            return False, "No OTP request found. Please request a new password reset."

        if record.is_expired:
            return False, "OTP has expired. Please request a new password reset."

        if record.verified:
            return False, "This OTP has already been used."

        if record.attempts >= max_attempts:
            return False, "Too many failed attempts. Please request a new password reset."

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
        return False, "Too many failed attempts. Please request a new password reset."

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
    def cleanup_expired() -> int:
        """Delete expired OTP records. Returns the number of rows removed."""
        deleted = OtpToken.query.filter(OtpToken.expires_at < datetime.utcnow()).delete()
        db.session.commit()
        return deleted
