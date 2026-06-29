"""Email delivery via Brevo SMTP (Flask-Mail).

Falls back to terminal logging when MAIL_USERNAME is not configured so
the app stays fully usable in local dev without credentials.
"""
from flask import current_app


class EmailService:
    _mail = None

    @classmethod
    def init_app(cls, mail_instance) -> None:
        cls._mail = mail_instance

    @classmethod
    def send_otp_email(cls, to_email: str, otp: str, first_name: str = '') -> bool:
        expiry_seconds = current_app.config.get('OTP_EXPIRY_SECONDS', 30)
        subject = "SITinform — Password Reset OTP"
        body = (
            f"Hello {first_name or 'there'},\n\n"
            f"Your one-time password (OTP) for resetting your SITinform account is:\n\n"
            f"    {otp}\n\n"
            f"This OTP is valid for {expiry_seconds} seconds and can be used only once.\n\n"
            f"If you did not request a password reset, please ignore this email. "
            f"Your account password has not been changed.\n\n"
            f"SITinform Security Team\n"
            f"Singapore Institute of Technology"
        )

        mail_user = current_app.config.get('MAIL_USERNAME')
        mail_server = current_app.config.get('MAIL_SERVER')
        mail_sender = current_app.config.get('MAIL_DEFAULT_SENDER')

        print(f"[EMAIL] MAIL_USERNAME  = {mail_user!r}", flush=True)
        print(f"[EMAIL] MAIL_SERVER    = {mail_server!r}", flush=True)
        print(f"[EMAIL] MAIL_SENDER    = {mail_sender!r}", flush=True)
        print(f"[EMAIL] Sending OTP to = {to_email!r}", flush=True)

        if not mail_user:
            print("[EMAIL] No MAIL_USERNAME — printing OTP to terminal (dev fallback)", flush=True)
            current_app.logger.warning(
                "[BREVO-NOT-CONFIGURED] OTP for %s: %s", to_email, otp
            )
            return True

        try:
            from flask_mail import Message
            msg = Message(
                subject=subject,
                recipients=[to_email],
                body=body,
                sender=mail_sender,
            )
            cls._mail.send(msg)
            print(f"[EMAIL] Sent successfully to {to_email}", flush=True)
            return True
        except Exception as exc:
            print(f"[EMAIL] FAILED: {exc}", flush=True)
            current_app.logger.error("Failed to send OTP email to %s: %s", to_email, exc)
            return False
