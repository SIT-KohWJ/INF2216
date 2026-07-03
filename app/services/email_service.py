"""Email delivery via Brevo SMTP (Flask-Mail)."""
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
        mail_sender = current_app.config.get('MAIL_DEFAULT_SENDER')

        if not mail_user:
            current_app.logger.error(
                "MAIL_USERNAME is not configured — OTP email could not be sent"
            )
            return False

        try:
            from flask_mail import Message
            msg = Message(
                subject=subject,
                recipients=[to_email],
                body=body,
                sender=mail_sender,
            )
            cls._mail.send(msg)
            return True
        except Exception as exc:
            current_app.logger.error("Failed to send OTP email: %s", exc)
            return False

    @classmethod
    def send_registration_otp_email(cls, to_email: str, otp: str, first_name: str = '') -> bool:
        expiry_seconds = current_app.config.get('OTP_EXPIRY_SECONDS', 30)
        subject = "SITinform — Verify Your Email to Complete Registration"
        body = (
            f"Hello {first_name or 'there'},\n\n"
            f"Your one-time password (OTP) to verify your email and complete your "
            f"SITinform registration is:\n\n"
            f"    {otp}\n\n"
            f"This OTP is valid for {expiry_seconds} seconds and can be used only once.\n\n"
            f"If you did not request to register for SITinform, please ignore this email.\n\n"
            f"SITinform Security Team\n"
            f"Singapore Institute of Technology"
        )

        mail_user = current_app.config.get('MAIL_USERNAME')
        mail_sender = current_app.config.get('MAIL_DEFAULT_SENDER')

        if not mail_user:
            current_app.logger.error(
                "MAIL_USERNAME is not configured — registration OTP email could not be sent"
            )
            return False

        try:
            from flask_mail import Message
            msg = Message(
                subject=subject,
                recipients=[to_email],
                body=body,
                sender=mail_sender,
            )
            cls._mail.send(msg)
            return True
        except Exception as exc:
            current_app.logger.error("Failed to send registration OTP email: %s", exc)
            return False
