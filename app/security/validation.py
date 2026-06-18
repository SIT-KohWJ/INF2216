"""ValidationService - input sanitisation + file validation.
Requirements B2 (XSS), B3 / B7 (file upload safety).
Lead: (Input safety story)
"""
import bleach
from email_validator import EmailNotValidError, validate_email


class ValidationService:
    SIT_EMAIL_DOMAIN = "sit.singaporetech.edu.sg"
    FULL_NAME_MAX_LENGTH = 255

    @staticmethod
    def sanitise_html(raw: str) -> str:
        """Strip/escape user input with bleach before storage. Output is also
        auto-escaped by Jinja2 on render (defence in depth)."""
        return bleach.clean(raw or "", tags=[], attributes={}, strip=True)

    @staticmethod
    def normalise_email(email: str) -> str:
        return (email or "").strip().lower()

    @staticmethod
    def validate_sit_email(email: str) -> str:
        normalised_email = ValidationService.normalise_email(email)
        if not normalised_email:
            raise ValueError("Enter your SIT email address.")

        try:
            validated = validate_email(
                normalised_email,
                check_deliverability=False,
            )
        except EmailNotValidError as exc:
            raise ValueError("Enter a valid email address.") from exc

        validated_email = validated.normalized.lower()
        if not validated_email.endswith(f"@{ValidationService.SIT_EMAIL_DOMAIN}"):
            raise ValueError("Use your @sit.singaporetech.edu.sg email address.")
        return validated_email

    @staticmethod
    def validate_full_name(full_name: str) -> str:
        cleaned_name = ValidationService.sanitise_html(full_name)
        cleaned_name = " ".join(cleaned_name.split())

        if not cleaned_name:
            raise ValueError("Enter your full name.")
        if len(cleaned_name) > ValidationService.FULL_NAME_MAX_LENGTH:
            raise ValueError("Full name must be 255 characters or fewer.")

        return cleaned_name

    @staticmethod
    def validate_upload(file_storage) -> None:
        """Reject uploads that fail magic-byte MIME check, exceed 10 MB, or are
        not in the allowlist (PDF, DOCX, PNG, JPG). Raise on failure."""
        raise NotImplementedError("B3/B7: implement magic-byte + size validation")
