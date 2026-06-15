"""ValidationService - input sanitisation + file validation.
Requirements B2 (XSS), B3 / B7 (file upload safety).
Lead: (Input safety story)
"""


class ValidationService:
    @staticmethod
    def sanitise_html(raw: str) -> str:
        """Strip/escape user input with bleach before storage. Output is also
        auto-escaped by Jinja2 on render (defence in depth)."""
        raise NotImplementedError("B2: implement bleach sanitisation")

    @staticmethod
    def validate_upload(file_storage) -> None:
        """Reject uploads that fail magic-byte MIME check, exceed 10 MB, or are
        not in the allowlist (PDF, DOCX, PNG, JPG). Raise on failure."""
        raise NotImplementedError("B3/B7: implement magic-byte + size validation")
