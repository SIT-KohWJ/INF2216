"""Sanitiser for audit-log `details` strings.

Goal: keep report content / decrypted values / secrets OUT of the audit log so
that even an admin with full DB read access cannot deanonymise a reporter or
recover sensitive data.

Two layers of defence:

  1. Pattern-based redaction  -- emails, SIT reference numbers, UUIDs are
     replaced with `[REDACTED:<category>]` before the entry is persisted.

  2. Hard denylist            -- if `details` contains any forbidden keyword
     (otp, password, decrypted, plaintext, token_value, _sid, csrf_token, ...)
     the whole entry is replaced with a placeholder and the original is
     dropped. This is the loud, testable backstop against developer mistakes:
     a `details=f'OTP {otp} sent'` will not silently leak the OTP, it will
     produce an obviously-broken log entry that a test can catch.

The denylist is intentionally aggressive. A legitimate use that needs one of
those words should rephrase (e.g. "credential" instead of "password") or, if
that's impossible, pass `allow_sensitive=True` to `AuditService.log()` after a
code review.
"""
import re


# Email addresses (loose pattern, catches most real-world forms).
_EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')

# SIT reference numbers look like `SIT-AB12CD34EF` (10 hex chars, uppercase).
_REF_RE = re.compile(r'\bSIT-[A-F0-9]{10}\b')

# Canonical UUID v4 (the form the app generates for every PK).
_UUID_RE = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
)

# Anything that looks like a Bearer / JWT token.
_TOKEN_RE = re.compile(r'\bBearer\s+[A-Za-z0-9._\-]+\b', re.IGNORECASE)
_JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')


# Patterns applied in order. Each replaces its match with a category tag so
# an auditor can still see "an email was here" without learning the address.
_REDACT_PATTERNS = [
    (_JWT_RE,    '[REDACTED:jwt]'),
    (_TOKEN_RE,  '[REDACTED:bearer]'),
    (_EMAIL_RE,  '[REDACTED:email]'),
    (_REF_RE,    '[REDACTED:reference]'),
    (_UUID_RE,   '[REDACTED:uuid]'),
]


# Substrings whose mere presence in `details` means we made a mistake -- the
# entry is dropped and replaced with a placeholder. Lower-cased for matching.
_FORBIDDEN_SUBSTRINGS = (
    'decrypted',
    'plaintext',
    'password',
    'otp',
    'token_value',
    'reset_token',
    'session_id',
    '_sid',
    'csrf_token',
    'secret_key',
    'encryption_key',
    'hmac_key',
    'private_key',
    'bcrypt',
)


class Sanitizer:
    """Redact / block sensitive content from audit-log `details` strings."""

    @staticmethod
    def redact(text, *, allow_sensitive: bool = False):
        """Return a sanitised version of *text*.

        - If *allow_sensitive* is True, only pattern-based redaction runs.
          Use this only after explicit review (e.g. logging that a password
          *policy* was violated, without including the password itself).
        - Otherwise, the denylist runs first and may block the entire entry.
        """
        if text is None:
            return None
        if not isinstance(text, str):
            # Coerce non-strings (rare: a developer passing an int) so the
            # redaction regexes still work.
            text = str(text)

        if not allow_sensitive:
            low = text.lower()
            for bad in _FORBIDDEN_SUBSTRINGS:
                if bad in low:
                    # Fail safe: the whole entry is suspicious, drop it.
                    return (
                        f'[BLOCKED:details contained forbidden keyword '
                        f'"{bad}"; original redacted]'
                    )

        for pattern, repl in _REDACT_PATTERNS:
            text = pattern.sub(repl, text)
        return text

    @staticmethod
    def is_blocked(text) -> bool:
        """True iff *text* would be blocked (rather than just redacted)."""
        if not text:
            return False
        low = text.lower() if isinstance(text, str) else str(text).lower()
        return any(bad in low for bad in _FORBIDDEN_SUBSTRINGS)
