"""Sanitiser tests: emails, refs, UUIDs are redacted; forbidden keywords block."""
import os
import uuid

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app  # noqa: E402
from app.securityfeature.sanitizers import Sanitizer  # noqa: E402
from app.securityfeature.audit import AuditService  # noqa: E402


@pytest.fixture
def app_ctx():
    app = create_app("testing")
    with app.app_context():
        yield app


# ---------------------------------------------------------------------------
# Pattern-based redaction
# ---------------------------------------------------------------------------

def test_redacts_email(app_ctx):
    out = Sanitizer.redact('User alice@sit.singaporetech.edu.sg logged in')
    assert 'alice@sit.singaporetech.edu.sg' not in out
    assert '[REDACTED:email]' in out


def test_redacts_reference_number(app_ctx):
    out = Sanitizer.redact('Report SIT-AB12CD34EF was submitted')
    assert 'SIT-AB12CD34EF' not in out
    assert '[REDACTED:reference]' in out


def test_redacts_uuid(app_ctx):
    u = str(uuid.uuid4())
    out = Sanitizer.redact(f'Acting on user {u}')
    assert u not in out
    assert '[REDACTED:uuid]' in out


def test_redacts_jwt(app_ctx):
    jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signaturepart'
    out = Sanitizer.redact(f'Token: {jwt}')
    assert jwt not in out
    assert '[REDACTED:jwt]' in out


def test_redacts_bearer_token(app_ctx):
    out = Sanitizer.redact('Authorization: Bearer abc123def456')
    assert 'abc123def456' not in out
    assert '[REDACTED:bearer]' in out


def test_redacts_multiple_patterns_in_one_string(app_ctx):
    u = str(uuid.uuid4())
    out = Sanitizer.redact(
        f'User {u} email alice@sit.singaporetech.edu.sg ref SIT-AB12CD34EF'
    )
    assert u not in out
    assert 'alice@sit.singaporetech.edu.sg' not in out
    assert 'SIT-AB12CD34EF' not in out
    assert '[REDACTED:uuid]' in out
    assert '[REDACTED:email]' in out
    assert '[REDACTED:reference]' in out


def test_none_passes_through(app_ctx):
    assert Sanitizer.redact(None) is None


def test_non_string_coerced(app_ctx):
    out = Sanitizer.redact(12345)
    assert out == '12345'


# ---------------------------------------------------------------------------
# Forbidden keyword denylist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('keyword', [
    'password', 'otp', 'decrypted', 'plaintext', 'token_value',
    'session_id', '_sid', 'csrf_token', 'secret_key',
    'encryption_key', 'hmac_key', 'private_key', 'bcrypt',
])
def test_forbidden_keyword_blocks_entry(app_ctx, keyword):
    text = f'User logged in with {keyword}=some_value'
    out = Sanitizer.redact(text)
    assert out.startswith('[BLOCKED:')
    assert keyword in out  # the block message names the keyword
    # The original sensitive value must NOT appear
    assert 'some_value' not in out


def test_forbidden_keyword_case_insensitive(app_ctx):
    out = Sanitizer.redact('User PASSWORD=hunter2')
    assert out.startswith('[BLOCKED:')
    assert 'hunter2' not in out


def test_allow_sensitive_bypasses_denylist(app_ctx):
    """allow_sensitive=True skips the denylist (pattern redaction still runs)."""
    out = Sanitizer.redact('Password policy violation: too short', allow_sensitive=True)
    assert out == 'Password policy violation: too short'  # no patterns to redact


def test_allow_sensitive_still_redacts_patterns(app_ctx):
    out = Sanitizer.redact(
        'Password reset for alice@sit.singaporetech.edu.sg',
        allow_sensitive=True,
    )
    assert 'alice@sit.singaporetech.edu.sg' not in out
    assert '[REDACTED:email]' in out


def test_is_blocked_detects_forbidden(app_ctx):
    assert Sanitizer.is_blocked('OTP=123456')
    assert Sanitizer.is_blocked('the password is hunter2')
    assert not Sanitizer.is_blocked('User logged in')
    assert not Sanitizer.is_blocked(None)


# ---------------------------------------------------------------------------
# AuditService.log end-to-end sanitisation
# ---------------------------------------------------------------------------

def test_audit_log_redacts_email_in_details(app_ctx):
    from app.models import AuditLog
    AuditService.log(
        action='user_login',
        acting_role='anonymous',
        details='Login from alice@sit.singaporetech.edu.sg',
    )
    log = AuditLog.query.order_by(AuditLog.timestamp.desc()).first()
    assert 'alice@sit.singaporetech.edu.sg' not in log.details
    assert '[REDACTED:email]' in log.details


def test_audit_log_blocks_otp_in_details(app_ctx):
    from app.models import AuditLog
    AuditService.log(
        action='otp_verified',
        acting_role='anonymous',
        details='OTP=123456 verified for user',
    )
    log = AuditLog.query.order_by(AuditLog.timestamp.desc()).first()
    assert '123456' not in log.details
    assert log.details.startswith('[BLOCKED:')


def test_audit_log_unknown_action_raises(app_ctx):
    with pytest.raises(ValueError, match='unknown action'):
        AuditService.log(action='totally_made_up', acting_role='anonymous')


def test_audit_log_canonical_action_set_has_no_typos(app_ctx):
    """Every action referenced by REPORT_ACTIONS / SYSTEM_ACTIONS must be in ACTIONS."""
    for action in AuditService.REPORT_ACTIONS | AuditService.SYSTEM_ACTIONS:
        assert action in AuditService.ACTIONS, (
            f'{action} is in REPORT/SYSTEM_ACTIONS but not in ACTIONS -- '
            f'it would never be writable.'
        )
