"""Tests for app.config.validate_production_secrets() (SEC-002).

Each test uses monkeypatch.setenv/delenv so environment changes are
automatically reverted after the test — never touches the real process env.
"""
import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app.config import validate_production_secrets  # noqa: E402


def test_raises_when_secret_key_unset(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("HMAC_SECRET_KEY", "h" * 32)
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", "y" * 32)
    monkeypatch.delenv("DISABLE_STAFF_OTP", raising=False)
    with pytest.raises(RuntimeError):
        validate_production_secrets()


def test_raises_when_hmac_secret_key_unset(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 32)
    monkeypatch.delenv("HMAC_SECRET_KEY", raising=False)
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", "y" * 32)
    monkeypatch.delenv("DISABLE_STAFF_OTP", raising=False)
    with pytest.raises(RuntimeError):
        validate_production_secrets()


def test_raises_when_no_encryption_key_set(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 32)
    monkeypatch.setenv("HMAC_SECRET_KEY", "h" * 32)
    monkeypatch.delenv("FIELD_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("DISABLE_STAFF_OTP", raising=False)
    with pytest.raises(RuntimeError):
        validate_production_secrets()


def test_raises_when_secret_key_is_dev_default(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "dev-secret-key-change-in-production")
    monkeypatch.setenv("HMAC_SECRET_KEY", "h" * 32)
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", "y" * 32)
    monkeypatch.delenv("DISABLE_STAFF_OTP", raising=False)
    with pytest.raises(RuntimeError):
        validate_production_secrets()


def test_does_not_raise_when_all_required_secrets_set(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 32)
    monkeypatch.setenv("HMAC_SECRET_KEY", "h" * 32)
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", "y" * 32)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("DISABLE_STAFF_OTP", raising=False)
    validate_production_secrets()  # should not raise
