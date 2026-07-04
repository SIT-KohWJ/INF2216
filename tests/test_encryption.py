"""Unit tests for the crypto service (A2 HMAC anonymity, A3 AES-256-GCM).

Run: pytest. The "testing" config uses in-memory SQLite, so no Postgres needed.
"""
import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app  # noqa: E402
from app.services.crypto_service import crypto_service  # noqa: E402


@pytest.fixture
def app_ctx():
    app = create_app("testing")
    with app.app_context():
        yield app


def test_round_trip(app_ctx):
    plaintext = "Sensitive report detail #42 — ünïcödé ✓"
    ct = crypto_service.encrypt_data(plaintext)
    assert isinstance(ct, str)  # base64 string
    assert crypto_service.decrypt_data(ct) == plaintext


def test_nonce_is_fresh_per_message(app_ctx):
    a = crypto_service.encrypt_data("same plaintext")
    b = crypto_service.encrypt_data("same plaintext")
    # Different nonce => different ciphertext, but both decrypt to the same value.
    assert a != b
    assert crypto_service.decrypt_data(a) == crypto_service.decrypt_data(b) == "same plaintext"


def test_tampering_is_detected(app_ctx):
    import base64

    ct = bytearray(base64.b64decode(crypto_service.encrypt_data("integrity matters")))
    ct[-1] ^= 0x01  # flip a bit in the GCM tag/ciphertext region
    tampered = base64.b64encode(bytes(ct)).decode()
    # decrypt_data swallows the auth-tag failure and returns None.
    assert crypto_service.decrypt_data(tampered) is None


def test_user_hash_is_deterministic_and_verifiable(app_ctx):
    user_id = "abc-123"
    h1 = crypto_service.generate_user_hash(user_id)
    h2 = crypto_service.generate_user_hash(user_id)
    assert h1 == h2  # stable HMAC for the same user
    assert crypto_service.verify_user_hash(user_id, h1)
    assert not crypto_service.verify_user_hash("someone-else", h1)
