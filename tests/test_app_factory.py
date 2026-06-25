"""Smoke test: the app factory builds and the health endpoint responds.

Run: pytest. The "testing" config uses an in-memory SQLite DB and disables
CSRF, so these unit tests don't need a running Postgres.
"""
import os

import pytest

# Throwaway values so the factory boots without a real .env. The crypto service
# derives a stable key from whatever string it's given, so plain text is fine.
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app  # noqa: E402


@pytest.fixture
def client():
    app = create_app("testing")  # in-memory SQLite, CSRF off
    return app.test_client()


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_login_page_renders(client):
    resp = client.get("/auth/login")
    assert resp.status_code == 200
