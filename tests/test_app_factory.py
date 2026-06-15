"""Smoke test: the factory builds and the health endpoint responds.
Run: pytest  (needs the env vars set, or a .env loaded)."""
import os
import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost:5433/test")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app  # noqa: E402


@pytest.fixture
def client():
    app = create_app("development")
    app.config.update(TESTING=True)
    return app.test_client()


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
