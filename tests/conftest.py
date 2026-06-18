import os
import re

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost:5433/test")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app  # noqa: E402


@pytest.fixture
def app():
    app = create_app("development")
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def csrf_token(client):
    def _csrf_token(path: str) -> str:
        response = client.get(path)
        assert response.status_code == 200

        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            response.get_data(as_text=True),
        )
        assert match is not None
        return match.group(1)

    return _csrf_token
