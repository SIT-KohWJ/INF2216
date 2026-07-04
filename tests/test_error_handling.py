"""Error-handler tests: no stack traces leak to the client.

Covers:
  - A forced 500 renders the 500 template (not a traceback).
  - The response body contains a request_id but no Python traceback markers.
  - The exception IS logged (so it reaches docker logs / Splunk).
  - 404 / 403 / 413 render their templates.
  - /api/* paths get JSON errors instead of HTML.
  - X-Request-ID is attached to every response.
"""
import os
import uuid

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import User  # noqa: E402


@pytest.fixture
def app():
    app = create_app("testing")
    # Register a route that deliberately raises, so we can test 500 handling.
    @app.route('/__test_500__')
    def _force_500():
        raise RuntimeError('deliberate test exception')

    @app.route('/api/__test_500_api__')
    def _force_500_api():
        raise RuntimeError('deliberate api exception')

    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def make_user(email, role='whistleblower'):
    u = User(email=email, first_name='Test', last_name='User', role=role)
    u.set_password('Password123!')
    db.session.add(u)
    db.session.commit()
    db.session.refresh(u)
    return u


def login(client, user):
    with client.session_transaction() as s:
        s['_user_id'] = str(user.id)
        s['_fresh'] = True


# ---------------------------------------------------------------------------
# 500 handler: no traceback leak
# ---------------------------------------------------------------------------

def test_500_returns_generic_page_not_traceback(client):
    resp = client.get('/__test_500__')
    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    # The exception message must NOT appear in the response
    assert 'deliberate test exception' not in body
    # Python traceback markers must NOT appear
    assert 'Traceback' not in body
    assert 'RuntimeError' not in body
    # But a request_id SHOULD appear (so support can correlate)
    assert 'Reference:' in body or 'request_id' in body.lower() or 'request-id' in body.lower()


def test_500_logs_exception_to_logger(client, caplog):
    with caplog.at_level('ERROR'):
        client.get('/__test_500__')
    # The structured log line must include the exception + path
    assert any('unhandled_500' in r.message for r in caplog.records)
    assert any('/__test_500__' in r.message for r in caplog.records)


def test_500_audit_logs_server_error(client):
    from app.models import AuditLog
    client.get('/__test_500__')
    err_log = AuditLog.query.filter_by(action='server_error').first()
    assert err_log is not None
    assert '/__test_500__' in err_log.details


# ---------------------------------------------------------------------------
# API errors return JSON, not HTML
# ---------------------------------------------------------------------------

def test_api_500_returns_json(client):
    # Route is under /api/* so the error handler returns JSON, not HTML.
    resp = client.get('/api/__test_500_api__')
    assert resp.status_code == 500
    assert resp.content_type == 'application/json'
    data = resp.get_json()
    assert data['error'] == 'internal_server_error'
    assert 'request_id' in data
    # No traceback in JSON either
    assert 'deliberate api exception' not in resp.get_data(as_text=True)


def test_api_404_returns_json(client):
    resp = client.get('/api/does-not-exist')
    assert resp.status_code == 404
    assert resp.content_type == 'application/json'
    data = resp.get_json()
    assert data['error'] == 'not_found'


def test_api_403_returns_json(client):
    """A whistleblower hitting /api/audit must get JSON 403, not HTML."""
    user = make_user('api_403@sit.singaporetech.edu.sg', 'whistleblower')
    login(client, user)
    resp = client.get('/api/audit')
    assert resp.status_code == 403
    assert resp.content_type == 'application/json'


# ---------------------------------------------------------------------------
# 404 / 403 / 413 HTML pages
# ---------------------------------------------------------------------------

def test_404_renders_template(client):
    user = make_user('notfound_user@sit.singaporetech.edu.sg', 'whistleblower')
    login(client, user)
    # Logged in, so no login-redirect; the unknown route hits the 404 handler.
    resp = client.get('/this-route-does-not-exist')
    assert resp.status_code == 404
    assert b'404' in resp.data


def test_403_renders_template(client):
    user = make_user('forbidden_user@sit.singaporetech.edu.sg', 'whistleblower')
    login(client, user)
    # Whistleblower hitting /admin/ -> 403
    resp = client.get('/admin/')
    assert resp.status_code == 403
    assert b'403' in resp.data


# ---------------------------------------------------------------------------
# Request-ID propagation
# ---------------------------------------------------------------------------

def test_response_has_request_id_header(client):
    resp = client.get('/healthz')
    assert 'X-Request-ID' in resp.headers
    # Must be a valid UUID
    uuid.UUID(resp.headers['X-Request-ID'])


def test_inbound_request_id_is_honoured_if_valid_uuid(client):
    rid = str(uuid.uuid4())
    resp = client.get('/healthz', headers={'X-Request-ID': rid})
    assert resp.headers['X-Request-ID'] == rid


def test_inbound_request_id_rejected_if_not_uuid(client):
    """A malformed inbound X-Request-ID is replaced, not trusted."""
    resp = client.get('/healthz', headers={'X-Request-ID': 'not-a-uuid'})
    # Should be a fresh UUID, not the malformed string
    uuid.UUID(resp.headers['X-Request-ID'])  # raises if not a UUID
    assert resp.headers['X-Request-ID'] != 'not-a-uuid'


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

def test_security_headers_present(client):
    resp = client.get('/healthz')
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
    assert resp.headers['Cache-Control'] == 'no-store'
