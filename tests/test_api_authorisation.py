"""API authorisation tests.

Covers:
  - /api/audit is locked to admins only (was previously open to all).
  - /api/stats is role-aware:
      * whistleblower -> own-reports counts only
      * report_admin -> system-wide + per-investigator load
      * system_admin -> user counts + role distribution
  - /api/reports returns only the caller's visible reports.
  - /api/reports/<id> does NOT leak decrypted_data.
"""
import os
import uuid

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import Report, User  # noqa: E402
from app.services.crypto_service import crypto_service  # noqa: E402


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def make_user(email, role):
    u = User(email=email, first_name='Test', last_name='User', role=role)
    u.set_password('Password123!')
    db.session.add(u)
    db.session.commit()
    db.session.refresh(u)
    db.session.expunge(u)
    return u


def make_report(submitter, status='Received'):
    r = Report(
        reference_number=f'SIT-{uuid.uuid4().hex[:10].upper()}',
        submitter_hash=crypto_service.generate_user_hash(submitter.id),
        title='[Encrypted Report]',
        description='[Encrypted]',
        category='other',
        status=status,
        user_id=submitter.id,
    )
    db.session.add(r)
    db.session.commit()
    db.session.refresh(r)
    db.session.expunge(r)
    return r


def login(client, user):
    with client.session_transaction() as s:
        s['_user_id'] = str(user.id)
        s['_fresh'] = True


# ---------------------------------------------------------------------------
# /api/audit lockdown
# ---------------------------------------------------------------------------

def test_api_audit_denied_for_whistleblower(app, client):
    wb = make_user('wb_audit@sit.singaporetech.edu.sg', 'whistleblower')
    login(client, wb)
    resp = client.get('/api/audit')
    assert resp.status_code == 403


def test_api_audit_denied_for_investigator(app, client):
    inv = make_user('inv_audit@sit.singaporetech.edu.sg', 'investigator')
    login(client, inv)
    resp = client.get('/api/audit')
    assert resp.status_code == 403


def test_api_audit_allowed_for_report_admin(app, client):
    ra = make_user('ra_audit@sit.singaporetech.edu.sg', 'report_admin')
    login(client, ra)
    resp = client.get('/api/audit')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'logs' in data
    # And only report-scoped actions are returned
    with app.app_context():
        from app.securityfeature.audit import AuditService
        for entry in data['logs']:
            assert entry['action'] in AuditService.REPORT_ACTIONS


def test_api_audit_allowed_for_system_admin(app, client):
    sa = make_user('sa_audit@sit.singaporetech.edu.sg', 'system_admin')
    login(client, sa)
    resp = client.get('/api/audit')
    assert resp.status_code == 200
    with app.app_context():
        from app.securityfeature.audit import AuditService
        data = resp.get_json()
        for entry in data['logs']:
            assert entry['action'] in AuditService.SYSTEM_ACTIONS


def test_api_audit_omits_sensitive_fields(app, client):
    """The JSON endpoint must NOT expose ip_address, acting_user_id, details."""
    ra = make_user('ra_audit2@sit.singaporetech.edu.sg', 'report_admin')
    login(client, ra)
    resp = client.get('/api/audit')
    data = resp.get_json()
    for entry in data['logs']:
        assert 'ip_address' not in entry
        assert 'acting_user_id' not in entry
        assert 'details' not in entry
        assert 'target_id' not in entry


# ---------------------------------------------------------------------------
# /api/stats role-aware behaviour
# ---------------------------------------------------------------------------

def test_api_stats_whistleblower_sees_own_counts_only(app, client):
    alice = make_user('alice_stats@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob_stats@sit.singaporetech.edu.sg', 'whistleblower')
    # Alice has 3 reports, Bob has 2
    make_report(alice, status='Received')
    make_report(alice, status='Investigating')
    make_report(alice, status='Closed')
    make_report(bob, status='Received')
    make_report(bob, status='Triaged')

    login(client, alice)
    resp = client.get('/api/stats')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['scope'] == 'own_reports'
    assert data['total'] == 3                  # Alice's reports only
    assert data['received'] == 1
    assert data['investigating'] == 1
    assert data['closed'] == 1
    assert data['triaged'] == 0                # Bob's, not Alice's


def test_api_stats_report_admin_sees_system_wide(app, client):
    alice = make_user('alice2@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob2@sit.singaporetech.edu.sg', 'whistleblower')
    inv = make_user('inv_stats@sit.singaporetech.edu.sg', 'investigator')
    ra = make_user('ra_stats@sit.singaporetech.edu.sg', 'report_admin')
    make_report(alice, status='Received')
    make_report(bob, status='Investigating')
    # Assign one to the investigator
    r = Report.query.filter_by(status='Investigating').first()
    r.investigator_id = inv.id
    db.session.commit()

    login(client, ra)
    resp = client.get('/api/stats')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['scope'] == 'system_reports'
    assert data['by_status']['total'] == 2
    assert data['by_status']['received'] == 1
    assert data['by_status']['investigating'] == 1
    # Investigator load shows the one open case
    assert any(il['open_cases'] == 1 for il in data['investigator_load'])


def test_api_stats_system_admin_sees_user_counts(app, client):
    for i in range(3):
        make_user(f'wb{i}_stats@sit.singaporetech.edu.sg', 'whistleblower')
    make_user('inv2_stats@sit.singaporetech.edu.sg', 'investigator')
    make_user('ra2_stats@sit.singaporetech.edu.sg', 'report_admin')
    sa = make_user('sa2_stats@sit.singaporetech.edu.sg', 'system_admin')

    login(client, sa)
    resp = client.get('/api/stats')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['scope'] == 'system_users'
    assert data['total_users'] == 6   # 3 wb + 1 inv + 1 ra + 1 sa
    assert data['by_role']['whistleblower'] == 3
    assert data['by_role']['investigator'] == 1
    assert data['by_role']['report_admin'] == 1
    assert data['by_role']['system_admin'] == 1


# ---------------------------------------------------------------------------
# /api/reports visibility
# ---------------------------------------------------------------------------

def test_api_reports_whistleblower_sees_own_only(app, client):
    alice = make_user('alice3@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob3@sit.singaporetech.edu.sg', 'whistleblower')
    make_report(alice)
    make_report(alice)
    make_report(bob)

    login(client, alice)
    resp = client.get('/api/reports')
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data['reports']) == 2     # Alice's only


def test_api_reports_does_not_leak_decrypted_title(app, client):
    """The /api/reports/<id> endpoint must NOT return decrypted_data -- only
    the encrypted placeholder column. (Decryption is server-side render only.)"""
    alice = make_user('alice4@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(alice)

    login(client, alice)
    resp = client.get(f'/api/reports/{report.id}')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'decrypted_data' not in data
    assert data['title'] == '[Encrypted Report]'   # placeholder only
    assert data['description'] == '[Encrypted]'


def test_api_reports_idor_whistleblower_cannot_access_others(app, client):
    alice = make_user('alice5@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob5@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(alice)

    login(client, bob)
    resp = client.get(f'/api/reports/{report.id}')
    assert resp.status_code == 403
