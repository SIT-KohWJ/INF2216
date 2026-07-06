"""Access-control matrix + IDOR tests.

Covers:
  - Every (role, action) pair in the permission matrix is correctly allowed/denied.
  - IDOR: whistleblower A cannot access whistleblower B's report UUID.
  - IDOR: investigator cannot access a report they are not assigned to.
  - IDOR: system_admin cannot access report content (their job is user mgmt).
  - Role escalation: a report_admin cannot grant system_admin (equal-or-higher).
  - Role whitelist: forging a POST with role='superuser' is rejected.
  - UUID validation: non-UUID report_id in URL returns 404 immediately.
  - @require_permission injects the fetched resource as `resource=` kwarg.
"""
import os
import uuid

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import Report, User  # noqa: E402
from app.securityfeature import AccessControlService  # noqa: E402
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(email, role, first='Test', last='User'):
    u = User(email=email, first_name=first, last_name=last, role=role)
    u.set_password('Password123!')
    db.session.add(u)
    db.session.commit()
    db.session.refresh(u)
    db.session.expunge(u)
    return u


def make_report(submitter, investigator=None, status='Received'):
    r = Report(
        reference_number=f'SIT-{uuid.uuid4().hex[:10].upper()}',
        submitter_hash=crypto_service.generate_user_hash(submitter.id),
        title='[Encrypted Report]',
        description='[Encrypted]',
        category='other',
        status=status,
        user_id=submitter.id,
        investigator_id=investigator.id if investigator else None,
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
        # Required by the strict check_session_revoked hook: without these the
        # session is treated as unauthenticated and the request 302s to /auth/login
        # before the route handler (and its @require_permission decorator) runs.
        s['_sid'] = 'test-sid'
        from datetime import datetime
        s['_session_created_at'] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Permission matrix: every role vs every action
# ---------------------------------------------------------------------------

def test_permission_matrix_complete(app):
    """Sanity: every role appears in the matrix, every action maps to a set."""
    for role in ['whistleblower', 'investigator', 'report_admin', 'system_admin']:
        assert role in AccessControlService.ROLE_HIERARCHY
    for action, allowed in AccessControlService.PERMISSIONS.items():
        assert isinstance(allowed, set) and len(allowed) > 0
        for r in allowed:
            assert r in AccessControlService.ROLE_HIERARCHY


def test_can_whistleblower_cannot_triage(app):
    wb = make_user('wb1@sit.singaporetech.edu.sg', 'whistleblower')
    assert not AccessControlService.can(wb, 'report.triage')
    assert not AccessControlService.can(wb, 'admin.manage_reports')
    assert AccessControlService.can(wb, 'report.create')


def test_can_investigator_cannot_triage_or_manage_users(app):
    inv = make_user('inv1@sit.singaporetech.edu.sg', 'investigator')
    assert not AccessControlService.can(inv, 'report.triage')
    assert not AccessControlService.can(inv, 'admin.manage_users')
    assert AccessControlService.can(inv, 'report.add_note')


def test_can_report_admin_cannot_manage_users(app):
    ra = make_user('ra1@sit.singaporetech.edu.sg', 'report_admin')
    assert AccessControlService.can(ra, 'admin.manage_reports')
    assert not AccessControlService.can(ra, 'admin.manage_users')
    assert not AccessControlService.can(ra, 'admin.change_role')


def test_can_system_admin_cannot_manage_reports(app):
    sa = make_user('sa1@sit.singaporetech.edu.sg', 'system_admin')
    assert AccessControlService.can(sa, 'admin.manage_users')
    assert not AccessControlService.can(sa, 'admin.manage_reports')
    assert not AccessControlService.can(sa, 'report.triage')


def test_unknown_action_fails_closed(app):
    wb = make_user('wb2@sit.singaporetech.edu.sg', 'whistleblower')
    assert not AccessControlService.can(wb, 'report.totally_made_up_action')


def test_inactive_user_denied_everything(app):
    wb = make_user('wb3@sit.singaporetech.edu.sg', 'whistleblower')
    # make_user() expunges the instance, so we must re-attach before mutating.
    wb = User.query.filter_by(email='wb3@sit.singaporetech.edu.sg').first()
    wb.is_active = False
    db.session.commit()
    db.session.expunge(wb)
    assert not AccessControlService.can(wb, 'report.create')
    assert not AccessControlService.can(wb, 'report.view')


# ---------------------------------------------------------------------------
# IDOR: report ownership checks
# ---------------------------------------------------------------------------

def test_idor_whistleblower_cannot_access_other_whistleblowers_report(app, client):
    alice = make_user('alice@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(alice)

    login(client, bob)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 403


def test_idor_investigator_cannot_access_unassigned_report(app, client):
    wb = make_user('wb4@sit.singaporetech.edu.sg', 'whistleblower')
    inv_assigned = make_user('inv_a@sit.singaporetech.edu.sg', 'investigator')
    inv_outsider = make_user('inv_b@sit.singaporetech.edu.sg', 'investigator')
    report = make_report(wb, investigator=inv_assigned, status='Investigating')

    login(client, inv_outsider)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 403


def test_idor_whistleblower_can_access_own_report(app, client):
    alice = make_user('alice2@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(alice)

    login(client, alice)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 200


def test_idor_investigator_can_access_assigned_report(app, client):
    wb = make_user('wb5@sit.singaporetech.edu.sg', 'whistleblower')
    inv = make_user('inv_c@sit.singaporetech.edu.sg', 'investigator')
    report = make_report(wb, investigator=inv, status='Investigating')

    login(client, inv)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 200


def test_idor_system_admin_cannot_access_report_content(app, client):
    """System admin's job is user management, not case content -- they should
    NOT be able to view a report even though they're 'admin'."""
    wb = make_user('wb6@sit.singaporetech.edu.sg', 'whistleblower')
    sa = make_user('sa2@sit.singaporetech.edu.sg', 'system_admin')
    report = make_report(wb)

    login(client, sa)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# UUID validation: probes return 404, not 500
# ---------------------------------------------------------------------------

def test_non_uuid_report_id_returns_404(app, client):
    wb = make_user('wb7@sit.singaporetech.edu.sg', 'whistleblower')
    login(client, wb)
    resp = client.get('/not-a-uuid')
    assert resp.status_code == 404


def test_non_uuid_report_id_in_admin_returns_404(app, client):
    sa = make_user('sa3@sit.singaporetech.edu.sg', 'system_admin')
    login(client, sa)
    # /admin/users/<user_id>/deactivate -- but with a forged UUID
    resp = client.post('/admin/users/not-a-uuid/deactivate')
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Role escalation guards
# ---------------------------------------------------------------------------

def test_report_admin_cannot_access_change_role_endpoint(app, client):
    """A report_admin cannot even reach the change_role endpoint -- it's
    system_admin-only. This is stricter than the old inline check, which
    let them through and then blocked escalation in the service layer."""
    ra = make_user('ra2@sit.singaporetech.edu.sg', 'report_admin')
    target = make_user('target1@sit.singaporetech.edu.sg', 'whistleblower')

    login(client, ra)
    # Direct can_assign_role check -- still False for equal-or-higher roles
    assert not AccessControlService.can_assign_role(ra, 'system_admin')
    assert not AccessControlService.can_assign_role(ra, 'report_admin')  # equal
    assert AccessControlService.can_assign_role(ra, 'investigator')
    assert AccessControlService.can_assign_role(ra, 'whistleblower')

    # End-to-end: the endpoint itself is 403 for report_admin
    resp = client.post(
        f'/admin/users/{target.id}/change_role',
        data={'role': 'system_admin', 'submit': 'Change Role'},
    )
    assert resp.status_code == 403
    with app.app_context():
        assert User.query.get(target.id).role == 'whistleblower'  # unchanged


def test_system_admin_cannot_grant_system_admin_role(app, client):
    """Even a system_admin cannot grant system_admin (equal-or-higher) --
    the escalation guard fires inside the route body."""
    sa = make_user('sa_esc@sit.singaporetech.edu.sg', 'system_admin')
    target = make_user('target_esc@sit.singaporetech.edu.sg', 'whistleblower')

    login(client, sa)
    # The system_admin CAN reach the endpoint (permission matrix allows it)...
    resp = client.post(
        f'/admin/users/{target.id}/change_role',
        data={'role': 'system_admin', 'submit': 'Change Role'},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    # ...but the escalation guard blocks the actual role change
    assert b'equal to or higher than your own' in resp.data
    with app.app_context():
        assert User.query.get(target.id).role == 'whistleblower'  # unchanged


def test_invalid_role_string_rejected(app, client):
    sa = make_user('sa4@sit.singaporetech.edu.sg', 'system_admin')
    target = make_user('target2@sit.singaporetech.edu.sg', 'whistleblower')

    login(client, sa)
    # Forge a POST with a role that doesn't exist in the whitelist
    resp = client.post(
        f'/admin/users/{target.id}/change_role',
        data={'role': 'superuser', 'submit': 'Change Role'},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    # WTForms SelectField rejects unknown choices -> validation error
    # OR our server-side whitelist rejects it. Either way, role is unchanged.
    with app.app_context():
        assert User.query.get(target.id).role == 'whistleblower'


def test_system_admin_cannot_change_own_role(app, client):
    sa = make_user('sa5@sit.singaporetech.edu.sg', 'system_admin')
    login(client, sa)
    resp = client.post(
        f'/admin/users/{sa.id}/change_role',
        data={'role': 'whistleblower', 'submit': 'Change Role'},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b'Cannot modify your own role' in resp.data


# ---------------------------------------------------------------------------
# Decorator behaviour: resource injection
# ---------------------------------------------------------------------------

def test_decorator_injects_resource_kwarg(app, client):
    """The @require_permission decorator should pass the fetched report as
    `resource=` so the route body doesn't re-fetch it."""
    wb = make_user('wb8@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(wb)

    login(client, wb)
    resp = client.get(f'/{report.id}')
    assert resp.status_code == 200
    # The view renders the reference number, so it must be in the response
    assert report.reference_number.encode() in resp.data


# ---------------------------------------------------------------------------
# Authorisation denial is audit-logged
# ---------------------------------------------------------------------------

def test_authorisation_denial_is_audit_logged(app, client):
    from app.models import AuditLog
    alice = make_user('alice3@sit.singaporetech.edu.sg', 'whistleblower')
    bob = make_user('bob2@sit.singaporetech.edu.sg', 'whistleblower')
    report = make_report(alice)

    login(client, bob)
    client.get(f'/{report.id}')

    with app.app_context():
        denial = AuditLog.query.filter_by(action='authorisation_denied').first()
        assert denial is not None
        assert 'report.view' in denial.details
