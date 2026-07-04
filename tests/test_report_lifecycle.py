import os
import uuid
from datetime import date, datetime

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import InvestigationPlan, InvestigationNote, Report, User  # noqa: E402
from app.services.crypto_service import crypto_service  # noqa: E402
from app.services.report_service import ReportService  # noqa: E402


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


def create_user(email, role, first_name="Test", last_name="User"):
    user = User(email=email, first_name=first_name, last_name=last_name, role=role)
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)
    db.session.expunge(user)
    return user


def create_report(submitter, investigator=None, status="Received", outcome=None, outcome_details=None):
    report = Report(
        reference_number=f"SIT-{uuid.uuid4().hex[:10].upper()}",
        submitter_hash=crypto_service.generate_user_hash(submitter.id),
        title="Lifecycle Report",
        description="Report description",
        category="other",
        status=status,
        outcome=outcome,
        outcome_details=outcome_details,
        user_id=submitter.id,
        investigator_id=investigator.id if investigator else None,
    )
    db.session.add(report)
    db.session.commit()
    db.session.refresh(report)
    db.session.expunge(report)
    return report


def create_plan(report, investigator):
    plan = InvestigationPlan(
        report_id=report.id,
        investigator_id=investigator.id,
        investigator_full_name=investigator.full_name,
        investigator_job_title="Senior Investigator",
        investigator_staff_id="INV-001",
        planning_date=date(2026, 6, 28),
        case_overview="Existing plan overview",
        incident_when=datetime(2026, 6, 21, 14, 30),
        incident_where="Main office",
    )
    db.session.add(plan)
    db.session.commit()
    db.session.refresh(plan)
    db.session.expunge(plan)
    return plan


def login_as(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True


def test_report_admin_can_triage_report(app, client):
    with app.app_context():
        whistleblower = create_user("wb_triage@sit.singaporetech.edu.sg", "whistleblower")
        report_admin = create_user("admin_triage@sit.singaporetech.edu.sg", "report_admin")
        report = create_report(whistleblower, status="Received")

    login_as(client, report_admin)
    response = client.post(
        f"/admin/reports/{report.id}/status",
        data={"status": "Triaged"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Status updated to Triaged" in response.data
    with app.app_context():
        assert Report.query.get(report.id).status == "Triaged"


def test_assign_investigator_requires_triage(app, client):
    with app.app_context():
        whistleblower = create_user("wb_assignblock@sit.singaporetech.edu.sg", "whistleblower")
        report_admin = create_user("admin_assignblock@sit.singaporetech.edu.sg", "report_admin")
        investigator = create_user("inv_assignblock@sit.singaporetech.edu.sg", "investigator")
        report = create_report(whistleblower, status="Received")

    login_as(client, report_admin)
    response = client.post(
        f"/admin/reports/{report.id}/assign",
        data={"investigator": investigator.id},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Report must be triaged before assigning an investigator" in response.data
    with app.app_context():
        refreshed = Report.query.get(report.id)
        assert refreshed.status == "Received"
        assert refreshed.investigator_id is None


def test_assigning_investigator_moves_triaged_report_to_planning(app, client):
    with app.app_context():
        whistleblower = create_user("wb_assign@sit.singaporetech.edu.sg", "whistleblower")
        report_admin = create_user("admin_assign@sit.singaporetech.edu.sg", "report_admin")
        investigator = create_user("inv_assign@sit.singaporetech.edu.sg", "investigator")
        report = create_report(whistleblower, status="Triaged")

    login_as(client, report_admin)
    response = client.post(
        f"/admin/reports/{report.id}/assign",
        data={"investigator": investigator.id},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        refreshed = Report.query.get(report.id)
        assert refreshed.investigator_id == investigator.id
        assert refreshed.status == "Planning"


def test_investigation_actions_blocked_until_plan_exists(app, client):
    with app.app_context():
        whistleblower = create_user("wb_gate@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_gate@sit.singaporetech.edu.sg", "investigator")
        report_admin = create_user("admin_gate@sit.singaporetech.edu.sg", "report_admin")
        report = create_report(whistleblower, investigator=investigator, status="Planning")

    login_as(client, investigator)
    view_response = client.get(f"/{report.id}")
    note_response = client.get(f"/{report.id}/add_note", follow_redirects=True)

    assert view_response.status_code == 200
    assert b"Add Note" in view_response.data
    assert b"Recommend Outcome" in view_response.data
    assert b"disabled" in view_response.data
    assert note_response.status_code == 200
    assert b"Complete the investigation plan before adding notes or recommending an outcome" in note_response.data

    login_as(client, report_admin)
    outcome_response = client.post(
        f"/{report.id}/recommend_outcome",
        data={"outcome": "dismissed", "outcome_details": "Blocked until plan exists"},
        follow_redirects=True,
    )

    assert outcome_response.status_code == 200
    assert b"Complete the investigation plan before adding notes or recommending an outcome" in outcome_response.data


def test_note_can_be_added_after_plan_exists(app, client):
    with app.app_context():
        whistleblower = create_user("wb_note@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_note@sit.singaporetech.edu.sg", "investigator")
        report = create_report(whistleblower, investigator=investigator, status="Investigating")
        create_plan(report, investigator)

    login_as(client, investigator)
    response = client.post(
        f"/{report.id}/add_note",
        data={"note": "Investigation started"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Note added successfully" in response.data
    with app.app_context():
        notes = InvestigationNote.query.filter_by(report_id=report.id).all()
        assert len(notes) == 1


def test_recommending_outcome_moves_report_to_under_review(app, client):
    with app.app_context():
        whistleblower = create_user("wb_outcome@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_outcome@sit.singaporetech.edu.sg", "investigator")
        report = create_report(whistleblower, investigator=investigator, status="Investigating")
        create_plan(report, investigator)

    login_as(client, investigator)
    response = client.post(
        f"/{report.id}/recommend_outcome",
        data={"outcome": "action_taken", "outcome_details": "Recommend action"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Outcome recommended successfully" in response.data
    with app.app_context():
        refreshed = Report.query.get(report.id)
        assert refreshed.status == "Under Review"
        assert refreshed.outcome == "action_taken"


def test_updating_outcome_keeps_report_under_review(app, client):
    with app.app_context():
        whistleblower = create_user("wb_outcomeedit@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_outcomeedit@sit.singaporetech.edu.sg", "investigator")
        report_admin = create_user("admin_outcomeedit@sit.singaporetech.edu.sg", "report_admin")
        report = create_report(
            whistleblower,
            investigator=investigator,
            status="Under Review",
            outcome="dismissed",
            outcome_details="Initial recommendation",
        )
        create_plan(report, investigator)

    login_as(client, report_admin)
    response = client.post(
        f"/{report.id}/recommend_outcome",
        data={"outcome": "referred", "outcome_details": "Escalate for review"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        refreshed = Report.query.get(report.id)
        assert refreshed.status == "Under Review"
        assert refreshed.outcome == "referred"


def test_close_requires_under_review_and_then_moves_to_closed(app, client):
    with app.app_context():
        whistleblower = create_user("wb_close@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_close@sit.singaporetech.edu.sg", "investigator")
        report_admin = create_user("admin_close@sit.singaporetech.edu.sg", "report_admin")
        report = create_report(whistleblower, investigator=investigator, status="Investigating")
        create_plan(report, investigator)

    login_as(client, investigator)
    blocked_response = client.post(f"/{report.id}/close", follow_redirects=True)

    assert blocked_response.status_code == 200
    assert b"Report must be in Under Review status to close" in blocked_response.data

    with app.app_context():
        refreshed = Report.query.get(report.id)
        refreshed.status = "Under Review"
        db.session.commit()

    login_as(client, report_admin)
    close_response = client.post(f"/{report.id}/close", follow_redirects=True)

    assert close_response.status_code == 200
    with app.app_context():
        assert Report.query.get(report.id).status == "Closed"


def test_api_stats_reflect_new_statuses(app, client):
    with app.app_context():
        whistleblower = create_user("wb_stats@sit.singaporetech.edu.sg", "whistleblower")
        report_admin = create_user("admin_stats@sit.singaporetech.edu.sg", "report_admin")
        create_report(whistleblower, status="Received")
        create_report(whistleblower, status="Triaged")
        create_report(whistleblower, status="Planning")
        create_report(whistleblower, status="Investigating")
        create_report(whistleblower, status="Under Review")
        create_report(whistleblower, status="Closed")

    login_as(client, report_admin)
    response = client.get("/api/stats")

    assert response.status_code == 200
    data = response.get_json()
    # The /api/stats endpoint is now role-aware. report_admin sees system-wide
    # stats under a `by_status` key (plus by_category and investigator_load).
    assert data['scope'] == 'system_reports'
    assert data['by_status']['total'] == 6
    assert data['by_status']['received'] == 1
    assert data['by_status']['triaged'] == 1
    assert data['by_status']['planning'] == 1
    assert data['by_status']['investigating'] == 1
    assert data['by_status']['under_review'] == 1
    assert data['by_status']['closed'] == 1


def test_status_normalization_updates_legacy_rows(app):
    with app.app_context():
        whistleblower = create_user("wb_normalize@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_normalize@sit.singaporetech.edu.sg", "investigator")
        closed_report = create_report(whistleblower, status="Resolved")
        planning_report = create_report(whistleblower, investigator=investigator, status="Triaged")
        investigating_report = create_report(whistleblower, investigator=investigator, status="Triaged")
        create_plan(investigating_report, investigator)
        review_report = create_report(
            whistleblower,
            investigator=investigator,
            status="Investigating",
            outcome="action_taken",
            outcome_details="Legacy outcome",
        )

        ReportService.normalize_report_statuses()

        assert Report.query.get(closed_report.id).status == "Closed"
        assert Report.query.get(planning_report.id).status == "Planning"
        assert Report.query.get(investigating_report.id).status == "Investigating"
        assert Report.query.get(review_report.id).status == "Under Review"
