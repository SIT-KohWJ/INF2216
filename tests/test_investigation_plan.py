import os
import uuid
from datetime import date, datetime

import pytest
from sqlalchemy import text

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import InvestigationPlan, Report, User  # noqa: E402
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


def create_report(submitter, investigator=None, status="Received"):
    report = Report(
        reference_number=f"SIT-{uuid.uuid4().hex[:10].upper()}",
        submitter_hash=crypto_service.generate_user_hash(submitter.id),
        title="Test Report",
        description="Report description",
        category="other",
        status=status,
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


def insert_plan_with_raw_incident_when(report, investigator, incident_when):
    plan_id = str(uuid.uuid4())
    db.session.execute(
        text("""
            INSERT INTO investigation_plans (
                id,
                report_id,
                investigator_id,
                investigator_full_name,
                investigator_job_title,
                investigator_staff_id,
                planning_date,
                case_overview,
                incident_when,
                incident_where,
                created_at
            ) VALUES (
                :id,
                :report_id,
                :investigator_id,
                :investigator_full_name,
                :investigator_job_title,
                :investigator_staff_id,
                :planning_date,
                :case_overview,
                :incident_when,
                :incident_where,
                :created_at
            )
        """),
        {
            "id": plan_id,
            "report_id": report.id,
            "investigator_id": investigator.id,
            "investigator_full_name": investigator.full_name,
            "investigator_job_title": "Senior Investigator",
            "investigator_staff_id": "INV-RAW",
            "planning_date": "2026-06-28",
            "case_overview": "Legacy raw SQL plan",
            "incident_when": incident_when,
            "incident_where": "Main office",
            "created_at": "2026-06-28 10:00:00",
        },
    )
    db.session.commit()

    plan = InvestigationPlan.query.filter_by(id=plan_id).first()
    db.session.expunge(plan)
    return plan


def login_as(client, user):
    import uuid
    from datetime import datetime
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True
        session["_sid"] = str(uuid.uuid4())
        session["_session_created_at"] = datetime.utcnow().isoformat()


def test_assigned_investigator_can_open_create_page(app, client):
    with app.app_context():
        whistleblower = create_user("wb_create@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_create@sit.singaporetech.edu.sg", "investigator", "Case", "Owner")
        report = create_report(whistleblower, investigator, status="Planning")

    login_as(client, investigator)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 200
    assert b"Create Investigation Plan" in response.data
    assert b'name="incident_date"' in response.data
    assert b'name="incident_time"' in response.data
    assert b'type="time"' in response.data


def test_assigned_investigator_can_submit_plan(app, client):
    with app.app_context():
        whistleblower = create_user("wb_submit@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_submit@sit.singaporetech.edu.sg", "investigator", "Plan", "Author")
        report = create_report(whistleblower, investigator, status="Planning")

    login_as(client, investigator)
    response = client.post(
        f"/{report.id}/investigation-plan",
        data={
            "investigator_full_name": investigator.full_name,
            "investigator_job_title": "Investigator",
            "investigator_staff_id": "INV-100",
            "planning_date": "2026-06-28",
            "case_overview": "Initial planning notes",
            "incident_date": "2026-06-20",
            "incident_time": "14:30",
            "incident_where": "SIT Campus",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Investigation plan created successfully" in response.data
    with app.app_context():
        plan = InvestigationPlan.query.filter_by(report_id=report.id).first()
        report = Report.query.get(report.id)
        assert plan is not None
        assert plan.investigator_id == investigator.id
        assert plan.case_overview == "Initial planning notes"
        assert plan.incident_when == datetime(2026, 6, 20, 14, 30)
        assert report.status == "Investigating"


def test_assigned_investigator_sees_edit_flow_when_plan_exists(app, client):
    with app.app_context():
        whistleblower = create_user("wb_edit@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_edit@sit.singaporetech.edu.sg", "investigator", "Edit", "Owner")
        report = create_report(whistleblower, investigator, status="Investigating")
        create_plan(report, investigator)

    login_as(client, investigator)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 200
    assert b"Edit Investigation Plan" in response.data
    assert b"Existing plan overview" in response.data
    assert b'value="2026-06-21"' in response.data
    assert b'value="14:30"' in response.data


def test_edit_route_handles_legacy_string_incident_when(app, client, monkeypatch):
    with app.app_context():
        whistleblower = create_user("wb_legacy@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_legacy@sit.singaporetech.edu.sg", "investigator", "Legacy", "Owner")
        report = create_report(whistleblower, investigator, status="Investigating")
        plan = insert_plan_with_raw_incident_when(report, investigator, "2026-06-21 14:30:00")
        plan.incident_when = "2026-06-21 14:30:00"

    monkeypatch.setattr(ReportService, "get_investigation_plan", staticmethod(lambda report_id: plan if report_id == report.id else None))
    login_as(client, investigator)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 200
    assert b"Edit Investigation Plan" in response.data
    assert b'value="2026-06-21"' in response.data
    assert b'value="14:30"' in response.data


def test_edit_route_ignores_unparsable_legacy_incident_when(app, client, monkeypatch):
    with app.app_context():
        whistleblower = create_user("wb_legacy_bad@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_legacy_bad@sit.singaporetech.edu.sg", "investigator", "Legacy", "Bad")
        report = create_report(whistleblower, investigator, status="Investigating")
        plan = insert_plan_with_raw_incident_when(report, investigator, "2026-06-21 14:30:00")
        plan.incident_when = "last week"

    monkeypatch.setattr(ReportService, "get_investigation_plan", staticmethod(lambda report_id: plan if report_id == report.id else None))
    login_as(client, investigator)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 200
    assert b"Edit Investigation Plan" in response.data
    assert b'value="2026-06-21"' not in response.data
    assert b'value="14:30"' not in response.data


def test_unassigned_investigator_is_denied(app, client):
    with app.app_context():
        whistleblower = create_user("wb_denied@sit.singaporetech.edu.sg", "whistleblower")
        assigned = create_user("inv_assigned@sit.singaporetech.edu.sg", "investigator")
        outsider = create_user("inv_outsider@sit.singaporetech.edu.sg", "investigator")
        report = create_report(whistleblower, assigned, status="Planning")

    login_as(client, outsider)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 302
    assert "/investigator" in response.headers["Location"]


def test_report_admin_can_view_existing_plan(app, client):
    with app.app_context():
        whistleblower = create_user("wb_adminview@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_adminview@sit.singaporetech.edu.sg", "investigator")
        report_admin = create_user("admin_view@sit.singaporetech.edu.sg", "report_admin")
        report = create_report(whistleblower, investigator, status="Investigating")
        create_plan(report, investigator)

    login_as(client, report_admin)
    response = client.get(f"/{report.id}/investigation-plan")

    assert response.status_code == 200
    assert b"View Investigation Plan" in response.data
    assert b"Save Investigation Plan" not in response.data


def test_report_admin_cannot_create_or_edit_plan(app, client):
    with app.app_context():
        whistleblower = create_user("wb_adminblock@sit.singaporetech.edu.sg", "whistleblower")
        investigator = create_user("inv_adminblock@sit.singaporetech.edu.sg", "investigator")
        report_admin = create_user("admin_block@sit.singaporetech.edu.sg", "report_admin")
        report_without_plan = create_report(whistleblower, investigator, status="Planning")
        report_with_plan = create_report(whistleblower, investigator, status="Investigating")
        create_plan(report_with_plan, investigator)

    login_as(client, report_admin)
    create_response = client.get(f"/{report_without_plan.id}/investigation-plan")
    edit_response = client.post(
        f"/{report_with_plan.id}/investigation-plan",
        data={
            "investigator_full_name": investigator.full_name,
            "investigator_job_title": "Changed Title",
            "investigator_staff_id": "INV-200",
            "planning_date": "2026-06-29",
            "case_overview": "Changed overview",
            "incident_date": "2026-06-29",
            "incident_time": "09:15",
            "incident_where": "Changed where",
        },
    )

    assert create_response.status_code == 404
    assert edit_response.status_code == 403
