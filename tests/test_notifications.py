import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-fek")

from app import create_app, db  # noqa: E402
from app.models import Notification, User  # noqa: E402
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


def create_user(email="wb@singaporetech.edu.sg"):
    user = User(email=email, first_name="W", last_name="One", role="whistleblower")
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()
    return user


def add_notifications(user_id, count, read=False):
    for i in range(count):
        db.session.add(
            Notification(
                user_id=user_id,
                message=f"msg {i}",
                notification_type="status_change",
                read=read,
            )
        )
    db.session.commit()


def test_count_unread_notifications(app):
    user = create_user()
    add_notifications(user.id, 2, read=False)
    add_notifications(user.id, 1, read=True)
    assert ReportService.count_unread_notifications(user.id) == 2


def test_mark_all_notifications_read(app):
    user = create_user()
    add_notifications(user.id, 3, read=False)

    updated = ReportService.mark_all_notifications_read(user.id)

    assert updated == 3
    assert ReportService.count_unread_notifications(user.id) == 0


def test_mark_all_only_affects_own_notifications(app):
    user_a = create_user(email="a@singaporetech.edu.sg")
    user_b = create_user(email="b@singaporetech.edu.sg")
    add_notifications(user_a.id, 2, read=False)
    add_notifications(user_b.id, 2, read=False)

    ReportService.mark_all_notifications_read(user_a.id)

    assert ReportService.count_unread_notifications(user_a.id) == 0
    assert ReportService.count_unread_notifications(user_b.id) == 2
