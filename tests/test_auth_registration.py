from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

import app.blueprints.auth as auth_blueprint_module
import app.services.user_service as user_service_module
from app.extensions import db
from app.models import User
from app.security.auth import AuthService
from app.security.validation import ValidationService
from app.services.user_service import (
    RegistrationError,
    RegistrationValidationError,
    UserService,
)


class FakeQuery:
    def __init__(self, existing_user=None):
        self.existing_user = existing_user
        self.filter_by_calls = []

    def filter_by(self, **kwargs):
        self.filter_by_calls.append(kwargs)
        return self

    def first(self):
        return self.existing_user


class FakeSession:
    def __init__(self, commit_error=None):
        self.commit_error = commit_error
        self.added = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, value):
        self.added.append(value)

    def commit(self):
        self.commit_calls += 1
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self):
        self.rollback_calls += 1


class FakeUserModel:
    query = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_validate_sit_email_normalises_and_accepts_sit_domain():
    assert (
        ValidationService.validate_sit_email(" Student@Sit.SingaporeTech.edu.sg ")
        == "student@sit.singaporetech.edu.sg"
    )


def test_validate_sit_email_rejects_invalid_format():
    with pytest.raises(ValueError, match="Enter a valid email address."):
        ValidationService.validate_sit_email("not-an-email")


def test_validate_sit_email_rejects_non_sit_domain():
    with pytest.raises(ValueError, match=r"Use your @sit\.singaporetech\.edu\.sg email address\."):
        ValidationService.validate_sit_email("student@example.com")


def test_validate_full_name_sanitises_html():
    assert ValidationService.validate_full_name("<b>Alice Tan</b>") == "Alice Tan"


def test_validate_full_name_rejects_blank_value():
    with pytest.raises(ValueError, match="Enter your full name."):
        ValidationService.validate_full_name("   ")


def test_hash_password_uses_bcrypt_and_verifies():
    password = "StrongPass!234"

    password_hash = AuthService.hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$2")
    assert AuthService.verify_password(password, password_hash) is True


def test_validate_password_strength_rejects_weak_password():
    with pytest.raises(ValueError, match="Password must be at least 12 characters long"):
        AuthService.validate_password_strength("weakpass123")


def test_user_model_uses_server_defaults_for_timestamps():
    assert User.__table__.c.created_at.nullable is False
    assert User.__table__.c.updated_at.nullable is False
    assert User.__table__.c.created_at.server_default is not None
    assert User.__table__.c.updated_at.server_default is not None


def test_user_service_register_creates_user_with_hashed_password(monkeypatch):
    fake_query = FakeQuery()
    fake_session = FakeSession()
    fake_user_model = type("FakeUserModelForCreate", (FakeUserModel,), {"query": fake_query})

    monkeypatch.setattr(user_service_module, "User", fake_user_model)
    monkeypatch.setattr(db, "session", fake_session)

    user = UserService.register(
        email=" Student@sit.singaporetech.edu.sg ",
        password="StrongPass!234",
        full_name="<b>Alice Tan</b>",
    )

    assert fake_query.filter_by_calls == [{"email": "student@sit.singaporetech.edu.sg"}]
    assert fake_session.added == [user]
    assert fake_session.commit_calls == 1
    assert user.email == "student@sit.singaporetech.edu.sg"
    assert user.full_name == "Alice Tan"
    assert user.password_hash != "StrongPass!234"
    assert AuthService.verify_password("StrongPass!234", user.password_hash) is True


def test_user_service_register_rejects_duplicate_email(monkeypatch):
    existing_user = object()
    fake_query = FakeQuery(existing_user=existing_user)
    fake_session = FakeSession()
    fake_user_model = type("FakeUserModelForDuplicate", (FakeUserModel,), {"query": fake_query})

    monkeypatch.setattr(user_service_module, "User", fake_user_model)
    monkeypatch.setattr(db, "session", fake_session)

    with pytest.raises(RegistrationError, match=UserService.GENERIC_FAILURE_MESSAGE):
        UserService.register(
            email="student@sit.singaporetech.edu.sg",
            password="StrongPass!234",
            full_name="Alice Tan",
        )

    assert fake_session.added == []
    assert fake_session.commit_calls == 0


def test_user_service_register_rolls_back_on_integrity_error(monkeypatch):
    fake_query = FakeQuery()
    fake_session = FakeSession(
        commit_error=IntegrityError("INSERT INTO users", {}, Exception("duplicate")),
    )
    fake_user_model = type("FakeUserModelForIntegrity", (FakeUserModel,), {"query": fake_query})

    monkeypatch.setattr(user_service_module, "User", fake_user_model)
    monkeypatch.setattr(db, "session", fake_session)

    with pytest.raises(RegistrationError, match=UserService.GENERIC_FAILURE_MESSAGE):
        UserService.register(
            email="student@sit.singaporetech.edu.sg",
            password="StrongPass!234",
            full_name="Alice Tan",
        )

    assert fake_session.rollback_calls == 1


def test_get_register_page_renders(client):
    response = client.get("/auth/register")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Create New Account" in body
    assert 'name="confirm_password"' in body
    assert "/static/auth.css" in body
    assert "/static/register.js" in body
    assert "Terms of Use" in body
    assert "Privacy Policy" in body
    assert "Already have an account?" in body


def test_auth_static_assets_are_served(client):
    css_response = client.get("/static/auth.css")
    js_response = client.get("/static/register.js")

    assert css_response.status_code == 200
    assert ".auth-card" in css_response.get_data(as_text=True)
    assert js_response.status_code == 200
    assert "Passwords do not match." in js_response.get_data(as_text=True)


def test_register_post_redirects_to_login_on_success(client, csrf_token, monkeypatch):
    captured = {}

    def fake_register(*, email, password, full_name):
        captured["email"] = email
        captured["password"] = password
        captured["full_name"] = full_name
        return SimpleNamespace(email=email)

    monkeypatch.setattr(auth_blueprint_module.UserService, "register", fake_register)

    response = client.post(
        "/auth/register",
        data={
            "csrf_token": csrf_token("/auth/register"),
            "email": "student@sit.singaporetech.edu.sg",
            "password": "StrongPass!234",
            "full_name": "Alice Tan",
        },
        follow_redirects=True,
    )

    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Registration successful. Please sign in." in body
    assert "<h1 id=\"login-title\">Sign In</h1>" in body
    assert captured == {
        "email": "student@sit.singaporetech.edu.sg",
        "password": "StrongPass!234",
        "full_name": "Alice Tan",
    }


def test_register_post_shows_field_errors_without_echoing_password(client, csrf_token, monkeypatch):
    def fake_register(*, email, password, full_name):
        raise RegistrationValidationError({"email": "Enter a valid email address."})

    monkeypatch.setattr(auth_blueprint_module.UserService, "register", fake_register)

    response = client.post(
        "/auth/register",
        data={
            "csrf_token": csrf_token("/auth/register"),
            "email": "bad-email",
            "password": "StrongPass!234",
            "full_name": "Alice Tan",
        },
    )

    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Enter a valid email address." in body
    assert 'value="bad-email"' in body
    assert "StrongPass!234" not in body
    assert 'name="confirm_password"' in body


def test_register_post_uses_generic_failure_message(client, csrf_token, monkeypatch):
    def fake_register(*, email, password, full_name):
        raise RegistrationError(UserService.GENERIC_FAILURE_MESSAGE)

    monkeypatch.setattr(auth_blueprint_module.UserService, "register", fake_register)

    response = client.post(
        "/auth/register",
        data={
            "csrf_token": csrf_token("/auth/register"),
            "email": "student@sit.singaporetech.edu.sg",
            "password": "StrongPass!234",
            "full_name": "Alice Tan",
        },
    )

    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert UserService.GENERIC_FAILURE_MESSAGE in body
    assert "Traceback" not in body


def test_register_post_requires_csrf(client):
    response = client.post(
        "/auth/register",
        data={
            "email": "student@sit.singaporetech.edu.sg",
            "password": "StrongPass!234",
            "full_name": "Alice Tan",
        },
    )

    assert response.status_code == 400
