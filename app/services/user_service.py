"""UserService - account lifecycle, SIT email domain validation on signup."""
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User
from ..security.auth import AuthService
from ..security.validation import ValidationService


class RegistrationValidationError(ValueError):
    def __init__(self, field_errors: dict[str, str]):
        super().__init__("Registration validation failed.")
        self.field_errors = field_errors


class RegistrationError(RuntimeError):
    pass


class UserService:
    GENERIC_FAILURE_MESSAGE = "Unable to register your account. Please try again."

    @staticmethod
    def register(email: str, password: str, full_name: str) -> User:
        field_errors: dict[str, str] = {}

        try:
            validated_email = ValidationService.validate_sit_email(email)
        except ValueError as exc:
            field_errors["email"] = str(exc)
            validated_email = ""

        try:
            cleaned_name = ValidationService.validate_full_name(full_name)
        except ValueError as exc:
            field_errors["full_name"] = str(exc)
            cleaned_name = ""

        try:
            AuthService.validate_password_strength(password)
        except ValueError as exc:
            field_errors["password"] = str(exc)

        if field_errors:
            raise RegistrationValidationError(field_errors)

        existing_user = User.query.filter_by(email=validated_email).first()
        if existing_user is not None:
            raise RegistrationError(UserService.GENERIC_FAILURE_MESSAGE)

        user = User(
            email=validated_email,
            full_name=cleaned_name,
            password_hash=AuthService.hash_password(password),
        )

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise RegistrationError(UserService.GENERIC_FAILURE_MESSAGE) from exc
        except Exception as exc:
            db.session.rollback()
            raise RegistrationError(UserService.GENERIC_FAILURE_MESSAGE) from exc

        return user
