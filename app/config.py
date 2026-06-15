"""Configuration, read entirely from environment variables.

The variable names match your existing .env.example, so nothing new to add
there. Missing required secrets fail loudly at boot (os.environ[...]) rather
than silently running insecure.
"""
import os


class BaseConfig:
    # Flask
    SECRET_KEY = os.environ["SECRET_KEY"]

    # Database (DATABASE_URL points at db:5432 inside docker)
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Project secrets consumed by the security services
    HMAC_SECRET_KEY = os.environ["HMAC_SECRET_KEY"]        # AnonymityService (A2)
    FIELD_ENCRYPTION_KEY = os.environ["FIELD_ENCRYPTION_KEY"]  # EncryptionService (A3)

    # Session-cookie hardening (D2, D-series)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True

    # Uploaded evidence: 10 MB hard cap (B7)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False   # no TLS on localhost


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True    # HTTPS only, behind nginx


def get_config(name: str | None = None):
    name = name or os.getenv("FLASK_ENV", "development")
    return {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
    }.get(name, DevelopmentConfig)
