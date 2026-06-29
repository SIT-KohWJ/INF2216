import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # DATABASE_URL drives the engine. In docker/CI this is a postgresql:// URL;
    # for a bare local run it falls back to a SQLite file so the app still boots.
    # SQLAlchemy 2.x needs the modern "postgresql://" scheme (not "postgres://").
    _db_url = os.environ.get('DATABASE_URL') or 'sqlite:///sitinform.db'
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # pool_pre_ping keeps long-lived Postgres connections healthy behind nginx.
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True} if _db_url.startswith('postgresql') else {}

    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    RATELIMIT_DEFAULT = "500 per day;100 per hour"
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'png', 'jpg', 'jpeg'}

    # The deploy stack (compose/CI) provides FIELD_ENCRYPTION_KEY; the original
    # SITinform .env used ENCRYPTION_KEY. Accept either so both keep working.
    HMAC_SECRET_KEY = os.environ.get('HMAC_SECRET_KEY') or os.urandom(32).hex()
    ENCRYPTION_KEY = (
        os.environ.get('FIELD_ENCRYPTION_KEY')
        or os.environ.get('ENCRYPTION_KEY')
        or os.urandom(32).hex()
    )
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or os.urandom(32).hex()
    JWT_ACCESS_TOKEN_EXPIRES = 3600

    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    PASSWORD_RESET_EXPIRY_MINUTES = 15   # minutes after OTP verification
    OTP_EXPIRY_SECONDS = int(os.environ.get('OTP_EXPIRY_SECONDS', 30))
    OTP_MAX_ATTEMPTS = int(os.environ.get('OTP_MAX_ATTEMPTS', 5))

    # bcrypt work factor — 12 is the OWASP-recommended minimum (≈250 ms/hash)
    BCRYPT_ROUNDS = int(os.environ.get('BCRYPT_ROUNDS', 12))

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')   # Brevo login email
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')   # Brevo SMTP key (not account password)
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@sitinform.sit.singaporetech.edu.sg')


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
