from flask import Flask
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
mail = Mail()


def create_app(config_name=None):
    app = Flask(__name__)

    import os
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')

    from app.config import config
    app.config.from_object(config.get(config_name, config['default']))

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    # Wire Flask-Mail into EmailService so OTP delivery works.
    from app.services.email_service import EmailService
    EmailService.init_app(mail)

    from app.services.crypto_service import init_crypto
    with app.app_context():
        init_crypto(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    from flask_wtf.csrf import generate_csrf
    app.jinja_env.globals['csrf_token'] = generate_csrf

    from app.routes.auth import auth_bp
    from app.routes.otp import otp_bp
    from app.routes.reports import reports_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(otp_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    from app.utils.helpers import (
        format_bytes, format_date, format_datetime,
        get_action_css, get_category_display_name, get_report_status_css,
        get_role_display_name, truncate_text,
    )
    from app.services.crypto_service import crypto_service as _crypto_service

    app.jinja_env.globals.update(
        get_report_status_css=get_report_status_css,
        get_action_css=get_action_css,
        format_datetime=format_datetime,
        format_date=format_date,
        get_role_display_name=get_role_display_name,
        get_category_display_name=get_category_display_name,
        truncate_text=truncate_text,
        format_bytes=format_bytes,
        crypto_service=_crypto_service,
    )

    # ── Per-request middleware ────────────────────────────────────────────
    # Request-ID + security headers MUST run before everything else so the
    # error handlers can read `g.request_id`.
    from app.securityfeature.error_handlers import register_request_context
    register_request_context(app)

    @app.before_request
    def check_session_revoked():
        from datetime import datetime as _dt
        from flask import redirect, session, url_for
        from flask_login import current_user, logout_user
        from app.models import RevokedToken

        if not current_user.is_authenticated:
            return

        # Gate 1 -- explicit per-session revocation (logout, password change on
        # this specific session).
        sid = session.get('_sid')
        if sid and RevokedToken.is_token_revoked(sid):
            logout_user()
            session.clear()
            return redirect(url_for('auth.login'))

        # Gate 2 -- global session invalidation watermark (password reset or
        # password change which bumps User.sessions_invalidated_at so that ALL
        # concurrent sessions -- including ones not caught by gate 1 -- are
        # expired).
        invalidated_at = getattr(current_user, 'sessions_invalidated_at', None)
        created_at_str = session.get('_session_created_at')
        if invalidated_at and created_at_str:
            try:
                session_created = _dt.fromisoformat(created_at_str)
                if invalidated_at > session_created:
                    logout_user()
                    session.clear()
                    return redirect(url_for('auth.login'))
            except (ValueError, TypeError):
                pass

    @app.before_request
    def enforce_https():
        from flask import request, redirect
        if app.config.get('SESSION_COOKIE_SECURE'):
            if not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
                return redirect(request.url.replace('http://', 'https://'), code=301)

    # ── Structured error handlers (no stack-trace leaks) ──────────────────
    from app.securityfeature.error_handlers import register_error_handlers
    register_error_handlers(app)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import flash, redirect, url_for, jsonify, g, request
        if request.path.startswith('/api/'):
            return jsonify({'error': 'rate_limited',
                            'request_id': g.get('request_id', '-')}), 429
        flash('Too many requests. Please slow down and try again later.', 'warning')
        # Never redirect to request.referrer -- if the rate-limited URL IS
        # the referrer, that creates an infinite redirect loop.
        return redirect(url_for('auth.login'))

    @app.get('/healthz')
    def healthz():
        return {'status': 'ok'}, 200

    with app.app_context():
        db.create_all()
        # Audit-log append-only guard: blocks UPDATE/DELETE on audit_logs at
        # the ORM layer. ONLY registered in testing/non-postgres environments
        # because the PostgreSQL trigger in scripts/init.sql already enforces
        # this at the DB layer for production, and the ORM event listener can
        # fire spuriously during SQLAlchemy's internal post-INSERT attribute
        # sync on some backend/driver combinations. The guard exists to make
        # the append-only guarantee testable on SQLite (which has no triggers).
        if db.engine.dialect.name != 'postgresql':
            from app.securityfeature.error_handlers import register_audit_append_only_guard
            register_audit_append_only_guard()

        from app.services.report_service import ReportService
        ReportService.migrate_investigation_plan_incident_when_column()
        ReportService.normalize_report_statuses()

    return app
