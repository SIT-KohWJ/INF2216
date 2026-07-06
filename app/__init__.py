from flask import Flask
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
mail = Mail()
talisman = Talisman()


def create_app(config_name=None):
    app = Flask(__name__)

    # nginx is the only process allowed to reach gunicorn (compose.prod.yaml
    # exposes web:5000 only on the internal docker network, never published
    # to the host), so it is the single trusted proxy hop. Without this,
    # request.remote_addr / request.is_secure reflect nginx's own address and
    # scheme, breaking per-client rate limiting and audit-log IP addresses,
    # and making every client share one Flask-Limiter bucket.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    import os
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')

    from app.config import config, validate_production_secrets
    app.config.from_object(config.get(config_name, config['default']))

    if config_name == 'production':
        validate_production_secrets()

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    # Security response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    # X-XSS-Protection, Referrer-Policy) — the app-level equivalent of Node's
    # "helmet", so headers apply in dev/test too, not just behind nginx in prod.
    # force_https / session_cookie_secure are left to this app's own
    # enforce_https before_request and app/config.py, so Talisman doesn't fight
    # them or force-redirect during tests (which don't run over TLS).
    talisman.init_app(
        app,
        force_https=False,
        session_cookie_secure=False,
        frame_options='DENY',
        x_xss_protection=True,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            'style-src': "'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            'font-src': "'self' https://cdnjs.cloudflare.com data:",
            'img-src': "'self' data:",
        },
    )

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

    @app.before_request
    def check_session_revoked():
        from datetime import datetime as _dt
        from flask import redirect, session, url_for
        from flask_login import current_user, logout_user
        from app.models import RevokedToken

        if not current_user.is_authenticated:
            return

        sid = session.get('_sid')
        created_at_str = session.get('_session_created_at')

        if not sid or not created_at_str:
            logout_user()
            session.clear()
            return redirect(url_for('auth.login'))

        # Gate 1 — explicit per-session revocation (logout, password change on
        # this specific session).
        if RevokedToken.is_token_revoked(sid):
            logout_user()
            session.clear()
            return redirect(url_for('auth.login'))

        # Gate 2 — global session invalidation watermark (password reset or
        # password change which bumps User.sessions_invalidated_at so that ALL
        # concurrent sessions — including ones not caught by gate 1 — are
        # expired).
        invalidated_at = getattr(current_user, 'sessions_invalidated_at', None)
        if invalidated_at:
            try:
                session_created = _dt.fromisoformat(created_at_str)
                if invalidated_at > session_created:
                    logout_user()
                    session.clear()
                    return redirect(url_for('auth.login'))
            except (ValueError, TypeError):
                logout_user()
                session.clear()
                return redirect(url_for('auth.login'))

    @app.before_request
    def enforce_https():
        from flask import request, redirect
        # request.is_secure is accurate now that ProxyFix (x_proto=1) rewrites
        # the WSGI environ from nginx's X-Forwarded-Proto — no need to also
        # check the header manually here.
        if app.config.get('SESSION_COOKIE_SECURE') and not request.is_secure:
            return redirect(request.url.replace('http://', 'https://'), code=301)

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def internal_error(e):
        from flask import render_template
        return render_template('errors/500.html'), 500

    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import flash, redirect, url_for
        flash('Too many requests. Please slow down and try again later.', 'warning')
        # Never redirect to request.referrer — if the rate-limited URL IS the
        # referrer, that creates an infinite redirect loop.
        return redirect(url_for('auth.login'))

    @app.get('/healthz')
    def healthz():
        return {'status': 'ok'}, 200

    with app.app_context():
        db.create_all()
        from app.services.report_service import ReportService
        ReportService.migrate_investigation_plan_incident_when_column()
        ReportService.normalize_report_statuses()
        # Apply admin-editable operational overrides on top of the static config
        # so consumers reading current_app.config.get(...) see the live values.
        from app.models import PlatformSetting
        PlatformSetting.apply_overrides(app)

    return app
