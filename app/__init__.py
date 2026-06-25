from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()


def create_app(config_name=None):
    app = Flask(__name__)

    # When no explicit config is passed (e.g. gunicorn -> wsgi:app), pick it
    # from FLASK_ENV so compose.prod.yaml (FLASK_ENV=production) gets the
    # hardened ProductionConfig and local dev gets DevelopmentConfig.
    import os
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')

    from app.config import config
    app.config.from_object(config.get(config_name, config['default']))

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    from app.services.crypto_service import init_crypto
    with app.app_context():
        init_crypto(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    from flask_wtf.csrf import generate_csrf
    app.jinja_env.globals['csrf_token'] = generate_csrf

    from app.routes.auth import auth_bp
    from app.routes.reports import reports_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    from app.utils.helpers import (
        get_report_status_css, get_action_css, format_datetime, format_date,
        get_role_display_name, get_category_display_name, truncate_text, format_bytes
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
        crypto_service=_crypto_service
    )

    @app.before_request
    def enforce_https():
        from flask import request, redirect
        if app.config.get('SESSION_COOKIE_SECURE'):
            if not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
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
        from flask import flash, redirect, request, url_for
        flash('Too many requests. Please try again later.', 'warning')
        return redirect(request.referrer or url_for('auth.login'))

    @app.get('/healthz')
    def healthz():
        """Liveness probe used by nginx and the deploy smoke check."""
        return {'status': 'ok'}, 200

    # On Postgres the schema is owned by scripts/init.sql (it runs once on first
    # DB boot), so create_all() is a harmless no-op there — it only fills in
    # missing tables, which is what we want for the SQLite dev fallback.
    with app.app_context():
        db.create_all()

    return app
