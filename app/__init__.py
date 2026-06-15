"""Application factory.

Layered design (mirrors the class diagram in Report 1):
  blueprints/  -> boundary controllers: routing + rendering ONLY, no security
                  logic, so every check is re-enforced server-side (E1).
  services/    -> domain logic (ReportService, InvestigationService, UserService)
  security/    -> isolated security services (Anonymity, Encryption, Validation,
                  Auth, AccessControl, Audit)
  models/      -> SQLAlchemy models mapping the tables in scripts/init.sql

NOTE: the schema is owned by scripts/init.sql (it runs once on first DB boot).
We never call db.create_all() — the models just map the existing tables.
"""
from flask import Flask

from .config import get_config
from .extensions import db, csrf, limiter


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))

    # Bind extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Import models so the ORM registers them (mapped to init.sql tables)
    from . import models  # noqa: F401

    # Register boundary controllers
    from .blueprints.auth import auth_bp
    from .blueprints.reports import reports_bp
    from .blueprints.investigations import investigations_bp
    from .blueprints.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(investigations_bp)
    app.register_blueprint(admin_bp)

    @app.get("/healthz")
    def healthz():
        """Liveness probe (used by compose/nginx health checks)."""
        return {"status": "ok"}, 200

    return app
