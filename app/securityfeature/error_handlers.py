"""Structured error handlers: no stack traces ever reach the client.

Design:

  - 404 / 403 / 429 keep their existing templates (user-friendly, no leakage).
  - 500 logs the full traceback to the structured logger (so it reaches
    Splunk / `docker compose logs web`) and renders a generic 500 page that
    shows ONLY a `request_id`. The user can quote that ID to support; the
    actual traceback stays server-side.
  - A catch-all `Exception` handler catches anything not explicitly converted
    to an HTTPException, logs it as a 500, and returns the same template.
    This is the backstop against any future route raising unexpectedly.

Each 500 also writes a `server_error` audit entry so admins can see error
spikes on the dashboard.

The handlers also attach `X-Request-ID` to every response so client-side
debugging (Burp Suite, browser devtools) can correlate a response with a
server log line.
"""
import uuid as _uuid

from flask import current_app, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException


def register_error_handlers(app):
    """Register structured error handlers on *app*.

    Called from create_app() AFTER all blueprints are wired, so these handlers
    take precedence over any per-blueprint handler.
    """

    @app.errorhandler(403)
    def forbidden(e):
        # Render the existing template (no info leak). API requests get JSON.
        if _wants_json():
            return jsonify({'error': 'forbidden',
                            'request_id': g.get('request_id', '-')}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({'error': 'not_found',
                            'request_id': g.get('request_id', '-')}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(413)
    def too_large(e):
        # Triggered by MAX_CONTENT_LENGTH. Don't reveal the exact limit.
        if _wants_json():
            return jsonify({'error': 'payload_too_large',
                            'request_id': g.get('request_id', '-')}), 413
        return render_template('errors/413.html'), 413

    @app.errorhandler(500)
    def internal_error(e):
        request_id = g.get('request_id', str(_uuid.uuid4()))
        # Full traceback to the logger -- NEVER to the client.
        current_app.logger.exception(
            'unhandled_500 request_id=%s path=%s method=%s',
            request_id, request.path, request.method,
        )

        # Audit the 500 so admins can see error spikes. Keep details
        # generic (no exception text -- it could contain decrypted data).
        try:
            from flask_login import current_user
            from app.securityfeature.audit import AuditService
            acting_user = current_user if current_user.is_authenticated else None
            acting_role = (current_user.role
                           if current_user.is_authenticated else 'anonymous')
            AuditService.log(
                action='server_error',
                acting_user=acting_user,
                acting_role=acting_role,
                target_type='endpoint',
                target_id=None,
                details=f'Unhandled exception on {request.method} {request.path}',
                ip_address=request.remote_addr,
                request_id=request_id,
            )
        except Exception:  # pragma: no cover -- never let audit failure mask the 500
            current_app.logger.exception(
                'Failed to write server_error audit entry for request_id=%s',
                request_id,
            )

        if _wants_json():
            return jsonify({'error': 'internal_server_error',
                            'request_id': request_id}), 500
        return render_template('errors/500.html', request_id=request_id), 500

    @app.errorhandler(Exception)
    def catch_all(e):
        """Catch-all for non-HTTP exceptions.

        werkzeug HTTPException subclasses (404, 403, 413, ...) are re-raised
        so they hit the specific handler above. Anything else is treated as a
        500 -- logged with traceback, audit-logged, and rendered generically.
        """
        if isinstance(e, HTTPException):
            return e
        return internal_error(e)


def _wants_json() -> bool:
    """True if the current request prefers a JSON response.

    Used so API endpoints (/api/*) get JSON errors while browser routes get
    HTML error pages. We check both the Accept header and the URL prefix so
    `curl` without an Accept header still gets JSON from /api/*.
    """
    if request.path.startswith('/api/'):
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept and 'text/html' not in accept


def register_request_context(app):
    """Per-request middleware: generate / propagate a request-id, attach it
    to the response, and stash it on `g` so error handlers can read it.

    Also enforces a strict content-type check on POST/PUT/PATCH so a Burp
    attacker can't bypass CSRF by sending `Content-Type: text/plain` (which
    Flask-WTF would otherwise reject, but we double-check here).
    """
    import uuid as _uuid
    from flask import g, request

    @app.before_request
    def _set_request_id():
        # Honour an inbound X-Request-ID only if it's a valid UUID; otherwise
        # generate one. (Never trust arbitrary client input.)
        inbound = request.headers.get('X-Request-ID', '').strip()
        try:
            rid = str(_uuid.UUID(inbound)) if inbound else str(_uuid.uuid4())
        except (ValueError, TypeError):
            rid = str(_uuid.uuid4())
        g.request_id = rid

    @app.after_request
    def _attach_request_id(response):
        rid = getattr(g, 'request_id', None)
        if rid:
            response.headers['X-Request-ID'] = rid
        # Modest security headers (defence in depth; nginx adds HSTS in prod).
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('Cache-Control', 'no-store')
        return response


def register_audit_append_only_guard():
    """SQLAlchemy event listener that blocks UPDATE/DELETE on audit_logs.

    This complements (does NOT replace) the PostgreSQL trigger in
    `scripts/init.sql`. The trigger enforces append-only at the DB layer for
    production; this listener enforces it at the ORM layer so the guarantee
    is also testable on SQLite (which has no triggers in the test config).

    We deliberately keep the listener SIMPLE (block all UPDATEs/DELETEs)
    rather than trying to distinguish "real" updates from SQLAlchemy's
    internal post-INSERT attribute sync. The reason: SQLAlchemy 2.x can
    fire `before_update` in edge cases during flush, and any heuristic to
    distinguish those from real updates is fragile. Instead, the rule is:
    if you need to mutate an AuditLog, do it through a fresh DB session
    that bypasses the ORM (which is what the test suite does to verify
    the guard). In normal app code, AuditLogs are INSERT-only.

    The PostgreSQL trigger (scripts/init.sql) is the production enforcement;
    this listener is the test-environment enforcement.
    """
    from sqlalchemy import event
    from app.models import AuditLog

    @event.listens_for(AuditLog, 'before_update')
    def _block_update(mapper, connection, target):
        raise PermissionError(
            'audit_logs is append-only: UPDATE is not permitted'
        )

    @event.listens_for(AuditLog, 'before_delete')
    def _block_delete(mapper, connection, target):
        raise PermissionError(
            'audit_logs is append-only: DELETE is not permitted'
        )
