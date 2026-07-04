"""SITinform security primitives package.

Layered design (one-way call flow):

    routes  ->  services  ->  securityfeature  +  models

Anything in this package is a reusable, isolated security primitive:
  * `access_control.AccessControlService`  -- central permission matrix + IDOR checks
  * `access_control.require_permission`    -- route decorator that enforces both
  * `audit.AuditService`                   -- single entry point for audit logging
                                              (sanitises details, validates action)
  * `sanitizers.Sanitizer`                 -- redacts emails/refs/UUIDs and blocks
                                              forbidden keywords (otp, password, ...)
  * `error_handlers.register_error_handlers` -- 500 handler that logs tracebacks to
                                                the logger (never to the client),
                                                plus a catch-all for unhandled
                                                exceptions

Nothing here imports from `app.routes` or `app.services` -- the dependency arrow
only points inward.
"""
from app.securityfeature.access_control import (
    AccessControlService,
    require_permission,
    load_report_from_url,
    load_evidence_from_url,
    load_user_from_url,
)
from app.securityfeature.audit import AuditService
from app.securityfeature.sanitizers import Sanitizer
from app.securityfeature.error_handlers import register_error_handlers

__all__ = [
    'AccessControlService',
    'require_permission',
    'load_report_from_url',
    'load_evidence_from_url',
    'load_user_from_url',
    'AuditService',
    'Sanitizer',
    'register_error_handlers',
]
