"""SITinform security primitives package — Access Control module (Sudipta).

This is the Authorisation story (SEC-004, SEC-005, SEC-006) of the security
sprint. It provides:

  * `AccessControlService`  — central permission matrix + IDOR checks
  * `require_permission`    — route decorator that enforces both
  * `load_report_from_url`  — IDOR resource loader for Report
  * `load_evidence_from_url`— IDOR resource loader for Evidence
  * `load_user_from_url`    — IDOR resource loader for User

==========================================================================
IMPORTANT — other team members will add their submodules here later:
  * `audit.py`             (Logging story — also Sudipta)
  * `sanitizers.py`        (Input validation story — Brendan)
  * `error_handlers.py`    (Logging story — Brendan)

When they do, they should add their imports to this `__init__.py` so the
full `from app.securityfeature import ...` surface is available. Until then,
only the access-control primitives are exported.

The `access_control.py` module has a *soft* dependency on `audit.py` for
logging `authorisation_denied` entries — but it's a lazy import wrapped in
try/except, so if `audit.py` doesn't exist yet, the 403 still fires
correctly; only the audit-log entry is skipped. Once `audit.py` is added,
the audit logging starts working automatically with no code change needed
here.
==========================================================================

Layered design (one-way call flow):

    routes  ->  services  ->  securityfeature  +  models

Nothing in this package imports from `app.routes` or `app.services` — the
dependency arrow only points inward.
"""
from app.securityfeature.access_control import (
    AccessControlService,
    require_permission,
    load_report_from_url,
    load_evidence_from_url,
    load_user_from_url,
)

__all__ = [
    'AccessControlService',
    'require_permission',
    'load_report_from_url',
    'load_evidence_from_url',
    'load_user_from_url',
]
