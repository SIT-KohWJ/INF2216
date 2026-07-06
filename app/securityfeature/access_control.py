"""Central access-control policy for SITinform.

Two responsibilities:

  1. **Role-level authorisation** -- a single permission matrix mapping every
     protected action to the set of roles allowed to perform it. This is the
     one place to audit "who can do what"; routes reference it via
     `@require_permission('action.name')`.

  2. **Resource-level authorisation (IDOR)** -- for actions that take a Report
     or User, the `can()` method performs an ownership check:
        whistleblower  -> must own the report
        investigator   -> must be assigned to the report
        report_admin   -> any report (but cannot read decrypted content of
                          reports they are not admin-ing; that lives in the
                          report view template, not here)
        system_admin   -> any user, but cannot self-escalate

The decorator `@require_permission(action, resource_loader=...)` enforces
BOTH layers on a route in one line:

    @reports_bp.route('/<report_id>')
    @login_required
    @require_permission('report.view', resource_loader=load_report_from_url)
    def view_report(report_id, resource=None):
        report = resource   # already ownership-checked, no need to re-fetch

Why a resource_loader instead of inline fetch?
  - The decorator fetches the resource once, checks ownership, and injects it
    into the route as `resource=<obj>`. The route body never has to repeat
    the fetch+check dance -- which is exactly where IDOR bugs used to slip in
    (a route that fetches the report but forgets the ownership check).

Burp-Suite resistance:
  - URL params are validated as UUIDs BEFORE hitting the DB, so probes like
    `/reports/1`, `/reports/2` get 404 immediately without leaking existence.
  - 403 vs 404 distinction: a non-existent UUID returns 404; an existing
    UUID the user cannot access returns 403. UUIDs make guessing impractical
    (122 bits of entropy), so this distinction does not enable enumeration.
  - Role names are whitelisted server-side -- `new_role` from a POST body
    is rejected if it isn't in ROLE_HIERARCHY, even if the WTForms choices
    list was bypassed.
"""
from functools import wraps
from uuid import UUID

from flask import abort, current_app, request
from flask_login import current_user


# ---------------------------------------------------------------------------
# Role hierarchy + permission matrix
# ---------------------------------------------------------------------------

class AccessControlService:
    """One place that answers "is *user* allowed to *action* on *resource*?\"."""

    # Hierarchy used for self-privilege-escalation guards
    # (system_admin can assign report_admin, but not vice versa; nobody can
    # assign a role higher than their own).
    ROLE_HIERARCHY = {
        'whistleblower': 1,
        'investigator':  2,
        'report_admin':  3,
        'system_admin':  4,
    }

    # Every protected action -> set of roles allowed.
    # Add new actions here first; routes that reference an unknown action
    # will raise at decoration time (fail-closed).
    PERMISSIONS = {
        # ---- Report lifecycle ----
        'report.create':              {'whistleblower'},
        'report.view':                {'whistleblower', 'investigator', 'report_admin'},
        'report.view_all':            {'report_admin'},
        'report.triage':              {'report_admin'},
        'report.assign_investigator': {'report_admin'},
        'report.update_severity':     {'report_admin'},
        'report.update_status':       {'report_admin'},
        'report.create_plan':         {'investigator'},
        'report.view_plan':           {'investigator', 'report_admin'},
        'report.add_note':            {'investigator', 'report_admin'},
        'report.recommend_outcome':   {'investigator'},
        'report.close':               {'report_admin'},
        'report.download_evidence':   {'whistleblower', 'investigator', 'report_admin'},
        'report.view_notifications':  {'whistleblower', 'investigator', 'report_admin'},
        'report.investigator_dashboard': {'investigator'},

        # ---- Report Admin ----
        'admin.view_dashboard':       {'report_admin', 'system_admin'},
        'admin.manage_reports':       {'report_admin'},
        'admin.view_report_audit':    {'report_admin'},
        'admin.export_audit':         {'report_admin'},
        'admin.view_security':        {'report_admin'},

        # ---- System Admin ----
        'admin.manage_users':         {'system_admin'},
        'admin.create_user':          {'system_admin'},
        'admin.change_role':          {'system_admin'},
        'admin.deactivate_user':      {'system_admin'},
        'admin.reactivate_user':      {'system_admin'},
        'admin.approve_deletion':     {'system_admin'},
        'admin.deny_deletion':        {'system_admin'},
        'admin.view_system_audit':    {'system_admin'},
        'admin.view_platform_config': {'system_admin'},

        # ---- API ----
        'api.view_audit':             {'report_admin', 'system_admin'},
        'api.view_stats':             {'whistleblower', 'report_admin', 'system_admin'},
    }

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------

    @classmethod
    def is_valid_role(cls, role: str) -> bool:
        return role in cls.ROLE_HIERARCHY

    @classmethod
    def can_assign_role(cls, acting_user, target_role: str) -> bool:
        """Privilege-escalation guard.

        Returns True iff *acting_user* may grant *target_role* to someone else.
        Rule: the target role must be strictly lower in the hierarchy than the
        acting user's own role (a system_admin can assign report_admin, but
        cannot assign system_admin to anyone -- including themselves).
        """
        if not cls.is_valid_role(target_role):
            return False
        if acting_user is None or acting_user.role not in cls.ROLE_HIERARCHY:
            return False
        return cls.ROLE_HIERARCHY[acting_user.role] > cls.ROLE_HIERARCHY[target_role]

    # ------------------------------------------------------------------
    # Action + resource checks
    # ------------------------------------------------------------------

    @classmethod
    def can(cls, user, action: str, resource=None) -> bool:
        """Return True iff *user* may perform *action* on *resource*.

        *resource* is optional and only inspected for report/user-scoped
        actions (the IDOR check below).
        """
        if user is None:
            return False
        # is_authenticated / is_active can raise DetachedInstanceError if the
        # user object was expunged (e.g. after session.clear()). Treat that
        # the same as "not authenticated" -- fail closed.
        try:
            if not getattr(user, 'is_authenticated', False):
                return False
            if not getattr(user, 'is_active', True):
                return False
        except Exception:
            return False

        allowed = cls.PERMISSIONS.get(action)
        if allowed is None:
            # Unknown action -- fail closed. This catches typos at runtime
            # (the decorator below catches them at import time too).
            current_app.logger.error(
                'AccessControl: unknown action "%s" requested by user %s',
                action, getattr(user, 'id', '?'),
            )
            return False
        if user.role not in allowed:
            return False

        # Resource-level (IDOR) check.
        if resource is not None:
            return cls._can_access_resource(user, action, resource)
        return True

    @classmethod
    def _can_access_resource(cls, user, action, resource):
        """IDOR guard. Returns True iff *user* may access *resource*."""
        # Late imports to avoid circular deps with app.models.
        from app.models import Report, User, Evidence

        if isinstance(resource, Evidence):
            # Ownership flows through the parent report.
            if resource.report_id is None:
                return False
            report = Report.query.get(resource.report_id)
            return report is not None and cls._can_access_report(user, report)

        if isinstance(resource, Report):
            return cls._can_access_report(user, resource)

        if isinstance(resource, User):
            # A user may always access their own profile. System admins may
            # access any user. Other roles have no business reading user
            # objects directly.
            if user.role == 'system_admin':
                return True
            return str(resource.id) == str(user.id)

        # Unknown resource type -- fail closed.
        return False

    @staticmethod
    def _can_access_report(user, report):
        """IDOR check for a Report row.

        whistleblower  -> must own it          (report.user_id == user.id)
        investigator   -> must be assigned      (report.investigator_id == user.id)
        report_admin   -> any report            (least-privilege: admin needs visibility
                                                 to triage, assign, and update status)
        system_admin   -> NO access to reports  (their job is user management, not
                                                 case content -- defence in depth)
        """
        if user is None or report is None:
            return False
        if user.role == 'whistleblower':
            return report.user_id is not None and str(report.user_id) == str(user.id)
        if user.role == 'investigator':
            return report.investigator_id is not None and str(report.investigator_id) == str(user.id)
        if user.role == 'report_admin':
            return True
        # system_admin, anonymous, or anything else: deny.
        return False

    # ------------------------------------------------------------------
    # Assert helper (used by the decorator)
    # ------------------------------------------------------------------

    @classmethod
    def assert_can(cls, user, action: str, resource=None):
        """Raise 403 if *user* cannot perform *action* on *resource*.

        Note: we return 403 (not 404) on auth failure so that legitimate users
        get a clear "you don't have permission" signal. UUIDs make the
        existence-or-not distinction impractical to probe (122 bits), so this
        does not enable enumeration.
        """
        if not cls.can(user, action, resource):
            # Log the denial so a SIEM can flag probes (Burp/scan patterns
            # stand out as a burst of 403s from one IP). Wrapped in
            # try/except so that an audit-log write failure (e.g. broken DB
            # session, trigger firing on a stale session) never cascades into
            # a 500 -- the 403 must still be returned to the client.
            try:
                from app.securityfeature.audit import AuditService
                AuditService.log(
                    action='authorisation_denied',
                    acting_user=user,
                    acting_role=getattr(user, 'role', 'anonymous') if user else 'anonymous',
                    details=f'Denied: {action}',
                    ip_address=getattr(request, 'remote_addr', None) if request else None,
                )
            except Exception:
                try:
                    current_app.logger.warning(
                        'Failed to write authorisation_denied audit entry '
                        'for action=%s (audit failure does not mask the 403)',
                        action,
                    )
                except Exception:
                    pass
            abort(403)


# ---------------------------------------------------------------------------
# UUID validation (used by resource loaders -- cheap, no DB hit)
# ---------------------------------------------------------------------------

def is_valid_uuid(value) -> bool:
    """True iff *value* looks like a canonical UUID string.

    Used to short-circuit URL probes (e.g. `/reports/1`) before they touch
    the database -- returns 404 immediately rather than a DB miss.
    """
    if not value or not isinstance(value, str):
        return False
    try:
        UUID(value, version=4)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Resource loaders (passed to @require_permission's resource_loader=...)
# ---------------------------------------------------------------------------

def load_report_from_url(kwargs):
    """Fetch a Report by `<report_id>` URL param, validating UUID first.

    Returns the Report or aborts (404 for malformed UUID or missing row).
    Ownership is NOT checked here -- the decorator runs `can()` on the
    returned resource, which is where the IDOR check lives.
    """
    from app.models import Report
    report_id = kwargs.get('report_id')
    if not is_valid_uuid(report_id):
        abort(404)
    report = Report.query.get(report_id)
    if report is None:
        abort(404)
    return report


def load_evidence_from_url(kwargs):
    """Fetch Evidence by `<evidence_id>` URL param.

    The IDOR check on Evidence flows through the parent Report -- the
    decorator's `can()` call will load the report and check ownership.
    """
    from app.models import Evidence
    evidence_id = kwargs.get('evidence_id')
    if not is_valid_uuid(evidence_id):
        abort(404)
    evidence = Evidence.query.get(evidence_id)
    if evidence is None:
        abort(404)
    return evidence


def load_user_from_url(kwargs):
    """Fetch a User by `<user_id>` URL param (used by admin user-management routes)."""
    from app.models import User
    user_id = kwargs.get('user_id')
    if not is_valid_uuid(user_id):
        abort(404)
    user = User.query.get(user_id)
    if user is None:
        abort(404)
    return user


# ---------------------------------------------------------------------------
# Route decorator
# ---------------------------------------------------------------------------

def require_permission(action: str, resource_loader=None):
    """Decorator enforcing role + resource-level access on a route.

    Usage:
        @reports_bp.route('/<report_id>')
        @login_required
        @require_permission('report.view', resource_loader=load_report_from_url)
        def view_report(report_id, resource=None):
            report = resource  # already fetched + ownership-checked

    Behaviour:
      1. The user must be authenticated (caller is expected to also apply
         @login_required; this decorator does NOT redirect, it 403s -- which
         is correct for an API, and @login_required handles the redirect case
         for browser routes).
      2. `can(user, action)` is checked. Unknown actions fail closed.
      3. If *resource_loader* is provided, it is called with the route's
         kwargs. The returned resource is then passed to `can(user, action,
         resource)` for the IDOR check, and injected into the route as
         `resource=<obj>` so the route body doesn't re-fetch it.
      4. On denial, 403 is raised and an `authorisation_denied` audit entry
         is written.
    """
    # Validate the action name at decoration time -- catches typos like
    # `@require_permission('report.vew')` on app boot, not at request time.
    if action not in AccessControlService.PERMISSIONS:
        raise RuntimeError(
            f'require_permission: unknown action "{action}". '
            f'Add it to AccessControlService.PERMISSIONS first.'
        )

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = current_user
            resource = None
            if resource_loader is not None:
                # Loader may abort(404) for malformed UUIDs or missing rows.
                resource = resource_loader(kwargs)
            AccessControlService.assert_can(user, action, resource)
            # Inject the loaded resource ONLY when a loader was provided, so
            # routes that don't take a URL param don't need to declare a
            # `resource=None` kwarg.
            if resource_loader is not None:
                kwargs['resource'] = resource
            return view_func(*args, **kwargs)
        return wrapper
    return decorator
