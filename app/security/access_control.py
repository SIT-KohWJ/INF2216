"""AccessControlService - ALL role/ownership/assignment checks in one place.
Requirements E1, E4. Lead: (Authorisation story, 14-18 Jun)

Centralising authorisation here is the design's core authz decision: controllers
hold no security logic, so a missed check in a route cannot bypass authz.
"""

ROLES = ("whistleblower", "investigator", "admin", "system_admin")


class AccessControlService:
    @staticmethod
    def require_role(user, *allowed_roles) -> None:
        """Raise/deny if user.role not in allowed_roles. Server-side only (E1)."""
        raise NotImplementedError("E1: server-side role enforcement")

    @staticmethod
    def can_view_report(user, report) -> bool:
        """Ownership / assignment check (E4). Use UUID public_id, never a
        sequential id, to prevent IDOR enumeration (E2)."""
        raise NotImplementedError("E2/E4: ownership + IDOR prevention")
