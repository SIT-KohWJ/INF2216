"""AuditService - append-only audit logging. Requirements F1-F4.
Lead: (Logging story, 25-30 Jun)
"""


class AuditService:
    @staticmethod
    def record(event_type: str, *, actor_role: str | None = None,
               report_id=None, target_entity: str | None = None,
               ip_address_hash: str | None = None, details: dict | None = None):
        """Insert an AuditLog row. Records the ACTING ROLE, never submitter
        identity (F2/F3). The DB trigger blocks UPDATE/DELETE, so this is
        insert-only by construction."""
        raise NotImplementedError("F1-F4: write append-only audit entry")
