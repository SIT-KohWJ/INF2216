"""Read-only diagnostic for audit-log integrity. Mutates nothing.

Prints, for the currently-invalid rows, how they sit relative to the most
recent VALID key_rotation marker. This tells us whether appending a fresh
rotation marker (dated now) would reclassify them as 'historical'.

Run inside the web container:
  docker compose -f compose.prod.yaml exec web python diagnose_audit.py
"""
from app import create_app
from app.models import AuditLog
from app.services.crypto_service import crypto_service
from app.services.audit_service import AuditService


def main():
    app = create_app()
    with app.app_context():
        boundary = AuditService._rotation_boundary()
        print(f"Most recent VALID key_rotation marker timestamp: {boundary}")

        markers = AuditLog.query.filter(AuditLog.action == 'key_rotation').all()
        print(f"Total key_rotation markers present: {len(markers)}")
        for m in markers:
            data = f"{m.action}:{m.acting_role}:{m.target_type}:{m.target_id}:{m.details}"
            ok = bool(m.signature and crypto_service.verify_signature(data, m.signature))
            print(f"  marker {m.timestamp}  verifies={ok}  details={m.details!r}")

        logs = AuditLog.query.all()
        invalid = []
        for log in logs:
            d = f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"
            if log.signature and crypto_service.verify_signature(d, log.signature):
                continue
            if boundary is not None and log.timestamp is not None and log.timestamp < boundary:
                continue  # already historical
            invalid.append(log)

        print(f"\nCurrently-INVALID rows (not covered by any marker): {len(invalid)}")
        if invalid:
            invalid.sort(key=lambda x: (x.timestamp is None, x.timestamp))
            print(f"  earliest invalid: {invalid[0].timestamp}")
            print(f"  latest   invalid: {invalid[-1].timestamp}")
            print("  action breakdown:")
            counts = {}
            for x in invalid:
                counts[x.action] = counts.get(x.action, 0) + 1
            for a, c in sorted(counts.items(), key=lambda kv: -kv[1]):
                print(f"    {c:4d}  {a}")
        print("\nIf ALL invalid rows are OLDER than 'now', appending a fresh "
              "key_rotation marker will reclassify them as historical.")


if __name__ == '__main__':
    main()
