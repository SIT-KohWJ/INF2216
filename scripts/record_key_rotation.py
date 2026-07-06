#!/usr/bin/env python3
"""Append a signed key-rotation marker to the audit log (one-off).

Run this ONCE, from inside the web container, after the ECDSA signing key has
changed and existing audit rows no longer verify (e.g. the first boot after the
persistent-key volume fix). It APPENDS a single signed 'key_rotation' row — it
never modifies existing rows, so it is compatible with the append-only trigger
on audit_logs.

After this runs, AuditService.verify_audit_integrity() reports rows written
before the marker as 'historical' (signed by a superseded key) instead of
'invalid', while any genuine tampering still surfaces as invalid.

    docker compose -f compose.prod.yaml exec web python scripts/record_key_rotation.py

Safe to think about before running: it only inserts one row. Re-running just
adds another marker (the newest valid one wins), so it is idempotent in effect
but leaves extra rows — run it only when you actually rotate the key.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.audit_service import AuditService


def main():
    app = create_app(os.environ.get('FLASK_ENV', 'production'))
    with app.app_context():
        before = AuditService.verify_audit_integrity()
        print(f"Before: total={before['total']} valid={before['valid']} "
              f"invalid={before['invalid']} historical={before.get('historical', 0)}")

        marker = AuditService.record_key_rotation()
        print(f"Appended key_rotation marker id={marker.id} at {marker.timestamp}")

        after = AuditService.verify_audit_integrity()
        print(f"After:  total={after['total']} valid={after['valid']} "
              f"invalid={after['invalid']} historical={after.get('historical', 0)}")
        print("Done. Pre-rotation rows are now reported as historical, not invalid.")


if __name__ == '__main__':
    main()
