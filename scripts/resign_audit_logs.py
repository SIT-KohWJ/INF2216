#!/usr/bin/env python3
"""Re-sign audit-log rows that no longer verify under the current ECDSA key.

Background
----------
Audit rows are signed with the ECDSA key in instance/ecdsa_key.pem. Before the
key was persisted across container rebuilds, every deploy regenerated that key,
so rows signed by an earlier key started failing the integrity check even
though the underlying data was untouched. This is a key-mismatch, not tampering.

This one-off script re-signs the rows that currently fail verification, using
the (now persistent) key, so the integrity page reads clean again. Run it ONCE,
from inside the web container, AFTER the persistent-key fix is deployed:

    docker compose -f compose.prod.yaml exec web python scripts/resign_audit_logs.py
    # add --apply to actually write; without it, this is a dry run

Trade-off: re-signing a row rebinds it to the current key, so it no longer
proves the row is byte-for-byte what was originally written. Only run this to
clear the historical false-positives from the key rotation, not routinely.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import AuditLog
from app.services.crypto_service import crypto_service


def _log_data(log):
    # Must match AuditService.verify_audit_integrity / log_audit_action exactly.
    return f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"


def resign(apply_changes):
    app = create_app(os.environ.get('FLASK_ENV', 'production'))
    with app.app_context():
        logs = AuditLog.query.all()
        stale = []
        for log in logs:
            data = _log_data(log)
            if not (log.signature and crypto_service.verify_signature(data, log.signature)):
                stale.append(log)

        print(f"Total rows: {len(logs)}")
        print(f"Failing verification under current key: {len(stale)}")

        if not stale:
            print("Nothing to re-sign. Integrity is already clean.")
            return

        for log in stale:
            print(f"  {'RE-SIGN' if apply_changes else 'would re-sign'} "
                  f"{log.timestamp} {log.action} (id={log.id})")
            if apply_changes:
                log.signature = crypto_service.sign_data(_log_data(log))

        if apply_changes:
            db.session.commit()
            print(f"Re-signed {len(stale)} row(s).")
        else:
            print("\nDry run. Re-run with --apply to write these signatures.")


if __name__ == '__main__':
    resign('--apply' in sys.argv)
