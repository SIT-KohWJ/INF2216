"""One-time re-baseline: re-sign audit log entries whose signatures no longer verify.

Before compose.prod.yaml persisted instance/ (instance_data volume), the ECDSA
audit-signing key lived in the web container's ephemeral layer, so every rebuild
minted a new key and permanently orphaned the signatures of all earlier entries.
Those rows are not tampered — the keys that signed them are simply gone. This
script re-signs exactly those rows with the current (now persistent) key so the
integrity check reflects tampering again instead of lost keys.

Trade-off to note in the project report: re-signing forfeits tamper-evidence for
the affected historical rows (anyone with the current key could have rewritten
them). Acceptable as a one-time baseline reset; entries written after the volume
fix keep their original signatures and full tamper-evidence.

Run once, inside the web container, ONLY AFTER the instance_data volume fix is
deployed (otherwise the next rebuild orphans everything again):
  docker compose -f compose.prod.yaml exec web python resign_audit_logs.py
"""
from app import create_app, db
from app.models import AuditLog
from app.services.crypto_service import crypto_service


def main():
    app = create_app()
    with app.app_context():
        logs = AuditLog.query.all()
        resigned = 0
        already_valid = 0
        for log in logs:
            log_data = f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"
            if log.signature and crypto_service.verify_signature(log_data, log.signature):
                already_valid += 1
            else:
                log.signature = crypto_service.sign_data(log_data)
                resigned += 1
        db.session.commit()
        print(f"Done. resigned={resigned} already_valid={already_valid} total={len(logs)}")


if __name__ == '__main__':
    main()
