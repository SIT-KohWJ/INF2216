"""One-time migration: strip submitter identity (email/name) from the encrypted
payload of ALL existing reports.

Older reports stored submitter_email/submitter_name inside encrypted_data, which
made a deleted whistleblower's identity recoverable by anyone with the encryption
key. New reports no longer store these fields; this backfill removes them from
reports created before that change (including reports of already-deleted accounts).

Run once inside the app environment:  python scrub_report_pii.py
"""
import json

from app import create_app, db
from app.models import Report
from app.services.crypto_service import crypto_service


def main():
    app = create_app()
    with app.app_context():
        reports = Report.query.all()
        scrubbed = 0
        skipped = 0
        errors = 0
        for report in reports:
            if not report.encrypted_data:
                skipped += 1
                continue
            try:
                data = json.loads(crypto_service.decrypt_data(report.encrypted_data))
            except Exception as exc:  # noqa: BLE001
                print(f"  ! {report.reference_number}: could not decrypt ({exc}) — skipped")
                errors += 1
                continue
            if 'submitter_email' in data or 'submitter_name' in data:
                data.pop('submitter_email', None)
                data.pop('submitter_name', None)
                report.encrypted_data = crypto_service.encrypt_data(json.dumps(data))
                scrubbed += 1
            else:
                skipped += 1
        db.session.commit()
        print(f"Done. scrubbed={scrubbed} already_clean/empty={skipped} errors={errors} total={len(reports)}")


if __name__ == '__main__':
    main()
