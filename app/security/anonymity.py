"""AnonymityService - irreversible submitter link. Requirement A2 / NFR1.
Lead: Glen  |  Review: Darren
"""
import hashlib
import hmac
from flask import current_app


class AnonymityService:
    @staticmethod
    def submitter_hash(user_id: str) -> str:
        """Return HMAC-SHA256(user_id, server_secret) as 64 hex chars.

        This is the ONLY link stored between a user and a report. It must be
        deterministic (same user -> same hash, so an investigator can group a
        submitter's reports) yet irreversible without the secret key.

        Reference implementation (verify against your test vectors before use):
        """
        secret = current_app.config["HMAC_SECRET_KEY"].encode()
        return hmac.new(secret, str(user_id).encode(), hashlib.sha256).hexdigest()
