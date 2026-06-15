"""EncryptionService - AES-256-GCM field encryption at rest. Requirement A3.
Lead: Glen  |  Review: Darren

NOTE for the crypto lead: .env.example currently generates FIELD_ENCRYPTION_KEY
with Fernet.generate_key() (Fernet = AES-128-CBC + HMAC), but Report 1 specifies
AES-256-GCM. Reconcile these two before implementing — either switch the key
generation to a 32-byte key for AESGCM, or document the deviation. Flagging so
it doesn't silently mismatch the design.
"""


class EncryptionService:
    @staticmethod
    def encrypt(plaintext: str) -> bytes:
        """Encrypt a field, returning ciphertext to store in a BYTEA column.
        Must use AES-256-GCM (confidentiality + integrity) with a fresh nonce
        per message, and store nonce alongside the ciphertext.
        """
        raise NotImplementedError("A3: implement AES-256-GCM encrypt (Glen)")

    @staticmethod
    def decrypt(ciphertext: bytes) -> str:
        raise NotImplementedError("A3: implement AES-256-GCM decrypt (Glen)")
