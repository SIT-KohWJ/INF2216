# NOTE: these are pycryptodome imports (maintained), NOT the dead pycrypto.
# Bandit's B413 can't tell them apart by namespace, so we suppress it here.
from Crypto.Cipher import AES  # nosec B413
from Crypto.Hash import HMAC, SHA256  # nosec B413
from Crypto.PublicKey import ECC  # nosec B413
from Crypto.Signature import DSS  # nosec B413
from Crypto.Random import get_random_bytes  # nosec B413
from Crypto.Util.Padding import pad, unpad  # nosec B413
import os
import base64


class CryptoService:
    def __init__(self):
        self.encryption_key = None
        self.hmac_key = None
        self.ecdsa_private_key = None
        self.ecdsa_public_key = None

    @staticmethod
    def _derive_key(value):
        """Return a stable 32-byte key from a config string.

        Key material reaches us in three shapes: a 64-char hex string (the
        original SITinform .env), a base64 Fernet key (compose
        FIELD_ENCRYPTION_KEY), or an arbitrary plain string (CI throwaway like
        "ci-field-encryption-key"). Only the first is valid hex of the right
        length; everything else is hashed to a deterministic 32 bytes so
        AES-256 always gets a usable key.
        """
        if value is None:
            value = os.urandom(32).hex()
        try:
            raw = bytes.fromhex(value)
            if len(raw) == 32:
                return raw
        except (ValueError, TypeError):
            pass
        return SHA256.new(value.encode('utf-8')).digest()

    def init_app(self, app):
        self.encryption_key = self._derive_key(app.config.get('ENCRYPTION_KEY'))
        self.hmac_key = self._derive_key(app.config.get('HMAC_SECRET_KEY'))

        instance_path = os.path.join(app.instance_path if hasattr(app, 'instance_path') else 'instance')
        os.makedirs(instance_path, exist_ok=True)
        key_path = os.path.join(instance_path, 'ecdsa_key.pem')

        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                self.ecdsa_private_key = ECC.import_key(f.read())
        else:
            self.ecdsa_private_key = ECC.generate(curve='P-256')
            with open(key_path, 'wb') as f:
                f.write(self.ecdsa_private_key.export_key(format='PEM').encode('utf-8'))

        self.ecdsa_public_key = self.ecdsa_private_key.public_key()

    def encrypt_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        nonce = get_random_bytes(12)
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = base64.b64decode(encrypted_data)
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
            decrypted = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception:
            return None

    def generate_user_hash(self, user_id):
        h = HMAC.new(self.hmac_key, digestmod=SHA256)
        h.update(user_id.encode('utf-8'))
        return h.hexdigest()

    def verify_user_hash(self, user_id, user_hash):
        return self.generate_user_hash(user_id) == user_hash

    def generate_reference_number(self):
        return 'SIT-' + get_random_bytes(5).hex().upper()

    def generate_password_reset_token(self):
        return get_random_bytes(32).hex()

    def sign_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = SHA256.new(data)
        signer = DSS.new(self.ecdsa_private_key, 'fips-186-3')
        return base64.b64encode(signer.sign(h)).decode('utf-8')

    def verify_signature(self, data, signature):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            h = SHA256.new(data)
            verifier = DSS.new(self.ecdsa_public_key, 'fips-186-3')
            verifier.verify(h, base64.b64decode(signature))
            return True
        except Exception:
            return False

    def log_audit_action(self, action, acting_user=None, acting_role='system', target_type=None, target_id=None, details=None, ip_address=None):
        from app.models import AuditLog
        from app import db

        log = AuditLog(
            action=action, acting_user_id=acting_user.id if acting_user else None,
            acting_role=acting_role, target_type=target_type, target_id=target_id,
            details=details, ip_address=ip_address
        )
        log_data = f"{log.action}:{log.acting_role}:{log.target_type}:{log.target_id}:{log.details}"
        log.signature = self.sign_data(log_data)
        db.session.add(log)
        db.session.commit()
        return log


crypto_service = CryptoService()


def init_crypto(app):
    crypto_service.init_app(app)
