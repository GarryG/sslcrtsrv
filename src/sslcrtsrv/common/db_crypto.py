# At-rest encryption for Certificate.private_key, using a dedicated RSA keypair
# (NOT the server's own identity keypair in server_config.json - see internal/security/SECURITY_FINDINGS.md #3).
# crtmanager.py/crtrequest.py only ever need the public half to encrypt on write;
# only server.py needs the private half to decrypt on retrieval.

import base64
import os
from functools import lru_cache

from .constants import DB_ENCRYPTION_PRIVATE_KEY_FILE, DB_ENCRYPTION_PUBLIC_KEY_FILE, SHARED_DIR_MODE
from .crypto_utils import generate_key_pair, save_keys, load_private_key, load_public_key, encrypt_data, decrypt_data
from .system_utils import ensure_secure_dir

# Legacy plaintext PEM always starts "-----BEGIN"; this marks ciphertext so migrated
# and not-yet-migrated rows are distinguishable without needing the key to check.
CIPHERTEXT_PREFIX = "ENC1:"


class DbKeyMissing(RuntimeError):
    """Raised when the DB encryption keypair is absent, unreadable, or the wrong one."""


def generate_db_keypair(overwrite=False, private_key_path=DB_ENCRYPTION_PRIVATE_KEY_FILE,
                         public_key_path=DB_ENCRYPTION_PUBLIC_KEY_FILE):
    """One-time setup: generate the dedicated keypair used to encrypt Certificate.private_key.
    Refuses to overwrite an existing private key, since doing so would make every
    already-encrypted row permanently unrecoverable."""
    if not overwrite and os.path.exists(private_key_path):
        raise FileExistsError(
            f"{private_key_path} already exists - refusing to overwrite it, since doing so "
            "would make every already-encrypted certificate private key permanently "
            "unrecoverable. Re-encrypt existing rows under a new key first if you really "
            "intend to replace this keypair."
        )
    config_dir = os.path.dirname(private_key_path)
    if config_dir:
        # Group-shared, like server_config.json's directory (usually the same
        # /etc/sslcrtsrv) - web_admin's "Add / Import Certificate" feature
        # needs to read the public key file here to encrypt on write. The
        # private key file itself stays owner-only regardless - see
        # crypto_utils.save_keys(), which never widens its permissions.
        ensure_secure_dir(config_dir, mode=SHARED_DIR_MODE)
    private_key, public_key = generate_key_pair()
    save_keys(private_key, public_key, private_key_path, public_key_path)


def is_encrypted(stored_value):
    return bool(stored_value) and stored_value.startswith(CIPHERTEXT_PREFIX)


@lru_cache(maxsize=4)
def _load_public_key_cached(path):
    return load_public_key(path)


@lru_cache(maxsize=4)
def _load_private_key_cached(path):
    return load_private_key(path)


def encrypt_for_storage(private_key_pem, public_key_path=DB_ENCRYPTION_PUBLIC_KEY_FILE):
    """Envelope-encrypt a PEM private-key string for the Certificate.private_key column.
    Empty/None values pass through unchanged (placeholder rows must stay falsy)."""
    if not private_key_pem:
        return private_key_pem
    try:
        public_key = _load_public_key_cached(public_key_path)
    except Exception as e:
        raise DbKeyMissing(
            f"Could not load DB encryption public key from {public_key_path}: {e}. "
            "Run 'crtmanager.py init-db-key' once and copy the public key file here."
        )
    encrypted_bytes = encrypt_data(private_key_pem, public_key)
    if encrypted_bytes is None:
        raise ValueError("Failed to encrypt private key for storage")
    return CIPHERTEXT_PREFIX + base64.b64encode(encrypted_bytes).decode("ascii")


def decrypt_for_storage(stored_value, private_key_path=DB_ENCRYPTION_PRIVATE_KEY_FILE):
    """Inverse of encrypt_for_storage. Passes through empty/None and legacy plaintext PEM
    (not yet migrated, i.e. no ENC1: prefix) unchanged."""
    if not stored_value or not is_encrypted(stored_value):
        return stored_value
    try:
        private_key = _load_private_key_cached(private_key_path)
    except Exception as e:
        raise DbKeyMissing(
            f"Could not load DB encryption private key from {private_key_path}: {e}. "
            "This file must exist on the host running server.py."
        )
    payload = stored_value[len(CIPHERTEXT_PREFIX):]
    encrypted_bytes = base64.b64decode(payload)
    decrypted_bytes = decrypt_data(encrypted_bytes, private_key)
    if decrypted_bytes is None:
        raise ValueError("Failed to decrypt private key from storage")
    return decrypted_bytes.decode("utf-8")
