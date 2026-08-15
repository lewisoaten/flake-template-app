"""Field-level encryption at rest, and the key schedule behind it.

Some columns hold credentials rather than data. A TOTP seed is the clearest
example: anyone holding it can mint valid codes forever, so a database dump —
or a backup on someone's laptop — hands over the second factor entirely.
Hashing is not an option, because the application has to recover the value to
verify a code. That leaves encryption.

**Key management.** Keys are derived from ``APP_SECRET_KEY`` via HKDF with a
per-purpose ``info`` label, so the encryption key is not the signing key even
though both come from one configured secret. One secret to manage, no
key-derivation ceremony for the operator, and no cross-purpose key reuse.

**Rotation.** ``APP_PREVIOUS_SECRET_KEYS`` holds superseded secrets. New writes
always use the current key; reads try the current key first and then each
previous one in turn. That makes rotation a deploy rather than an outage:

1. Move the live secret into ``APP_PREVIOUS_SECRET_KEYS`` and set a new
   ``APP_SECRET_KEY``. Deploy. Everything still decrypts and existing sessions
   still validate.
2. Run ``just rotate-encrypted`` to rewrite stored ciphertext under the new key.
3. Drop the old secret from ``APP_PREVIOUS_SECRET_KEYS``. Deploy.

Skipping step 2 is safe but leaves you unable to ever retire the old secret.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Any, Final

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import String, TypeDecorator
from sqlalchemy.engine import Dialect

from app.core.settings import get_settings

# Domain separation: a key derived for encryption must never coincide with one
# used for signing, even though both descend from APP_SECRET_KEY.
_ENCRYPTION_INFO: Final = b"app-field-encryption-v1"


class DecryptionError(RuntimeError):
    """Stored ciphertext could not be read with any configured key.

    In practice this means a secret was rotated without keeping the old value
    in ``APP_PREVIOUS_SECRET_KEYS``, and the affected rows are unrecoverable.
    """


def _fernet_key(secret: str) -> bytes:
    """Derive a Fernet key from an application secret."""
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_ENCRYPTION_INFO)
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


@lru_cache(maxsize=1)
def _cipher() -> MultiFernet:
    """The cipher stack: current key first, then superseded keys.

    MultiFernet encrypts with the first key and decrypts with whichever works,
    which is exactly the rotation behaviour described above.
    """
    settings = get_settings()
    secrets = [settings.secret_key.get_secret_value()]
    secrets.extend(key.get_secret_value() for key in settings.previous_secret_keys)
    return MultiFernet([Fernet(_fernet_key(secret)) for secret in secrets])


def reset_cipher_cache() -> None:
    """Forget the derived keys. Called after settings change, and in tests."""
    _cipher.cache_clear()


def encrypt(value: str) -> str:
    """Encrypt ``value`` under the current key."""
    return _cipher().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    """Decrypt ``token`` using whichever configured key wrote it."""
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        msg = (
            "Could not decrypt a stored value with any configured key. "
            "Was APP_SECRET_KEY rotated without keeping the old value in "
            "APP_PREVIOUS_SECRET_KEYS?"
        )
        raise DecryptionError(msg) from exc


def rotate(token: str) -> str:
    """Re-encrypt existing ciphertext under the current key."""
    return _cipher().rotate(token.encode()).decode()


class EncryptedString(TypeDecorator[str]):
    """A string column encrypted at rest, transparent to the ORM.

    Values are ciphertext in the database and plaintext in Python, so the
    application code that uses them needs no changes.

    The cost is that the column becomes opaque to SQL: you cannot index it,
    search it, or filter on it, because every row encrypts to different bytes.
    Reach for this only where that is acceptable — a credential you look up *by
    something else* and then use, which is exactly the TOTP seed case.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:  # noqa: ARG002
        if value is None:
            return None
        return encrypt(str(value))

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:  # noqa: ARG002
        if value is None:
            return None
        return decrypt(str(value))
