"""Primitives for the dual authentication context.

Two audiences, two mechanisms:

* **Internal admins** authenticate with a password and carry a signed,
  HTTP-only session cookie (see :func:`issue_session` / :func:`read_session`).
* **External integrations** present a bearer API key. Only the SHA-256 digest
  is persisted, so a database leak does not yield usable credentials.

Scoped JWTs are also provided for short-lived, delegated machine access.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.database import utcnow
from app.core.settings import get_settings

# Argon2id with library defaults: a deliberate, review-friendly choice over
# hand-tuned parameters that drift out of date.
_hasher: Final = PasswordHasher()

_SESSION_SALT: Final = "session-v1"
API_KEY_PREFIX: Final = "app_sk_"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Return an Argon2id digest for ``password``."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification that never raises on bad input."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True when the stored digest predates the current Argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class GeneratedApiKey:
    """A freshly minted key: the plaintext is returned to the caller once."""

    plaintext: str
    digest: str


def generate_api_key() -> GeneratedApiKey:
    """Mint an API key, returning the plaintext and the digest to persist."""
    plaintext = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return GeneratedApiKey(plaintext=plaintext, digest=hash_api_key(plaintext))


def hash_api_key(plaintext: str) -> str:
    """Digest an API key for storage and lookup.

    A plain SHA-256 is correct here (unlike for passwords): the key is
    high-entropy random, so there is nothing to brute-force, and lookups must
    stay a single indexed query.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def api_keys_equal(left: str, right: str) -> bool:
    """Compare two digests without leaking timing information."""
    return hmac.compare_digest(left, right)


# ---------------------------------------------------------------------------
# Session cookies (admin context)
# ---------------------------------------------------------------------------
def _serializers() -> list[URLSafeTimedSerializer]:
    """One serializer per configured secret, current first.

    Signing always uses the first; verification tries each in turn, so a
    secret rotation does not sign every live session out. See core/crypto.py
    for the rotation procedure.
    """
    settings = get_settings()
    secrets_in_use = [settings.secret_key.get_secret_value()]
    secrets_in_use.extend(key.get_secret_value() for key in settings.previous_secret_keys)
    return [
        URLSafeTimedSerializer(secret_key=secret, salt=_SESSION_SALT) for secret in secrets_in_use
    ]


def issue_session(user_id: str) -> str:
    """Sign a session payload for the given user, with the current secret."""
    return _serializers()[0].dumps({"sub": user_id})


def read_session(token: str) -> str | None:
    """Return the user id from a session cookie, or ``None`` if unusable."""
    settings = get_settings()
    for serializer in _serializers():
        try:
            payload = serializer.loads(token, max_age=settings.session_max_age_seconds)
        except (BadSignature, SignatureExpired):
            continue
        if not isinstance(payload, dict):
            return None
        subject = payload.get("sub")
        return subject if isinstance(subject, str) else None
    return None


# ---------------------------------------------------------------------------
# Scoped JWTs (machine context)
# ---------------------------------------------------------------------------
def issue_access_token(
    subject: str,
    scopes: list[str],
    ttl: timedelta | None = None,
) -> str:
    """Issue a short-lived bearer token carrying explicit scopes."""
    settings = get_settings()
    lifetime = ttl or timedelta(seconds=settings.access_token_ttl_seconds)
    now = utcnow()
    claims: dict[str, Any] = {
        "sub": subject,
        "scope": " ".join(scopes),
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
    }
    return jwt.encode(
        claims,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Validated claims extracted from an access token."""

    subject: str
    scopes: frozenset[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def decode_access_token(token: str) -> TokenClaims | None:
    """Verify and decode a token, returning ``None`` if it is not valid."""
    settings = get_settings()
    candidates = [settings.secret_key.get_secret_value()]
    candidates.extend(key.get_secret_value() for key in settings.previous_secret_keys)

    payload: dict[str, Any] | None = None
    for secret in candidates:
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[settings.jwt_algorithm],
                options={"require": ["exp", "sub"]},
            )
        except jwt.PyJWTError:
            continue
        break

    if payload is None:
        return None

    subject = payload.get("sub")
    if not isinstance(subject, str):
        return None
    raw_scope = payload.get("scope", "")
    scopes = frozenset(raw_scope.split()) if isinstance(raw_scope, str) else frozenset()
    return TokenClaims(subject=subject, scopes=scopes)
