"""Authentication and credential lifecycle logic.

Pure service functions over an :class:`AsyncSession` — no FastAPI types here,
so every rule below is unit-testable without a request.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import utcnow
from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.passwords import validate as validate_password
from app.core.security import (
    generate_api_key,
    hash_api_key,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from app.core.settings import Settings, get_settings
from app.domains.auth.models import ApiKey, Role, User
from app.domains.auth.schemas import ApiKeyCreate, UserCreate

log = get_logger(__name__)

# Presented for every failure mode so the response cannot be used to probe
# which email addresses exist.
_GENERIC_AUTH_FAILURE = "Invalid credentials."
_INVALID_API_KEY = "Invalid API key."
_EXPIRED_API_KEY = "API key has expired."


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()


async def get_user(session: AsyncSession, user_id: str) -> User | None:
    return await session.get(User, user_id)


async def create_user(session: AsyncSession, payload: UserCreate) -> User:
    """Provision a user. Raises :class:`ConflictError` if the email is taken."""
    if await get_user_by_email(session, payload.email) is not None:
        msg = f"A user with email {payload.email} already exists."
        raise ConflictError(msg)

    # Policy is enforced here rather than in the schema because the breach
    # check is asynchronous and the schema is not.
    await validate_password(payload.password, get_settings(), email=payload.email)

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    session.add(user)
    await session.flush()
    log.info("user_created", user_id=user.id, role=user.role)
    return user


async def authenticate(
    session: AsyncSession,
    email: str,
    password: str,
    mfa_code: str | None = None,
) -> User:
    """Verify credentials and return the user.

    Raises :class:`AuthenticationError` with a deliberately uniform message for
    unknown user, wrong password, disabled account and bad MFA code alike.
    """
    settings = get_settings()
    now = utcnow()
    user = await get_user_by_email(session, email)

    if user is None:
        # Spend comparable time hashing so a missing user is not detectable by
        # response latency.
        hash_password(password)
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)

    # Checked before the password, so a locked account costs an attacker an
    # Argon2 verification they do not get to make — and so a correct password
    # cannot reset the counter while a lockout is in force.
    if settings.account_lockout_enabled and user.is_locked(now):
        log.warning("auth_failed", reason="locked", user_id=user.id)
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)

    if not verify_password(password, user.password_hash):
        await _register_failure(session, user, settings, now, reason="bad_password")
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)

    if not user.is_active:
        log.info("auth_failed", reason="inactive", user_id=user.id)
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)

    if user.role == Role.ADMIN:
        try:
            _verify_admin_mfa(user, mfa_code)
        except AuthenticationError:
            # A correct password with a wrong code still counts: otherwise the
            # second factor becomes an unlimited guessing oracle.
            await _register_failure(session, user, settings, now, reason="bad_mfa")
            raise

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    await session.flush()
    log.info("auth_succeeded", user_id=user.id, role=user.role)
    return user


async def _register_failure(
    session: AsyncSession,
    user: User,
    settings: Settings,
    now: datetime,
    *,
    reason: str,
) -> None:
    """Count a failed attempt, locking the account once the threshold is hit.

    Committed rather than flushed: the caller raises immediately afterwards,
    and the request's transaction would otherwise roll the counter back —
    leaving the lockout permanently one attempt from triggering.
    """
    if not settings.account_lockout_enabled:
        log.info("auth_failed", reason=reason, user_id=user.id)
        return

    user.failed_login_attempts += 1
    locked = user.failed_login_attempts >= settings.account_lockout_threshold

    if locked:
        locked_until = now + timedelta(seconds=settings.account_lockout_seconds)
        user.locked_until = locked_until
        log.warning(
            "account_locked",
            user_id=user.id,
            attempts=user.failed_login_attempts,
            until=locked_until.isoformat(),
        )
    else:
        log.info("auth_failed", reason=reason, user_id=user.id, attempts=user.failed_login_attempts)

    await session.commit()


def _verify_admin_mfa(user: User, mfa_code: str | None) -> None:
    """Admins must complete MFA; enrolment is not optional."""
    if user.mfa_secret is None:
        log.warning("auth_failed", reason="admin_mfa_not_enrolled", user_id=user.id)
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)
    if mfa_code is None or not pyotp.TOTP(user.mfa_secret).verify(mfa_code, valid_window=1):
        log.info("auth_failed", reason="bad_mfa", user_id=user.id)
        raise AuthenticationError(_GENERIC_AUTH_FAILURE)


def provision_mfa_secret(user: User, issuer: str) -> str:
    """Assign a fresh TOTP seed and return the enrolment URI for a QR code."""
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    return pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=issuer)


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
async def create_api_key(
    session: AsyncSession,
    payload: ApiKeyCreate,
    default_owner: User,
) -> tuple[ApiKey, str]:
    """Mint an API key, returning the row and the one-time plaintext.

    A key always has an owner, and acts with exactly that user's
    visibility — there is no way to mint a key that sees more than the
    person holding it.
    """
    generated = generate_api_key()
    api_key = ApiKey(
        name=payload.name,
        key_digest=generated.digest,
        scopes=" ".join(sorted(set(payload.scopes))),
        expires_at=payload.expires_at,
        owner_id=payload.owner_id or default_owner.id,
    )
    session.add(api_key)
    await session.flush()
    log.info("api_key_created", api_key_id=api_key.id, scopes=api_key.scopes)
    return api_key, generated.plaintext


async def resolve_api_key(session: AsyncSession, plaintext: str) -> ApiKey:
    """Look up a live key by its plaintext, updating ``last_used_at``."""
    digest = hash_api_key(plaintext)
    result = await session.execute(select(ApiKey).where(ApiKey.key_digest == digest))
    api_key = result.scalar_one_or_none()

    if api_key is None or api_key.revoked_at is not None:
        raise AuthenticationError(_INVALID_API_KEY)
    if api_key.expires_at is not None and api_key.expires_at <= utcnow():
        raise AuthenticationError(_EXPIRED_API_KEY)

    api_key.last_used_at = utcnow()
    return api_key


async def revoke_api_key(session: AsyncSession, api_key_id: str) -> ApiKey:
    api_key = await session.get(ApiKey, api_key_id)
    if api_key is None:
        msg = f"No API key with id {api_key_id}."
        raise NotFoundError(msg)
    api_key.revoked_at = utcnow()
    log.info("api_key_revoked", api_key_id=api_key_id)
    return api_key
