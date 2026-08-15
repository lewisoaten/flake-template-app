"""Account lockout.

Rate limiting throttles a *source*. Lockout protects an *account*, which is the
case rate limiting misses: attempts spread across many addresses each stay under
the per-source limit while still hammering one login.
"""

from __future__ import annotations

import httpx
import pyotp
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_sessionmaker, utcnow
from app.core.settings import get_settings
from app.domains.auth.models import User
from tests.conftest import MEMBER_PASSWORD


async def _attempt(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post("/login", data={"email": email, "password": password})


async def _reload(user_id: str) -> User:
    """Read the user on an independent session.

    The lockout counter is committed by `_register_failure` precisely so it
    survives the failed request's rollback; reading it back on another session
    is what proves that.
    """
    async with get_sessionmaker()() as session:
        user = await session.get(User, user_id)
        assert user is not None
        return user


class TestLockout:
    async def test_repeated_failures_lock_the_account(
        self,
        client: httpx.AsyncClient,
        member_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP_ACCOUNT_LOCKOUT_THRESHOLD", "3")
        # Take rate limiting out of the picture so this test describes lockout.
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        for _ in range(3):
            assert (await _attempt(client, member_user.email, "wrong-password")).status_code == 401

        reloaded = await _reload(member_user.id)
        assert reloaded.failed_login_attempts >= 3
        assert reloaded.is_locked(utcnow())

    async def test_a_locked_account_refuses_the_correct_password(
        self,
        client: httpx.AsyncClient,
        member_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The point of lockout: knowing the password is no longer sufficient."""
        monkeypatch.setenv("APP_ACCOUNT_LOCKOUT_THRESHOLD", "3")
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        for _ in range(3):
            await _attempt(client, member_user.email, "wrong-password")

        response = await _attempt(client, member_user.email, MEMBER_PASSWORD)
        assert response.status_code == 401

    async def test_the_counter_survives_the_failed_requests_rollback(
        self,
        client: httpx.AsyncClient,
        member_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression guard: a flush rather than a commit would be discarded
        when the request raises, leaving the account permanently one attempt
        away from locking."""
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        await _attempt(client, member_user.email, "wrong-password")
        assert (await _reload(member_user.id)).failed_login_attempts == 1

    async def test_a_successful_sign_in_clears_the_counter(
        self,
        client: httpx.AsyncClient,
        member_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        await _attempt(client, member_user.email, "wrong-password")
        assert (await _attempt(client, member_user.email, MEMBER_PASSWORD)).status_code == 303

        reloaded = await _reload(member_user.id)
        assert reloaded.failed_login_attempts == 0
        assert reloaded.locked_until is None

    async def test_a_wrong_mfa_code_counts_as_a_failure(
        self,
        client: httpx.AsyncClient,
        admin_user: User,
        db_session: AsyncSession,  # noqa: ARG002 - ensures the user is committed
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Otherwise the second factor is an unlimited guessing oracle for
        anyone who already has the password."""
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        from tests.conftest import ADMIN_PASSWORD

        response = await client.post(
            "/login",
            data={
                "email": admin_user.email,
                "password": ADMIN_PASSWORD,
                "mfa_code": "000000",
            },
        )
        assert response.status_code == 401
        assert (await _reload(admin_user.id)).failed_login_attempts == 1

    async def test_a_correct_code_after_a_wrong_one_still_works(
        self,
        client: httpx.AsyncClient,
        admin_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        from tests.conftest import ADMIN_PASSWORD

        assert admin_user.mfa_secret is not None
        await client.post(
            "/login",
            data={"email": admin_user.email, "password": ADMIN_PASSWORD, "mfa_code": "000000"},
        )
        response = await client.post(
            "/login",
            data={
                "email": admin_user.email,
                "password": ADMIN_PASSWORD,
                "mfa_code": pyotp.TOTP(admin_user.mfa_secret).now(),
            },
        )
        assert response.status_code == 303

    async def test_lockout_can_be_disabled(
        self,
        client: httpx.AsyncClient,
        member_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP_ACCOUNT_LOCKOUT_ENABLED", "false")
        monkeypatch.setenv("APP_RATE_LIMIT_ENABLED", "false")
        get_settings.cache_clear()

        for _ in range(5):
            await _attempt(client, member_user.email, "wrong-password")

        assert (await _reload(member_user.id)).failed_login_attempts == 0
        assert (await _attempt(client, member_user.email, MEMBER_PASSWORD)).status_code == 303


class TestEncryptedSecretAtRest:
    async def test_the_totp_seed_is_ciphertext_in_the_database(
        self,
        admin_user: User,
    ) -> None:
        """A database dump must not hand over the second factor."""
        from sqlalchemy import text

        plaintext = admin_user.mfa_secret
        assert plaintext is not None

        # Bypass the ORM so the type decorator does not decrypt on the way out.
        async with get_sessionmaker()() as session:
            stored = await session.scalar(
                text("SELECT mfa_secret FROM users WHERE id = :id"),
                {"id": admin_user.id},
            )

        assert stored is not None
        assert stored != plaintext
        assert plaintext not in stored

    async def test_it_still_round_trips_through_the_orm(self, admin_user: User) -> None:
        async with get_sessionmaker()() as session:
            reloaded = await session.get(User, admin_user.id)
            assert reloaded is not None
            assert reloaded.mfa_secret == admin_user.mfa_secret
