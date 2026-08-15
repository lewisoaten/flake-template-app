"""The rate limiter, exercised against both backends.

The two are tested through the same assertions on purpose: the point of the
``RateLimiter`` protocol is that swapping backends changes throughput and
correctness-under-concurrency, not behaviour.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ratelimit import (
    DatabaseLimiter,
    MemoryLimiter,
    RateLimitCounter,
    database_limiter,
    limiter_for,
    memory_limiter,
    purge_expired,
)
from app.core.settings import Settings

WINDOW = 60


@pytest.fixture
def memory() -> MemoryLimiter:
    """A private instance, so these tests describe the algorithm rather than
    whatever state the rest of the suite happened to leave behind."""
    limiter = MemoryLimiter()
    limiter.reset()
    return limiter


class TestMemoryBackend:
    async def test_allows_up_to_the_limit_then_denies(self, memory: MemoryLimiter) -> None:
        for _ in range(3):
            assert (await memory.check(None, "k", 3, WINDOW)).allowed

        verdict = await memory.check(None, "k", 3, WINDOW)
        assert not verdict.allowed
        assert verdict.remaining == 0
        # Without Retry-After a client has no way to back off correctly.
        assert verdict.retry_after_seconds > 0

    async def test_keys_are_independent(self, memory: MemoryLimiter) -> None:
        for _ in range(3):
            await memory.check(None, "a", 3, WINDOW)

        assert (await memory.check(None, "b", 3, WINDOW)).allowed

    async def test_remaining_counts_down(self, memory: MemoryLimiter) -> None:
        assert (await memory.check(None, "k", 5, WINDOW)).remaining == 4
        assert (await memory.check(None, "k", 5, WINDOW)).remaining == 3

    async def test_reset_clears_counters(self, memory: MemoryLimiter) -> None:
        for _ in range(3):
            await memory.check(None, "k", 3, WINDOW)
        memory.reset()
        assert (await memory.check(None, "k", 3, WINDOW)).allowed


class TestDatabaseBackend:
    """The default backend: counters shared through the application database."""

    async def test_allows_up_to_the_limit_then_denies(self, db_session: AsyncSession) -> None:
        limiter = DatabaseLimiter()
        for _ in range(3):
            assert (await limiter.check(db_session, "k", 3, WINDOW)).allowed

        verdict = await limiter.check(db_session, "k", 3, WINDOW)
        assert not verdict.allowed
        assert verdict.retry_after_seconds > 0

    async def test_keys_are_independent(self, db_session: AsyncSession) -> None:
        limiter = DatabaseLimiter()
        for _ in range(3):
            await limiter.check(db_session, "a", 3, WINDOW)

        assert (await limiter.check(db_session, "b", 3, WINDOW)).allowed

    async def test_counts_survive_a_different_session(self, db_session: AsyncSession) -> None:
        """The whole point of this backend: state is not per-process.

        The memory backend would start from zero on the second connection,
        which is exactly the per-worker weakness this replaces.
        """
        from app.core.database import get_sessionmaker

        limiter = DatabaseLimiter()
        for _ in range(3):
            await limiter.check(db_session, "shared", 3, WINDOW)

        async with get_sessionmaker()() as other:
            assert not (await limiter.check(other, "shared", 3, WINDOW)).allowed

    async def test_requires_a_session(self) -> None:
        with pytest.raises(RuntimeError, match="requires a session"):
            await DatabaseLimiter().check(None, "k", 3, WINDOW)

    async def test_purge_removes_only_dead_windows(self, db_session: AsyncSession) -> None:
        limiter = DatabaseLimiter()
        await limiter.check(db_session, "current", 10, WINDOW)

        # A row from far enough in the past that it can never be hit again.
        db_session.add(RateLimitCounter(bucket_key="ancient", window_start=0, hits=99))
        await db_session.commit()

        removed = await purge_expired(db_session, WINDOW)
        assert removed == 1
        assert await db_session.get(RateLimitCounter, ("ancient", 0)) is None


class TestBackendSelection:
    @pytest.mark.parametrize(
        ("backend", "expected"),
        [("memory", memory_limiter), ("database", database_limiter)],
    )
    def test_settings_choose_the_backend(self, backend: str, expected: object) -> None:
        settings = Settings(_env_file=None, rate_limit_backend=backend)  # pyright: ignore[reportCallIssue,reportArgumentType]
        assert limiter_for(settings) is expected

    def test_database_is_the_default(self) -> None:
        # A per-worker limit is a footgun; the safe option should be what you
        # get without thinking about it.
        assert Settings(_env_file=None).rate_limit_backend == "database"  # pyright: ignore[reportCallIssue]
