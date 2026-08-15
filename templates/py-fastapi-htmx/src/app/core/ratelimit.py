"""Rate limiting, with two interchangeable backends.

``memory`` counts per process. Fast and dependency-free, but **the limit is per
worker**: four uvicorn workers means roughly four times the configured rate, and
horizontal scaling multiplies it again.

``database`` (the default) shares counters through the database you already
run, so the limit is genuinely global. It costs one round trip per limited
request — which is why it is applied to sign-in and the unauthenticated inbound
endpoint rather than to every route.

Both are fixed-window rather than token-bucket, because the failure mode is
gentler: at worst a caller gets 2x the limit across a window boundary, and the
state is one integer per key instead of a timestamp plus a float.

If you outgrow the database backend, add a Redis one — the interface is a
single method, and nothing above this module changes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol, cast

from fastapi import Request
from sqlalchemy import Integer, String, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.settings import Settings


@dataclass(frozen=True, slots=True)
class RateLimitVerdict:
    """The outcome of one limiter consultation."""

    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    """What a backend has to provide. One method, deliberately."""

    async def check(
        self,
        session: AsyncSession | None,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitVerdict: ...


# ---------------------------------------------------------------------------
# Shared window arithmetic
# ---------------------------------------------------------------------------
def _window(now: int, window_seconds: int) -> int:
    return now // window_seconds


def _verdict(
    count: int, limit: int, window: int, window_seconds: int, now: int
) -> RateLimitVerdict:
    reset_at = (window + 1) * window_seconds
    return RateLimitVerdict(
        allowed=count <= limit,
        remaining=max(0, limit - count),
        retry_after_seconds=max(1, reset_at - now),
    )


# ---------------------------------------------------------------------------
# In-process backend
# ---------------------------------------------------------------------------
_PRUNE_THRESHOLD = 10_000


class MemoryLimiter:
    """Counts hits per key within a wall-clock window, in this process only.

    Thread-safe: uvicorn may run the ASGI app across a thread pool, and the
    counters would otherwise race.
    """

    def __init__(self) -> None:
        self._hits: dict[tuple[str, int], int] = {}
        self._lock = threading.Lock()

    async def check(
        self,
        session: AsyncSession | None,  # noqa: ARG002 - unused; satisfies the protocol
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitVerdict:
        now = int(time.time())
        window = _window(now, window_seconds)
        bucket = (key, window)

        with self._lock:
            # Windows are monotonic, so anything from an earlier one is dead.
            # Pruning here keeps the dict bounded without a background task.
            if len(self._hits) > _PRUNE_THRESHOLD:
                self._hits = {k: v for k, v in self._hits.items() if k[1] >= window}

            count = self._hits.get(bucket, 0) + 1
            self._hits[bucket] = count

        return _verdict(count, limit, window, window_seconds, now)

    def reset(self) -> None:
        """Forget every counter. Used between tests."""
        with self._lock:
            self._hits.clear()


# ---------------------------------------------------------------------------
# Database backend
# ---------------------------------------------------------------------------
class RateLimitCounter(Base):
    """One row per (key, window). Rows age out; see :func:`purge_expired`."""

    __tablename__ = "rate_limit_counters"

    bucket_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    window_start: Mapped[int] = mapped_column(Integer, primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class DatabaseLimiter:
    """Counters shared through the application database.

    The increment is a single atomic upsert, so concurrent workers cannot lose
    a count to a read-modify-write race — which is the whole point of using the
    database rather than process memory.
    """

    async def check(
        self,
        session: AsyncSession | None,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitVerdict:
        if session is None:  # pragma: no cover - programming error
            msg = "The database rate limiter requires a session."
            raise RuntimeError(msg)

        now = int(time.time())
        window = _window(now, window_seconds)

        # get_bind() is always populated for a session created by the app's
        # sessionmaker; the dialect decides which upsert syntax to emit.
        dialect = session.get_bind().dialect.name
        insert = pg_insert if dialect == "postgresql" else sqlite_insert

        stmt = insert(RateLimitCounter).values(bucket_key=key, window_start=window, hits=1)
        stmt = stmt.on_conflict_do_update(
            index_elements=[RateLimitCounter.bucket_key, RateLimitCounter.window_start],
            set_={"hits": RateLimitCounter.__table__.c.hits + 1},
        ).returning(RateLimitCounter.hits)

        count = await session.scalar(stmt) or 1
        # Committed immediately: a refused request usually raises, and the
        # count must survive that rollback or the limit never bites.
        await session.commit()

        return _verdict(count, limit, window, window_seconds, now)


async def purge_expired(session: AsyncSession, window_seconds: int, keep_windows: int = 2) -> int:
    """Delete counter rows from windows that can no longer be hit.

    Call periodically — a cron, or the start of a daily job. Leaving them costs
    only disk, but the table grows without bound.
    """
    cutoff = _window(int(time.time()), window_seconds) - keep_windows
    # execute() is typed as returning Result, but a DELETE always yields a
    # CursorResult at runtime — which is where rowcount lives.
    result = cast(
        "CursorResult[Any]",
        await session.execute(
            delete(RateLimitCounter).where(RateLimitCounter.window_start < cutoff)
        ),
    )
    await session.commit()
    return result.rowcount


# ---------------------------------------------------------------------------
# Selection and helpers
# ---------------------------------------------------------------------------
memory_limiter = MemoryLimiter()
database_limiter = DatabaseLimiter()


def limiter_for(settings: Settings) -> RateLimiter:
    return memory_limiter if settings.rate_limit_backend == "memory" else database_limiter


def client_key(request: Request, bucket: str) -> str:
    """Identify the caller for limiting purposes.

    Uses the peer address. Behind a proxy that is the proxy's address, which
    would lump every client together — so if you deploy behind one, configure it
    to set a trusted forwarded-for header and read that here. Doing it blindly
    would let a caller spoof the header and evade the limit entirely, which is
    why this does not read it by default.
    """
    client = request.client
    host = client.host if client else "unknown"
    return f"{bucket}:{host}"


async def consult(
    request: Request,
    settings: Settings,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    session: AsyncSession | None = None,
) -> RateLimitVerdict:
    """Check the limit for ``bucket``, honouring the global on/off switch."""
    if not settings.rate_limit_enabled:
        return RateLimitVerdict(allowed=True, remaining=limit, retry_after_seconds=0)

    limiter = limiter_for(settings)
    return await limiter.check(session, client_key(request, bucket), limit, window_seconds)


def reset_all() -> None:
    """Clear in-process state. Database counters are per-test-database."""
    memory_limiter.reset()
