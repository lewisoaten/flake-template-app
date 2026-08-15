"""Async SQLAlchemy 2.0 engine, session factory and declarative base.

The engine is created lazily and cached, so importing this module has no side
effects — important for tests, Alembic and serverless cold starts alike.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy import DateTime, MetaData, String, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import ConnectionPoolEntry

from app.core.settings import get_settings

# Explicit constraint naming keeps Alembic autogenerate diffs stable: without
# it, unnamed constraints get backend-specific names and every migration churns.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def new_id() -> str:
    """Generate a primary key.

    String keys (rather than integers) keep IDs opaque in URLs, safe to mint
    client-side, and portable between SQLite and Postgres without a UUID type.
    """
    return uuid.uuid4().hex


def utcnow() -> datetime:
    """Timezone-aware ``now``. Never use naive datetimes in persisted rows."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base shared by every model in the application."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {  # noqa: RUF012
        datetime: DateTime(timezone=True),
    }


class TimestampMixin:
    """Adds ``created_at`` / ``updated_at`` maintained by the ORM."""

    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow, nullable=False)


class IdMixin:
    """Adds the standard opaque string primary key."""

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Create (once) the process-wide async engine."""
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "echo": settings.database_echo,
        "pool_pre_ping": True,
    }
    if not settings.is_sqlite:
        # SQLite's aiosqlite pool does not accept these; Postgres wants them.
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow

    engine = create_async_engine(settings.database_url, **kwargs)

    if settings.is_sqlite:
        _tune_sqlite(engine)

    return engine


def _tune_sqlite(engine: AsyncEngine) -> None:
    """Apply the pragmas that make SQLite behave like a real database.

    * ``foreign_keys`` — off by default, which silently hides referential bugs
      until you deploy to Postgres and they surface as constraint violations.
    * ``journal_mode=WAL`` — the default rollback journal blocks readers behind
      a writer. This app writes webhook deliveries from a background task while
      requests are being served, so without WAL those two contend and one of
      them waits out ``busy_timeout``.
    * ``busy_timeout`` — wait for a contended lock instead of failing instantly
      with "database is locked".
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragmas(
        dbapi_connection: DBAPIConnection,
        _record: ConnectionPoolEntry,
    ) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Create (once) the process-wide session factory."""
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional session.

    The session commits when the handler returns normally and rolls back on any
    exception, so handlers never manage transactions by hand.
    """
    async with get_sessionmaker()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()


async def dispose_engine() -> None:
    """Close pooled connections. Called from the application lifespan."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


SessionDep = Annotated[AsyncSession, Depends(get_session)]
