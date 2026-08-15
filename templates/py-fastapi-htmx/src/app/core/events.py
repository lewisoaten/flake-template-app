"""A tiny in-process domain event bus.

Why this exists: the ``items`` domain must not import ``webhooks`` or ``audit``.
When an item changes status, ``items`` publishes a fact and the other two
decide — independently — that the fact is worth POSTing to a partner and worth
recording. Adding a third consumer later touches no item code.

Handlers run after the response via ``BackgroundTasks``, each on its own
database session. A handler that raises is logged and affects neither the
request nor the other handlers.

**Ordering matters here, and the obvious code is wrong.** Starlette runs
background tasks while sending the response, which is *before* FastAPI unwinds
its dependency stack — so the commit performed by ``get_session``'s exit code
has not happened yet. Scheduling a handler and letting the dependency commit
later means the handler observes an uncommitted transaction: on Postgres it
silently reads stale state, and on SQLite it deadlocks against the open writer.
Always schedule through :func:`publish_after_commit`.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import utcnow
from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base class for facts about things that have already happened."""

    occurred_at: datetime = field(default_factory=utcnow, kw_only=True)

    @property
    def name(self) -> str:
        return type(self).__name__


@dataclass(frozen=True, slots=True)
class ItemStatusChanged(DomainEvent):
    """An item moved from one status to another."""

    item_id: str
    owner_id: str
    previous_status: str
    new_status: str
    actor_id: str | None = None


@dataclass(frozen=True, slots=True)
class InboundWebhookReceived(DomainEvent):
    """A signed request arrived on the inbound endpoint and was accepted."""

    delivery_id: str
    source: str
    payload_digest: str


Handler = Callable[[DomainEvent], Awaitable[None]]


class EventBus:
    """Synchronous registration, concurrent asynchronous dispatch."""

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[Handler]] = defaultdict(list)

    def subscribe(self, event_type: type[DomainEvent], handler: Handler) -> None:
        """Register ``handler``, ignoring a repeat registration.

        Idempotent on purpose: the bus is process-global but ``create_app`` may
        run more than once (tests, a Lambda warm start after an import-time
        registration). Double-subscribing would silently send every webhook
        twice — a bug that only shows up in production traffic.
        """
        if handler in self._handlers[event_type]:
            return
        self._handlers[event_type].append(handler)

    def clear(self) -> None:
        """Drop all subscriptions. Used between tests."""
        self._handlers.clear()

    async def publish(self, event: DomainEvent) -> None:
        """Run every handler for ``event``, isolating failures."""
        handlers = self._handlers.get(type(event), [])
        if not handlers:
            log.debug("event_no_handlers", domain_event=event.name)
            return

        results = await asyncio.gather(
            *(handler(event) for handler in handlers),
            return_exceptions=True,
        )
        for handler, result in zip(handlers, results, strict=True):
            if isinstance(result, BaseException):
                log.error(
                    "event_handler_failed",
                    domain_event=event.name,
                    handler=getattr(handler, "__qualname__", repr(handler)),
                    error=str(result),
                    exc_info=result,
                )


# One bus per process. Domains subscribe during application startup.
event_bus = EventBus()


async def publish_after_commit(
    session: AsyncSession,
    background: BackgroundTasks,
    events: Sequence[DomainEvent],
) -> None:
    """Commit the request's work, then schedule its events for dispatch.

    The explicit commit is the whole point: see the module docstring. It makes
    the later commit in ``get_session``'s teardown a no-op, and guarantees a
    handler can never observe — or worse, publish — a change that was rolled
    back.
    """
    if not events:
        return

    await session.commit()
    for event in events:
        background.add_task(event_bus.publish, event)
