"""Recording and reading the audit trail.

The subscriber here is the reason the event bus exists. ``items`` publishes a
fact and knows nothing about audit; audit decides the fact is worth keeping.
Adding a second consumer later touches neither.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_sessionmaker
from app.core.events import DomainEvent, InboundWebhookReceived, ItemStatusChanged, event_bus
from app.core.logging import get_logger
from app.domains.audit.models import AuditEvent

log = get_logger(__name__)


def _serialise(event: DomainEvent) -> str:
    payload: dict[str, Any] = asdict(event)
    payload["occurred_at"] = event.occurred_at.isoformat()
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


async def record(
    session: AsyncSession,
    event: DomainEvent,
    *,
    subject_id: str | None,
    actor_id: str | None = None,
) -> AuditEvent:
    """Append one event to the trail."""
    entry = AuditEvent(
        event_name=event.name,
        subject_id=subject_id,
        actor_id=actor_id,
        payload=_serialise(event),
    )
    session.add(entry)
    await session.flush()
    return entry


async def list_events(
    session: AsyncSession,
    *,
    subject_id: str | None = None,
    event_name: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[AuditEvent], int]:
    """Read the trail, most recent first."""
    stmt = select(AuditEvent)
    if subject_id is not None:
        stmt = stmt.where(AuditEvent.subject_id == subject_id)
    if event_name is not None:
        stmt = stmt.where(AuditEvent.event_name == event_name)

    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = await session.execute(
        stmt.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
    )
    return rows.scalars().all(), total


# ---------------------------------------------------------------------------
# Bus handlers
# ---------------------------------------------------------------------------
async def on_item_status_changed(event: DomainEvent) -> None:
    """Record an item transition."""
    if not isinstance(event, ItemStatusChanged):  # pragma: no cover - defensive
        return
    # Its own session: this runs after the request's transaction has committed
    # and that session is closed.
    async with get_sessionmaker()() as session:
        await record(session, event, subject_id=event.item_id, actor_id=event.actor_id)
        await session.commit()


async def on_inbound_webhook(event: DomainEvent) -> None:
    """Record an accepted inbound delivery."""
    if not isinstance(event, InboundWebhookReceived):  # pragma: no cover - defensive
        return
    async with get_sessionmaker()() as session:
        await record(session, event, subject_id=event.delivery_id)
        await session.commit()


def register_subscriptions() -> None:
    """Wire this domain's handlers onto the bus. Called at startup."""
    event_bus.subscribe(ItemStatusChanged, on_item_status_changed)
    event_bus.subscribe(InboundWebhookReceived, on_inbound_webhook)
