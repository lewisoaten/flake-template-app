"""The append-only audit trail.

The trail is the reason the event bus exists: ``items`` publishes a fact and
knows nothing about audit. These tests assert the seam holds — that a transition
produces exactly one entry, attributed to the right actor and subject, without
the items domain ever mentioning the audit domain.
"""

from __future__ import annotations

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.audit.models import AuditEvent
from app.domains.auth.models import User
from app.domains.items.models import Item
from tests.conftest import issue_api_key


async def _entries_for(session: AsyncSession, subject_id: str) -> list[AuditEvent]:
    rows = await session.execute(
        select(AuditEvent)
        .where(AuditEvent.subject_id == subject_id)
        .order_by(AuditEvent.created_at.desc())
    )
    return list(rows.scalars().all())


async def test_a_transition_writes_exactly_one_entry(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
    admin_user: User,
    item: Item,
) -> None:
    response = await client.put(
        f"/api/v1/items/{item.id}/status",
        headers=api_headers,
        json={"status": "active"},
    )
    assert response.status_code == 200

    entries = await _entries_for(db_session, item.id)
    assert len(entries) == 1

    entry = entries[0]
    assert entry.event_name == "ItemStatusChanged"
    assert entry.subject_id == item.id
    # The API key acts as its owner, so the trail names the human, not the key.
    assert entry.actor_id == admin_user.id
    assert '"new_status":"active"' in entry.payload


async def test_a_no_op_transition_writes_nothing(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
    item: Item,
) -> None:
    # No event, therefore no entry. An audit trail that records non-events is
    # noise that people learn to ignore.
    await client.put(
        f"/api/v1/items/{item.id}/status",
        headers=api_headers,
        json={"status": "draft"},
    )

    assert await _entries_for(db_session, item.id) == []


async def test_a_rejected_transition_writes_nothing(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
    item: Item,
) -> None:
    await client.put(
        f"/api/v1/items/{item.id}/status",
        headers=api_headers,
        json={"status": "archived"},
    )
    await client.put(
        f"/api/v1/items/{item.id}/status",
        headers=api_headers,
        json={"status": "active"},
    )

    # Only the archive, not the refusal.
    entries = await _entries_for(db_session, item.id)
    assert len(entries) == 1
    assert '"new_status":"archived"' in entries[0].payload


async def test_the_trail_is_ordered_newest_first(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
) -> None:
    for status in ("active", "archived"):
        response = await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": status},
        )
        assert response.status_code == 200

    listing = await client.get(
        f"/api/v1/audit/events?subject_id={item.id}",
        headers=api_headers,
    )

    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 2
    # Newest first: an operator reading this wants the most recent change at the
    # top, not to page to the end for it.
    assert '"new_status":"archived"' in body["items"][0]["payload"]
    assert '"new_status":"active"' in body["items"][1]["payload"]


async def test_the_trail_can_be_filtered_by_event_name(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
) -> None:
    await client.put(
        f"/api/v1/items/{item.id}/status",
        headers=api_headers,
        json={"status": "active"},
    )

    matching = await client.get(
        "/api/v1/audit/events?event_name=ItemStatusChanged",
        headers=api_headers,
    )
    empty = await client.get(
        "/api/v1/audit/events?event_name=SomethingElse",
        headers=api_headers,
    )

    assert matching.json()["total"] == 1
    assert empty.json()["total"] == 0


async def test_reading_the_trail_requires_the_audit_scope(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    admin_user: User,
) -> None:
    # The trail records who did what; it is not something every integration
    # should be able to read merely because it can read items.
    _, plaintext = await issue_api_key(
        db_session,
        name="items-only",
        scopes=["items:read", "items:write"],
        owner=admin_user,
    )
    await db_session.commit()

    response = await client.get(
        "/api/v1/audit/events",
        headers={"Authorization": f"Bearer {plaintext}"},
    )

    assert response.status_code == 403
    assert "audit:read" in response.json()["error"]["message"]


async def test_the_trail_is_closed_to_anonymous_callers(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/audit/events")).status_code == 401


async def test_the_api_exposes_no_way_to_write_to_the_trail(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    # An audit table you can edit is not evidence of anything. Entries arrive
    # solely through the event bus.
    response = await client.post(
        "/api/v1/audit/events",
        headers=api_headers,
        json={"event_name": "Fabricated", "subject_id": "item-101"},
    )

    assert response.status_code == 405
    total = await db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert total == 0
