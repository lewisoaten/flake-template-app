"""Receiving signed deliveries from a third party.

This is the one unauthenticated write in the application: the HMAC signature
*is* the authentication, because that is how webhook senders work. Everything
below is therefore about failing closed — a bad signature, a stale timestamp and
a replay each have to be handled differently, and getting any of them wrong
turns a public endpoint into a public database.
"""

from __future__ import annotations

import json
import time

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.audit.models import AuditEvent
from app.domains.webhooks.models import InboundDelivery
from app.domains.webhooks.signing import digest
from tests.conftest import inbound_headers

INBOUND_URL = "/api/v1/webhooks/inbound"
BODY = json.dumps({"kind": "partner.thing.happened", "reference": "abc-123"})


async def test_a_correctly_signed_delivery_is_accepted(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    response = await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1", source="acme"),
    )

    assert response.status_code == 202
    assert response.json() == {"status": "accepted", "delivery_id": "delivery-1"}

    row = await db_session.get(InboundDelivery, "delivery-1")
    assert row is not None
    assert row.source == "acme"
    assert row.payload == BODY


async def test_the_stored_digest_is_a_hash_of_the_raw_body(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    # Stored so a later dispute about "what did you actually receive" has an
    # answer that does not depend on trusting the payload column.
    await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1"),
    )

    row = await db_session.get(InboundDelivery, "delivery-1")
    assert row is not None
    assert row.payload_digest == digest(BODY)


async def test_a_bad_signature_is_refused(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    headers = inbound_headers(BODY, delivery_id="delivery-1", secret="the-wrong-secret")

    response = await client.post(INBOUND_URL, content=BODY, headers=headers)

    assert response.status_code == 401
    assert await db_session.get(InboundDelivery, "delivery-1") is None


async def test_a_tampered_body_is_refused(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    # The signature covers the raw bytes, so an intermediary that rewrites the
    # payload cannot pass it off as the sender's.
    headers = inbound_headers(BODY, delivery_id="delivery-1")

    response = await client.post(
        INBOUND_URL,
        content=BODY.replace("abc-123", "xyz-999"),
        headers=headers,
    )

    assert response.status_code == 401
    assert await db_session.get(InboundDelivery, "delivery-1") is None


async def test_a_stale_timestamp_is_refused(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    # Freshness is checked before the signature, so a captured-but-valid request
    # is refused as a replay rather than accepted.
    stale = int(time.time()) - 3600
    headers = inbound_headers(BODY, delivery_id="delivery-1", timestamp=stale)

    response = await client.post(INBOUND_URL, content=BODY, headers=headers)

    assert response.status_code == 401
    assert await db_session.get(InboundDelivery, "delivery-1") is None


async def test_a_replayed_delivery_id_is_acknowledged_without_reprocessing(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A resend is the sender's normal behaviour, not an error.

    Returning an error would make them retry forever; processing it twice would
    duplicate whatever the delivery triggers. So: acknowledge, and do no work.
    """
    first = await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1"),
    )
    assert first.status_code == 202

    # Freshly signed: a real retry would carry a new timestamp, and reusing the
    # old one would test the freshness check instead of the replay check.
    replay = await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1"),
    )

    assert replay.status_code == 200
    assert replay.json()["status"] == "duplicate"

    total = await db_session.scalar(select(func.count()).select_from(InboundDelivery))
    assert total == 1


async def test_a_replay_does_not_write_a_second_audit_entry(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    for _ in range(2):
        await client.post(
            INBOUND_URL,
            content=BODY,
            headers=inbound_headers(BODY, delivery_id="delivery-1"),
        )

    rows = await db_session.execute(select(AuditEvent).where(AuditEvent.subject_id == "delivery-1"))
    assert len(list(rows.scalars().all())) == 1


async def test_an_accepted_delivery_is_written_to_the_audit_trail(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    # The audit subscriber is wired to InboundWebhookReceived, which is only
    # published after the receipt has been committed.
    await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1", source="acme"),
    )

    rows = await db_session.execute(select(AuditEvent).where(AuditEvent.subject_id == "delivery-1"))
    entries = list(rows.scalars().all())

    assert len(entries) == 1
    assert entries[0].event_name == "InboundWebhookReceived"
    # Nobody signed in caused this, so there is no actor to record.
    assert entries[0].actor_id is None
    assert "acme" in entries[0].payload


async def test_a_delivery_without_a_signature_is_rejected(client: httpx.AsyncClient) -> None:
    # The signature header is a required header, so this never reaches the
    # service — which is the cheapest possible way to refuse it.
    response = await client.post(INBOUND_URL, content=BODY)
    assert response.status_code == 422


async def test_the_endpoint_needs_no_api_key(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    # Stated as a test because it looks like an omission until you remember
    # senders have no way to hold one.
    response = await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1"),
    )

    assert response.status_code == 202
    assert await db_session.get(InboundDelivery, "delivery-1") is not None


async def test_recorded_deliveries_are_readable_through_the_api(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
) -> None:
    await client.post(
        INBOUND_URL,
        content=BODY,
        headers=inbound_headers(BODY, delivery_id="delivery-1", source="acme"),
    )

    listing = await client.get("/api/v1/webhooks/inbound", headers=api_headers)

    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["source"] == "acme"
