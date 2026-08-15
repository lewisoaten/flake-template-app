"""Outbound webhook dispatch.

Runs as a background task after the response has been sent, on its own database
session — the request's session is committed and closed by then, which is
exactly the guarantee we want: nothing is dispatched for work that rolled back.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_sessionmaker, utcnow
from app.core.events import DomainEvent, ItemStatusChanged, event_bus
from app.core.logging import get_logger
from app.core.netguard import UnsafeTargetError, pin_target
from app.core.settings import get_settings
from app.domains.webhooks.models import WebhookDelivery, WebhookEndpoint
from app.domains.webhooks.signing import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign,
)

log = get_logger(__name__)

# Response bodies are stored for debugging, not archival. Truncate so a peer
# returning an HTML error page cannot bloat the table.
_MAX_STORED_BODY: Final = 2048
_SERVER_ERROR: Final = 500


def event_payload(event: DomainEvent) -> dict[str, Any]:
    payload = asdict(event)
    payload["occurred_at"] = event.occurred_at.isoformat()
    payload["event"] = event.name
    return payload


async def _matching_endpoints(session: AsyncSession, event_name: str) -> list[WebhookEndpoint]:
    rows = await session.execute(select(WebhookEndpoint).where(WebhookEndpoint.is_active.is_(True)))
    return [endpoint for endpoint in rows.scalars().all() if endpoint.wants(event_name)]


async def deliver(
    client: httpx.AsyncClient,
    session: AsyncSession,
    endpoint: WebhookEndpoint,
    event: DomainEvent,
    subject_id: str | None,
) -> WebhookDelivery:
    """POST one event to one endpoint, retrying, recording every attempt.

    Only connection failures and 5xx are retried. A 4xx means the peer rejected
    the payload; sending it again would fail identically.
    """
    settings = get_settings()
    body = json.dumps(event_payload(event), separators=(",", ":"), sort_keys=True)

    # Resolve and validate once, here, then connect to that address for every
    # attempt. Re-resolving per attempt would reopen the rebinding window the
    # registration check was meant to close.
    parsed = urlsplit(endpoint.url)
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        pinned = pin_target(
            parsed.hostname or "",
            parsed.port or default_port,
            allow_private=settings.private_targets_allowed,
        )
    except UnsafeTargetError as exc:
        log.warning("webhook_target_unsafe", endpoint_id=endpoint.id, error=str(exc))
        delivery = WebhookDelivery(
            endpoint_id=endpoint.id,
            event_name=event.name,
            subject_id=subject_id,
            request_body=body,
            attempt=1,
            error=f"Target refused by the SSRF guard: {exc}",
        )
        session.add(delivery)
        await session.flush()
        return delivery

    # Always the pinned address, in every environment. Branching here would
    # mean local development never exercised the pinned path.
    target_url = pinned.url_for(endpoint.url)

    delivery: WebhookDelivery | None = None

    for attempt in range(1, settings.webhook_max_attempts + 1):
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "User-Agent": settings.webhook_user_agent,
            EVENT_HEADER: event.name,
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: sign(endpoint.signing_secret, timestamp, body),
            # The connection goes to the pinned IP, so the peer needs the real
            # name to route and to match its certificate.
            "Host": pinned.host,
        }

        delivery = WebhookDelivery(
            endpoint_id=endpoint.id,
            event_name=event.name,
            subject_id=subject_id,
            request_body=body,
            attempt=attempt,
        )
        started = time.perf_counter()

        try:
            response = await client.post(
                target_url,
                content=body,
                headers=headers,
                timeout=settings.webhook_timeout_seconds,
                # TLS is negotiated against the original hostname even though
                # the socket goes to the pinned address, so certificate
                # verification is unaffected.
                extensions={"sni_hostname": pinned.host},
            )
        except httpx.HTTPError as exc:
            delivery.error = f"{type(exc).__name__}: {exc}"
            retryable = True
        else:
            delivery.response_status = response.status_code
            delivery.response_body = response.text[:_MAX_STORED_BODY]
            if response.is_success:
                delivery.succeeded_at = utcnow()
            retryable = response.status_code >= _SERVER_ERROR

        delivery.duration_ms = int((time.perf_counter() - started) * 1000)
        session.add(delivery)
        await session.flush()

        if delivery.succeeded:
            log.info(
                "webhook_delivered",
                endpoint_id=endpoint.id,
                domain_event=event.name,
                status=delivery.response_status,
                attempt=attempt,
            )
            return delivery

        if not retryable or attempt == settings.webhook_max_attempts:
            log.warning(
                "webhook_failed",
                endpoint_id=endpoint.id,
                domain_event=event.name,
                status=delivery.response_status,
                error=delivery.error,
                attempt=attempt,
            )
            return delivery

        # Exponential backoff: 0.5s, 1s, 2s, …
        await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

    raise AssertionError  # unreachable: the loop returns on its final iteration


async def dispatch_event(event: DomainEvent, subject_id: str) -> None:
    """Fan an event out to every subscribed endpoint, concurrently."""
    async with get_sessionmaker()() as session:
        endpoints = await _matching_endpoints(session, event.name)
        if not endpoints:
            log.debug("webhook_no_endpoints", domain_event=event.name)
            return

        # follow_redirects=False: a redirect could send a signed payload
        # carrying our data to a third party.
        async with httpx.AsyncClient(follow_redirects=False) as client:
            await asyncio.gather(
                *(deliver(client, session, endpoint, event, subject_id) for endpoint in endpoints),
                return_exceptions=True,
            )
        await session.commit()


async def on_item_status_changed(event: DomainEvent) -> None:
    """Bus handler for :class:`ItemStatusChanged`."""
    if not isinstance(event, ItemStatusChanged):  # pragma: no cover - defensive
        return
    await dispatch_event(event, subject_id=event.item_id)


def register_subscriptions() -> None:
    """Wire this domain's handlers onto the bus. Called at startup."""
    event_bus.subscribe(ItemStatusChanged, on_item_status_changed)
