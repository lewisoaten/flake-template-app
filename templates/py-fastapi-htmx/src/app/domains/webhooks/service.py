"""Registration, inspection, and inbound receipt."""

from __future__ import annotations

import secrets
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import InboundWebhookReceived
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.netguard import UnsafeTargetError, assert_safe_target
from app.core.settings import get_settings
from app.domains.webhooks.models import InboundDelivery, WebhookDelivery, WebhookEndpoint
from app.domains.webhooks.schemas import WebhookEndpointCreate, WebhookEndpointUpdate
from app.domains.webhooks.signing import SignatureError, digest, verify_signature

log = get_logger(__name__)

_DEFAULT_PORTS = {"https": 443, "http": 80}


# ---------------------------------------------------------------------------
# Outbound endpoints
# ---------------------------------------------------------------------------
async def register_endpoint(
    session: AsyncSession,
    payload: WebhookEndpointCreate,
) -> WebhookEndpoint:
    """Register an endpoint and mint its signing secret.

    The SSRF check happens here rather than at dispatch time so an operator
    gets an immediate, actionable error instead of a delivery that mysteriously
    fails later.
    """
    settings = get_settings()
    host = payload.url.host or ""
    port = payload.url.port or _DEFAULT_PORTS.get(payload.url.scheme, 443)

    try:
        assert_safe_target(host, port, allow_private=settings.private_targets_allowed)
    except UnsafeTargetError as exc:
        raise ValidationError(str(exc)) from exc

    endpoint = WebhookEndpoint(
        url=str(payload.url),
        description=payload.description,
        event_types=" ".join(sorted(set(payload.event_types))),
        signing_secret=secrets.token_urlsafe(32),
    )
    session.add(endpoint)
    await session.flush()
    log.info("webhook_endpoint_registered", endpoint_id=endpoint.id, url=endpoint.url)
    return endpoint


async def get_endpoint(session: AsyncSession, endpoint_id: str) -> WebhookEndpoint:
    endpoint = await session.get(WebhookEndpoint, endpoint_id)
    if endpoint is None:
        msg = f"No webhook endpoint with id {endpoint_id}."
        raise NotFoundError(msg)
    return endpoint


async def list_endpoints(session: AsyncSession) -> Sequence[WebhookEndpoint]:
    rows = await session.execute(
        select(WebhookEndpoint).order_by(WebhookEndpoint.created_at.desc())
    )
    return rows.scalars().all()


async def update_endpoint(
    session: AsyncSession,
    endpoint_id: str,
    payload: WebhookEndpointUpdate,
) -> WebhookEndpoint:
    endpoint = await get_endpoint(session, endpoint_id)
    data = payload.model_dump(exclude_unset=True)
    if data.get("event_types") is not None:
        data["event_types"] = " ".join(sorted(set(data["event_types"])))
    for key, value in data.items():
        setattr(endpoint, key, value)
    await session.flush()
    return endpoint


async def delete_endpoint(session: AsyncSession, endpoint_id: str) -> None:
    endpoint = await get_endpoint(session, endpoint_id)
    await session.delete(endpoint)
    log.info("webhook_endpoint_deleted", endpoint_id=endpoint_id)


async def list_deliveries(
    session: AsyncSession,
    *,
    endpoint_id: str | None = None,
    subject_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[WebhookDelivery], int]:
    """Read the outbound audit trail, most recent first."""
    stmt = select(WebhookDelivery)
    if endpoint_id is not None:
        stmt = stmt.where(WebhookDelivery.endpoint_id == endpoint_id)
    if subject_id is not None:
        stmt = stmt.where(WebhookDelivery.subject_id == subject_id)

    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = await session.execute(
        stmt.order_by(WebhookDelivery.created_at.desc()).limit(limit).offset(offset)
    )
    return rows.scalars().all(), total


# ---------------------------------------------------------------------------
# Inbound receipt
# ---------------------------------------------------------------------------
async def accept_inbound(
    session: AsyncSession,
    *,
    delivery_id: str,
    source: str,
    event_name: str,
    body: str,
    timestamp: str,
    signature: str,
) -> tuple[InboundDelivery, list[InboundWebhookReceived]]:
    """Verify and record an inbound delivery.

    Returns the row and the events to publish once the caller has committed —
    the same discipline as everywhere else, so an audit entry is never written
    for a delivery that rolled back.

    Raises :class:`AuthenticationError` for a bad signature and
    :class:`ConflictError` for a replay of an id already seen.
    """
    from app.core.exceptions import AuthenticationError  # noqa: PLC0415 - avoids a cycle

    settings = get_settings()
    secret = settings.inbound_webhook_secret

    if secret is None:
        # Refusing by default beats accepting unsigned traffic because nobody
        # remembered to configure the secret.
        msg = "Inbound webhooks are not configured."
        raise AuthenticationError(msg)

    try:
        verify_signature(
            secret.get_secret_value(),
            timestamp,
            body,
            signature,
            tolerance_seconds=settings.inbound_webhook_tolerance_seconds,
        )
    except SignatureError as exc:
        log.warning("inbound_webhook_rejected", source=source, reason=str(exc))
        raise AuthenticationError(str(exc)) from exc

    if await session.get(InboundDelivery, delivery_id) is not None:
        # Not an error condition for the sender — they retried, we already have
        # it — but the caller returns 200 and does no work.
        msg = f"Delivery {delivery_id} has already been recorded."
        raise ConflictError(msg)

    delivery = InboundDelivery(
        id=delivery_id,
        source=source,
        event_name=event_name,
        payload=body,
        payload_digest=digest(body),
    )
    session.add(delivery)
    await session.flush()
    log.info("inbound_webhook_accepted", delivery_id=delivery_id, source=source)

    event = InboundWebhookReceived(
        delivery_id=delivery_id,
        source=source,
        payload_digest=delivery.payload_digest,
    )
    return delivery, [event]


async def list_inbound(
    session: AsyncSession,
    *,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[InboundDelivery], int]:
    stmt = select(InboundDelivery)
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = await session.execute(
        stmt.order_by(InboundDelivery.created_at.desc()).limit(limit).offset(offset)
    )
    return rows.scalars().all(), total
