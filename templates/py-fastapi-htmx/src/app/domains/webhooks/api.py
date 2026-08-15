"""JSON API: manage outbound endpoints, and receive inbound deliveries."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Header, Query, Request, status
from starlette.responses import JSONResponse

from app.core.database import SessionDep
from app.core.events import publish_after_commit
from app.core.exceptions import ConflictError, RateLimitedError
from app.core.ratelimit import consult
from app.core.schemas import Page
from app.core.settings import get_settings
from app.domains.auth.dependencies import ScopedPrincipal, requires_scopes
from app.domains.webhooks import service
from app.domains.webhooks.models import WebhookEndpoint
from app.domains.webhooks.schemas import (
    InboundDeliveryRead,
    WebhookDeliveryRead,
    WebhookEndpointCreate,
    WebhookEndpointCreated,
    WebhookEndpointRead,
    WebhookEndpointUpdate,
)
from app.domains.webhooks.signing import (
    DELIVERY_HEADER,
    EVENT_HEADER,
    SIGNATURE_HEADER,
    SOURCE_HEADER,
    TIMESTAMP_HEADER,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# ---------------------------------------------------------------------------
# Outbound endpoint management
# ---------------------------------------------------------------------------
@router.post(
    "/endpoints",
    response_model=WebhookEndpointCreated,
    status_code=status.HTTP_201_CREATED,
)
async def register_endpoint(
    payload: WebhookEndpointCreate,
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:write"))],
) -> WebhookEndpointCreated:
    """Register an endpoint. The signing secret is returned only here."""
    endpoint = await service.register_endpoint(session, payload)
    return WebhookEndpointCreated.model_validate(endpoint)


@router.get("/endpoints", response_model=list[WebhookEndpointRead])
async def list_endpoints(
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:read"))],
) -> list[WebhookEndpoint]:
    return list(await service.list_endpoints(session))


@router.patch("/endpoints/{endpoint_id}", response_model=WebhookEndpointRead)
async def update_endpoint(
    endpoint_id: str,
    payload: WebhookEndpointUpdate,
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:write"))],
) -> WebhookEndpoint:
    return await service.update_endpoint(session, endpoint_id, payload)


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(
    endpoint_id: str,
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:write"))],
) -> None:
    await service.delete_endpoint(session, endpoint_id)


@router.get("/deliveries", response_model=Page[WebhookDeliveryRead])
async def list_deliveries(
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:read"))],
    endpoint_id: str | None = None,
    subject_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[WebhookDeliveryRead]:
    """The outbound audit trail: every dispatch attempt."""
    rows, total = await service.list_deliveries(
        session, endpoint_id=endpoint_id, subject_id=subject_id, limit=limit, offset=offset
    )
    return Page[WebhookDeliveryRead](
        items=[WebhookDeliveryRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/inbound", response_model=Page[InboundDeliveryRead])
async def list_inbound(
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("webhooks:read"))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[InboundDeliveryRead]:
    rows, total = await service.list_inbound(session, limit=limit, offset=offset)
    return Page[InboundDeliveryRead](
        items=[InboundDeliveryRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Inbound receipt
# ---------------------------------------------------------------------------
@router.post("/inbound", status_code=status.HTTP_202_ACCEPTED)
async def receive_inbound(
    request: Request,
    session: SessionDep,
    background: BackgroundTasks,
    signature: Annotated[str, Header(alias=SIGNATURE_HEADER)],
    timestamp: Annotated[str, Header(alias=TIMESTAMP_HEADER)],
    delivery_id: Annotated[str, Header(alias=DELIVERY_HEADER)],
    event_name: Annotated[str, Header(alias=EVENT_HEADER)] = "unknown",
    source: Annotated[str, Header(alias=SOURCE_HEADER)] = "unknown",
) -> JSONResponse:
    """Accept a signed delivery from a third party.

    Deliberately **not** behind an API key: the HMAC signature *is* the
    authentication, which is how webhook senders work. That makes it the one
    unauthenticated write in the application, so it is rate-limited and its
    body size is capped.

    A replayed delivery id returns 200 rather than an error — the sender did
    nothing wrong, we simply already have it, and returning an error would make
    them retry forever.
    """
    settings = get_settings()

    verdict = await consult(
        request,
        settings,
        bucket="inbound-webhook",
        limit=settings.api_rate_limit,
        window_seconds=settings.api_rate_limit_window_seconds,
        session=session,
    )
    if not verdict.allowed:
        msg = "Too many inbound deliveries. Slow down."
        raise RateLimitedError(msg, verdict.retry_after_seconds)

    raw = await request.body()
    if len(raw) > _MAX_INBOUND_BODY:
        msg = "Payload too large."
        raise RateLimitedError(msg, 1)

    body = raw.decode("utf-8", errors="replace")

    try:
        _, events = await service.accept_inbound(
            session,
            delivery_id=delivery_id,
            source=source,
            event_name=event_name,
            body=body,
            timestamp=timestamp,
            signature=signature,
        )
    except ConflictError:
        # 200, not the route's default 202: 202 means "accepted, work pending",
        # and there is no pending work — we already have this delivery. An
        # error status would be worse still; the sender did nothing wrong and
        # would just keep retrying.
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "duplicate", "delivery_id": delivery_id},
        )

    await publish_after_commit(session, background, events)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"status": "accepted", "delivery_id": delivery_id},
    )


# 1 MiB. Generous for a webhook, small enough that an unauthenticated caller
# cannot use this endpoint to exhaust memory.
_MAX_INBOUND_BODY = 1024 * 1024
