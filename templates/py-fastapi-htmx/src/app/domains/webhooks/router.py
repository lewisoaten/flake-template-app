"""Admin HTML surface for webhooks."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Query, Request
from pydantic import ValidationError as PydanticValidationError
from starlette.responses import Response

from app.core import csrf
from app.core.database import SessionDep
from app.core.exceptions import ValidationError
from app.core.settings import get_settings
from app.core.templating import render
from app.domains.auth.dependencies import CurrentAdmin
from app.domains.webhooks import service
from app.domains.webhooks.schemas import WebhookEndpointCreate

router = APIRouter(
    prefix="/admin/webhooks",
    tags=["admin"],
    include_in_schema=False,
    dependencies=[Depends(csrf.verify)],
)


async def _page(
    request: Request,
    session: SessionDep,
    admin: CurrentAdmin,
    limit: int,
    created_secret: str | None,
) -> Response:
    endpoints = await service.list_endpoints(session)
    deliveries, total = await service.list_deliveries(session, limit=limit)
    inbound, inbound_total = await service.list_inbound(session, limit=limit)

    settings = get_settings()
    token = csrf.token_for(request, settings)

    response = render(
        request,
        "webhooks/index.html",
        {
            "user": admin,
            "endpoints": endpoints,
            "deliveries": deliveries,
            "total": total,
            "inbound": inbound,
            "inbound_total": inbound_total,
            "created_secret": created_secret,
            "csrf_token": token,
        },
    )
    csrf.attach(response, token, settings)
    return response


@router.get("")
async def index(
    request: Request,
    session: SessionDep,
    admin: CurrentAdmin,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Response:
    """Registered endpoints, plus both audit trails."""
    return await _page(request, session, admin, limit, created_secret=None)


@router.post("/endpoints")
async def create_endpoint(
    request: Request,
    session: SessionDep,
    admin: CurrentAdmin,
    url: Annotated[str, Form()],
    description: Annotated[str | None, Form()] = None,
    event_types: Annotated[str, Form()] = "",
) -> Response:
    """Register an endpoint from the admin form and reveal its secret once."""
    try:
        payload = WebhookEndpointCreate(
            url=url,  # pyright: ignore[reportArgumentType] - validated by pydantic
            description=description or None,
            event_types=event_types.split(),
        )
    except PydanticValidationError as exc:
        message = "; ".join(err["msg"] for err in exc.errors())
        raise ValidationError(message) from exc

    endpoint = await service.register_endpoint(session, payload)
    await session.flush()
    return await _page(request, session, admin, 50, created_secret=endpoint.signing_secret)
