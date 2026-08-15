"""HTML surface for items: list, detail, create, status change.

Every route here is behind a session cookie, so the router carries the CSRF
dependency. The JSON API in ``api.py`` deliberately does not — bearer callers
cannot be CSRF'd, and demanding a token would break every non-browser client.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Query, Request
from starlette.responses import Response

from app.core import csrf
from app.core.database import SessionDep
from app.core.events import publish_after_commit
from app.core.settings import get_settings
from app.core.templating import hx_redirect, render, render_partial_or_page
from app.domains.auth.dependencies import CurrentUser
from app.domains.items import service
from app.domains.items.models import ItemStatus
from app.domains.items.schemas import ItemCreate

router = APIRouter(
    prefix="/items",
    tags=["items"],
    include_in_schema=False,
    dependencies=[Depends(csrf.verify)],
)


@router.get("")
async def index(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: Annotated[ItemStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Response:
    """List items. The search box drives this with ``hx-get``."""
    items, total = await service.list_items(
        session, user, search=q, status=status, limit=limit, offset=offset
    )
    counts = await service.status_summary(session, user)

    context = {
        "user": user,
        "items": items,
        "total": total,
        "counts": counts,
        "query": q or "",
        "status": status,
        "statuses": list(ItemStatus),
        "limit": limit,
        "offset": offset,
    }
    settings = get_settings()
    token = csrf.token_for(request, settings)
    context["csrf_token"] = token

    response = render_partial_or_page(
        request,
        page="items/list.html",
        partial="partials/item_rows.html",
        context=context,
    )
    csrf.attach(response, token, settings)
    return response


@router.get("/{item_id}")
async def detail(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    item_id: str,
) -> Response:
    """One item, plus the audit trail it has generated."""
    from app.domains.audit.service import list_events  # noqa: PLC0415 - avoids a cycle

    item = await service.get(session, item_id, user)
    events, _ = await list_events(session, subject_id=item_id, limit=20)

    settings = get_settings()
    token = csrf.token_for(request, settings)

    response = render(
        request,
        "items/detail.html",
        {
            "user": user,
            "item": item,
            "events": events,
            "statuses": list(ItemStatus),
            "allowed": service.selectable_statuses(item.status),
            "csrf_token": token,
        },
    )
    csrf.attach(response, token, settings)
    return response


@router.post("")
async def create(
    request: Request,  # noqa: ARG001 - required for the CSRF dependency
    session: SessionDep,
    user: CurrentUser,
    name: Annotated[str, Form()],
    description: Annotated[str | None, Form()] = None,
) -> Response:
    """Create an item and send the browser to it."""
    item = await service.create(
        session,
        ItemCreate(name=name, description=description or None, id=None),
        owner=user,
    )
    await session.commit()
    return hx_redirect(f"/items/{item.id}")


@router.post("/{item_id}/status")
async def update_status(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    background: BackgroundTasks,
    item_id: str,
    status: Annotated[ItemStatus, Form()],
) -> Response:
    """Apply a status change and schedule the resulting background work.

    Events are published only after the transaction commits — see
    ``core/events.publish_after_commit``.
    """
    item, events = await service.change_status(session, item_id, status, user)
    await publish_after_commit(session, background, events)

    return render(
        request,
        "partials/item_status_card.html",
        {
            "item": item,
            "statuses": list(ItemStatus),
            "allowed": service.selectable_statuses(item.status),
            "saved": True,
        },
    )
