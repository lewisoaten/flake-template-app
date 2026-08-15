"""JSON API for items.

Every route declares the scope it needs. Read and write are separate so an
integration that only reports on items cannot mutate them.

Note the ``viewer``: an API key acts as the user that owns it, so ownership
scoping applies identically to machine callers. A key with no owner is treated
as an admin — see ``auth.dependencies.principal_user``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status

from app.core.database import SessionDep
from app.core.events import publish_after_commit
from app.core.schemas import Page
from app.domains.auth.dependencies import ScopedPrincipal, requires_scopes
from app.domains.items import service
from app.domains.items.models import Item, ItemStatus
from app.domains.items.schemas import ItemCreate, ItemRead, ItemStatusUpdate, ItemUpdate

router = APIRouter(prefix="/items", tags=["items"])


@router.get("", response_model=Page[ItemRead])
async def list_items(
    session: SessionDep,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:read"))],
    q: Annotated[str | None, Query(max_length=200)] = None,
    item_status: Annotated[ItemStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ItemRead]:
    items, total = await service.list_items(
        session, principal.viewer, search=q, status=item_status, limit=limit, offset=offset
    )
    return Page[ItemRead](
        items=[ItemRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ItemRead, status_code=status.HTTP_201_CREATED)
async def create_item(
    payload: ItemCreate,
    session: SessionDep,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:write"))],
) -> Item:
    return await service.create(session, payload, owner=principal.viewer)


@router.get("/{item_id}", response_model=ItemRead)
async def get_item(
    item_id: str,
    session: SessionDep,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:read"))],
) -> Item:
    return await service.get(session, item_id, principal.viewer)


@router.patch("/{item_id}", response_model=ItemRead)
async def update_item(
    item_id: str,
    payload: ItemUpdate,
    session: SessionDep,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:write"))],
) -> Item:
    return await service.update(session, item_id, payload, principal.viewer)


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(
    item_id: str,
    session: SessionDep,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:write"))],
) -> None:
    await service.delete(session, item_id, principal.viewer)


@router.put("/{item_id}/status", response_model=ItemRead)
async def change_status(
    item_id: str,
    payload: ItemStatusUpdate,
    session: SessionDep,
    background: BackgroundTasks,
    principal: Annotated[ScopedPrincipal, Depends(requires_scopes("items:write"))],
) -> Item:
    """Transition an item and schedule the resulting background work."""
    item, events = await service.change_status(session, item_id, payload.status, principal.viewer)
    await publish_after_commit(session, background, events)
    return item
