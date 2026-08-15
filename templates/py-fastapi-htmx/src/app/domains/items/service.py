"""Item business rules.

Two things here are load-bearing for the rest of the template:

* **Ownership scoping.** Every read takes a ``viewer`` and filters on it unless
  the viewer is an admin. Another user's item returns *not found*, never
  *forbidden*, so identifiers cannot be enumerated.
* **Event return, not event dispatch.** :func:`change_status` hands the caller
  the events it produced rather than publishing them, so the caller can commit
  first. See ``core/events.publish_after_commit`` for why that matters.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import utcnow
from app.core.events import DomainEvent, ItemStatusChanged
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.domains.auth.models import User
from app.domains.items.models import Item, ItemStatus
from app.domains.items.schemas import ItemCreate, ItemUpdate

log = get_logger(__name__)

# An archived item is history. Reopening it would invalidate anything
# downstream that already reacted to the archive, so it is refused outright.
_ALLOWED_TRANSITIONS: dict[ItemStatus, frozenset[ItemStatus]] = {
    ItemStatus.DRAFT: frozenset({ItemStatus.ACTIVE, ItemStatus.ARCHIVED}),
    ItemStatus.ACTIVE: frozenset({ItemStatus.ARCHIVED}),
    ItemStatus.ARCHIVED: frozenset(),
}


def selectable_statuses(current: ItemStatus) -> list[ItemStatus]:
    """Statuses the UI may offer: the current one, plus every legal move.

    Keeping this beside the transition table means the dropdown and the
    server-side check can never drift apart.
    """
    return [current, *sorted(_ALLOWED_TRANSITIONS[current])]


def _visible_to(viewer: User):  # noqa: ANN202 - SQLAlchemy filter clause
    """The ownership predicate for ``viewer``, or None for an admin."""
    return None if viewer.is_admin else Item.owner_id == viewer.id


async def create(session: AsyncSession, payload: ItemCreate, owner: User) -> Item:
    """Create an item owned by ``owner``."""
    data = payload.model_dump(exclude_none=True)
    item_id = data.pop("id", None)

    if item_id is not None and await session.get(Item, item_id) is not None:
        msg = f"An item with id {item_id} already exists."
        raise ConflictError(msg)

    item = Item(**data, owner_id=owner.id)
    if item_id is not None:
        item.id = item_id

    session.add(item)
    await session.flush()
    log.info("item_created", item_id=item.id, owner_id=owner.id)
    return item


async def get(session: AsyncSession, item_id: str, viewer: User) -> Item:
    """Fetch an item ``viewer`` is allowed to see.

    Returns *not found* rather than *forbidden* for someone else's item: a 403
    would confirm the id exists and let a caller enumerate the table.
    """
    item = await session.get(Item, item_id)
    if item is None or (not viewer.is_admin and item.owner_id != viewer.id):
        msg = f"No item with id {item_id}."
        raise NotFoundError(msg)
    return item


async def list_items(
    session: AsyncSession,
    viewer: User,
    *,
    search: str | None = None,
    status: ItemStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[Item], int]:
    """List the items ``viewer`` may see, newest first."""
    stmt = select(Item)

    scope = _visible_to(viewer)
    if scope is not None:
        stmt = stmt.where(scope)
    if search:
        stmt = stmt.where(Item.name.ilike(f"%{search}%"))
    if status is not None:
        stmt = stmt.where(Item.status == status)

    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = await session.execute(stmt.order_by(Item.updated_at.desc()).limit(limit).offset(offset))
    return rows.scalars().all(), total


async def update(
    session: AsyncSession,
    item_id: str,
    payload: ItemUpdate,
    viewer: User,
) -> Item:
    item = await get(session, item_id, viewer)
    # exclude_unset distinguishes "set to null" from "not mentioned".
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, key, value)
    await session.flush()
    return item


async def delete(session: AsyncSession, item_id: str, viewer: User) -> None:
    item = await get(session, item_id, viewer)
    await session.delete(item)
    log.info("item_deleted", item_id=item_id)


async def change_status(
    session: AsyncSession,
    item_id: str,
    new_status: ItemStatus,
    viewer: User,
) -> tuple[Item, list[DomainEvent]]:
    """Move an item to ``new_status``, returning the events to publish.

    Idempotent: setting the status an item already holds is a no-op and emits
    nothing, so a retried request or a double-clicked button cannot fire a
    second round of downstream work.
    """
    item = await get(session, item_id, viewer)
    previous = item.status

    if new_status == previous:
        return item, []

    if new_status not in _ALLOWED_TRANSITIONS[previous]:
        msg = f"Cannot move an item from {previous} to {new_status}."
        raise ValidationError(msg)

    item.status = new_status
    if new_status.is_terminal:
        item.archived_at = utcnow()
    await session.flush()

    log.info(
        "item_status_changed",
        item_id=item.id,
        previous_status=previous,
        new_status=new_status,
    )
    event = ItemStatusChanged(
        item_id=item.id,
        owner_id=item.owner_id,
        previous_status=str(previous),
        new_status=str(new_status),
        actor_id=viewer.id,
    )
    return item, [event]


async def status_summary(session: AsyncSession, viewer: User) -> dict[ItemStatus, int]:
    """Count of items by status, for the list page header."""
    stmt = select(Item.status, func.count()).group_by(Item.status)

    scope = _visible_to(viewer)
    if scope is not None:
        stmt = stmt.where(scope)

    rows = await session.execute(stmt)
    counts = dict.fromkeys(ItemStatus, 0)
    for status, count in rows.all():
        counts[ItemStatus(status)] = count
    return counts
