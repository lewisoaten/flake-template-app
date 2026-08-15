"""Ownership scoping at the service layer.

Asserted here, without a request, because this is the tenant boundary: every
route and every API key ultimately funnels into these functions with a
``viewer``. If the rule holds here it holds everywhere; if it does not, no
amount of route-level testing will save it.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.domains.auth.models import User
from app.domains.items.models import Item, ItemStatus
from app.domains.items.service import get, list_items, status_summary


async def _item_for(session: AsyncSession, owner: User, name: str) -> Item:
    row = Item(name=name, owner_id=owner.id, status=ItemStatus.DRAFT)
    session.add(row)
    await session.flush()
    return row


async def test_a_member_lists_only_their_own_items(
    db_session: AsyncSession,
    member_user: User,
    other_member: User,
) -> None:
    mine = await _item_for(db_session, member_user, "Mine")
    await _item_for(db_session, other_member, "Theirs")

    rows, total = await list_items(db_session, member_user)

    assert total == 1
    assert [row.id for row in rows] == [mine.id]


async def test_an_admin_lists_everything(
    db_session: AsyncSession,
    admin_user: User,
    member_user: User,
    other_member: User,
) -> None:
    await _item_for(db_session, member_user, "Mine")
    await _item_for(db_session, other_member, "Theirs")

    _, total = await list_items(db_session, admin_user)

    assert total == 2


async def test_another_members_item_is_not_found_rather_than_forbidden(
    db_session: AsyncSession,
    member_user: User,
    other_member: User,
) -> None:
    # A 403 would confirm the id exists and let a caller enumerate the table.
    # NotFoundError gives away nothing.
    theirs = await _item_for(db_session, other_member, "Theirs")

    with pytest.raises(NotFoundError):
        await get(db_session, theirs.id, member_user)


async def test_a_member_can_read_their_own_item(
    db_session: AsyncSession,
    member_user: User,
) -> None:
    mine = await _item_for(db_session, member_user, "Mine")
    assert (await get(db_session, mine.id, member_user)).id == mine.id


async def test_an_admin_can_read_anyones_item(
    db_session: AsyncSession,
    admin_user: User,
    other_member: User,
) -> None:
    theirs = await _item_for(db_session, other_member, "Theirs")
    assert (await get(db_session, theirs.id, admin_user)).id == theirs.id


async def test_a_missing_id_is_not_found_for_an_admin_too(
    db_session: AsyncSession,
    admin_user: User,
) -> None:
    with pytest.raises(NotFoundError):
        await get(db_session, "no-such-item", admin_user)


async def test_search_cannot_reach_across_the_ownership_boundary(
    db_session: AsyncSession,
    member_user: User,
    other_member: User,
) -> None:
    # The filter is applied on top of the scope, not instead of it.
    await _item_for(db_session, other_member, "Telemetry rollout")

    _, total = await list_items(db_session, member_user, search="Telemetry")

    assert total == 0


async def test_status_summary_is_scoped_as_well(
    db_session: AsyncSession,
    member_user: User,
    other_member: User,
) -> None:
    # The counts sit in the page header; an unscoped aggregate would leak how
    # many records other members hold even though none of them are listed.
    await _item_for(db_session, member_user, "Mine")
    await _item_for(db_session, other_member, "Theirs")

    counts = await status_summary(db_session, member_user)

    assert counts[ItemStatus.DRAFT] == 1
