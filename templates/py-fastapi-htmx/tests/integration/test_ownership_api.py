"""Ownership scoping over the JSON API.

The service-level rules are proved in tests/unit/test_ownership.py. What is
asserted here is that a *machine* caller inherits them: an API key acts as the
user that owns it, so a member's integration sees exactly what the member does
and no more.
"""

from __future__ import annotations

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.models import ApiKey, User
from app.domains.items.models import Item, ItemStatus


async def _item_for(session: AsyncSession, owner: User, name: str) -> Item:
    row = Item(name=name, owner_id=owner.id, status=ItemStatus.DRAFT)
    session.add(row)
    await session.commit()
    return row


async def test_a_members_key_lists_only_their_items(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    member_api_key: tuple[ApiKey, str],
    member_user: User,
    other_member: User,
) -> None:
    mine = await _item_for(db_session, member_user, "Mine")
    await _item_for(db_session, other_member, "Theirs")

    response = await client.get(
        "/api/v1/items",
        headers={"Authorization": f"Bearer {member_api_key[1]}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [row["id"] for row in body["items"]] == [mine.id]


async def test_another_members_item_is_404_not_403(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    member_api_key: tuple[ApiKey, str],
    other_member: User,
) -> None:
    # A 403 would confirm the id exists and let a caller walk the table one
    # guess at a time. 404 gives away nothing.
    theirs = await _item_for(db_session, other_member, "Theirs")

    response = await client.get(
        f"/api/v1/items/{theirs.id}",
        headers={"Authorization": f"Bearer {member_api_key[1]}"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


async def test_another_members_item_cannot_be_written_either(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    member_api_key: tuple[ApiKey, str],
    other_member: User,
) -> None:
    # The write paths route through the same `get`, so the scope holds without
    # each of them re-implementing it.
    theirs = await _item_for(db_session, other_member, "Theirs")
    headers = {"Authorization": f"Bearer {member_api_key[1]}"}

    patched = await client.patch(
        f"/api/v1/items/{theirs.id}",
        headers=headers,
        json={"name": "Hijacked"},
    )
    transitioned = await client.put(
        f"/api/v1/items/{theirs.id}/status",
        headers=headers,
        json={"status": "archived"},
    )

    assert patched.status_code == 404
    assert transitioned.status_code == 404


async def test_an_admins_key_sees_everything(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    api_headers: dict[str, str],
    member_user: User,
    other_member: User,
) -> None:
    await _item_for(db_session, member_user, "Mine")
    theirs = await _item_for(db_session, other_member, "Theirs")

    listing = await client.get("/api/v1/items", headers=api_headers)
    detail = await client.get(f"/api/v1/items/{theirs.id}", headers=api_headers)

    assert listing.json()["total"] == 2
    assert detail.status_code == 200


async def test_a_created_item_is_owned_by_the_keys_user(
    client: httpx.AsyncClient,
    member_api_key: tuple[ApiKey, str],
    member_user: User,
) -> None:
    # Ownership is taken from the principal, never from the payload — which is
    # what makes the scoping above unforgeable.
    response = await client.post(
        "/api/v1/items",
        headers={"Authorization": f"Bearer {member_api_key[1]}"},
        json={"name": "Mine by construction"},
    )

    assert response.status_code == 201
    assert response.json()["owner_id"] == member_user.id


async def test_the_member_still_sees_their_own_item(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    member_api_key: tuple[ApiKey, str],
    member_user: User,
) -> None:
    # The control case: scoping that refused everything would pass every test
    # above and be useless.
    mine = await _item_for(db_session, member_user, "Mine")

    response = await client.get(
        f"/api/v1/items/{mine.id}",
        headers={"Authorization": f"Bearer {member_api_key[1]}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == mine.id
