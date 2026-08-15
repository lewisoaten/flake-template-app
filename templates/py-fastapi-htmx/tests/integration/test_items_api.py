"""The external JSON API: authentication, scopes and CRUD.

An API key acts *as* a user, so everything here is also an assertion about the
principal: the key that reaches these routes carries a viewer, and the service
layer never learns how that viewer authenticated.
"""

from __future__ import annotations

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.models import ApiKey, User
from app.domains.items.models import Item
from tests.conftest import issue_api_key


class TestAuthentication:
    async def test_missing_credentials_are_refused(self, client: httpx.AsyncClient) -> None:
        assert (await client.get("/api/v1/items")).status_code == 401

    async def test_unknown_key_is_refused(self, client: httpx.AsyncClient) -> None:
        response = await client.get(
            "/api/v1/items",
            headers={"Authorization": "Bearer app_sk_not-a-real-key"},
        )
        assert response.status_code == 401

    async def test_valid_key_is_accepted(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        assert (await client.get("/api/v1/items", headers=api_headers)).status_code == 200

    async def test_revoked_key_is_refused(
        self,
        client: httpx.AsyncClient,
        db_session: AsyncSession,
        api_key: tuple[ApiKey, str],
    ) -> None:
        from app.domains.auth.service import revoke_api_key

        await revoke_api_key(db_session, api_key[0].id)
        await db_session.commit()

        response = await client.get(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {api_key[1]}"},
        )
        assert response.status_code == 401


class TestScopes:
    async def test_insufficient_scope_is_403_not_401(
        self,
        client: httpx.AsyncClient,
        db_session: AsyncSession,
        admin_user: User,
    ) -> None:
        # The caller *is* authenticated; they simply may not do this.
        _, plaintext = await issue_api_key(
            db_session,
            name="read-only",
            scopes=["items:read"],
            owner=admin_user,
        )
        await db_session.commit()

        response = await client.post(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {plaintext}"},
            json={"name": "Nope"},
        )
        assert response.status_code == 403
        assert "items:write" in response.json()["error"]["message"]

    async def test_read_scope_permits_reading(
        self,
        client: httpx.AsyncClient,
        db_session: AsyncSession,
        admin_user: User,
    ) -> None:
        _, plaintext = await issue_api_key(
            db_session,
            name="read-only",
            scopes=["items:read"],
            owner=admin_user,
        )
        await db_session.commit()

        response = await client.get(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200

    async def test_an_items_key_cannot_read_the_audit_trail(
        self,
        client: httpx.AsyncClient,
        db_session: AsyncSession,
        admin_user: User,
    ) -> None:
        # Scopes are the reason a reporting integration cannot quietly become a
        # surveillance one.
        _, plaintext = await issue_api_key(
            db_session,
            name="items-only",
            scopes=["items:read", "items:write"],
            owner=admin_user,
        )
        await db_session.commit()

        response = await client.get(
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 403


class TestTokenExchange:
    async def test_exchanged_token_works(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        exchange = await client.post("/api/v1/auth/token", headers=api_headers)
        assert exchange.status_code == 200

        body = exchange.json()
        assert body["token_type"] == "bearer"
        assert "items:read" in body["scope"]

        response = await client.get(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert response.status_code == 200

    async def test_a_token_cannot_widen_its_key_scopes(
        self,
        client: httpx.AsyncClient,
        db_session: AsyncSession,
        admin_user: User,
    ) -> None:
        # Forge a token claiming write access for a read-only key. The
        # dependency intersects claimed scopes with the key's real ones, so the
        # token can only ever narrow them.
        from app.core.security import issue_access_token

        key, _ = await issue_api_key(
            db_session,
            name="read-only",
            scopes=["items:read"],
            owner=admin_user,
        )
        await db_session.commit()

        forged = issue_access_token(key.id, ["items:read", "items:write"])
        response = await client.post(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {forged}"},
            json={"name": "Nope"},
        )
        assert response.status_code == 403


class TestCrud:
    async def test_create_and_fetch(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        created = await client.post(
            "/api/v1/items",
            headers=api_headers,
            json={"name": "Telemetry rollout", "description": "First pass"},
        )
        assert created.status_code == 201

        body = created.json()
        # The lifecycle starts at draft and ownership comes from the caller;
        # neither was in the payload.
        assert body["status"] == "draft"
        assert body["owner_id"]

        fetched = await client.get(f"/api/v1/items/{body['id']}", headers=api_headers)
        assert fetched.status_code == 200
        assert fetched.json()["name"] == "Telemetry rollout"

    async def test_partial_update_leaves_other_fields_alone(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        response = await client.patch(
            f"/api/v1/items/{item.id}",
            headers=api_headers,
            json={"description": "Revised"},
        )
        assert response.status_code == 200
        assert response.json()["description"] == "Revised"
        assert response.json()["name"] == item.name

    async def test_delete_removes_the_row(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        assert (
            await client.delete(f"/api/v1/items/{item.id}", headers=api_headers)
        ).status_code == 204
        assert (
            await client.get(f"/api/v1/items/{item.id}", headers=api_headers)
        ).status_code == 404

    async def test_unknown_item_is_404(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        response = await client.get("/api/v1/items/nope", headers=api_headers)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    async def test_create_with_a_caller_supplied_id(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        # Lets an integration make creation idempotent under retry.
        payload = {"name": "Renewal", "id": "item-999"}

        response = await client.post("/api/v1/items", headers=api_headers, json=payload)
        assert response.status_code == 201
        assert response.json()["id"] == "item-999"

        repeat = await client.post("/api/v1/items", headers=api_headers, json=payload)
        assert repeat.status_code == 409

    async def test_an_undeclared_field_is_rejected(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        # Mass assignment, refused at the schema boundary rather than silently
        # ignored on the way to the ORM.
        response = await client.post(
            "/api/v1/items",
            headers=api_headers,
            json={"name": "T", "owner_id": "somebody-else"},
        )
        assert response.status_code == 422


class TestListing:
    async def test_list_is_paginated(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        response = await client.get("/api/v1/items?limit=10", headers=api_headers)
        assert response.status_code == 200

        body = response.json()
        assert body["total"] == 1
        assert body["limit"] == 10
        assert body["offset"] == 0
        assert body["items"][0]["id"] == item.id

    async def test_filter_by_status(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,  # noqa: ARG002 - fixture seeds the row under test
    ) -> None:
        matching = await client.get("/api/v1/items?status=draft", headers=api_headers)
        assert matching.json()["total"] == 1

        empty = await client.get("/api/v1/items?status=archived", headers=api_headers)
        assert empty.json()["total"] == 0

    async def test_search_filters_by_name(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,  # noqa: ARG002 - fixture seeds the row under test
    ) -> None:
        assert (await client.get("/api/v1/items?q=Telemetry", headers=api_headers)).json()[
            "total"
        ] == 1
        assert (await client.get("/api/v1/items?q=Nothing", headers=api_headers)).json()[
            "total"
        ] == 0

    async def test_an_out_of_range_limit_is_rejected(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
    ) -> None:
        # The cap is what stops one caller asking for the whole table.
        response = await client.get("/api/v1/items?limit=5000", headers=api_headers)
        assert response.status_code == 422


class TestStatusChanges:
    async def test_a_legal_transition_is_applied(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        response = await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": "active"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "active"

    async def test_an_illegal_transition_is_422(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        # Archived is terminal: reopening it would invalidate everything
        # downstream that already reacted to the archive.
        await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": "archived"},
        )

        response = await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": "active"},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"

    async def test_an_unknown_status_is_422(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        response = await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": "Closed-Won"},
        )
        assert response.status_code == 422

    async def test_archiving_records_the_time(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        item: Item,
    ) -> None:
        response = await client.put(
            f"/api/v1/items/{item.id}/status",
            headers=api_headers,
            json={"status": "archived"},
        )
        assert response.status_code == 200
        assert response.json()["archived_at"] is not None


class TestScopeNarrowingDoesNotMutateTheKey:
    """Regression: a narrowed token must not shrink the stored key.

    `ScopedPrincipal.scopes` used to be a property over `api_key.scope_set`,
    and the JWT path assigned the narrowed set back onto the ORM object. The
    request session commits on the way out, so one narrow-scoped request
    permanently removed permissions from the key — silently, and for good.
    """

    async def test_stored_scopes_survive_a_narrowed_token(
        self,
        client: httpx.AsyncClient,
        api_key: tuple[ApiKey, str],
    ) -> None:
        from app.core.security import issue_access_token

        key, _ = api_key
        original = key.scope_set
        assert "items:write" in original

        # A token deliberately narrower than the key it came from.
        narrowed = issue_access_token(key.id, ["items:read"])
        response = await client.get(
            "/api/v1/items",
            headers={"Authorization": f"Bearer {narrowed}"},
        )
        assert response.status_code == 200

        # Read the key back on an independent session, so the assertion cannot
        # be satisfied by a stale identity-map copy of the object under test.
        from app.core.database import get_sessionmaker

        async with get_sessionmaker()() as fresh:
            refreshed = await fresh.get(ApiKey, key.id)
            assert refreshed is not None
            assert refreshed.scope_set == original

    async def test_the_key_still_writes_after_a_narrowed_request(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        api_key: tuple[ApiKey, str],
    ) -> None:
        from app.core.security import issue_access_token

        key, _ = api_key
        narrowed = issue_access_token(key.id, ["items:read"])
        await client.get("/api/v1/items", headers={"Authorization": f"Bearer {narrowed}"})

        # The full key must retain items:write. Before the fix this was a 403.
        response = await client.post(
            "/api/v1/items",
            headers=api_headers,
            json={"name": "Still writable"},
        )
        assert response.status_code == 201
