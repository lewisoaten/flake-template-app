"""Operational endpoints, the root redirect, and the published schema."""

from __future__ import annotations

import httpx
import pytest


async def test_liveness_does_not_touch_the_database(client: httpx.AsyncClient) -> None:
    # It must stay green while the database is down, or the orchestrator will
    # restart healthy processes during a database incident and make it worse.
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readiness_reports_the_database(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_readiness_degrades_instead_of_crashing(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A probe that 500s is indistinguishable from a crashed process; reporting
    # "degraded" with a 200 keeps the signal readable.
    def _explode() -> None:
        msg = "connection refused"
        raise OSError(msg)

    monkeypatch.setattr("app.main.get_sessionmaker", _explode)

    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "database": "unavailable"}


async def test_probes_are_not_in_the_published_schema(client: httpx.AsyncClient) -> None:
    # They exist for the orchestrator, not for a generated SDK.
    schema = (await client.get("/api/openapi.json")).json()
    assert "/healthz" not in schema["paths"]
    assert "/readyz" not in schema["paths"]


async def test_root_sends_anonymous_visitors_to_login(client: httpx.AsyncClient) -> None:
    response = await client.get("/")
    assert response.status_code == 307
    assert response.headers["location"] == "/login"


async def test_root_sends_a_signed_in_member_to_the_item_list(
    member_client: httpx.AsyncClient,
) -> None:
    response = await member_client.get("/")
    assert response.status_code == 307
    assert response.headers["location"] == "/items"


async def test_root_sends_a_signed_in_admin_to_the_item_list(
    admin_client: httpx.AsyncClient,
) -> None:
    response = await admin_client.get("/")
    assert response.status_code == 307
    assert response.headers["location"] == "/items"


async def test_openapi_schema_is_served(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/openapi.json")
    assert response.status_code == 200

    schema = response.json()
    assert "/api/v1/items" in schema["paths"]
    assert "/api/v1/webhooks/inbound" in schema["paths"]
    assert "/api/v1/audit/events" in schema["paths"]


async def test_the_html_surface_is_excluded_from_the_schema(client: httpx.AsyncClient) -> None:
    # A generated SDK should expose the JSON API and nothing else; the HTML
    # routes return fragments no client could use.
    schema = (await client.get("/api/openapi.json")).json()

    for path in ("/items", "/login", "/logout", "/admin/webhooks"):
        assert path not in schema["paths"]
