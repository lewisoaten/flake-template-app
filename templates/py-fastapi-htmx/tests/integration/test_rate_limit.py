"""Rate limiting on the two unauthenticated write surfaces.

Both need it for the same reason and neither can rely on a credential to
identify the caller: ``/login`` is where credential stuffing lands, and the
inbound webhook endpoint is the one route anyone on the internet may POST to.

Each test builds its own application so it can set the limit low enough to reach
in a handful of requests. The counters live in the process rather than the
database, so conftest's autouse ``limiter.reset()`` is what keeps them from
leaking into the next test.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import pytest

from app.core.database import dispose_engine
from app.core.settings import get_settings
from app.main import create_app
from tests.conftest import inbound_headers

BAD_LOGIN = {"email": "nobody@example.com", "password": "some-password-value"}


@asynccontextmanager
async def _client_with(
    monkeypatch: pytest.MonkeyPatch,
    **overrides: str,
) -> AsyncGenerator[httpx.AsyncClient]:
    """An app built with ``overrides`` applied to the environment."""
    for name, value in overrides.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()

    transport = httpx.ASGITransport(app=create_app(get_settings()))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            follow_redirects=False,
        ) as client:
            yield client
    finally:
        # The engine is bound to this test's loop; leaving it cached would hand
        # a dead loop to the next test.
        await dispose_engine()


async def test_login_is_limited_and_says_when_to_come_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Turning a credential-stuffing run from thousands of attempts per second
    # into a handful is the entire objective; an exact global limit is not.
    async with _client_with(monkeypatch, APP_LOGIN_RATE_LIMIT="3") as client:
        allowed = [(await client.post("/login", data=BAD_LOGIN)).status_code for _ in range(3)]
        blocked = await client.post("/login", data=BAD_LOGIN)

    assert allowed == [401, 401, 401]
    assert blocked.status_code == 429
    # Without Retry-After a client has no way to back off correctly and will
    # usually just hammer harder.
    assert int(blocked.headers["Retry-After"]) > 0


async def test_a_different_bucket_is_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"ping": True})

    async with _client_with(monkeypatch, APP_LOGIN_RATE_LIMIT="1") as client:
        await client.post("/login", data=BAD_LOGIN)
        assert (await client.post("/login", data=BAD_LOGIN)).status_code == 429

        # Same caller, different bucket: exhausting one must not deny the other.
        inbound = await client.post(
            "/api/v1/webhooks/inbound",
            content=body,
            headers=inbound_headers(body, delivery_id="delivery-1"),
        )

    assert inbound.status_code == 202


async def test_the_inbound_endpoint_is_limited_too(monkeypatch: pytest.MonkeyPatch) -> None:
    # The one unauthenticated write in the application. The HMAC proves who is
    # calling, but only after we have already read and hashed the body.
    async with _client_with(monkeypatch, APP_API_RATE_LIMIT="2") as client:
        statuses: list[int] = []
        for index in range(3):
            body = json.dumps({"sequence": index})
            response = await client.post(
                "/api/v1/webhooks/inbound",
                content=body,
                headers=inbound_headers(body, delivery_id=f"delivery-{index}"),
            )
            statuses.append(response.status_code)

    assert statuses == [202, 202, 429]


async def test_limiting_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # A single-tenant deployment behind its own gateway may not want a second,
    # per-worker limit fighting the first one.
    async with _client_with(
        monkeypatch,
        APP_RATE_LIMIT_ENABLED="false",
        APP_LOGIN_RATE_LIMIT="1",
    ) as client:
        statuses = [(await client.post("/login", data=BAD_LOGIN)).status_code for _ in range(4)]

    assert statuses == [401, 401, 401, 401]
