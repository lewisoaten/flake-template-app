"""Outbound webhook dispatch — the executable form of features/item_lifecycle.feature.

respx intercepts the partner call; requests to the app itself are passed through
to the ASGI transport, so one test can drive the API and observe the outbound
side effect it causes.

Background tasks are awaited inside the ASGI call, so by the time a response is
returned here the dispatch has already finished. That is a property of
ASGITransport, not of the app — the BDD suite, which runs against a real socket,
has to poll instead.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from sqlalchemy import create_engine, func, select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool

from app.core.database import get_sessionmaker
from app.core.settings import Settings
from app.domains.items.models import Item
from app.domains.webhooks.models import WebhookDelivery, WebhookEndpoint
from app.domains.webhooks.signing import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign,
)
from tests.conftest import PARTNER_URL, sync_database_url


async def _deliveries(subject_id: str) -> list[WebhookDelivery]:
    """Read the audit trail on a fresh session.

    The dispatcher commits on its own session, so the fixture session would
    otherwise hand back a stale identity-map view.
    """
    async with get_sessionmaker()() as session:
        rows = await session.execute(
            select(WebhookDelivery)
            .where(WebhookDelivery.subject_id == subject_id)
            .order_by(WebhookDelivery.created_at, WebhookDelivery.attempt)
        )
        return list(rows.scalars().all())


async def _set_status(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    item_id: str,
    status: str,
) -> httpx.Response:
    return await client.put(
        f"/api/v1/items/{item_id}/status",
        headers=headers,
        json={"status": status},
    )


async def test_activating_then_archiving_dispatches_one_signed_post_each(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,
) -> None:
    """Each transition dispatches exactly once — not zero, and not twice.

    Two respx blocks rather than one so the count is asserted *per transition*.
    A single block could hide a double dispatch on the first transition behind a
    missing one on the second.
    """
    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        activate = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
        activated = await _set_status(client, api_headers, item.id, "active")

    assert activated.status_code == 200
    assert activate.call_count == 1

    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        archive = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
        archived = await _set_status(client, api_headers, item.id, "archived")

    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"
    assert archive.call_count == 1

    request = archive.calls[0].request
    assert request.method == "POST"

    body = request.content.decode()
    payload = json.loads(body)
    assert payload["event"] == "ItemStatusChanged"
    assert payload["item_id"] == item.id
    assert payload["previous_status"] == "active"
    assert payload["new_status"] == "archived"

    # The partner recomputes exactly this to decide the request is ours.
    assert request.headers[EVENT_HEADER] == "ItemStatusChanged"
    assert request.headers[SIGNATURE_HEADER] == sign(
        webhook_endpoint.signing_secret,
        request.headers[TIMESTAMP_HEADER],
        body,
    )


async def test_the_audit_trail_records_a_200(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,
) -> None:
    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        mock.post(PARTNER_URL).mock(return_value=httpx.Response(200, text="thanks"))

        await _set_status(client, api_headers, item.id, "active")

    rows = await _deliveries(item.id)
    assert len(rows) == 1

    delivery = rows[0]
    assert delivery.endpoint_id == webhook_endpoint.id
    assert delivery.event_name == "ItemStatusChanged"
    assert delivery.response_status == 200
    assert delivery.succeeded_at is not None
    assert delivery.attempt == 1
    assert delivery.duration_ms is not None
    assert delivery.error is None


async def test_dispatch_observes_a_committed_transaction(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,  # noqa: ARG001 - registers the endpoint
) -> None:
    """Regression guard for the ordering trap described in core/events.py.

    Starlette runs background tasks *before* FastAPI unwinds its dependency
    stack, so relying on ``get_session``'s teardown commit would dispatch from
    inside an open transaction. On Postgres that silently reads stale state; on
    SQLite it deadlocks against the open writer. This asserts the opposite: by
    the time a partner is called, the change is durable and visible to an
    entirely independent connection.
    """
    observed: list[str] = []

    def _inspect(_request: httpx.Request) -> httpx.Response:
        # Runs synchronously inside the dispatch, so it sees exactly what any
        # other connection would see at that moment.
        engine = create_engine(sync_database_url(), poolclass=NullPool)
        try:
            with engine.connect() as connection:
                row = connection.execute(
                    sa_text("SELECT status FROM items WHERE id = :id"),
                    {"id": item.id},
                ).one()
        finally:
            engine.dispose()
        observed.append(str(row[0]))
        return httpx.Response(200)

    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        mock.post(PARTNER_URL).mock(side_effect=_inspect)

        await _set_status(client, api_headers, item.id, "active")

    assert observed == ["active"]


@pytest.mark.slow
async def test_a_failing_partner_is_retried_and_recorded(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    settings: Settings,
    webhook_endpoint: WebhookEndpoint,  # noqa: ARG001 - registers the endpoint
) -> None:
    # 5xx is transient by definition, so the dispatcher backs off and retries up
    # to webhook_max_attempts before giving up. The backoff is why this is slow.
    attempts = settings.webhook_max_attempts

    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(500, text="boom"))

        response = await _set_status(client, api_headers, item.id, "active")

    # The item still moved: a partner outage must not roll back our own state.
    assert response.status_code == 200
    assert route.call_count == attempts

    rows = await _deliveries(item.id)
    assert [row.attempt for row in rows] == list(range(1, attempts + 1))
    assert all(row.response_status == 500 for row in rows)
    assert not any(row.succeeded for row in rows)


async def test_a_4xx_is_not_retried(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,  # noqa: ARG001 - registers the endpoint
) -> None:
    # The partner rejected the payload; sending it again would fail identically
    # and only add load to an endpoint that is already unhappy.
    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(400, text="bad"))

        await _set_status(client, api_headers, item.id, "active")

    assert route.call_count == 1
    assert len(await _deliveries(item.id)) == 1


async def test_a_no_op_status_change_dispatches_nothing(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,  # noqa: ARG001 - registers the endpoint
) -> None:
    # A double-clicked button or a retried request must not fire a second round
    # of downstream work.
    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200))

        response = await _set_status(client, api_headers, item.id, "draft")

    assert response.status_code == 200
    assert route.call_count == 0


async def test_an_illegal_transition_dispatches_nothing(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    item: Item,
    webhook_endpoint: WebhookEndpoint,  # noqa: ARG001 - registers the endpoint
) -> None:
    # Archived is terminal. A partner that already reacted to the archive must
    # never be told the record reopened, so the refusal has to happen before
    # anything is published — not be compensated for afterwards.
    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200))

        archived = await _set_status(client, api_headers, item.id, "archived")
        reopened = await _set_status(client, api_headers, item.id, "active")

    assert archived.status_code == 200
    assert reopened.status_code == 422
    # One POST for the legal archive, none for the rejected reopen.
    assert route.call_count == 1


async def test_an_unsubscribed_endpoint_is_skipped(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
    item: Item,
) -> None:
    endpoint = WebhookEndpoint(
        url=PARTNER_URL,
        event_types="SomeOtherEvent",
        signing_secret="secret",
    )
    db_session.add(endpoint)
    await db_session.commit()

    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200))

        await _set_status(client, api_headers, item.id, "active")

    assert route.call_count == 0


async def test_an_inactive_endpoint_is_skipped(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
    db_session: AsyncSession,
    item: Item,
    webhook_endpoint: WebhookEndpoint,
) -> None:
    webhook_endpoint.is_active = False
    db_session.add(webhook_endpoint)
    await db_session.commit()

    async with respx.mock(assert_all_called=False) as mock:
        mock.route(host="testserver").pass_through()
        route = mock.post(PARTNER_URL).mock(return_value=httpx.Response(200))

        await _set_status(client, api_headers, item.id, "active")

    assert route.call_count == 0
    async with get_sessionmaker()() as session:
        total = await session.scalar(select(func.count()).select_from(WebhookDelivery))
    assert total == 0
