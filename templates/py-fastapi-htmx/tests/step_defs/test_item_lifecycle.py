"""Step definitions for features/item_lifecycle.feature.

Driven over HTTP against a real uvicorn server, using the JSON API with a real
API key — the same path a partner integration takes. No browser, because nothing
in this feature is about rendering; the browser-driven features live alongside
this file.

``respx`` patches httpx process-wide, so it intercepts the outbound partner call
made *inside* the server thread while letting this test's own requests to
127.0.0.1 pass through.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from urllib.parse import urlsplit

import httpx
import pytest
import respx
from pytest_bdd import given, parsers, scenarios, then, when
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_api_key, hash_password
from app.domains.audit.models import AuditEvent
from app.domains.auth.models import ApiKey, Role, User
from app.domains.items.models import Item, ItemStatus
from app.domains.webhooks.models import WebhookDelivery, WebhookEndpoint
from app.domains.webhooks.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

scenarios("item_lifecycle.feature")

# Loopback rather than a fake hostname: the dispatcher resolves and pins
# the target in every environment, so an unresolvable name would fail
# before the request was made. 127.0.0.1 pins to itself, leaving the
# request URL unchanged for respx to match.
PARTNER_URL = "http://127.0.0.1:9099/hooks/items"
ADMIN_EMAIL = "bdd-admin@example.com"
ADMIN_PASSWORD = "bdd-admin-password-long"
SIGNING_SECRET = "bdd-signing-secret"

# Generous: the retry scenario deliberately backs off between attempts.
DISPATCH_TIMEOUT_SECONDS = 20.0

# How long to let a dispatch that should never happen fail to happen.
GRACE_SECONDS = 0.5


def _wait_until(predicate: Callable[[], bool], message: str) -> None:
    """Poll ``predicate`` until it holds, or fail after the dispatch timeout.

    Background work finishes after the response has been sent, so a step that
    asserts on it immediately is asserting on a race. Polling makes the wait
    explicit — and bounded, so a genuine failure stays a failure rather than a
    hang.
    """
    deadline = time.monotonic() + DISPATCH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"{message} within {DISPATCH_TIMEOUT_SECONDS}s")


@pytest.fixture
def partner_route(live_server: str) -> Iterator[respx.Route]:
    """Intercept the partner endpoint; let calls to the app itself through.

    Both the live server and the partner stub are on 127.0.0.1 — the dispatcher
    resolves and pins its target, so the stub has to be a resolvable address —
    which means the pass-through rule has to discriminate by *port*, not host.
    Matching on host alone would let the partner request escape to a socket
    nobody is listening on.
    """
    app_port = int(urlsplit(live_server).port or 80)
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host="127.0.0.1", port=app_port).pass_through()
        yield mock.post(PARTNER_URL).mock(return_value=httpx.Response(200, json={"received": True}))


@pytest.fixture
def integration(live_server: str, sync_session: Session) -> Iterator[httpx.Client]:
    """A client presenting a fully-scoped API key over a real socket.

    The key is owned by an admin so that ownership scoping — proved elsewhere —
    never gets in the way of what this feature is actually about.
    """
    owner = User(
        email=ADMIN_EMAIL,
        full_name="BDD Admin",
        password_hash=hash_password(ADMIN_PASSWORD),
        role=Role.ADMIN,
    )
    sync_session.add(owner)
    sync_session.flush()

    generated = generate_api_key()
    sync_session.add(
        ApiKey(
            name="bdd-integration",
            key_digest=generated.digest,
            scopes="audit:read items:read items:write webhooks:read",
            owner_id=owner.id,
        )
    )
    sync_session.commit()

    with httpx.Client(
        base_url=live_server,
        headers={"Authorization": f"Bearer {generated.plaintext}"},
        timeout=30.0,
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# Given
# ---------------------------------------------------------------------------
@given("an integration holding an API key scoped to items and audit")
def _integration(integration: httpx.Client) -> None:
    assert integration.headers["Authorization"].startswith("Bearer app_sk_")


@given(parsers.parse('an item "{item_id}" in status "{status}"'), target_fixture="item_row")
def _item(
    sync_session: Session,
    integration: httpx.Client,  # noqa: ARG001 - seeds the owner this item needs
    item_id: str,
    status: str,
) -> Item:
    # Inserted directly rather than through the API, so a scenario can start
    # from any status without walking the whole state machine to get there.
    owner = sync_session.scalars(select(User).where(User.email == ADMIN_EMAIL)).one()
    row = Item(
        id=item_id,
        name="Telemetry rollout",
        description="An example record with a lifecycle.",
        owner_id=owner.id,
        status=ItemStatus(status),
    )
    sync_session.add(row)
    sync_session.commit()
    return row


@given(parsers.parse('a registered webhook endpoint "{url}"'), target_fixture="endpoint_row")
def _endpoint(sync_session: Session, url: str) -> WebhookEndpoint:
    endpoint = WebhookEndpoint(
        url=url,
        description="Partner item feed",
        event_types="ItemStatusChanged",
        signing_secret=SIGNING_SECRET,
    )
    sync_session.add(endpoint)
    sync_session.commit()
    return endpoint


@given(parsers.parse("the partner endpoint responds with status {status:d}"))
def _partner_fails(partner_route: respx.Route, status: int) -> None:
    partner_route.mock(return_value=httpx.Response(status, text="upstream error"))


@given(parsers.parse('the item is already in status "{status}"'))
def _force_status(sync_session: Session, item_row: Item, status: str) -> None:
    item_row.status = ItemStatus(status)
    sync_session.add(item_row)
    sync_session.commit()


# ---------------------------------------------------------------------------
# When
# ---------------------------------------------------------------------------
@when(
    parsers.parse('the integration changes the item status to "{new_status}"'),
    target_fixture="update_response",
)
def _change_status(
    integration: httpx.Client,
    partner_route: respx.Route,  # noqa: ARG001 - must be patched before the request
    item_row: Item,
    new_status: str,
) -> httpx.Response:
    return integration.put(
        f"/api/v1/items/{item_row.id}/status",
        json={"status": new_status},
    )


# ---------------------------------------------------------------------------
# Then
# ---------------------------------------------------------------------------
@then("the change is accepted")
def _accepted(update_response: httpx.Response) -> None:
    assert update_response.status_code == 200, update_response.text


@then("the change is rejected as invalid")
def _rejected(update_response: httpx.Response) -> None:
    assert update_response.status_code == 422, update_response.text


@then(parsers.parse('an audit entry named "{event_name}" is recorded for the item'))
def _audit_entry(sync_session: Session, item_row: Item, event_name: str) -> None:
    # The subscriber runs after the response, on its own session.
    _wait_until(
        lambda: len(_audit_entries(sync_session, item_row.id)) == 1,
        "no audit entry was recorded",
    )
    entry = _audit_entries(sync_session, item_row.id)[0]
    assert entry.event_name == event_name
    assert entry.subject_id == item_row.id


@then(parsers.parse("{count:d} HTTP POST payloads are dispatched to the endpoint"))
def _dispatched(partner_route: respx.Route, count: int) -> None:
    # "Asynchronous" is the point of the scenario: the response has already come
    # back, so the dispatch may still be in flight on the server.
    _wait_until(
        lambda: partner_route.call_count >= count,
        f"fewer than {count} POSTs were dispatched",
    )
    assert partner_route.call_count == count
    assert all(call.request.method == "POST" for call in partner_route.calls)


@then("every dispatched payload carries a valid signature")
def _signatures_verify(partner_route: respx.Route, endpoint_row: WebhookEndpoint) -> None:
    # Recomputed the way the partner's own SDK would, from the secret they were
    # given at registration.
    for call in partner_route.calls:
        request = call.request
        body = request.content.decode()
        expected = sign(endpoint_row.signing_secret, request.headers[TIMESTAMP_HEADER], body)
        assert request.headers[SIGNATURE_HEADER] == expected


@then(parsers.parse("the response status code logged in the DB audit trail should be {code:d}"))
def _delivery_status(sync_session: Session, item_row: Item, code: int) -> None:
    _wait_until(
        lambda: len(_deliveries(sync_session, item_row.id)) >= 1,
        "no delivery was recorded",
    )
    deliveries = _deliveries(sync_session, item_row.id)
    assert all(delivery.response_status == code for delivery in deliveries)
    assert all(delivery.succeeded for delivery in deliveries)


@then(parsers.parse("{count:d} delivery attempts are recorded in the DB audit trail"))
def _attempt_count(sync_session: Session, item_row: Item, count: int) -> None:
    # Each retry backs off, so this waits seconds rather than milliseconds.
    _wait_until(
        lambda: len(_deliveries(sync_session, item_row.id)) >= count,
        f"fewer than {count} attempts were recorded",
    )
    deliveries = _deliveries(sync_session, item_row.id)
    assert [delivery.attempt for delivery in deliveries] == list(range(1, count + 1))


@then("no delivery is marked as successful")
def _none_succeeded(sync_session: Session, item_row: Item) -> None:
    assert not any(delivery.succeeded for delivery in _deliveries(sync_session, item_row.id))


@then("no HTTP POST is dispatched to the endpoint")
def _not_dispatched(partner_route: respx.Route) -> None:
    # Absence cannot be waited for, only given a fair chance to appear.
    time.sleep(GRACE_SECONDS)
    assert partner_route.call_count == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _deliveries(session: Session, subject_id: str) -> list[WebhookDelivery]:
    """Read the outbound trail, discarding anything already cached.

    The rows were written by the server thread on a different connection, so the
    identity map here is stale by construction.
    """
    session.expire_all()
    return list(
        session.scalars(
            select(WebhookDelivery)
            .where(WebhookDelivery.subject_id == subject_id)
            .order_by(WebhookDelivery.attempt)
        )
    )


def _audit_entries(session: Session, subject_id: str) -> list[AuditEvent]:
    session.expire_all()
    return list(session.scalars(select(AuditEvent).where(AuditEvent.subject_id == subject_id)))
