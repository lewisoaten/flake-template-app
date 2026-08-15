"""Shared fixtures.

Isolation strategy: every test gets its own SQLite *file* and its own engine.
A file (rather than ``:memory:``) is required because the webhook dispatcher and
the audit subscriber each open a second, independent session — an in-memory
database would be invisible to them. Rebuilding per test is cheap on SQLite and
removes every ordering dependency between tests.
"""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

# Settings are read at import time by anything that touches `app.core`, so the
# environment must be correct before the first `app.*` import below.
os.environ.setdefault("APP_ENVIRONMENT", "test")
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-not-used-outside-tests")
os.environ.setdefault("APP_DATABASE_URL", "sqlite+aiosqlite:///./test-bootstrap.db")
os.environ.setdefault("APP_INBOUND_WEBHOOK_SECRET", "test-inbound-webhook-secret")

import httpx
import pyotp
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool

from app import models
from app.core.database import Base, get_engine, get_sessionmaker
from app.core.events import event_bus
from app.core.ratelimit import reset_all as reset_rate_limiters
from app.core.settings import Settings, get_settings
from app.domains.audit.service import register_subscriptions as register_audit
from app.domains.auth.models import ApiKey, Role, User
from app.domains.auth.schemas import ApiKeyCreate, UserCreate
from app.domains.auth.service import create_api_key, create_user, provision_mfa_secret
from app.domains.items.models import Item
from app.domains.items.schemas import ItemCreate
from app.domains.items.service import create as create_item
from app.domains.webhooks.dispatcher import register_subscriptions as register_webhooks
from app.domains.webhooks.models import WebhookEndpoint
from app.domains.webhooks.schemas import WebhookEndpointCreate
from app.domains.webhooks.service import register_endpoint
from app.domains.webhooks.signing import (
    DELIVERY_HEADER,
    EVENT_HEADER,
    SIGNATURE_HEADER,
    SOURCE_HEADER,
    TIMESTAMP_HEADER,
    sign,
)
from app.main import create_app

# Deliberately not derived from the email local part: the password policy
# rejects that, and these fixtures should exercise the happy path rather than
# accidentally test the policy.
ADMIN_PASSWORD = "correct-horse-battery-staple-7"
MEMBER_PASSWORD = "trombone-lantern-quartz-42"

# Must match APP_INBOUND_WEBHOOK_SECRET below: the inbound tests sign their own
# requests with it, exactly as a third-party sender would.
INBOUND_SECRET = "test-inbound-webhook-secret"

# Every scope the application defines. The admin key carries all of them so a
# test only has to opt *out* of a permission when that is the thing under test.
ALL_SCOPES = [
    "audit:read",
    "items:read",
    "items:write",
    "webhooks:read",
    "webhooks:write",
]

# Loopback rather than a fake hostname: the dispatcher resolves and pins
# the target in every environment, so an unresolvable name would fail
# before the request was made. 127.0.0.1 pins to itself, leaving the
# request URL unchanged for respx to match.
PARTNER_URL = "http://127.0.0.1:9099/hooks/items"


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point each test at a private database and reset the settings singleton."""
    monkeypatch.setenv("APP_ENVIRONMENT", "test")
    monkeypatch.setenv("APP_DEBUG", "false")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-not-used-outside-tests")
    monkeypatch.setenv("APP_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("APP_INBOUND_WEBHOOK_SECRET", INBOUND_SECRET)

    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture(autouse=True)
def _schema(_isolated_settings: None) -> None:
    """Build the schema using a throwaway *synchronous* engine.

    Synchronous on purpose: pytest-bdd generates sync test functions, and a
    sync test cannot consume an async fixture. Creating the schema over the
    same SQLite file with a blocking driver sidesteps that entirely and leaves
    the async engine untouched until a test actually asks for one.
    """
    models.configure()
    engine = create_engine(sync_database_url(), poolclass=NullPool)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def sync_database_url() -> str:
    """The configured database URL with the async driver stripped off."""
    return get_settings().database_url.replace("+aiosqlite", "").replace("+asyncpg", "")


@pytest.fixture(autouse=True)
def _reset_event_bus() -> Iterator[None]:
    """The bus is process-global; give every test a known set of handlers.

    ``create_app``'s lifespan does not run under ASGITransport, so the
    subscriptions it would normally install are wired here instead — both
    domains, because ``ItemStatusChanged`` has two independent consumers and a
    test that only registered one would silently prove half the behaviour.
    """
    event_bus.clear()
    register_webhooks()
    register_audit()
    yield
    event_bus.clear()


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> Iterator[None]:
    """Counters live in the process, not the database, so tmp_path cannot help.

    Without this, the first test to exhaust a bucket would leave every later
    test in the same window rate-limited.
    """
    reset_rate_limiters()
    yield
    reset_rate_limiters()


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture
def fastapi_app(settings: Settings) -> FastAPI:
    """A fresh application instance.

    Its lifespan does not run under ASGITransport, which is why
    ``_reset_event_bus`` wires the subscribers explicitly.
    """
    return create_app(settings)


@pytest.fixture
async def client(fastapi_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client speaking directly to the ASGI app.

    Background tasks are awaited inside the ASGI call, so a response returned
    here already reflects any webhook dispatch or audit write it triggered.
    """
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=False,
    ) as http_client:
        yield http_client

    # The engine is bound to this test's event loop; leaving it in the cache
    # would hand a dead loop to the next test.
    await get_engine().dispose()


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A session for arranging and asserting on database state."""
    async with get_sessionmaker()() as session:
        yield session
    await get_engine().dispose()


# ---------------------------------------------------------------------------
# Identity factories
# ---------------------------------------------------------------------------
@pytest.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """An admin with MFA enrolled — the only kind that can sign in."""
    user = await create_user(
        db_session,
        UserCreate(
            email="admin@example.com",  # pyright: ignore[reportArgumentType]
            full_name="Ada Admin",
            password=ADMIN_PASSWORD,
            role=Role.ADMIN,
        ),
    )
    provision_mfa_secret(user, issuer="test")
    await db_session.commit()
    return user


@pytest.fixture
async def member_user(db_session: AsyncSession) -> User:
    """An ordinary user, scoped to the records they own."""
    user = await create_user(
        db_session,
        UserCreate(
            email="member@example.com",  # pyright: ignore[reportArgumentType]
            full_name="Mo Member",
            password=MEMBER_PASSWORD,
            role=Role.MEMBER,
        ),
    )
    await db_session.commit()
    return user


@pytest.fixture
async def other_member(db_session: AsyncSession) -> User:
    """A second member, so isolation can be asserted rather than assumed."""
    user = await create_user(
        db_session,
        UserCreate(
            email="other@example.com",  # pyright: ignore[reportArgumentType]
            full_name="Ola Other",
            password=MEMBER_PASSWORD,
            role=Role.MEMBER,
        ),
    )
    await db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Domain factories
# ---------------------------------------------------------------------------
@pytest.fixture
async def item(db_session: AsyncSession, member_user: User) -> Item:
    """A draft item owned by ``member_user``, with a pinned id.

    Pinned so a failing assertion names something recognisable, and so the
    Gherkin features can refer to the same identifier.
    """
    row = await create_item(
        db_session,
        ItemCreate(
            id="item-101",
            name="Telemetry rollout",
            description="An example record with a lifecycle.",
        ),
        owner=member_user,
    )
    await db_session.commit()
    return row


@pytest.fixture
async def api_key(db_session: AsyncSession, admin_user: User) -> tuple[ApiKey, str]:
    """A fully-scoped admin key, plus its one-time plaintext.

    Owned by the admin, so it inherits an admin's visibility: a key can never
    see more than the person who holds it.
    """
    key, plaintext = await issue_api_key(
        db_session,
        name="integration-tests",
        scopes=ALL_SCOPES,
        owner=admin_user,
    )
    await db_session.commit()
    return key, plaintext


@pytest.fixture
async def member_api_key(db_session: AsyncSession, member_user: User) -> tuple[ApiKey, str]:
    """The same scopes, but owned by a member — so the rows differ, not the RBAC."""
    key, plaintext = await issue_api_key(
        db_session,
        name="member-integration",
        scopes=ALL_SCOPES,
        owner=member_user,
    )
    await db_session.commit()
    return key, plaintext


@pytest.fixture
def api_headers(api_key: tuple[ApiKey, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key[1]}"}


@pytest.fixture
async def webhook_endpoint(db_session: AsyncSession) -> WebhookEndpoint:
    """A partner subscribed to item transitions."""
    endpoint = await register_endpoint(
        db_session,
        WebhookEndpointCreate(
            url=PARTNER_URL,  # pyright: ignore[reportArgumentType]
            description="Partner item feed",
            event_types=["ItemStatusChanged"],
        ),
    )
    await db_session.commit()
    return endpoint


async def issue_api_key(
    session: AsyncSession,
    *,
    name: str,
    scopes: list[str],
    owner: User,
) -> tuple[ApiKey, str]:
    """Mint a key owned by ``owner``.

    Wrapped rather than called inline because ``ApiKey.owner_id`` is mandatory:
    if the service's ownership parameter is ever renamed, this is the single
    place the suite has to follow it.
    """
    return await create_api_key(
        session,
        ApiKeyCreate(name=name, scopes=scopes, expires_at=None),
        default_owner=owner,
    )


def inbound_headers(
    body: str,
    *,
    delivery_id: str,
    source: str = "partner-stub",
    event_name: str = "partner.thing.happened",
    timestamp: int | None = None,
    secret: str = INBOUND_SECRET,
) -> dict[str, str]:
    """Sign ``body`` the way a third-party sender would.

    Built from the same ``sign`` the application uses to verify, because the
    scheme is symmetric by design — see ``webhooks/signing.py``. The parameters
    exist so a test can deliberately get one of them wrong.
    """
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    return {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: sign(secret, stamp, body),
        TIMESTAMP_HEADER: stamp,
        DELIVERY_HEADER: delivery_id,
        EVENT_HEADER: event_name,
        SOURCE_HEADER: source,
    }


# ---------------------------------------------------------------------------
# Authenticated clients
# ---------------------------------------------------------------------------
def totp_for(user: User) -> str:
    """Current six-digit code for a user's enrolled MFA secret."""
    assert user.mfa_secret is not None
    return pyotp.TOTP(user.mfa_secret).now()


async def _sign_in(
    client: httpx.AsyncClient,
    *,
    email: str,
    password: str,
    mfa_code: str | None = None,
) -> httpx.AsyncClient:
    """Log in the way a browser does, and keep the CSRF token it was issued.

    The GET is not decoration: it is what mints the ``app_csrf`` cookie. Every
    later unsafe request from this client carries a session cookie, so
    ``csrf.verify`` will demand the matching token — setting it as a default
    header is exactly what ``app.js`` does in the browser.
    """
    settings = get_settings()

    form = await client.get("/login")
    assert form.status_code == 200, form.text

    data = {"email": email, "password": password}
    if mfa_code is not None:
        data["mfa_code"] = mfa_code

    response = await client.post("/login", data=data)
    assert response.status_code == 303, response.text

    csrf_token = client.cookies.get(settings.csrf_cookie_name)
    assert csrf_token is not None, "the login page did not set a CSRF cookie"
    client.headers[settings.csrf_header_name] = csrf_token
    return client


@pytest.fixture
async def admin_client(client: httpx.AsyncClient, admin_user: User) -> httpx.AsyncClient:
    """A client carrying a valid admin session cookie and CSRF token."""
    return await _sign_in(
        client,
        email=admin_user.email,
        password=ADMIN_PASSWORD,
        mfa_code=totp_for(admin_user),
    )


@pytest.fixture
async def member_client(client: httpx.AsyncClient, member_user: User) -> httpx.AsyncClient:
    """A client carrying a valid member session cookie and CSRF token."""
    return await _sign_in(client, email=member_user.email, password=MEMBER_PASSWORD)
