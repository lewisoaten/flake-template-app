"""Step definitions for features/web_ui.feature, driven by a real browser.

These are the slowest tests in the suite and the only ones that prove the HTMX
wiring works: that a status change swaps the card in place, and that the search
box updates the table without a page load.

Nothing here handles CSRF. The page's ``app.js`` echoes the readable
``app_csrf`` cookie into the ``X-CSRF-Token`` header from an
``htmx:configRequest`` listener, so a real browser is already compliant — and if
that listener regressed, these scenarios would fail with a 403, which is exactly
the signal wanted.
"""

from __future__ import annotations

import re

import pyotp
import pytest
from playwright.sync_api import Page, expect
from pytest_bdd import given, parsers, scenarios, then, when
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.domains.auth.models import Role, User
from app.domains.items.models import Item, ItemStatus

pytestmark = pytest.mark.e2e

scenarios("web_ui.feature")

ADMIN_EMAIL = "bdd-admin@example.com"
ADMIN_PASSWORD = "bdd-admin-password-long"


def _sign_in(page: Page, base_url: str, secret: str, *, with_code: bool) -> None:
    page.goto(f"{base_url}/login")
    page.fill("#email", ADMIN_EMAIL)
    page.fill("#password", ADMIN_PASSWORD)
    if with_code:
        page.fill("#mfa_code", pyotp.TOTP(secret).now())
    page.click("#sign-in")


# ---------------------------------------------------------------------------
# Given
# ---------------------------------------------------------------------------
@given("a seeded application with an admin user and two items", target_fixture="seed")
def _seed(sync_session: Session) -> dict[str, str]:
    admin = User(
        email=ADMIN_EMAIL,
        full_name="BDD Admin",
        password_hash=hash_password(ADMIN_PASSWORD),
        role=Role.ADMIN,
        mfa_secret=pyotp.random_base32(),
    )
    sync_session.add(admin)
    sync_session.flush()

    # Two items so the search scenario has something to filter *out*. A search
    # that matched everything would pass whether or not it ran.
    sync_session.add_all(
        [
            Item(
                id="item-101",
                name="Telemetry rollout",
                description="An example record with a lifecycle.",
                owner_id=admin.id,
                status=ItemStatus.DRAFT,
            ),
            Item(
                id="item-102",
                name="Depot refresh",
                owner_id=admin.id,
                status=ItemStatus.DRAFT,
            ),
        ]
    )
    sync_session.commit()

    assert admin.mfa_secret is not None
    return {"mfa_secret": admin.mfa_secret, "admin_id": admin.id}


@given("I am on the sign-in page")
def _on_login(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/login")


@given("I am signed in as the admin")
def _signed_in(page: Page, live_server: str, seed: dict[str, str]) -> None:
    _sign_in(page, live_server, seed["mfa_secret"], with_code=True)
    expect(page).to_have_url(f"{live_server}/items")


# ---------------------------------------------------------------------------
# When
# ---------------------------------------------------------------------------
@when("I sign in as the admin with a valid authentication code")
def _sign_in_valid(page: Page, live_server: str, seed: dict[str, str]) -> None:
    _sign_in(page, live_server, seed["mfa_secret"], with_code=True)


@when("I sign in as the admin without an authentication code")
def _sign_in_no_code(page: Page, live_server: str, seed: dict[str, str]) -> None:
    _sign_in(page, live_server, seed["mfa_secret"], with_code=False)


@when(parsers.parse('I open the item "{item_id}"'))
def _open_item(page: Page, live_server: str, item_id: str) -> None:
    page.goto(f"{live_server}/items/{item_id}")


@when(parsers.parse('I change its status to "{new_status}"'))
def _change_status(page: Page, new_status: str) -> None:
    page.select_option("select#item-status", new_status)
    page.click("button#save-item")


@when(parsers.parse('I search the item list for "{term}"'))
def _search(page: Page, live_server: str, term: str) -> None:
    page.goto(f"{live_server}/items")
    page.fill("#item-search", term)


# ---------------------------------------------------------------------------
# Then
# ---------------------------------------------------------------------------
@then("I land on the item list")
def _on_item_list(page: Page, live_server: str) -> None:
    expect(page).to_have_url(f"{live_server}/items")
    expect(page.locator("#create-item")).to_be_visible()


@then("I am shown an authentication error")
def _auth_error(page: Page) -> None:
    # One message for every failure mode, so the response cannot be used to
    # probe which accounts exist or which factor was wrong.
    expect(page.get_by_test_id("error-banner")).to_contain_text("Invalid credentials")


@then("I remain signed out")
def _still_signed_out(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/items")
    expect(page).to_have_url(re.compile(r"/login"))


@then(parsers.parse('the item status badge reads "{status}"'))
def _badge_reads(page: Page, status: str) -> None:
    # The badge lives inside the fragment htmx swapped in, so seeing the new
    # value here proves the round trip completed — request signed with the CSRF
    # token, response rendered, card replaced in place.
    expect(page.get_by_test_id("item-status-badge")).to_have_text(status)


@then("a save confirmation is shown")
def _saved_shown(page: Page) -> None:
    expect(page.get_by_test_id("item-saved")).to_be_visible()


@then(parsers.parse("exactly {count:d} item row is listed"))
@then(parsers.parse("exactly {count:d} item rows are listed"))
def _item_rows(page: Page, count: int) -> None:
    expect(page.get_by_test_id("item-row")).to_have_count(count)
