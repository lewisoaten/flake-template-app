"""Step definitions for features/access_control.feature.

The point of driving these through a browser rather than the API is that the
ownership boundary must hold for the rendered page too — a leak in a template
loop is just as bad as a leak in a query, and only one of the two is caught by
testing the service layer.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect
from pytest_bdd import given, parsers, scenarios, then, when
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.domains.auth.models import Role, User
from app.domains.items.models import Item, ItemStatus

pytestmark = pytest.mark.e2e

scenarios("access_control.feature")

MEMBER_EMAIL = "bdd-member@example.com"
OTHER_EMAIL = "bdd-other@example.com"
MEMBER_PASSWORD = "bdd-member-password-long"

MY_ITEM_NAME = "Telemetry rollout"
THEIR_ITEM_NAME = "Depot refresh"


@given("two members who each own one item", target_fixture="tenants")
def _tenants(sync_session: Session) -> dict[str, str]:
    mine_owner = User(
        email=MEMBER_EMAIL,
        full_name="Mo Member",
        password_hash=hash_password(MEMBER_PASSWORD),
        role=Role.MEMBER,
    )
    theirs_owner = User(
        email=OTHER_EMAIL,
        full_name="Ola Other",
        password_hash=hash_password(MEMBER_PASSWORD),
        role=Role.MEMBER,
    )
    sync_session.add_all([mine_owner, theirs_owner])
    sync_session.flush()

    mine = Item(name=MY_ITEM_NAME, owner_id=mine_owner.id, status=ItemStatus.DRAFT)
    theirs = Item(name=THEIR_ITEM_NAME, owner_id=theirs_owner.id, status=ItemStatus.DRAFT)
    sync_session.add_all([mine, theirs])
    sync_session.commit()

    return {"my_item_id": mine.id, "their_item_id": theirs.id}


@given("I am signed in as the first member")
def _signed_in(page: Page, live_server: str, tenants: dict[str, str]) -> None:  # noqa: ARG001
    page.goto(f"{live_server}/login")
    page.fill("#email", MEMBER_EMAIL)
    page.fill("#password", MEMBER_PASSWORD)
    # No authentication code: MFA is mandatory for admins only.
    page.click("#sign-in")
    expect(page).to_have_url(f"{live_server}/items")


@when("I open the item list")
def _open_items(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/items")


@when("I request the item belonging to the second member")
def _request_other_item(page: Page, live_server: str, tenants: dict[str, str]) -> None:
    page.goto(f"{live_server}/items/{tenants['their_item_id']}")


@when("I request the webhooks admin area")
def _request_admin(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/admin/webhooks")


@then(parsers.parse("exactly {count:d} item row is listed"))
@then(parsers.parse("exactly {count:d} item rows are listed"))
def _item_rows(page: Page, count: int) -> None:
    expect(page.get_by_test_id("item-row")).to_have_count(count)


@then("the listed item is the one I own")
def _own_item_listed(page: Page) -> None:
    expect(page.get_by_test_id("item-row")).to_contain_text(MY_ITEM_NAME)
    # The decisive assertion: the other member's item is nowhere on the page,
    # not merely absent from the row we happened to check.
    expect(page.locator("body")).not_to_contain_text(THEIR_ITEM_NAME)


@then("I am shown a not found page")
def _not_found(page: Page) -> None:
    # Not found rather than forbidden: a 403 would confirm the id exists and let
    # a member enumerate everyone else's records one guess at a time.
    expect(page.get_by_role("heading")).to_contain_text("No item with id")


@then("I am shown a permission denied page")
def _forbidden(page: Page) -> None:
    expect(page.get_by_role("heading")).to_contain_text("restricted to administrators")
