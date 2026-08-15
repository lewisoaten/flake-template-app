"""Sign-in, sessions, and how each surface reacts to an unauthenticated caller."""

from __future__ import annotations

import httpx

from app.core.settings import get_settings
from app.domains.auth.models import User
from tests.conftest import ADMIN_PASSWORD, MEMBER_PASSWORD, totp_for


async def test_login_page_renders(client: httpx.AsyncClient) -> None:
    response = await client.get("/login")
    assert response.status_code == 200
    assert 'id="sign-in"' in response.text
    assert 'id="mfa_code"' in response.text


async def test_admin_signs_in_with_a_valid_code(
    client: httpx.AsyncClient,
    admin_user: User,
) -> None:
    response = await client.post(
        "/login",
        data={
            "email": admin_user.email,
            "password": ADMIN_PASSWORD,
            "mfa_code": totp_for(admin_user),
            "next": "/items",
        },
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/items"

    cookie = response.headers["set-cookie"]
    assert get_settings().session_cookie_name in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    # Not Secure in test/local: the browser would refuse to send it back over
    # plain http and every subsequent request would appear signed out.
    assert "Secure" not in cookie


async def test_admin_without_a_code_is_refused(
    client: httpx.AsyncClient,
    admin_user: User,
) -> None:
    # MFA is mandatory for admins, not an optional second factor.
    response = await client.post(
        "/login",
        data={"email": admin_user.email, "password": ADMIN_PASSWORD, "next": "/items"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.text


async def test_wrong_password_is_refused(
    client: httpx.AsyncClient,
    admin_user: User,
) -> None:
    response = await client.post(
        "/login",
        data={
            "email": admin_user.email,
            "password": "definitely-not-the-password",
            "mfa_code": totp_for(admin_user),
        },
    )
    assert response.status_code == 401


async def test_unknown_email_gives_the_same_answer_as_a_wrong_password(
    client: httpx.AsyncClient,
) -> None:
    # User enumeration defence: the response must not distinguish the two.
    response = await client.post(
        "/login",
        data={"email": "nobody@example.com", "password": "some-password-value"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.text


async def test_member_signs_in_without_a_code(
    client: httpx.AsyncClient,
    member_user: User,
) -> None:
    # MFA is enforced for admins only; a member has no enrolled secret to check.
    response = await client.post(
        "/login",
        data={"email": member_user.email, "password": MEMBER_PASSWORD},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/items"


async def test_logout_clears_the_cookie(member_client: httpx.AsyncClient) -> None:
    response = await member_client.post("/logout")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    # The cookie jar is now empty, so the item list bounces us back.
    follow_up = await member_client.get("/items")
    assert follow_up.status_code == 303
    assert follow_up.headers["location"].startswith("/login")


async def test_browser_is_redirected_to_login_with_a_return_path(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/items")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/items"


async def test_api_paths_get_401_json_not_a_redirect(client: httpx.AsyncClient) -> None:
    # A JSON client has no browser to redirect and no login form to render.
    response = await client.get("/api/v1/items")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_htmx_gets_a_client_side_redirect(client: httpx.AsyncClient) -> None:
    # A 303 would be followed by fetch and swapped into the page, leaving the
    # user staring at a login form inside a table cell.
    response = await client.get("/items", headers={"HX-Request": "true"})
    assert response.status_code == 204
    assert response.headers["HX-Redirect"] == "/login?next=/items"


async def test_open_redirect_is_not_honoured(
    client: httpx.AsyncClient,
    admin_user: User,
) -> None:
    # `//evil.example` is a protocol-relative URL, so checking for a leading
    # slash alone would let it through.
    response = await client.post(
        "/login",
        data={
            "email": admin_user.email,
            "password": ADMIN_PASSWORD,
            "mfa_code": totp_for(admin_user),
            "next": "//evil.example/phish",
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/items"


async def test_an_already_signed_in_visitor_is_bounced_off_the_login_page(
    member_client: httpx.AsyncClient,
) -> None:
    response = await member_client.get("/login")
    assert response.status_code == 303
    assert response.headers["location"] == "/items"


async def test_a_member_cannot_reach_the_webhooks_admin_area(
    member_client: httpx.AsyncClient,
) -> None:
    # 403, not a login prompt: they are authenticated, just not staff.
    response = await member_client.get("/admin/webhooks")
    assert response.status_code == 403
