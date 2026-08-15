"""CSRF on the cookie-authenticated HTML surface, and its deliberate absence on the API.

The asymmetry is the point. A browser attaches cookies to a cross-site request
whether the user meant it or not, so the HTML surface needs a token it cannot
forge. A browser does *not* attach an Authorization header cross-site, so
demanding a token from bearer callers would protect nobody and break every
non-browser client.
"""

from __future__ import annotations

import httpx

from app.core.settings import Settings


def _without_token(client: httpx.AsyncClient, settings: Settings) -> httpx.AsyncClient:
    """Drop the token the conftest client echoes, keeping the session cookie.

    This is the shape of a cross-site forgery: the ambient cookie arrives, the
    proof of intent does not.
    """
    client.headers.pop(settings.csrf_header_name, None)
    return client


async def test_a_cookie_authenticated_write_without_a_token_is_refused(
    member_client: httpx.AsyncClient,
    settings: Settings,
) -> None:
    response = await _without_token(member_client, settings).post(
        "/items",
        data={"name": "Forged"},
    )
    assert response.status_code == 403


async def test_the_refusal_names_the_reason(
    member_client: httpx.AsyncClient,
    settings: Settings,
) -> None:
    # 403 rather than 400: the request was understood perfectly well, and
    # refusing it is an authorisation decision.
    response = await _without_token(member_client, settings).post(
        "/items",
        data={"name": "Forged"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_a_mismatched_token_is_refused(
    member_client: httpx.AsyncClient,
    settings: Settings,
) -> None:
    # An attacker who can guess the cookie's *format* still cannot produce a
    # value that matches it.
    member_client.headers[settings.csrf_header_name] = "not-the-cookie-value"

    response = await member_client.post("/items", data={"name": "Forged"})
    assert response.status_code == 403


async def test_the_header_lets_a_write_through(member_client: httpx.AsyncClient) -> None:
    # The conftest client sets X-CSRF-Token from the cookie, exactly as app.js
    # does for HTMX requests in the browser.
    response = await member_client.post("/items", data={"name": "Legitimate"})

    assert response.status_code == 204
    assert response.headers["HX-Redirect"].startswith("/items/")


async def test_the_form_field_lets_a_write_through(
    member_client: httpx.AsyncClient,
    settings: Settings,
) -> None:
    # The no-JavaScript path: every rendered form carries a hidden csrf_token.
    token = member_client.cookies.get(settings.csrf_cookie_name)
    assert token is not None

    response = await _without_token(member_client, settings).post(
        "/items",
        data={"name": "Legitimate", settings.csrf_field_name: token},
    )
    assert response.status_code == 204


async def test_safe_methods_need_no_token(
    member_client: httpx.AsyncClient,
    settings: Settings,
) -> None:
    # GET cannot change state, so demanding a token would only break bookmarks
    # and the back button.
    response = await _without_token(member_client, settings).get("/items")
    assert response.status_code == 200


async def test_the_json_api_needs_no_token(
    client: httpx.AsyncClient,
    api_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/api/v1/items",
        headers=api_headers,
        json={"name": "From an integration"},
    )
    assert response.status_code == 201


async def test_an_anonymous_write_is_not_treated_as_a_csrf_failure(
    client: httpx.AsyncClient,
) -> None:
    # No session cookie means no ambient authority to abuse. The request is
    # still refused — but as unauthenticated, which is the accurate answer.
    response = await client.post("/items", data={"name": "Anonymous"})
    assert response.status_code != 403


class TestLogoutIsProtected:
    """Regression: /logout used to accept a cross-site POST.

    Forcing a sign-out is a denial of service on the session rather than a
    data breach, but it is trivially preventable and the token is already on
    the page.
    """

    async def test_logout_without_a_token_is_refused(
        self,
        member_client: httpx.AsyncClient,
    ) -> None:
        response = await member_client.post(
            "/logout",
            headers={"X-CSRF-Token": ""},
        )
        assert response.status_code == 403
        assert "csrf" in response.text.lower()

    async def test_the_session_survives_a_refused_logout(
        self,
        member_client: httpx.AsyncClient,
    ) -> None:
        await member_client.post("/logout", headers={"X-CSRF-Token": ""})
        # Still signed in: the forged request changed nothing.
        response = await member_client.get("/items")
        assert response.status_code == 200

    async def test_logout_with_a_token_succeeds(
        self,
        member_client: httpx.AsyncClient,
    ) -> None:
        response = await member_client.post("/logout")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
