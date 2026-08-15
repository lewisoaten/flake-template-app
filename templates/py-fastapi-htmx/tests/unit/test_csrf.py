"""The signed half of the double-submit CSRF scheme.

What the signature buys over a bare random value: an attacker who can set a
cookie on our domain (a subdomain takeover, say) still cannot mint a token the
server will accept, because they cannot forge it.
"""

from __future__ import annotations

import pytest
from fastapi import Request
from starlette.responses import Response
from starlette.types import Scope

from app.core import csrf
from app.core.settings import Settings, get_settings


def _request_with_cookie(settings: Settings, value: str | None) -> Request:
    """A bare ASGI request carrying (or not carrying) the CSRF cookie."""
    headers: list[tuple[bytes, bytes]] = []
    if value is not None:
        headers.append((b"cookie", f"{settings.csrf_cookie_name}={value}".encode()))

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": headers,
    }
    return Request(scope)


class TestTokens:
    def test_round_trip(self) -> None:
        assert csrf.token_is_valid(csrf.issue_token())

    def test_tokens_are_unique(self) -> None:
        # A per-session constant would be replayable across tabs and forms.
        assert csrf.issue_token() != csrf.issue_token()

    def test_tampered_token_is_rejected(self) -> None:
        token = csrf.issue_token()
        tampered = ("A" if token[0] != "A" else "B") + token[1:]
        assert not csrf.token_is_valid(tampered)

    def test_garbage_is_rejected(self) -> None:
        assert not csrf.token_is_valid("not-a-token")

    def test_token_signed_with_another_secret_is_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        token = csrf.issue_token()

        monkeypatch.setenv("APP_SECRET_KEY", "a-completely-different-secret-value")
        get_settings.cache_clear()
        assert not csrf.token_is_valid(token)


class TestTokenFor:
    def test_reuses_a_valid_cookie(self, settings: Settings) -> None:
        # Reissuing on every render would invalidate the token on a form the
        # user already has open in another tab.
        existing = csrf.issue_token()
        request = _request_with_cookie(settings, existing)

        assert csrf.token_for(request, settings) == existing

    def test_replaces_an_invalid_cookie(self, settings: Settings) -> None:
        request = _request_with_cookie(settings, "forged-or-corrupted")

        token = csrf.token_for(request, settings)

        assert token != "forged-or-corrupted"
        assert csrf.token_is_valid(token)

    def test_mints_one_when_there_is_no_cookie(self, settings: Settings) -> None:
        token = csrf.token_for(_request_with_cookie(settings, None), settings)
        assert csrf.token_is_valid(token)


class TestAttach:
    def test_cookie_is_readable_by_javascript(self, settings: Settings) -> None:
        # Deliberately not HttpOnly: app.js echoes it into the X-CSRF-Token
        # header for HTMX requests. Its secrecy from *other origins* is what
        # matters, and the same-origin policy provides that.
        response = Response()
        csrf.attach(response, csrf.issue_token(), settings)

        header = response.headers["set-cookie"]
        assert settings.csrf_cookie_name in header
        assert "HttpOnly" not in header
        assert "SameSite=lax" in header
