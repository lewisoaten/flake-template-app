"""Every response, including error responses, must carry the hardening headers.

Error paths are tested explicitly because they are produced by exception
handlers rather than route handlers — a middleware ordering mistake typically
shows up there first.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from app.core.database import dispose_engine
from app.core.settings import Settings, get_settings
from app.main import create_app

EXPECTED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@pytest.mark.parametrize(("header", "value"), list(EXPECTED.items()))
async def test_headers_on_a_normal_response(
    client: httpx.AsyncClient,
    header: str,
    value: str,
) -> None:
    response = await client.get("/login")
    assert response.headers[header] == value


@pytest.mark.parametrize(("header", "value"), list(EXPECTED.items()))
async def test_headers_on_a_404(
    client: httpx.AsyncClient,
    header: str,
    value: str,
) -> None:
    response = await client.get("/no-such-page")
    assert response.status_code == 404
    assert response.headers[header] == value


async def test_content_security_policy_is_present_on_an_error_too(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/no-such-page")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


async def test_content_security_policy_is_strict(client: httpx.AsyncClient) -> None:
    csp = (await client.get("/login")).headers["Content-Security-Policy"]

    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp
    # The whole point of the Alpine CSP build and the compiled stylesheet: if
    # either of these appears, the protection is largely gone.
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


async def test_permissions_policy_disables_hardware(client: httpx.AsyncClient) -> None:
    policy = (await client.get("/login")).headers["Permissions-Policy"]
    for feature in ("camera=()", "geolocation=()", "microphone=()"):
        assert feature in policy


async def test_permissions_policy_is_present_on_a_404(client: httpx.AsyncClient) -> None:
    response = await client.get("/no-such-page")
    assert "camera=()" in response.headers["Permissions-Policy"]


async def test_hsts_is_absent_without_tls(client: httpx.AsyncClient) -> None:
    # Sending HSTS from a plain-http dev server would poison the browser's
    # cache for localhost across every other project on the machine.
    response = await client.get("/login")
    assert "Strict-Transport-Security" not in response.headers


async def test_hsts_is_sent_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_HSTS_ENABLED", "true")
    get_settings.cache_clear()

    settings: Settings = get_settings()
    app: FastAPI = create_app(settings)

    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/login")
    finally:
        await dispose_engine()

    header = response.headers["Strict-Transport-Security"]
    assert "max-age=" in header
    assert "includeSubDomains" in header


async def test_request_id_is_generated_and_echoed(client: httpx.AsyncClient) -> None:
    response = await client.get("/login")
    assert response.headers["X-Request-ID"]


async def test_supplied_request_id_is_preserved(client: httpx.AsyncClient) -> None:
    # Lets a reverse proxy or upstream service correlate its logs with ours.
    response = await client.get("/login", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["X-Request-ID"] == "trace-abc-123"


async def test_absurdly_long_request_id_is_replaced(client: httpx.AsyncClient) -> None:
    # The value is echoed back and written to every log line, so an unbounded
    # one is a log-injection and log-volume problem.
    response = await client.get("/login", headers={"X-Request-ID": "x" * 500})
    assert response.headers["X-Request-ID"] != "x" * 500


async def test_request_id_is_present_on_an_error_response(client: httpx.AsyncClient) -> None:
    # This is the value the error page tells the user to quote, so it has to
    # survive the exception handler.
    response = await client.get("/no-such-page")
    assert response.headers["X-Request-ID"]


async def test_html_fragments_vary_on_hx_request(client: httpx.AsyncClient) -> None:
    # Without this a shared cache could serve a bare <tr> to a full page load.
    response = await client.get("/login")
    assert "HX-Request" in response.headers.get("Vary", "")
