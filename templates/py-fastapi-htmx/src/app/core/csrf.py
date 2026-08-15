"""CSRF protection for the cookie-authenticated HTML surface.

Signed double-submit: a random token is signed with the app secret and set as a
readable cookie, and the same value must come back in a form field or header.
An attacker on another origin can cause a request to be sent with the victim's
cookies, but cannot *read* the cookie to echo it back, and cannot forge the
signature.

Two things this deliberately does not do:

* It does not protect the JSON API. Bearer credentials are not attached by the
  browser to cross-site requests, so there is nothing to forge. Requiring a
  token there would only break every non-browser client.
* It does not replace ``SameSite=Lax`` on the session cookie. These are layers:
  SameSite blocks the common case at the browser, this blocks the rest.
"""

from __future__ import annotations

import secrets
from typing import Final

from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer
from starlette.responses import Response

from app.core.exceptions import CsrfError
from app.core.settings import Settings, get_settings

_CSRF_SALT: Final = "csrf-v1"

# Methods that cannot change state, so need no token.
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(
        secret_key=get_settings().secret_key.get_secret_value(),
        salt=_CSRF_SALT,
    )


def issue_token() -> str:
    """Mint a fresh signed CSRF token."""
    return _serializer().dumps(secrets.token_urlsafe(16))


def token_is_valid(token: str) -> bool:
    """True when ``token`` carries our signature."""
    try:
        _serializer().loads(token)
    except BadSignature:
        return False
    return True


def token_for(request: Request, settings: Settings) -> str:
    """The request's CSRF token, reusing the cookie's value when it is valid.

    Called *before* rendering so the token can go into the template context;
    :func:`attach` then puts it on the response.
    """
    existing = request.cookies.get(settings.csrf_cookie_name)
    if existing and token_is_valid(existing):
        return existing
    return issue_token()


def attach(response: Response, token: str, settings: Settings) -> None:
    """Set the CSRF cookie on ``response``."""
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        max_age=settings.session_max_age_seconds,
        # Readable by JavaScript on purpose: app.js echoes it into the
        # X-CSRF-Token header for HTMX requests. Its secrecy from *other
        # origins* is what matters, and the same-origin policy provides that.
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


async def verify(request: Request) -> None:
    """Reject an unsafe cookie-authenticated request without a valid token.

    Installed as a router-level dependency on the HTML surface.
    """
    settings = get_settings()

    if request.method in _SAFE_METHODS:
        return

    # No session cookie means no ambient authority to abuse — this is either an
    # anonymous request or a bearer-token API call.
    if settings.session_cookie_name not in request.cookies:
        return

    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    if not cookie_token:
        msg = "Missing CSRF cookie. Reload the page and try again."
        raise CsrfError(msg)

    submitted = request.headers.get(settings.csrf_header_name)
    if submitted is None:
        form = await request.form()
        value = form.get(settings.csrf_field_name)
        submitted = value if isinstance(value, str) else None

    if not submitted:
        msg = "Missing CSRF token."
        raise CsrfError(msg)

    # Compare the signed values directly: both are signed with the same secret,
    # so equality is sufficient and constant-time comparison guards the rest.
    if not secrets.compare_digest(cookie_token, submitted):
        msg = "CSRF token mismatch."
        raise CsrfError(msg)

    if not token_is_valid(submitted):
        msg = "CSRF token is not valid."
        raise CsrfError(msg)
