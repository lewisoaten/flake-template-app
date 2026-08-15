"""HTML routes for signing in and out."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import ValidationError as PydanticValidationError
from starlette.responses import RedirectResponse, Response

from app.core import csrf
from app.core.database import SessionDep
from app.core.exceptions import AuthenticationError, RateLimitedError
from app.core.ratelimit import consult
from app.core.security import issue_session
from app.core.settings import get_settings
from app.core.templating import render
from app.domains.auth.dependencies import OptionalUser
from app.domains.auth.models import Role
from app.domains.auth.schemas import LoginRequest
from app.domains.auth.service import authenticate

router = APIRouter(tags=["auth"], include_in_schema=False)


def _safe_next(candidate: str | None) -> str:
    """Reject open redirects: only same-origin absolute paths are honoured.

    ``//evil.example`` is a protocol-relative URL, so checking for a leading
    slash alone is not enough.
    """
    if not candidate or not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    return candidate


@router.get("/login")
async def login_form(
    request: Request,
    user: OptionalUser,
    next: str | None = None,  # noqa: A002 - matches the query parameter name
) -> Response:
    """Render the sign-in page, or bounce an already-authenticated user home."""
    if user is not None:
        return RedirectResponse(_home_for(user.role), status_code=303)
    settings = get_settings()
    token = csrf.token_for(request, settings)
    response = render(
        request,
        "auth/login.html",
        {"next": _safe_next(next), "error": None, "email": "", "csrf_token": token},
    )
    csrf.attach(response, token, settings)
    return response


@router.post("/login")
async def login_submit(
    request: Request,
    session: SessionDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    mfa_code: Annotated[str | None, Form()] = None,
    next: Annotated[str | None, Form()] = None,  # noqa: A002
) -> Response:
    """Verify credentials and set the session cookie."""
    destination = _safe_next(next)

    # Rate limited before any hashing work, so a flood cannot be turned into a
    # CPU exhaustion attack via Argon2.
    settings = get_settings()
    verdict = await consult(
        request,
        settings,
        bucket="login",
        limit=settings.login_rate_limit,
        window_seconds=settings.login_rate_limit_window_seconds,
        session=session,
    )
    if not verdict.allowed:
        msg = "Too many sign-in attempts. Try again shortly."
        raise RateLimitedError(msg, verdict.retry_after_seconds)

    try:
        payload = LoginRequest(
            email=email,
            password=password,
            mfa_code=mfa_code or None,
        )
        user = await authenticate(
            session,
            payload.email,
            payload.password,
            payload.mfa_code,
        )
    except (AuthenticationError, PydanticValidationError):
        # One message for every failure: see service.authenticate.
        return render(
            request,
            "auth/login.html",
            {
                "next": destination,
                "error": "Invalid credentials.",
                "email": email,
                "csrf_token": csrf.token_for(request, get_settings()),
            },
            status_code=401,
        )

    if destination == "/":
        destination = _home_for(user.role)

    response = RedirectResponse(destination, status_code=303)
    _set_session_cookie(response, issue_session(user.id))
    return response


@router.post("/logout", dependencies=[Depends(csrf.verify)])
async def logout() -> Response:
    """Clear the session cookie.

    CSRF-protected: without it, any third-party page could submit a cross-site
    POST and force-log-out a visitor. Harmless-looking, but it is a denial of
    service on the session — and the base template already carries the token.

    Applied per-route rather than to the whole router because ``POST /login``
    must stay reachable for someone with no session. ``csrf.verify`` exempts
    requests carrying no session cookie anyway, so applying it router-wide
    would also work; being explicit here documents which routes are protected.
    """
    settings = get_settings()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(
        settings.session_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )
    return response


def _home_for(_role: Role) -> str:
    return "/items"


def _set_session_cookie(response: Response, token: str) -> None:
    """Set the session cookie with every hardening flag we can afford.

    ``samesite=lax`` (not ``strict``) so that following a link from an email
    into the app keeps the user signed in, while still blocking cross-site
    POSTs.
    """
    settings = get_settings()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
