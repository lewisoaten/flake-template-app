"""HTTP middleware: hardened response headers and request correlation IDs."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Final

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.settings import Settings

REQUEST_ID_HEADER: Final = "X-Request-ID"

# A client-supplied ID is echoed back and written to every log line, so cap it:
# an unbounded value is a log-injection and log-volume problem.
MAX_REQUEST_ID_LENGTH: Final = 128

# A deliberately tight policy. It is achievable because the frontend ships no
# inline scripts or styles: HTMX and the Alpine.js *CSP build* are served from
# /static, and Tailwind is compiled to a stylesheet ahead of time. If you find
# yourself wanting 'unsafe-inline' or 'unsafe-eval' here, move the code into a
# file under static/ instead.
_CSP_DIRECTIVES: Final = (
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the standard hardening headers to every response.

    Applied outermost so that error responses produced deeper in the stack are
    covered too.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings
        self._csp = "; ".join(_CSP_DIRECTIVES)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        headers = response.headers

        headers.setdefault("Content-Security-Policy", self._csp)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=()",
        )

        if self._settings.hsts_enabled:
            headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={self._settings.hsts_max_age_seconds}; includeSubDomains; preload",
            )

        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign each request an ID and bind it to the structlog context.

    Every log line emitted while handling a request carries the same
    ``request_id``, and the ID is echoed back to the client so a user-reported
    failure can be traced to its logs.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER)
        usable = bool(incoming) and len(incoming or "") <= MAX_REQUEST_ID_LENGTH
        request_id = incoming if usable and incoming else uuid.uuid4().hex
        request.state.request_id = request_id

        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()

        response.headers[REQUEST_ID_HEADER] = request_id
        return response
