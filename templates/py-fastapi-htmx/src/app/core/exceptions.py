"""Domain-level errors and the handlers that turn them into responses.

Domain and service code raises these; it never imports ``HTTPException``. That
keeps business logic transport-agnostic and testable without a web client, and
gives one place to decide how an error is rendered — JSON for the API, an HTML
fragment for HTMX.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse, RedirectResponse, Response

from app.core.logging import get_logger
from app.core.templating import is_htmx, render

log = get_logger(__name__)


class AppError(Exception):
    """Base class for expected, user-facing failures."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "app_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(AppError):
    """The request is valid but conflicts with current state."""

    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class ValidationError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "validation_error"


class AuthenticationError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthenticated"


class LoginRequiredError(AuthenticationError):
    """No session on an HTML route — send the browser to the login page.

    Distinct from :class:`AuthenticationError` because the right answer differs
    by surface: an API caller wants a 401, a browser wants a redirect that
    remembers where it was going.
    """

    code = "login_required"

    def __init__(self, next_url: str = "/") -> None:
        super().__init__("Please sign in to continue.")
        self.next_url = next_url


class PermissionDeniedError(AppError):
    """Authenticated, but not allowed.

    Deliberately distinct from :class:`NotFoundError` — but note that ownership
    scoping returns *not found* for another user's row, so this class never
    leaks the existence of a record.
    """

    status_code = status.HTTP_403_FORBIDDEN
    code = "permission_denied"


class CsrfError(AppError):
    """A cookie-authenticated write arrived without a valid CSRF token.

    403 rather than 400: the request was understood perfectly well, and
    refusing it is an authorisation decision.
    """

    status_code = status.HTTP_403_FORBIDDEN
    code = "csrf_failed"


class RateLimitedError(AppError):
    """Too many requests from this caller in the current window."""

    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, message: str, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


def register_exception_handlers(app: FastAPI) -> None:
    """Install handlers that content-negotiate between JSON and HTML."""

    @app.exception_handler(RateLimitedError)
    async def _handle_rate_limited(request: Request, exc: RateLimitedError) -> Response:
        # Retry-After is the whole point of a 429; without it a client has no
        # way to back off correctly and will usually just hammer harder.
        headers = {"Retry-After": str(exc.retry_after_seconds)}
        log.warning("rate_limited", path=request.url.path, retry_after=exc.retry_after_seconds)
        if _wants_json(request):
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.code, "message": exc.message}},
                headers=headers,
            )
        return render(
            request,
            "partials/error_banner.html" if is_htmx(request) else "errors/error.html",
            {"message": exc.message, "status_code": exc.status_code},
            status_code=exc.status_code,
            headers=headers,
        )

    @app.exception_handler(LoginRequiredError)
    async def _handle_login_required(
        request: Request,
        exc: LoginRequiredError,
    ) -> Response:
        if _wants_json(request):
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.code, "message": exc.message}},
            )
        target = f"/login?next={quote(exc.next_url, safe='/')}"
        if is_htmx(request):
            # A 303 would be followed by fetch and swapped into the page.
            return Response(status_code=204, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    @app.exception_handler(AppError)
    async def _handle_app_error(request: Request, exc: AppError) -> Response:
        log.info("app_error", code=exc.code, message=exc.message)
        if _wants_json(request):
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.code, "message": exc.message}},
            )
        if is_htmx(request):
            return render(
                request,
                "partials/error_banner.html",
                {"message": exc.message},
                status_code=exc.status_code,
            )
        return render(
            request,
            "errors/error.html",
            {"status_code": exc.status_code, "message": exc.message},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(
        request: Request,
        exc: RequestValidationError,
    ) -> Response:
        if _wants_json(request):
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                content={
                    "error": {
                        "code": "validation_error",
                        "message": "Request payload failed validation.",
                        "details": exc.errors(),
                    }
                },
            )
        message = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'][1:])}: {err['msg']}" for err in exc.errors()
        )
        return render(
            request,
            "partials/error_banner.html" if is_htmx(request) else "errors/error.html",
            {"message": message, "status_code": 422},
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )


def _wants_json(request: Request) -> bool:
    """Route API paths and explicit Accept headers to JSON."""
    if request.url.path.startswith("/api/"):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept
