"""Jinja2 rendering helpers tuned for HTMX partial responses.

Jinja2's context-aware autoescaping is what protects HTMX fragments from XSS:
because fragments are injected as HTML rather than text, any unescaped value
would execute. Autoescape is therefore on for every extension we render, and
``|safe`` should be treated as a code-review trigger.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import StrictUndefined
from starlette.responses import HTMLResponse, Response

TEMPLATES_DIR: Final = Path(__file__).resolve().parent.parent / "templates"

templates: Final = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True
templates.env.trim_blocks = True
templates.env.lstrip_blocks = True
# Undefined variables in a template are a bug, not an empty string.
templates.env.undefined = StrictUndefined


def is_htmx(request: Request) -> bool:
    """True when the request came from HTMX rather than a full page load."""
    return request.headers.get("HX-Request") == "true"


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a full page or a fragment.

    Pass the *fragment* template name for HTMX-targeted routes; use
    :func:`render_partial_or_page` when one route must serve both.
    """
    response = templates.TemplateResponse(
        request=request,
        name=name,
        context=context or {},
        status_code=status_code,
        headers=headers,
    )
    # Caches must not serve a fragment to a full page load, or vice versa.
    response.headers.setdefault("Vary", "HX-Request")
    return response


def render_partial_or_page(
    request: Request,
    *,
    page: str,
    partial: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Serve ``partial`` to HTMX and ``page`` to a browser navigation.

    This keeps every URL bookmarkable: deep-linking to an HTMX-driven view
    still returns a complete document.
    """
    name = partial if is_htmx(request) else page
    return render(request, name, context, status_code=status_code)


def hx_redirect(url: str) -> Response:
    """Tell HTMX to perform a client-side redirect.

    A 3xx would be followed by ``fetch`` and swapped into the target element,
    which is never what you want after a form submission.
    """
    return Response(status_code=204, headers={"HX-Redirect": url})


def hx_trigger(response: Response, event: str) -> Response:
    """Ask the client to fire ``event`` once the swap completes."""
    existing = response.headers.get("HX-Trigger")
    response.headers["HX-Trigger"] = f"{existing}, {event}" if existing else event
    return response
