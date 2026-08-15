"""ASGI application factory and route registration.

Import-time work is kept to a minimum so that a serverless cold start (or a
scaled-to-zero container) spends its first milliseconds on real work. The
factory is called once, at module scope, to produce ``app`` for uvicorn.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.responses import RedirectResponse, Response

from app import models
from app.core.database import dispose_engine, get_sessionmaker
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.settings import Settings, get_settings
from app.domains.audit import api as audit_api
from app.domains.audit.service import register_subscriptions as register_audit
from app.domains.auth import api as auth_api
from app.domains.auth import router as auth_router
from app.domains.auth.dependencies import OptionalUser
from app.domains.items import api as items_api
from app.domains.items import router as items_router
from app.domains.webhooks import api as webhooks_api
from app.domains.webhooks import router as webhooks_router
from app.domains.webhooks.dispatcher import register_subscriptions as register_webhooks

STATIC_DIR = Path(__file__).resolve().parent / "static"

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Start-up and shut-down hooks."""
    settings: Settings = app.state.settings
    register_webhooks()
    register_audit()
    log.info(
        "application_started",
        environment=settings.environment,
        database=settings.database_url.split("://", 1)[0],
    )
    yield
    await dispose_engine()
    log.info("application_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Tests call this directly with overridden settings."""
    settings = settings or get_settings()
    configure_logging(settings)
    # Fail loudly here rather than on the first request that needs a mapper.
    models.configure()

    app = FastAPI(
        title=settings.project_name,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings

    _register_middleware(app, settings)
    register_exception_handlers(app)
    _register_routes(app)

    return app


def _register_middleware(app: FastAPI, settings: Settings) -> None:
    """Order matters: the last added middleware runs first.

    Security headers are therefore added last, so they wrap everything —
    including responses produced by the CORS layer and by error handlers.
    """
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "HX-Request", "HX-Target"],
        )

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)


def _register_routes(app: FastAPI) -> None:
    """Mount static assets, the HTML surface and the versioned JSON API."""
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # --- HTML surface -----------------------------------------------------
    app.include_router(auth_router.router)
    app.include_router(items_router.router)
    app.include_router(webhooks_router.router)

    # --- JSON API ---------------------------------------------------------
    api = APIRouter(prefix="/api/v1")
    api.include_router(auth_api.router)
    api.include_router(items_api.router)
    api.include_router(webhooks_api.router)
    api.include_router(audit_api.router)
    app.include_router(api)

    # --- Operational ------------------------------------------------------
    @app.get("/healthz", tags=["ops"], include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness probe. Deliberately does not touch the database.

        A failing database should not cause the orchestrator to restart a
        perfectly healthy process; that is what the readiness probe is for.
        """
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"], include_in_schema=False)
    async def readyz() -> dict[str, Any]:
        """Readiness probe: can we actually serve traffic?"""
        try:
            async with get_sessionmaker()() as session:
                await session.execute(text("SELECT 1"))
        except Exception as exc:
            log.warning("readiness_failed", error=str(exc))
            return {"status": "degraded", "database": "unavailable"}
        return {"status": "ok", "database": "ok"}

    @app.get("/", include_in_schema=False)
    async def index(user: OptionalUser) -> Response:
        """Send each visitor to the surface they belong on."""
        if user is None:
            return RedirectResponse("/login", status_code=307)
        return RedirectResponse("/items", status_code=307)


app = create_app()
