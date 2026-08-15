"""structlog configuration: human-readable locally, JSON everywhere else.

Deliberately *not* routed through the stdlib logging machinery. structlog writes
straight to stderr, which is what a container or Lambda wants, and avoids the
usual trap of mixing ``structlog.stdlib`` processors with a non-stdlib logger
factory (``add_logger_name`` would then fail on every log call).

Library logs that *do* go through stdlib — SQLAlchemy, uvicorn — are configured
separately at the bottom.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.typing import FilteringBoundLogger

from app.core.settings import Settings


def configure_logging(settings: Settings) -> None:
    """Install the processor chain and pick a renderer for this environment."""
    level = logging.DEBUG if settings.debug else logging.INFO

    shared: list[Any] = [
        # Pulls in request_id/method/path bound by RequestContextMiddleware.
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.format_exc_info,
    ]

    renderer: Any = (
        structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
        if settings.environment == "local"
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level, force=True)
    # uvicorn's access log duplicates what RequestContextMiddleware records,
    # without the request id.
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> FilteringBoundLogger:
    """Return a logger that tags every line with its module name."""
    return structlog.get_logger().bind(logger=name)
