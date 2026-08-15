"""Fixtures for the BDD layer.

Every scenario here needs a real socket — the API-driven ones because the
dispatch they assert on happens after the response, and the browser-driven ones
for the obvious reason. ``live_server`` runs uvicorn in a background thread
against the same per-test database the root conftest built.

``sync_session`` is the counterpart: a *blocking* session over that same file.
pytest-bdd generates synchronous test functions, so a step cannot await
anything; talking to SQLite with a blocking driver sidesteps that entirely.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from tests.conftest import sync_database_url

STARTUP_TIMEOUT_SECONDS = 15.0


def _free_port() -> int:
    """Ask the kernel for an unused port, then let it go.

    Racy in principle; in practice the window is microseconds and this avoids
    hard-coding a port that a developer's own server may already hold.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def live_server(fastapi_app: FastAPI) -> Iterator[str]:
    """Serve the app on a real port and yield its base URL."""
    port = _free_port()
    config = uvicorn.Config(
        fastapi_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="on",
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if server.started:
            break
        time.sleep(0.05)
    else:  # pragma: no cover - only on a pathologically slow machine
        server.should_exit = True
        pytest.fail("live_server did not start in time")

    # Confirm it actually answers, not merely that the socket is bound.
    with httpx.Client(base_url=base_url, timeout=5.0) as probe:
        probe.get("/healthz").raise_for_status()

    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def sync_session() -> Iterator[Session]:
    """A blocking session over the same database file the app uses."""
    engine = create_engine(sync_database_url())
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.fixture
def bdd_context() -> dict[str, object]:
    """A scratchpad for passing state between Given/When/Then steps."""
    return {}
