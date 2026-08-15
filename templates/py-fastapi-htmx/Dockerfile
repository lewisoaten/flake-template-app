# Multi-stage production build.
#
# Two stages, so the runtime image contains no build toolchain: just Python, the
# resolved virtualenv, and the app.
#
# Frontend assets — the compiled stylesheet and the two vendored JS files — are
# produced on the host by `just css` and `just vendor` and copied in from the
# build context. `just docker-build` runs both first.
#
# They are deliberately *not* built here. Doing so would mean a second, pinned
# copy of the Tailwind version and of the htmx/Alpine versions inside this file,
# where neither Dependabot nor the flake can see them — exactly the drift this
# project is set up to avoid. The guard below turns a missing asset into a build
# failure rather than a silently broken UI.

# ---------------------------------------------------------------------------
# Stage 1: resolve the virtualenv from uv.lock
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# Bytecode compilation moves import cost from every cold start to build time —
# worth ~100ms on a scale-to-zero container.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first, without the project itself: this layer is cached until
# uv.lock or pyproject.toml changes.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev --extra postgres

COPY . /app

# None of these are committed: the stylesheet is generated, and the two JS files
# are third-party. Fail loudly rather than shipping an image whose UI silently
# does nothing because its script and style tags 404.
RUN for f in src/app/static/css/app.css \
             src/app/static/vendor/htmx.min.js \
             src/app/static/vendor/alpine-csp.min.js; do \
      test -s "/app/$f" || { \
        echo "ERROR: $f missing from the build context." >&2; \
        echo "Run 'just css && just vendor' first, or use 'just docker-build'." >&2; \
        exit 1; \
      }; \
    done

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra postgres

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# tini reaps zombies and forwards signals, so SIGTERM from the orchestrator
# actually reaches uvicorn and the container shuts down promptly rather than
# being killed after the grace period.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

WORKDIR /app
COPY --from=builder --chown=appuser:appuser /app /app

USER appuser

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENVIRONMENT=production

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
