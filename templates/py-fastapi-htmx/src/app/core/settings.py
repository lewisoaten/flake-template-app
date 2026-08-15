"""Application settings, sourced from the environment via pydantic-settings.

Every knob the app needs lives here. Nothing else in the codebase reads
``os.environ`` directly, so the full configuration surface is one file and one
type. Secrets are wrapped in :class:`~pydantic.SecretStr` so they cannot be
leaked by an accidental ``repr()`` in a log line or traceback.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]

ENV_PREFIX = "APP_"

# Placeholder used when no secret is supplied. Rejected outside local/test.
_DEV_SECRET = "dev-secret-not-for-production"  # noqa: S105


class Settings(BaseSettings):
    """Strongly-typed application configuration.

    Values are read from (in precedence order) the process environment, then a
    local ``.env`` file. All variables are prefixed with ``APP_`` — e.g.
    ``APP_DATABASE_URL``.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        # Unknown APP_* variables are a typo, not a feature.
        extra="forbid",
        frozen=True,
    )

    # -- Runtime ----------------------------------------------------------
    environment: Environment = "local"
    debug: bool = False
    project_name: str = "Example App"

    host: str = "127.0.0.1"
    port: int = 8000

    # -- Database ---------------------------------------------------------
    # SQLite keeps local dev zero-dependency; production points at Postgres,
    # e.g. postgresql+asyncpg://user:pass@host:5432/app
    database_url: str = "sqlite+aiosqlite:///./app.db"
    database_echo: bool = False
    database_pool_size: int = 5
    database_max_overflow: int = 10

    # -- Sessions and tokens ----------------------------------------------
    secret_key: SecretStr = SecretStr(_DEV_SECRET)

    # Superseded secrets, still accepted for *reading*. Lets you rotate
    # APP_SECRET_KEY without invalidating live sessions or making encrypted
    # columns unreadable. See core/crypto.py for the rotation procedure.
    previous_secret_keys: list[SecretStr] = Field(default_factory=list)

    session_cookie_name: str = "app_session"
    session_max_age_seconds: int = 60 * 60 * 8
    access_token_ttl_seconds: int = 60 * 15
    jwt_algorithm: Literal["HS256", "HS512"] = "HS256"

    # -- CSRF -------------------------------------------------------------
    # Only cookie-authenticated requests need this. A bearer-token caller
    # cannot be CSRF'd, because a browser will not attach an Authorization
    # header to a cross-site request.
    csrf_cookie_name: str = "app_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    csrf_field_name: str = "csrf_token"

    # -- Rate limiting ----------------------------------------------------
    # Requests per window, per client, per bucket. The backend is in-process;
    # core/ratelimit.py documents what that does and does not give you behind
    # multiple workers.
    rate_limit_enabled: bool = True
    login_rate_limit: int = 10
    login_rate_limit_window_seconds: int = 300
    api_rate_limit: int = 120
    api_rate_limit_window_seconds: int = 60

    # "memory" counts per process — fast, and wrong by a factor of the worker
    # count. "database" shares counters through the database you already run,
    # giving a genuinely global limit at the cost of one round trip per
    # limited request. See core/ratelimit.py.
    rate_limit_backend: Literal["memory", "database"] = "database"

    # -- Account lockout ---------------------------------------------------
    # Rate limiting throttles a source; lockout protects an *account*, which is
    # the case rate limiting misses when attempts arrive from many addresses.
    account_lockout_enabled: bool = True
    account_lockout_threshold: int = 10
    account_lockout_seconds: int = 900

    # -- Password policy ---------------------------------------------------
    # Off by default: it makes an outbound call to Have I Been Pwned. The
    # lookup is k-anonymous — the password never leaves the process — but a
    # template should not phone home unless asked. See core/passwords.py.
    password_breach_check_enabled: bool = False

    # -- Transport security ------------------------------------------------
    # Origins permitted to call the JSON API from a browser. Empty by default:
    # the HTML surface is same-origin, so CORS is opt-in per deployment.
    cors_origins: list[str] = Field(default_factory=list)

    # HSTS is only meaningful over TLS, so it stays off until you say otherwise.
    hsts_enabled: bool = False
    hsts_max_age_seconds: int = 60 * 60 * 24 * 365

    # -- Outbound webhooks -------------------------------------------------
    webhook_timeout_seconds: float = 10.0
    webhook_max_attempts: int = 3
    webhook_user_agent: str = "example-app-webhooks/1.0"

    # Refuse to register outbound targets resolving to private, loopback or
    # link-local addresses. Relaxed in local/test so the suite can point at a
    # stub on 127.0.0.1 — see core/netguard.py.
    allow_private_webhook_targets: bool = False

    # -- Inbound webhooks --------------------------------------------------
    # Shared secret a sender signs their requests with. Unset means the inbound
    # endpoint rejects everything, which is the right default.
    inbound_webhook_secret: SecretStr | None = None
    # How stale a signed timestamp may be before it is treated as a replay.
    inbound_webhook_tolerance_seconds: int = 300

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_local_or_test(self) -> bool:
        return self.environment in ("local", "test")

    @property
    def cookie_secure(self) -> bool:
        """Only send cookies over TLS outside of local development."""
        return not self.is_local_or_test

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def private_targets_allowed(self) -> bool:
        """Private outbound targets are permitted only in local/test."""
        return self.allow_private_webhook_targets or self.is_local_or_test

    @model_validator(mode="after")
    def _reject_unknown_app_variables(self) -> Self:
        """Refuse to start if an ``APP_*`` variable matches no field.

        ``extra="forbid"`` alone does not do this: pydantic-settings only reads
        the variables it knows about, so ``APP_DATABSE_URL`` would be silently
        ignored and the app would quietly run on the default database. Checking
        the environment ourselves turns that class of typo into a boot failure.
        """
        prefix = ENV_PREFIX.upper()
        known = {f"{prefix}{name}".upper() for name in type(self).model_fields}
        unknown = sorted(
            name
            for name in os.environ
            if name.upper().startswith(prefix) and name.upper() not in known
        )
        if unknown:
            msg = (
                f"Unrecognised {prefix}* environment variable(s): {', '.join(unknown)}. "
                "Either fix the spelling or add the field to Settings."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _reject_dev_defaults_in_production(self) -> Self:
        """Fail fast at boot rather than serving traffic with a known secret."""
        if self.is_local_or_test:
            return self
        if self.secret_key.get_secret_value() == _DEV_SECRET:
            msg = (
                "APP_SECRET_KEY must be set outside local/test environments. "
                "Generate one with: just secret-key"
            )
            raise ValueError(msg)
        if self.debug:
            msg = "APP_DEBUG must be false in staging/production."
            raise ValueError(msg)
        if self.is_sqlite:
            # The production image installs only the `postgres` extra, so the
            # SQLite default would otherwise surface as a ModuleNotFoundError
            # on the first request rather than at boot. It is the wrong choice
            # for a scale-to-zero container regardless: the file lives on an
            # ephemeral filesystem.
            msg = (
                "APP_DATABASE_URL points at SQLite, which is only supported in "
                "local/test. Use postgresql+asyncpg://… outside development."
            )
            raise ValueError(msg)
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so that importing modules and FastAPI dependencies all observe the
    same object. Tests call ``get_settings.cache_clear()`` after mutating the
    environment.
    """
    return Settings()


def generate_secret_key() -> str:
    """Convenience helper for operators bootstrapping a new deployment."""
    return secrets.token_urlsafe(48)
