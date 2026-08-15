"""Configuration behaviour, including the boot-time guards on production."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from app.core.settings import ENV_PREFIX, Settings


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every APP_* variable before each test in this module.

    The root conftest sets several of them so the rest of the suite has a
    working database; here they would mask the defaults under test.
    """
    for name in list(os.environ):
        if name.upper().startswith(ENV_PREFIX):
            monkeypatch.delenv(name, raising=False)


PROD_DATABASE_URL = "postgresql+asyncpg://user:pw@db:5432/app"


def _settings(**overrides: str) -> Settings:
    """Build settings from an explicit environment, ignoring any .env file."""
    return Settings(_env_file=None, **overrides)  # pyright: ignore[reportCallIssue]


def _deployed(**overrides: str) -> Settings:
    """Settings for a staging/production-shaped deployment.

    Both a real secret and a non-SQLite URL are required outside local/test, so
    every such test needs them; keeping the pair here stops the tests from
    accidentally asserting on the wrong guard.
    """
    return _settings(
        secret_key="a-real-secret",  # pyright: ignore[reportArgumentType]
        database_url=PROD_DATABASE_URL,
        **overrides,
    )


class TestDefaults:
    def test_local_defaults_are_usable_without_configuration(self) -> None:
        settings = _settings()
        assert settings.environment == "local"
        assert settings.is_sqlite
        assert not settings.is_production
        # No TLS locally, so a Secure cookie would never be sent back.
        assert not settings.cookie_secure

    def test_inbound_webhooks_are_off_until_a_secret_is_configured(self) -> None:
        # Accepting unsigned traffic because nobody set the secret is the one
        # failure mode this default exists to prevent.
        assert _settings().inbound_webhook_secret is None

    def test_environment_variables_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APP_PORT", "9001")
        monkeypatch.setenv("APP_PROJECT_NAME", "Acme Widgets")
        settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
        assert settings.port == 9001
        assert settings.project_name == "Acme Widgets"


class TestValidation:
    def test_unknown_variables_are_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A typo like APP_DATABSE_URL must fail loudly rather than silently
        # leaving the real setting at its default. pydantic-settings will not
        # catch this on its own — see Settings._reject_unknown_app_variables.
        monkeypatch.setenv("APP_DATABSE_URL", "postgresql+asyncpg://x/y")
        with pytest.raises(ValidationError, match="APP_DATABSE_URL"):
            Settings(_env_file=None)  # pyright: ignore[reportCallIssue]

    def test_production_rejects_the_development_secret(self) -> None:
        with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
            _settings(environment="production")  # pyright: ignore[reportArgumentType]

    def test_production_rejects_debug(self) -> None:
        with pytest.raises(ValidationError, match="APP_DEBUG"):
            _deployed(
                environment="production",  # pyright: ignore[reportArgumentType]
                debug="true",  # pyright: ignore[reportArgumentType]
            )

    def test_production_rejects_sqlite(self) -> None:
        # The production image only installs the postgres extra, so SQLite
        # would fail on the first request instead of at boot.
        with pytest.raises(ValidationError, match="SQLite"):
            _settings(
                environment="production",  # pyright: ignore[reportArgumentType]
                secret_key="a-real-secret",  # pyright: ignore[reportArgumentType]
            )

    def test_production_accepts_a_valid_configuration(self) -> None:
        settings = _deployed(environment="production")  # pyright: ignore[reportArgumentType]
        assert settings.is_production
        assert settings.cookie_secure
        assert not settings.is_sqlite

    def test_secret_is_not_printed(self) -> None:
        settings = _settings(
            environment="staging",  # pyright: ignore[reportArgumentType]
            secret_key="hunter2-hunter2",  # pyright: ignore[reportArgumentType]
            database_url=PROD_DATABASE_URL,
        )
        assert "hunter2" not in repr(settings)


class TestDerivedProperties:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("sqlite+aiosqlite:///./app.db", True),
            ("postgresql+asyncpg://user:pw@host/db", False),
        ],
    )
    def test_is_sqlite(self, url: str, expected: bool) -> None:
        assert _settings(database_url=url).is_sqlite is expected

    @pytest.mark.parametrize(
        ("environment", "expected"),
        [("local", False), ("test", False), ("staging", True), ("production", True)],
    )
    def test_cookie_secure_tracks_environment(self, environment: str, expected: bool) -> None:
        build = _deployed if environment in ("staging", "production") else _settings
        assert build(environment=environment).cookie_secure is expected  # pyright: ignore[reportArgumentType]

    @pytest.mark.parametrize("environment", ["local", "test"])
    def test_private_targets_are_allowed_in_development(self, environment: str) -> None:
        # The suite points webhook endpoints at 127.0.0.1; the SSRF guard has to
        # stand aside for that, and only for that.
        assert _settings(environment=environment).private_targets_allowed  # pyright: ignore[reportArgumentType]

    @pytest.mark.parametrize("environment", ["staging", "production"])
    def test_private_targets_are_refused_when_deployed(self, environment: str) -> None:
        assert not _deployed(environment=environment).private_targets_allowed  # pyright: ignore[reportArgumentType]

    def test_private_targets_can_be_opted_into_explicitly(self) -> None:
        # An escape hatch for a deployment whose partners genuinely live on a
        # private network. It has to be asked for by name.
        settings = _deployed(
            environment="production",  # pyright: ignore[reportArgumentType]
            allow_private_webhook_targets="true",  # pyright: ignore[reportArgumentType]
        )
        assert settings.private_targets_allowed
