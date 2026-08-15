"""Password policy: offline rules, and the opt-in breach check."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core.passwords import WeakPasswordError, check_not_breached, check_strength, validate
from app.core.settings import Settings, get_settings

HIBP = "https://api.pwnedpasswords.com/range/"


class TestOfflineRules:
    @pytest.mark.parametrize("password", ["password", "qwerty", "letmein", "PASSWORD"])
    def test_common_passwords_are_rejected(self, password: str) -> None:
        with pytest.raises(WeakPasswordError, match="common"):
            check_strength(password)

    def test_a_password_containing_the_email_is_rejected(self) -> None:
        # The first thing anyone tries, and it survives a naive length check.
        with pytest.raises(WeakPasswordError, match="email"):
            check_strength("alice-lives-here-2024", email="alice@example.com")

    def test_a_short_local_part_is_not_matched(self) -> None:
        # "al" is too short to be meaningful; rejecting on it would fail
        # perfectly good passwords.
        check_strength("naturally-occurring-substring", email="al@example.com")

    def test_low_variety_is_rejected(self) -> None:
        with pytest.raises(WeakPasswordError, match="distinct"):
            check_strength("aaaaaaaaaaaaaaaaaaaa")

    def test_a_good_password_passes(self) -> None:
        check_strength("trombone-lantern-quartz-42", email="alice@example.com")


class TestBreachCheck:
    async def test_disabled_by_default(self) -> None:
        # A template must not phone home unless asked.
        assert get_settings().password_breach_check_enabled is False

    async def test_a_breached_password_is_rejected(self) -> None:
        settings = Settings(_env_file=None, password_breach_check_enabled=True)  # pyright: ignore[reportCallIssue]
        # SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        async with respx.mock:
            respx.get(f"{HIBP}5BAA6").mock(
                return_value=httpx.Response(200, text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345")
            )
            with pytest.raises(WeakPasswordError, match="breach"):
                await check_not_breached("password", settings)

    async def test_only_the_hash_prefix_is_sent(self) -> None:
        """k-anonymity: the password must never leave the process."""
        settings = Settings(_env_file=None, password_breach_check_enabled=True)  # pyright: ignore[reportCallIssue]
        async with respx.mock:
            route = respx.get(url__startswith=HIBP).mock(
                return_value=httpx.Response(200, text="0000000000000000000000000000000000000:1")
            )
            await check_not_breached("some-unbreached-password", settings)

        url = str(route.calls[0].request.url)
        assert url.startswith(HIBP)
        # Five hex characters and nothing more.
        assert len(url.removeprefix(HIBP)) == 5
        assert "some-unbreached-password" not in url

    async def test_an_unlisted_password_passes(self) -> None:
        settings = Settings(_env_file=None, password_breach_check_enabled=True)  # pyright: ignore[reportCallIssue]
        async with respx.mock:
            respx.get(url__startswith=HIBP).mock(
                return_value=httpx.Response(200, text="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9")
            )
            await check_not_breached("trombone-lantern-quartz-42", settings)

    async def test_it_fails_open_when_the_service_is_down(self) -> None:
        """A third-party outage must not become our outage.

        The offline rules still apply, so failing open degrades the check
        rather than removing password policy altogether.
        """
        settings = Settings(_env_file=None, password_breach_check_enabled=True)  # pyright: ignore[reportCallIssue]
        async with respx.mock:
            respx.get(url__startswith=HIBP).mock(side_effect=httpx.ConnectError("down"))
            await check_not_breached("trombone-lantern-quartz-42", settings)


class TestValidate:
    async def test_offline_rules_apply_even_with_the_check_disabled(self) -> None:
        with pytest.raises(WeakPasswordError):
            await validate("password", get_settings())
