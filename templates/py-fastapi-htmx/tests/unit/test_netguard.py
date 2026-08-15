"""The SSRF guard.

Literal IP addresses throughout: ``getaddrinfo`` short-circuits on those, so
these tests need no DNS and cannot fail because a CI runner has none.
"""

from __future__ import annotations

import pytest

from app.core.netguard import (
    UnsafeTargetError,
    assert_safe_target,
    pin_target,
    resolve_addresses,
)

PORT = 443

# Each of these is somewhere only the server can reach, which is precisely what
# makes it worth stealing.
UNSAFE = [
    "127.0.0.1",  # loopback: our own admin surface
    "10.0.0.1",  # RFC1918: an internal service
    "192.168.1.1",  # RFC1918: the router
    "169.254.169.254",  # link-local: cloud metadata, and therefore credentials
]

# A public address, spelled as a literal for the same no-DNS reason.
PUBLIC = "93.184.216.34"


@pytest.mark.parametrize("host", UNSAFE)
def test_non_public_targets_are_refused(host: str) -> None:
    with pytest.raises(UnsafeTargetError, match="non-public"):
        assert_safe_target(host, PORT, allow_private=False)


@pytest.mark.parametrize("host", UNSAFE)
def test_allow_private_permits_them(host: str) -> None:
    # Driven by Settings.private_targets_allowed, which is only ever true in
    # local and test — where the "partner" is a stub on 127.0.0.1.
    assert_safe_target(host, PORT, allow_private=True)


def test_a_public_target_is_permitted() -> None:
    assert_safe_target(PUBLIC, PORT, allow_private=False)


def test_an_unresolvable_host_is_refused_rather_than_raising_socket_errors() -> None:
    # Failing closed matters: an operator registering a typo should get a
    # validation error, not a 500.
    with pytest.raises(UnsafeTargetError, match="Could not resolve"):
        assert_safe_target("no-such-host.invalid", PORT, allow_private=False)


def test_resolution_returns_every_address() -> None:
    # All of them are checked, not just the first: a name resolving to one
    # public and one private address must be refused, or the choice of which to
    # connect to decides whether the guard held.
    assert resolve_addresses("127.0.0.1", PORT) == ["127.0.0.1"]


class TestPinningIsUnconditional:
    """Regression: `allow_private` must skip validation, not resolution.

    Returning an unresolved hostname would leave the caller to resolve it again
    at connect time — the second lookup pinning exists to remove — and would
    quietly reopen the rebinding window in exactly the mode local development
    runs in.
    """

    def test_a_private_address_is_still_resolved_and_pinned(self) -> None:
        pinned = pin_target("127.0.0.1", 8000, allow_private=True)
        assert pinned.address == "127.0.0.1"
        assert pinned.host == "127.0.0.1"

    def test_allow_private_only_skips_validation(self) -> None:
        # The same target: refused when validating, pinned when not.
        with pytest.raises(UnsafeTargetError):
            pin_target("127.0.0.1", 8000, allow_private=False)

        assert pin_target("127.0.0.1", 8000, allow_private=True).address == "127.0.0.1"

    def test_an_unresolvable_host_fails_even_when_private_is_allowed(self) -> None:
        # Proves resolution actually happens in this mode rather than being
        # short-circuited: a name that cannot resolve has no address to pin.
        with pytest.raises(UnsafeTargetError, match="resolve"):
            pin_target("no-such-host.invalid", 443, allow_private=True)

    def test_url_for_rewrites_only_the_authority(self) -> None:
        pinned = pin_target("127.0.0.1", 9099, allow_private=True)
        assert pinned.url_for("http://127.0.0.1:9099/hooks/items") == (
            "http://127.0.0.1:9099/hooks/items"
        )
