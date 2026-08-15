"""SSRF guard for operator-supplied outbound URLs.

Anywhere a user can name a URL the server will then fetch, they can aim it at
infrastructure only the server can reach: cloud metadata endpoints
(169.254.169.254 hands out credentials), internal admin panels, databases on a
private subnet.

The check resolves the hostname and refuses any address that is loopback,
private, link-local, reserved or multicast. Resolving matters — a public name
like ``metadata.example.com`` can resolve to 169.254.169.254, so validating the
string alone proves nothing.

Two checks, at different moments and for different reasons:

* :func:`assert_safe_target` runs at **registration**, so an operator gets an
  immediate, actionable error rather than a delivery that mysteriously fails.
* :func:`pin_target` runs at **dispatch**, resolving once and returning the
  address to connect to. The name is never resolved a second time, which is
  what closes the DNS-rebinding window — a target that passed registration
  cannot be repointed at a private address before the request goes out.

Residual risk worth knowing: an address that is public at dispatch time is
accepted, so this does not defend against a genuinely hostile *public* host, and
it does not stop redirects (the dispatcher disables those separately). If
untrusted users can register endpoints, put an egress proxy in front as well.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.core.logging import get_logger

log = get_logger(__name__)


class UnsafeTargetError(ValueError):
    """The URL resolves somewhere the server should not be asked to reach."""


def _address_is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_addresses(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to, v4 and v6.

    All of them are checked, not just the first: a name resolving to one public
    and one private address must be refused, or the choice of which to connect
    to decides whether the guard held.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        msg = f"Could not resolve {host}."
        raise UnsafeTargetError(msg) from exc

    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True, slots=True)
class PinnedTarget:
    """A destination resolved once and validated, ready to connect to.

    Connecting to ``address`` rather than re-resolving ``host`` is what closes
    the DNS-rebinding window: the name cannot resolve to something else between
    the check and the connection, because it is never resolved twice.
    """

    host: str
    address: str
    port: int

    def url_for(self, url: str) -> str:
        """Rewrite ``url`` to point at the pinned address."""
        parsed = urlsplit(url)
        # IPv6 literals need brackets in an authority.
        literal = f"[{self.address}]" if ":" in self.address else self.address
        return urlunsplit(parsed._replace(netloc=f"{literal}:{self.port}"))


def pin_target(host: str, port: int, *, allow_private: bool) -> PinnedTarget:
    """Resolve ``host`` once, validate the addresses, and pin the first.

    Callers connect to ``PinnedTarget.address`` while presenting ``host`` in the
    ``Host`` header and TLS SNI, so certificate validation still works.

    ``allow_private`` skips the public-only *validation* and nothing else. It
    deliberately does not skip resolution: handing back an unresolved hostname
    would leave the caller to resolve it again at connect time, which is exactly
    the second lookup this function exists to remove — and would quietly reopen
    the rebinding window in the mode local development runs in. Pinning must
    behave identically everywhere, or development exercises a different code
    path from production.
    """
    addresses = resolve_addresses(host, port)

    if not allow_private:
        unsafe = [address for address in addresses if not _address_is_public(address)]
        if unsafe:
            log.warning("ssrf_target_rejected", host=host, addresses=unsafe)
            msg = (
                f"{host} resolves to a non-public address ({', '.join(unsafe)}). "
                "Outbound targets must be reachable on the public internet."
            )
            raise UnsafeTargetError(msg)

    return PinnedTarget(host=host, address=addresses[0], port=port)


def assert_safe_target(host: str, port: int, *, allow_private: bool) -> None:
    """Raise :class:`UnsafeTargetError` if ``host`` is not a safe destination.

    ``allow_private`` exists so the test suite and local partner stubs can use
    127.0.0.1; it is driven by ``Settings.private_targets_allowed`` and is never
    true in staging or production.
    """
    if allow_private:
        return

    addresses = resolve_addresses(host, port)
    unsafe = [address for address in addresses if not _address_is_public(address)]

    if unsafe:
        log.warning("ssrf_target_rejected", host=host, addresses=unsafe)
        msg = (
            f"{host} resolves to a non-public address ({', '.join(unsafe)}). "
            "Outbound targets must be reachable on the public internet."
        )
        raise UnsafeTargetError(msg)
