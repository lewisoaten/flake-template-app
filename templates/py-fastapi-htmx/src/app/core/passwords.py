"""Password policy: strength rules, and an optional breach-list check.

Two independent questions, deliberately separated:

* **Is it strong enough?** Answered offline, always, from rules below.
* **Is it known to be breached?** Answered by Have I Been Pwned, over the
  network, and therefore **off by default** — a template should not make an
  outbound call during sign-up without the operator opting in.

The rules favour length over character-class gymnastics. Requiring a symbol and
a digit reliably produces ``Password1!``; requiring length produces something
an attacker has to work for. NIST SP 800-63B has said so since 2017.
"""

from __future__ import annotations

import hashlib
from typing import Final

import httpx

from app.core.logging import get_logger
from app.core.settings import Settings

log = get_logger(__name__)

# The passwords that appear at the top of every breach corpus. This is a
# deliberately tiny sample: the real defence is the HIBP check below, and a
# bundled list of millions would bloat the template for marginal benefit.
_COMMON: Final = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "password",
        "password1",
        "password123",
        "qwerty",
        "qwertyuiop",
        "letmein",
        "welcome",
        "admin",
        "administrator",
        "iloveyou",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "changeme",
        "secret",
        "trustno1",
    }
)

_HIBP_RANGE_URL: Final = "https://api.pwnedpasswords.com/range/"
_HIBP_TIMEOUT: Final = 5.0


class WeakPasswordError(ValueError):
    """The password does not meet policy."""


def check_strength(password: str, *, email: str | None = None) -> None:
    """Raise :class:`WeakPasswordError` if ``password`` fails policy.

    Length is enforced by the schema; the rules here catch the passwords that
    are long enough but still guessable.
    """
    lowered = password.lower()

    if lowered in _COMMON:
        msg = "That password appears on every list of common passwords."
        raise WeakPasswordError(msg)

    # A password built from the account it protects is the first thing anyone
    # tries, and it survives a naive length check.
    if email:
        local_part = email.split("@", 1)[0].lower()
        if len(local_part) >= _MIN_LOCAL_PART and local_part in lowered:
            msg = "The password must not contain your email address."
            raise WeakPasswordError(msg)

    # "aaaaaaaaaaaaaaaa" is sixteen characters and worthless.
    if len(set(password)) < _MIN_DISTINCT_CHARS:
        msg = "The password must not be made of so few distinct characters."
        raise WeakPasswordError(msg)


_MIN_DISTINCT_CHARS: Final = 5
_MIN_LOCAL_PART: Final = 3


async def check_not_breached(password: str, settings: Settings) -> None:
    """Reject a password known to appear in a public breach corpus.

    Uses the HIBP range API, which is **k-anonymous**: only the first five
    characters of the SHA-1 hash leave this process, and the service returns
    every suffix sharing that prefix for us to match locally. The password
    itself is never transmitted, and HIBP cannot tell which of the ~800
    candidates was being checked.

    Fails **open** on a network error. That is a deliberate trade: a breach
    lookup is a nice-to-have, and letting an outage block every password change
    would turn a third-party dependency into a self-inflicted outage. The
    offline rules above always apply.
    """
    if not settings.password_breach_check_enabled:
        return

    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    try:
        async with httpx.AsyncClient(timeout=_HIBP_TIMEOUT) as client:
            response = await client.get(
                f"{_HIBP_RANGE_URL}{prefix}",
                headers={"Add-Padding": "true"},
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("breach_check_unavailable", error=str(exc))
        return

    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix and count.strip() not in ("", "0"):
            msg = (
                "That password has appeared in a known data breach. "
                "Choose one you have not used elsewhere."
            )
            raise WeakPasswordError(msg)


async def validate(password: str, settings: Settings, *, email: str | None = None) -> None:
    """Apply the whole policy: offline rules first, then the breach check."""
    check_strength(password, email=email)
    await check_not_breached(password, settings)
