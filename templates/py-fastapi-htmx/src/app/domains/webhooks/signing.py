"""HMAC signing and verification, shared by both directions.

One implementation for outbound and inbound, so the scheme this app *sends*
is exactly the scheme it *accepts* — which makes the round trip testable and
stops the two drifting apart.

Scheme::

    X-Webhook-Timestamp: <unix seconds>
    X-Webhook-Signature: <hex HMAC-SHA256 of "{timestamp}.{raw body}">

The timestamp is inside the signed material, so a captured request cannot be
replayed later against a receiver that checks freshness — which
:func:`verify_signature` does.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Final

SIGNATURE_HEADER: Final = "X-Webhook-Signature"
TIMESTAMP_HEADER: Final = "X-Webhook-Timestamp"
EVENT_HEADER: Final = "X-Webhook-Event"
DELIVERY_HEADER: Final = "X-Webhook-Delivery"
SOURCE_HEADER: Final = "X-Webhook-Source"


class SignatureError(ValueError):
    """The request is not correctly signed, or is too old."""


def sign(secret: str, timestamp: str, body: str) -> str:
    """Return the hex HMAC-SHA256 a peer should recompute to verify us."""
    message = f"{timestamp}.{body}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def digest(body: str) -> str:
    """A stable content hash, for deduplication and audit."""
    return hashlib.sha256(body.encode()).hexdigest()


def verify_signature(
    secret: str,
    timestamp: str,
    body: str,
    provided: str,
    *,
    tolerance_seconds: int,
    now: int | None = None,
) -> None:
    """Raise :class:`SignatureError` unless the request is signed and fresh.

    Order matters: freshness is checked first so a replayed-but-valid request
    is rejected as a replay rather than accepted.
    """
    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        msg = "Timestamp is not an integer."
        raise SignatureError(msg) from exc

    current = int(time.time()) if now is None else now
    if abs(current - sent_at) > tolerance_seconds:
        msg = f"Timestamp is outside the {tolerance_seconds}s tolerance."
        raise SignatureError(msg)

    expected = sign(secret, timestamp, body)
    # compare_digest, not ==: a naive comparison leaks how much of the
    # signature was correct through its timing.
    if not hmac.compare_digest(expected, provided):
        msg = "Signature does not match."
        raise SignatureError(msg)
