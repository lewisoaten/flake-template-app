"""The HMAC scheme, in both directions.

One implementation signs what we send and verifies what we receive, so these
tests are also the specification a partner's SDK has to match.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from app.domains.webhooks.signing import SignatureError, digest, sign, verify_signature

SECRET = "s3cret-signing-key"
TIMESTAMP = "1700000000"
NOW = 1_700_000_000
TOLERANCE = 300
BODY = '{"event":"ItemStatusChanged","item_id":"item-101"}'


class TestSign:
    def test_matches_an_independently_computed_hmac(self) -> None:
        # Recomputed the way a partner's own SDK would, rather than by calling
        # the function under test twice.
        expected = hmac.new(
            SECRET.encode(),
            f"{TIMESTAMP}.{BODY}".encode(),
            hashlib.sha256,
        ).hexdigest()

        assert sign(SECRET, TIMESTAMP, BODY) == expected

    def test_is_deterministic(self) -> None:
        assert sign(SECRET, TIMESTAMP, BODY) == sign(SECRET, TIMESTAMP, BODY)

    def test_differs_by_secret(self) -> None:
        assert sign(SECRET, TIMESTAMP, BODY) != sign("other", TIMESTAMP, BODY)

    def test_differs_by_body(self) -> None:
        assert sign(SECRET, TIMESTAMP, BODY) != sign(SECRET, TIMESTAMP, BODY + " ")

    def test_timestamp_is_covered_by_the_signature(self) -> None:
        # If it were not, a captured request could be replayed indefinitely
        # against a receiver that checks freshness.
        assert sign(SECRET, TIMESTAMP, BODY) != sign(SECRET, "1700000001", BODY)

    def test_is_hex_sha256(self) -> None:
        signature = sign(SECRET, TIMESTAMP, BODY)
        assert len(signature) == 64
        assert all(character in "0123456789abcdef" for character in signature)


class TestVerifySignature:
    def test_accepts_a_correctly_signed_request(self) -> None:
        verify_signature(
            SECRET,
            TIMESTAMP,
            BODY,
            sign(SECRET, TIMESTAMP, BODY),
            tolerance_seconds=TOLERANCE,
            now=NOW,
        )

    def test_rejects_a_wrong_signature(self) -> None:
        with pytest.raises(SignatureError, match="does not match"):
            verify_signature(
                SECRET,
                TIMESTAMP,
                BODY,
                sign("the-wrong-secret", TIMESTAMP, BODY),
                tolerance_seconds=TOLERANCE,
                now=NOW,
            )

    def test_rejects_a_tampered_body(self) -> None:
        # The signature is over the raw body, so an intermediary that reformats
        # the JSON breaks it — which is the point.
        with pytest.raises(SignatureError, match="does not match"):
            verify_signature(
                SECRET,
                TIMESTAMP,
                BODY.replace("item-101", "item-999"),
                sign(SECRET, TIMESTAMP, BODY),
                tolerance_seconds=TOLERANCE,
                now=NOW,
            )

    @pytest.mark.parametrize("skew", [TOLERANCE + 1, -(TOLERANCE + 1)])
    def test_rejects_a_stale_or_future_timestamp(self, skew: int) -> None:
        # Freshness is checked before the signature, so a captured-but-valid
        # request is refused as a replay rather than accepted.
        with pytest.raises(SignatureError, match="tolerance"):
            verify_signature(
                SECRET,
                TIMESTAMP,
                BODY,
                sign(SECRET, TIMESTAMP, BODY),
                tolerance_seconds=TOLERANCE,
                now=NOW + skew,
            )

    def test_accepts_a_timestamp_at_the_edge_of_the_tolerance(self) -> None:
        verify_signature(
            SECRET,
            TIMESTAMP,
            BODY,
            sign(SECRET, TIMESTAMP, BODY),
            tolerance_seconds=TOLERANCE,
            now=NOW + TOLERANCE,
        )

    def test_rejects_a_non_integer_timestamp(self) -> None:
        # An attacker controls this header; parsing it must fail closed rather
        # than raise ValueError out of the request handler.
        with pytest.raises(SignatureError, match="not an integer"):
            verify_signature(
                SECRET,
                "not-a-timestamp",
                BODY,
                sign(SECRET, "not-a-timestamp", BODY),
                tolerance_seconds=TOLERANCE,
                now=NOW,
            )


class TestDigest:
    def test_is_a_stable_content_hash(self) -> None:
        assert digest(BODY) == hashlib.sha256(BODY.encode()).hexdigest()

    def test_differs_by_content(self) -> None:
        assert digest(BODY) != digest(BODY + " ")
