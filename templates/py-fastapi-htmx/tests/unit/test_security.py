"""Cryptographic primitives: the bits that are silently catastrophic if wrong."""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app.core.security import (
    API_KEY_PREFIX,
    api_keys_equal,
    decode_access_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    issue_access_token,
    issue_session,
    read_session,
    verify_password,
)


class TestPasswords:
    def test_round_trip(self) -> None:
        digest = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", digest)

    def test_wrong_password_is_rejected(self) -> None:
        digest = hash_password("correct horse battery staple")
        assert not verify_password("Correct horse battery staple", digest)

    def test_hashes_are_salted(self) -> None:
        # Identical passwords must not produce identical digests, or the
        # database leaks which users share a password.
        assert hash_password("same") != hash_password("same")

    def test_malformed_digest_does_not_raise(self) -> None:
        # A corrupted row must fail the login, not 500 the request.
        assert not verify_password("anything", "not-a-real-argon2-hash")


class TestApiKeys:
    def test_generated_key_is_prefixed_and_matches_its_digest(self) -> None:
        generated = generate_api_key()
        assert generated.plaintext.startswith(API_KEY_PREFIX)
        assert hash_api_key(generated.plaintext) == generated.digest

    def test_digest_is_deterministic(self) -> None:
        assert hash_api_key("app_sk_abc") == hash_api_key("app_sk_abc")

    def test_digest_is_hex_sha256(self) -> None:
        # Lookups are a single indexed query on this column, so its shape is
        # part of the schema, not an implementation detail.
        digest = hash_api_key("app_sk_abc")
        assert len(digest) == 64
        assert all(character in "0123456789abcdef" for character in digest)

    def test_keys_are_unique(self) -> None:
        assert generate_api_key().plaintext != generate_api_key().plaintext

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [("a" * 64, "a" * 64, True), ("a" * 64, "b" * 64, False)],
    )
    def test_constant_time_comparison(self, left: str, right: str, expected: bool) -> None:
        assert api_keys_equal(left, right) is expected


class TestSessions:
    def test_round_trip(self) -> None:
        assert read_session(issue_session("user-123")) == "user-123"

    def test_tampered_token_is_rejected(self) -> None:
        token = issue_session("user-123")
        # Flip a character in the payload; the signature no longer matches.
        tampered = ("A" if token[0] != "A" else "B") + token[1:]
        assert read_session(tampered) is None

    def test_garbage_is_rejected(self) -> None:
        assert read_session("not-a-token") is None

    def test_expired_token_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APP_SESSION_MAX_AGE_SECONDS", "1")
        from app.core.settings import get_settings

        get_settings.cache_clear()
        token = issue_session("user-123")
        # itsdangerous compares whole seconds, so the wait has to clear the
        # max_age by a full second, not merely exceed it fractionally.
        time.sleep(2.1)
        assert read_session(token) is None


class TestAccessTokens:
    def test_round_trip_preserves_subject_and_scopes(self) -> None:
        token = issue_access_token("key-1", ["items:read", "items:write"])
        claims = decode_access_token(token)
        assert claims is not None
        assert claims.subject == "key-1"
        assert claims.scopes == frozenset({"items:read", "items:write"})
        assert claims.has_scope("items:read")
        assert not claims.has_scope("webhooks:write")

    def test_expired_token_is_rejected(self) -> None:
        token = issue_access_token("key-1", ["items:read"], ttl=timedelta(seconds=-1))
        assert decode_access_token(token) is None

    def test_token_signed_with_another_key_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core.settings import get_settings

        token = issue_access_token("key-1", ["items:read"])

        monkeypatch.setenv("APP_SECRET_KEY", "a-completely-different-secret-value")
        get_settings.cache_clear()
        assert decode_access_token(token) is None

    def test_garbage_is_rejected(self) -> None:
        assert decode_access_token("header.payload.signature") is None
