"""Field-level encryption and the key schedule behind it."""

from __future__ import annotations

import pytest

from app.core import crypto
from app.core.settings import get_settings


@pytest.fixture(autouse=True)
def _fresh_cipher() -> None:
    """Derived keys are cached; each test may change the configured secrets."""
    crypto.reset_cipher_cache()


class TestRoundTrip:
    def test_encrypt_then_decrypt(self) -> None:
        assert crypto.decrypt(crypto.encrypt("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"

    def test_ciphertext_is_not_the_plaintext(self) -> None:
        token = crypto.encrypt("JBSWY3DPEHPK3PXP")
        assert "JBSWY3DPEHPK3PXP" not in token

    def test_encryption_is_non_deterministic(self) -> None:
        # Fernet includes a random IV, so equal plaintexts must not produce
        # equal ciphertexts — otherwise the column leaks which rows match.
        assert crypto.encrypt("same") != crypto.encrypt("same")

    def test_tampered_ciphertext_is_rejected(self) -> None:
        token = crypto.encrypt("secret")
        tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt(tampered)


class TestKeyDerivation:
    def test_the_encryption_key_is_not_the_signing_key(self) -> None:
        # HKDF with a purpose label: sharing APP_SECRET_KEY between signing and
        # encryption must not mean sharing the actual key material.
        secret = get_settings().secret_key.get_secret_value()
        derived = crypto._fernet_key(secret)
        assert secret.encode() not in derived


class TestRotation:
    def test_a_previous_key_still_decrypts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The scenario rotation exists for: ciphertext written under the old
        secret must stay readable after the new one is deployed."""
        original = get_settings().secret_key.get_secret_value()
        token = crypto.encrypt("written-under-the-old-key")

        monkeypatch.setenv("APP_SECRET_KEY", "a-brand-new-application-secret")
        monkeypatch.setenv("APP_PREVIOUS_SECRET_KEYS", f'["{original}"]')
        get_settings.cache_clear()
        crypto.reset_cipher_cache()

        assert crypto.decrypt(token) == "written-under-the-old-key"

    def test_dropping_the_previous_key_makes_it_unreadable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The failure mode operators must understand: retire the old secret
        # before re-encrypting and the data is gone.
        token = crypto.encrypt("written-under-the-old-key")

        monkeypatch.setenv("APP_SECRET_KEY", "a-brand-new-application-secret")
        monkeypatch.delenv("APP_PREVIOUS_SECRET_KEYS", raising=False)
        get_settings.cache_clear()
        crypto.reset_cipher_cache()

        with pytest.raises(crypto.DecryptionError, match="APP_PREVIOUS_SECRET_KEYS"):
            crypto.decrypt(token)

    def test_rotate_rewrites_under_the_current_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original = get_settings().secret_key.get_secret_value()
        token = crypto.encrypt("payload")

        monkeypatch.setenv("APP_SECRET_KEY", "a-brand-new-application-secret")
        monkeypatch.setenv("APP_PREVIOUS_SECRET_KEYS", f'["{original}"]')
        get_settings.cache_clear()
        crypto.reset_cipher_cache()

        rotated = crypto.rotate(token)

        # Now readable with the new key alone, which is what lets the old
        # secret finally be retired.
        monkeypatch.delenv("APP_PREVIOUS_SECRET_KEYS", raising=False)
        get_settings.cache_clear()
        crypto.reset_cipher_cache()
        assert crypto.decrypt(rotated) == "payload"
