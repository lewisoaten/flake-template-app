"""Schema-level defences.

``extra="forbid"`` is the mass-assignment control: a payload naming a field the
schema does not declare is rejected, so no client can reach a column simply by
guessing its name. The columns tested here are the ones that would matter —
ownership, lifecycle, activation — rather than an arbitrary sample.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.domains.auth.models import Role
from app.domains.auth.schemas import ApiKeyCreate, UserCreate
from app.domains.items.schemas import ItemCreate, ItemUpdate
from app.domains.webhooks.schemas import WebhookEndpointCreate


class TestMassAssignment:
    def test_item_create_rejects_an_owner(self) -> None:
        # Ownership comes from the authenticated caller. If this were settable,
        # every ownership test elsewhere in the suite would be theatre.
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ItemCreate(
                name="Mine, allegedly",
                owner_id="somebody-else",  # pyright: ignore[reportCallIssue]
            )

    def test_item_create_rejects_a_status(self) -> None:
        # The lifecycle starts at draft and moves only through change_status,
        # which is what emits the events the rest of the system reacts to.
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ItemCreate(
                name="Born active",
                status="active",  # pyright: ignore[reportCallIssue]
            )

    def test_item_create_rejects_an_archive_timestamp(self) -> None:
        with pytest.raises(ValidationError):
            ItemCreate(
                name="T",
                archived_at="2020-01-01T00:00:00Z",  # pyright: ignore[reportCallIssue]
            )

    def test_user_create_rejects_undeclared_fields(self) -> None:
        # `is_active` and `mfa_secret` are real columns, deliberately absent.
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            UserCreate(
                email="a@example.com",  # pyright: ignore[reportArgumentType]
                full_name="A",
                password="a-long-enough-password",
                is_active=False,  # pyright: ignore[reportCallIssue]
            )

    def test_api_key_create_rejects_a_forged_digest(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyCreate(
                name="forged",
                key_digest="deadbeef",  # pyright: ignore[reportCallIssue]
            )

    def test_declared_fields_still_work(self) -> None:
        payload = UserCreate(
            email="a@example.com",  # pyright: ignore[reportArgumentType]
            full_name="A",
            password="a-long-enough-password",
            role=Role.ADMIN,
        )
        assert payload.role == Role.ADMIN


class TestStrictMode:
    def test_a_number_is_not_coerced_into_a_name(self) -> None:
        # ItemCreate is a StrictInputSchema: the JSON API should not silently
        # accept 42 where a string is specified.
        with pytest.raises(ValidationError):
            ItemCreate(name=42)  # pyright: ignore[reportArgumentType]

    def test_a_string_is_not_coerced_into_a_list(self) -> None:
        with pytest.raises(ValidationError):
            WebhookEndpointCreate(
                url="https://partner.example.com/hooks",  # pyright: ignore[reportArgumentType]
                event_types="ItemStatusChanged",  # pyright: ignore[reportArgumentType]
            )

    def test_declared_types_are_accepted(self) -> None:
        payload = ItemCreate(name="Telemetry rollout", description=None, id=None)
        assert payload.name == "Telemetry rollout"


class TestWebhookEndpointCreate:
    def test_rejects_plaintext_http(self) -> None:
        # Payloads carry application data; sending them over http would expose
        # it, and the signature proves origin rather than confidentiality.
        with pytest.raises(ValidationError, match="https"):
            WebhookEndpointCreate(
                url="http://partner.example.com/hooks",  # pyright: ignore[reportArgumentType]
            )

    @pytest.mark.parametrize(
        "url",
        [
            "https://partner.example.com/hooks",
            "http://localhost:8080/hooks",
            "http://127.0.0.1:8080/hooks",
        ],
    )
    def test_accepts_https_and_loopback(self, url: str) -> None:
        # Loopback is exempt so the test suite and local stubs can run over
        # http. Whether the host is *reachable* is the SSRF guard's question.
        endpoint = WebhookEndpointCreate(url=url)  # pyright: ignore[reportArgumentType]
        assert str(endpoint.url).startswith(("https://", "http://localhost", "http://127.0.0.1"))


class TestPartialUpdates:
    def test_unset_fields_are_distinguishable_from_explicit_null(self) -> None:
        # This is what lets items.service.update() leave untouched columns alone
        # instead of nulling everything the client did not mention.
        assert ItemUpdate().model_dump(exclude_unset=True) == {}
        assert ItemUpdate(description=None).model_dump(exclude_unset=True) == {"description": None}

    def test_whitespace_is_stripped(self) -> None:
        assert ItemUpdate(name="  Telemetry rollout  ").name == "Telemetry rollout"
