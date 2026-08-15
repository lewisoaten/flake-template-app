"""Request and response contracts for the webhooks domain."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, HttpUrl, field_validator

from app.core.schemas import InputSchema, OutputSchema, StrictInputSchema


class WebhookEndpointCreate(StrictInputSchema):
    url: HttpUrl
    description: str | None = Field(default=None, max_length=255)
    event_types: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def _require_https(cls, value: HttpUrl) -> HttpUrl:
        """Refuse plaintext endpoints: the payload carries application data.

        Localhost is exempted so the test suite and local stubs can run over
        HTTP. Whether the host is *reachable* — as opposed to merely https — is
        a separate question, answered by the SSRF guard at registration time.
        """
        if value.scheme != "https" and value.host not in ("localhost", "127.0.0.1"):
            msg = "Webhook endpoints must use https."
            raise ValueError(msg)
        return value


class WebhookEndpointUpdate(InputSchema):
    description: str | None = Field(default=None, max_length=255)
    event_types: list[str] | None = None
    is_active: bool | None = None


class WebhookEndpointRead(OutputSchema):
    id: str
    url: str
    description: str | None
    event_types: str
    is_active: bool
    created_at: datetime


class WebhookEndpointCreated(WebhookEndpointRead):
    """Includes the signing secret, shown to the operator exactly once."""

    signing_secret: str


class WebhookDeliveryRead(OutputSchema):
    id: str
    endpoint_id: str
    event_name: str
    subject_id: str | None
    attempt: int
    response_status: int | None
    error: str | None
    duration_ms: int | None
    succeeded_at: datetime | None
    created_at: datetime


class InboundDeliveryRead(OutputSchema):
    id: str
    source: str
    event_name: str
    payload_digest: str
    created_at: datetime
