"""Persistence for outbound and inbound webhooks."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, IdMixin, TimestampMixin


class WebhookEndpoint(IdMixin, TimestampMixin, Base):
    """A URL that should receive selected domain events."""

    __tablename__ = "webhook_endpoints"
    __table_args__ = (Index("ix_webhook_endpoints_active", "is_active"),)

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Space-separated event names, e.g. "ItemStatusChanged". Empty means all.
    event_types: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Shared secret for the HMAC-SHA256 request signature. Generated at
    # registration and shown to the operator exactly once.
    signing_secret: Mapped[str] = mapped_column(String(128), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    deliveries: Mapped[list[WebhookDelivery]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )

    def wants(self, event_name: str) -> bool:
        """True when this endpoint is subscribed to ``event_name``."""
        if not self.is_active:
            return False
        subscribed = self.event_types.split()
        return not subscribed or event_name in subscribed

    def __repr__(self) -> str:
        return f"<WebhookEndpoint {self.url}>"


class WebhookDelivery(IdMixin, TimestampMixin, Base):
    """One outbound dispatch attempt, recorded whether it succeeded or not.

    This is what an operator reads when a partner claims they never received an
    event, and what the BDD suite asserts against.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (Index("ix_webhook_deliveries_endpoint_time", "endpoint_id", "created_at"),)

    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )

    event_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Correlates the delivery back to the row that changed.
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    request_body: Mapped[str] = mapped_column(Text, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # NULL when the request never got a reply (timeout, DNS, connection reset).
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    succeeded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    endpoint: Mapped[WebhookEndpoint] = relationship(back_populates="deliveries")

    @property
    def succeeded(self) -> bool:
        return self.succeeded_at is not None

    def __repr__(self) -> str:
        return f"<WebhookDelivery {self.event_name} status={self.response_status}>"


class InboundDelivery(IdMixin, TimestampMixin, Base):
    """A request accepted on the inbound endpoint.

    The primary key is the sender's own delivery id, which is what makes
    receipt idempotent: a resend collides on insert instead of being processed
    twice. Senders retry aggressively, so this is not a theoretical concern.
    """

    __tablename__ = "inbound_deliveries"

    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    payload: Mapped[str] = mapped_column(Text, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    def __repr__(self) -> str:
        return f"<InboundDelivery {self.id} from={self.source}>"
