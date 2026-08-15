"""Append-only audit trail.

Rows are written and never updated or deleted. That is the point: an audit
table you can edit is not evidence of anything. There is no update path in the
service, and nothing in the API exposes one.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, IdMixin, TimestampMixin


class AuditEvent(IdMixin, TimestampMixin, Base):
    """One recorded fact: who did what to which record, and when."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_subject_time", "subject_id", "created_at"),
        Index("ix_audit_events_name_time", "event_name", "created_at"),
    )

    # The domain event class name, e.g. "ItemStatusChanged".
    event_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # The record the event concerns — an item id, a delivery id.
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Who caused it. NULL for machine-originated events such as an inbound
    # webhook, which has no user behind it.
    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # The event payload as JSON. Stored as text rather than a JSON column so
    # the same schema works unchanged on SQLite and Postgres.
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    def __repr__(self) -> str:
        return f"<AuditEvent {self.event_name} subject={self.subject_id}>"
