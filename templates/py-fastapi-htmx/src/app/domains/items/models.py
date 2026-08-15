"""The example resource.

Deliberately anonymous: an item is a name, some text and a status. It exists to
give every capability in the stack something concrete to act on — ownership
scoping, a state machine, domain events, HTMX fragments, the JSON API — without
implying a domain you would then have to unpick.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, IdMixin, TimestampMixin


class ItemStatus(enum.StrEnum):
    """Lifecycle of an item.

    The string values are the wire format: they appear in URLs, webhook
    payloads and the Gherkin features, so they are part of the public contract.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"

    @property
    def is_terminal(self) -> bool:
        return self is ItemStatus.ARCHIVED


class Item(IdMixin, TimestampMixin, Base):
    """A record owned by exactly one user."""

    __tablename__ = "items"
    __table_args__ = (Index("ix_items_owner_status", "owner_id", "status"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[ItemStatus] = mapped_column(
        String(32), nullable=False, default=ItemStatus.DRAFT, index=True
    )

    # The tenant boundary. Every query a non-admin makes is filtered on this
    # column, and it is never accepted from the client.
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Item {self.id} {self.status}>"
