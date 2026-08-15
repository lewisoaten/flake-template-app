"""Request and response contracts for the items domain."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.core.schemas import InputSchema, OutputSchema, StrictInputSchema
from app.domains.items.models import ItemStatus


class ItemCreate(StrictInputSchema):
    """Payload for creating an item.

    Note the absence of ``owner_id`` and ``status``: ownership is taken from
    the authenticated caller and the lifecycle starts at draft. Neither is
    client-settable, and ``extra="forbid"`` makes attempting either a 422.
    """

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    # Callers may pin the identifier so integrations can be idempotent.
    id: str | None = Field(default=None, max_length=64)


class ItemUpdate(InputSchema):
    """All fields optional: absent means "leave unchanged"."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)


class ItemStatusUpdate(InputSchema):
    """Status changes are their own operation: they emit a domain event."""

    status: ItemStatus


class ItemRead(OutputSchema):
    id: str
    name: str
    description: str | None
    status: ItemStatus
    owner_id: str
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime
