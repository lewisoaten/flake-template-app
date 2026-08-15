"""Model registry.

SQLAlchemy resolves relationships and string-based foreign keys lazily, at
first mapper configuration. Importing every model module in one place
guarantees that has happened before Alembic autogenerates a migration or the
app opens its first session — otherwise you get a mapper error whose message
depends on import order.
"""

from __future__ import annotations

from sqlalchemy.orm import configure_mappers

from app.core.database import Base
from app.core.ratelimit import RateLimitCounter
from app.domains.audit.models import AuditEvent
from app.domains.auth.models import ApiKey, Role, User
from app.domains.items.models import Item, ItemStatus
from app.domains.webhooks.models import InboundDelivery, WebhookDelivery, WebhookEndpoint


def configure() -> None:
    """Resolve every mapper now.

    Called from the application factory so that a broken relationship or an
    unresolvable string foreign key fails at start-up with a clear error,
    rather than on whichever request happens to touch it first.
    """
    configure_mappers()


__all__ = [
    "ApiKey",
    "AuditEvent",
    "Base",
    "InboundDelivery",
    "Item",
    "ItemStatus",
    "RateLimitCounter",
    "Role",
    "User",
    "WebhookDelivery",
    "WebhookEndpoint",
    "configure",
]
