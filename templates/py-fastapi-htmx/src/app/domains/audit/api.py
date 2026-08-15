"""Read-only JSON API over the audit trail.

Read-only by design — there is no create, update or delete. Entries arrive
solely through the event bus.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.database import SessionDep
from app.core.schemas import OutputSchema, Page
from app.domains.audit.service import list_events
from app.domains.auth.dependencies import ScopedPrincipal, requires_scopes

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventRead(OutputSchema):
    id: str
    event_name: str
    subject_id: str | None
    actor_id: str | None
    payload: str
    created_at: datetime


@router.get("/events", response_model=Page[AuditEventRead])
async def list_audit_events(
    session: SessionDep,
    _: Annotated[ScopedPrincipal, Depends(requires_scopes("audit:read"))],
    subject_id: str | None = None,
    event_name: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditEventRead]:
    rows, total = await list_events(
        session,
        subject_id=subject_id,
        event_name=event_name,
        limit=limit,
        offset=offset,
    )
    return Page[AuditEventRead](
        items=[AuditEventRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
