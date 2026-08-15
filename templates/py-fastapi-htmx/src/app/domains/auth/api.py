"""JSON API for credential management and token exchange."""

from __future__ import annotations

from fastapi import APIRouter, status

from app.core.database import SessionDep
from app.core.security import issue_access_token
from app.core.settings import get_settings
from app.domains.auth.dependencies import ApiPrincipal, CurrentAdmin
from app.domains.auth.models import ApiKey
from app.domains.auth.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRead,
    TokenResponse,
)
from app.domains.auth.service import create_api_key, revoke_api_key

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
async def exchange_token(principal: ApiPrincipal) -> TokenResponse:
    """Trade a long-lived API key for a short-lived scoped access token.

    Integrations should do this once per run and use the token thereafter, so
    the key itself crosses the wire as rarely as possible.
    """
    settings = get_settings()
    scopes = sorted(principal.scopes)
    return TokenResponse(
        access_token=issue_access_token(principal.api_key.id, scopes),
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
    )


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_key(
    payload: ApiKeyCreate,
    session: SessionDep,
    admin: CurrentAdmin,
) -> ApiKeyCreated:
    """Mint an API key. The plaintext is returned here and never again.

    The key is owned by the admin creating it unless another owner is named,
    and it inherits that user's visibility — so a key can never see more than
    the person who holds it.
    """
    api_key, plaintext = await create_api_key(session, payload, default_owner=admin)
    return ApiKeyCreated(
        **ApiKeyRead.model_validate(api_key).model_dump(),
        plaintext_key=plaintext,
    )


@router.delete("/api-keys/{api_key_id}", response_model=ApiKeyRead)
async def revoke_key(
    api_key_id: str,
    session: SessionDep,
    _admin: CurrentAdmin,
) -> ApiKey:
    """Revoke a key immediately; tokens minted from it stop working too."""
    return await revoke_api_key(session, api_key_id)
