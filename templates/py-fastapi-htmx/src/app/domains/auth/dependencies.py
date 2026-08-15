"""RBAC enforcement: the dependencies every protected route declares.

This module is the single gate through which both authentication contexts pass.
Routes never inspect cookies or headers themselves — they declare what they
need (``CurrentAdmin``, ``requires_scopes("items:write")``) and get a typed
principal or a 401/403.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.database import SessionDep
from app.core.exceptions import (
    AuthenticationError,
    LoginRequiredError,
    PermissionDeniedError,
)
from app.core.security import decode_access_token, read_session
from app.core.settings import Settings, get_settings
from app.domains.auth.models import ApiKey, Role, User
from app.domains.auth.service import get_user, resolve_api_key

# auto_error=False so we can raise our own, consistently-shaped errors.
_bearer = HTTPBearer(auto_error=False, scheme_name="API key or access token")

_ADMIN_ONLY = "This area is restricted to administrators."
_NO_CREDENTIALS = "Missing bearer credentials."
_STALE_TOKEN_SUBJECT = "Token subject is no longer valid."  # noqa: S105 - a message, not a secret

SettingsDep = Annotated[Settings, Depends(get_settings)]


async def get_current_user_optional(request: Request, session: SessionDep) -> User | None:
    """Resolve the session cookie to a user, or ``None`` when signed out.

    Used by layout templates to decide whether to render the account menu.
    """
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None

    user_id = read_session(token)
    if user_id is None:
        return None

    user = await get_user(session, user_id)
    if user is None or not user.is_active:
        return None
    return user


OptionalUser = Annotated[User | None, Depends(get_current_user_optional)]


async def require_user(request: Request, user: OptionalUser) -> User:
    """Require any signed-in human."""
    if user is None:
        raise LoginRequiredError(next_url=str(request.url.path))
    return user


CurrentUser = Annotated[User, Depends(require_user)]


async def require_admin(user: CurrentUser) -> User:
    """Require an internal admin. Customers get a 403, not a login prompt."""
    if user.role != Role.ADMIN:
        raise PermissionDeniedError(_ADMIN_ONLY)
    return user


CurrentAdmin = Annotated[User, Depends(require_admin)]


# ---------------------------------------------------------------------------
# Machine context
# ---------------------------------------------------------------------------
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


@dataclass(frozen=True, slots=True)
class ScopedPrincipal:
    """An authenticated machine caller, and the user it acts as.

    Carrying the user is what lets ownership scoping treat machines and humans
    identically: services take a ``viewer`` and never ask how it authenticated.

    ``scopes`` is an explicit field rather than a property reading
    ``api_key.scope_set``, and that distinction is load-bearing. A token may
    carry *fewer* scopes than the key it was minted from, and the obvious way to
    express that — assigning the narrowed set back onto ``api_key.scopes`` —
    mutates a live ORM object. The request session commits on the way out, so
    one narrow-scoped request would permanently shrink the stored key's
    permissions. Keeping the effective set here means the model is never
    touched.
    """

    api_key: ApiKey
    viewer: User
    scopes: frozenset[str]


async def require_api_principal(
    credentials: BearerCredentials,
    session: SessionDep,
) -> ScopedPrincipal:
    """Authenticate the JSON API.

    Accepts either a long-lived API key (``app_sk_…``) or a short-lived scoped
    JWT minted from one. Both resolve to the same :class:`ApiKey` row so
    auditing and scope checks have a single code path.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(_NO_CREDENTIALS)

    token = credentials.credentials

    claims = decode_access_token(token)
    if claims is not None:
        api_key = await session.get(ApiKey, claims.subject)
        if api_key is None or api_key.revoked_at is not None:
            raise AuthenticationError(_STALE_TOKEN_SUBJECT)
        # A token may only ever narrow the key's scopes, never widen them.
        # Computed, not assigned back onto api_key: see ScopedPrincipal.
        effective = claims.scopes & api_key.scope_set
    else:
        api_key = await resolve_api_key(session, token)
        effective = api_key.scope_set

    owner = await session.get(User, api_key.owner_id)
    if owner is None or not owner.is_active:
        raise AuthenticationError(_STALE_TOKEN_SUBJECT)

    return ScopedPrincipal(api_key=api_key, viewer=owner, scopes=effective)


ApiPrincipal = Annotated[ScopedPrincipal, Depends(require_api_principal)]


def requires_scopes(
    *required: str,
) -> Callable[[ScopedPrincipal], Coroutine[Any, Any, ScopedPrincipal]]:
    """Build a dependency asserting the principal holds every listed scope."""
    needed = frozenset(required)

    async def _dependency(principal: ApiPrincipal) -> ScopedPrincipal:
        missing = needed - principal.scopes
        if missing:
            msg = f"Missing required scope(s): {', '.join(sorted(missing))}."
            raise PermissionDeniedError(msg)
        return principal

    return _dependency
