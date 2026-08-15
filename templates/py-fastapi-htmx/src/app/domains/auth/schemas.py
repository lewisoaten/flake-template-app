"""Request and response contracts for the auth domain."""

from __future__ import annotations

from datetime import datetime

from pydantic import EmailStr, Field

from app.core.schemas import InputSchema, OutputSchema, StrictInputSchema
from app.domains.auth.models import Role


class LoginRequest(InputSchema):
    """Credentials posted by the admin login form."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=1024)
    # Required for admins once enrolled; ignored for customer logins.
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class UserCreate(StrictInputSchema):
    """Payload for provisioning a user.

    Note the absence of ``is_active`` and ``mfa_secret``: they are not
    client-settable, and ``extra="forbid"`` makes attempting to set them a 422.
    """

    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=1024)
    role: Role = Role.MEMBER


class UserRead(OutputSchema):
    id: str
    email: str
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class ApiKeyCreate(StrictInputSchema):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    # Whose visibility the key inherits. Defaults to the admin creating it.
    owner_id: str | None = None


class ApiKeyRead(OutputSchema):
    id: str
    name: str
    scopes: str
    owner_id: str
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyRead):
    """Returned once, at creation, and never again."""

    plaintext_key: str


class TokenResponse(OutputSchema):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    scope: str
