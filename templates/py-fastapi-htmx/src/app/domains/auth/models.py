"""Persistence models for identity, roles and machine credentials."""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedString
from app.core.database import Base, IdMixin, TimestampMixin


class Role(enum.StrEnum):
    """Coarse-grained role. Fine-grained access uses scopes on API keys."""

    ADMIN = "admin"
    """Staff: sees and manages every record."""

    MEMBER = "member"
    """Ordinary user: scoped to the records they own."""


class User(IdMixin, TimestampMixin, Base):
    """A human principal, authenticated by password and a session cookie."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[Role] = mapped_column(String(32), nullable=False, default=Role.MEMBER)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Base32 TOTP seed. NULL means MFA is not yet enrolled; enrolment is
    # mandatory for admins before they can be granted a session.
    #
    # Encrypted at rest: this is a credential, not data. Anyone holding it can
    # mint valid codes indefinitely, so a database dump would hand over the
    # second factor outright. It cannot be hashed — verification needs the
    # value back — which leaves encryption. Ciphertext is ~100 chars for a
    # 32-char seed, hence the width.
    mfa_secret: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Lockout ---------------------------------------------------------
    # Rate limiting throttles a *source*; this protects an *account*, which is
    # the case rate limiting misses when attempts arrive from many addresses.
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def is_locked(self, now: datetime) -> bool:
        """True while a lockout window is still in force.

        The stored value is normalised to UTC first because SQLite has no
        timezone type: it hands back a naive datetime where Postgres returns an
        aware one, despite both columns being declared ``DateTime(timezone=True)``.
        Comparing the two directly raises ``TypeError`` — so this would have
        worked in production and crashed in local development, which is the
        worse way round to find out.
        """
        if self.locked_until is None:
            return False
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        return locked_until > now

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"


class ApiKey(IdMixin, TimestampMixin, Base):
    """A machine credential for the JSON API.

    Only the SHA-256 digest is stored. The plaintext is shown to the operator
    exactly once, at creation.
    """

    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_active", "revoked_at"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    # Space-separated OAuth2-style scopes, e.g. "items:read webhooks:write".
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # A key always acts *as* a user, never as an anonymous superuser. That is
    # what lets ownership scoping apply identically to machine callers: an
    # admin's key sees everything, a member's key sees only their own records.
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def scope_set(self) -> frozenset[str]:
        return frozenset(self.scopes.split())

    def __repr__(self) -> str:
        return f"<ApiKey {self.name}>"
