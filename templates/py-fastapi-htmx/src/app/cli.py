"""Operational CLI: ``uv run python -m app.cli <command>``.

Kept deliberately small. Schema changes belong in Alembic migrations, not here;
``create-tables`` exists only for throwaway local databases and tests.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy.ext.asyncio import AsyncSession

from app import models
from app.core.database import Base, get_engine, get_sessionmaker
from app.core.logging import configure_logging
from app.core.settings import Settings, generate_secret_key, get_settings
from app.domains.auth.models import Role, User
from app.domains.auth.schemas import ApiKeyCreate, UserCreate
from app.domains.auth.service import (
    create_api_key,
    create_user,
    get_user_by_email,
    provision_mfa_secret,
)
from app.domains.items.schemas import ItemCreate
from app.domains.items.service import create as create_item

# Demo fixtures. The item id matches features/item_lifecycle.feature.
DEMO_ITEM_ID = "item-101"
DEMO_ADMIN_EMAIL = "admin@example.com"
DEMO_MEMBER_EMAIL = "member@example.com"
DEMO_PASSWORD = "change-me-please-123"  # noqa: S105 - local fixture only

ALL_SCOPES = [
    "audit:read",
    "items:read",
    "items:write",
    "webhooks:read",
    "webhooks:write",
]


async def create_tables() -> None:
    """Create the schema directly from the models (local/test only)."""
    models.configure()
    async with get_engine().begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sys.stdout.write("Schema created.\n")


async def drop_tables() -> None:
    models.configure()
    async with get_engine().begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    sys.stdout.write("Schema dropped.\n")


async def create_admin(email: str, full_name: str, password: str) -> None:
    """Provision an admin and print their MFA enrolment URI."""
    async with get_sessionmaker()() as session:
        if await get_user_by_email(session, email) is not None:
            sys.stdout.write(f"User {email} already exists; nothing to do.\n")
            return

        user = await create_user(
            session,
            UserCreate(
                email=email,  # pyright: ignore[reportArgumentType]
                full_name=full_name,
                password=password,
                role=Role.ADMIN,
            ),
        )
        uri = provision_mfa_secret(user, issuer=get_settings().project_name)
        await session.commit()

    sys.stdout.write(f"Created admin {email}\n")
    sys.stdout.write(f"MFA enrolment URI (add to your authenticator):\n  {uri}\n")


async def seed_demo() -> None:
    """Populate a local database with the data the feature files expect."""
    settings = get_settings()
    if not settings.is_local_or_test:
        sys.stderr.write("Refusing to seed demo data outside local/test.\n")
        raise SystemExit(1)

    async with get_sessionmaker()() as session:
        if await get_user_by_email(session, DEMO_ADMIN_EMAIL) is not None:
            sys.stdout.write("Demo data already present.\n")
            return

        admin = await _seed_admin(session)
        member = await _seed_member(session)
        await _seed_items(session, member)
        _, plaintext = await create_api_key(
            session,
            ApiKeyCreate(name="local-development", scopes=ALL_SCOPES),
            default_owner=admin,
        )
        mfa_uri = provision_mfa_secret(admin, issuer=settings.project_name)
        await session.commit()

    # The MFA URI is printed because admin sign-in *requires* a TOTP code —
    # without it the seeded admin account would be unusable.
    sys.stdout.write(
        "Seeded demo data.\n"
        f"  admin:   {DEMO_ADMIN_EMAIL} / {DEMO_PASSWORD}\n"
        f"  member:  {DEMO_MEMBER_EMAIL} / {DEMO_PASSWORD}\n"
        f"  item:    {DEMO_ITEM_ID}\n"
        f"  api key: {plaintext}\n"
        "\nAdd the admin to your authenticator app:\n"
        f"  {mfa_uri}\n"
    )


async def _seed_admin(session: AsyncSession) -> User:
    return await create_user(
        session,
        UserCreate(
            email=DEMO_ADMIN_EMAIL,  # pyright: ignore[reportArgumentType]
            full_name="Example Admin",
            password=DEMO_PASSWORD,
            role=Role.ADMIN,
        ),
    )


async def _seed_member(session: AsyncSession) -> User:
    return await create_user(
        session,
        UserCreate(
            email=DEMO_MEMBER_EMAIL,  # pyright: ignore[reportArgumentType]
            full_name="Example Member",
            password=DEMO_PASSWORD,
            role=Role.MEMBER,
        ),
    )


async def _seed_items(session: AsyncSession, owner: User) -> None:
    await create_item(
        session,
        ItemCreate(
            id=DEMO_ITEM_ID,
            name="First example item",
            description="A record with no meaning beyond exercising the stack.",
        ),
        owner=owner,
    )
    await create_item(
        session,
        ItemCreate(id=None, name="Second example item", description=None),
        owner=owner,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("create-tables", help="Create the schema from the models")
    sub.add_parser("drop-tables", help="Drop every table")
    sub.add_parser("seed-demo", help="Insert demo users, items and an API key")
    sub.add_parser("secret-key", help="Print a fresh APP_SECRET_KEY value")

    admin = sub.add_parser("create-admin", help="Provision an admin user")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--password", required=True)

    args = parser.parse_args(argv)
    settings: Settings = get_settings()
    configure_logging(settings)

    match args.command:
        case "create-tables":
            asyncio.run(create_tables())
        case "drop-tables":
            asyncio.run(drop_tables())
        case "seed-demo":
            asyncio.run(seed_demo())
        case "create-admin":
            asyncio.run(create_admin(args.email, args.name, args.password))
        case "secret-key":
            sys.stdout.write(f"{generate_secret_key()}\n")
        case _:  # pragma: no cover - argparse rejects unknown commands first
            parser.error(f"unknown command: {args.command}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
