"""Alembic environment, wired to the application's own settings and metadata.

Reading ``APP_DATABASE_URL`` through :func:`get_settings` rather than
``alembic.ini`` means there is exactly one definition of "which database" in
the project, and migrations cannot be accidentally run against the wrong one.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# Importing the registry ensures every table is attached to Base.metadata
# before autogenerate compares it against the database.
from app.core.crypto import EncryptedString
from app.core.database import Base
from app.core.settings import get_settings
from app.models import *  # noqa: F403 - registers every mapper

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)


def _include_object(
    _obj: Any,
    name: str | None,
    type_: str,
    _reflected: bool,
    _compare_to: Any,
) -> bool:
    """Ignore tables the application does not own."""
    if type_ == "table" and name is not None:
        return not name.startswith(("sqlite_", "pg_"))
    return True


def _render_item(type_: str, obj: Any, _autogen_context: Any) -> str | bool:
    """Render application-level column types as their database equivalent.

    ``EncryptedString`` encrypts in Python and stores a ``VARCHAR``. Alembic
    would otherwise emit ``app.core.crypto.EncryptedString(...)`` into the
    migration, which fails to import and wrongly implies the database knows
    about encryption. A migration should describe the schema, not the
    application's use of it.
    """
    if type_ == "type" and isinstance(obj, EncryptedString):
        return f"sa.String(length={obj.impl.length})"  # pyright: ignore[reportAttributeAccessIssue]
    return False


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_object=_include_object,
        render_item=_render_item,
        # Detect column type changes, which alembic ignores by default.
        compare_type=True,
        compare_server_default=True,
        # SQLite cannot ALTER most things; batch mode rewrites the table
        # instead, so the same migration scripts work on both backends.
        render_as_batch=settings.is_sqlite,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade --sql``)."""
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=_include_object,
        render_as_batch=settings.is_sqlite,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live async connection."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
