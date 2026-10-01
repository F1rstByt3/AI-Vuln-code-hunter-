"""Async SQLAlchemy engine, session factory, and declarative base."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import datetime

from sqlalchemy import DateTime, func, text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings

engine = create_async_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    """Declarative base with common id/timestamp columns."""

    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped session."""
    async with SessionLocal() as session:
        yield session


async def init_models() -> None:
    """Dev convenience: create tables from metadata. Prod uses Alembic migrations."""
    from app import models  # noqa: F401  (register mappers)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if conn.dialect.name == "postgresql":
            # Widen columns that were too narrow in earlier schema versions.
            for col in ("cwe", "owasp", "category"):
                await conn.execute(
                    sa_text(f"ALTER TABLE findings ALTER COLUMN {col} TYPE varchar(200)")
                )
            # Byte sizes were int32 — uploads over ~2.1GB failed to insert.
            for table in ("artifacts", "artifact_files"):
                await conn.execute(
                    sa_text(f"ALTER TABLE {table} ALTER COLUMN size_bytes TYPE bigint")
                )
            # Per-target DAST mode config added later; backfill on existing DBs.
            await conn.execute(sa_text(
                "ALTER TABLE dast_targets ADD COLUMN IF NOT EXISTS "
                "mode_config JSON DEFAULT '{}'::json"))

    if engine.dialect.name == "postgresql":
        # Enum values added after the type was first created. ADD VALUE must be
        # committed before use, so run it outside the DDL transaction. The api
        # and worker both call this at startup; a concurrent duplicate add is
        # harmless, so swallow that race.
        async with engine.connect() as conn:
            conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
            for value in ("access", "dast"):
                try:
                    await conn.execute(sa_text(
                        f"ALTER TYPE findingsource ADD VALUE IF NOT EXISTS '{value}'"))
                except Exception:  # noqa: BLE001
                    pass
            # DastStatus gained approval states after the enum was created.
            for value in ("pending_approval", "rejected"):
                try:
                    await conn.execute(sa_text(
                        f"ALTER TYPE daststatus ADD VALUE IF NOT EXISTS '{value}'"))
                except Exception:  # noqa: BLE001
                    pass
