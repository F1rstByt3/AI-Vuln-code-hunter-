"""Shared API dependencies and helpers."""

from __future__ import annotations

from typing import TypeVar

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import Base

T = TypeVar("T", bound=Base)
_pool: ArqRedis | None = None


async def get_arq() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    return _pool


async def get_or_404(session: AsyncSession, model: type[T], obj_id: str) -> T:
    obj = await session.get(model, obj_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{model.__name__} not found")
    return obj
