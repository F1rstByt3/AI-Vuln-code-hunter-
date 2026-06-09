"""Client (tenant/customer) endpoints."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.auth import require_role
from app.db import get_session
from app.models import Client, Role
from app.schemas import ClientCreate, ClientOut

router = APIRouter(prefix="/clients", tags=["clients"])


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:120] or "client"


@router.get("", response_model=list[ClientOut])
async def list_clients(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(Client).order_by(Client.name))).scalars().all()
    return rows


@router.post("", response_model=ClientOut, dependencies=[Depends(require_role(Role.reviewer))])
async def create_client(body: ClientCreate, session: AsyncSession = Depends(get_session)):
    client = Client(
        name=body.name,
        slug=body.slug or _slugify(body.name),
        contact_email=body.contact_email,
        notes=body.notes,
    )
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client


@router.get("/{client_id}", response_model=ClientOut)
async def get_client(client_id: str, session: AsyncSession = Depends(get_session)):
    return await get_or_404(session, Client, client_id)


@router.delete("/{client_id}", status_code=204, dependencies=[Depends(require_role(Role.admin))])
async def delete_client(client_id: str, session: AsyncSession = Depends(get_session)):
    client = await get_or_404(session, Client, client_id)
    await session.delete(client)
    await session.commit()
