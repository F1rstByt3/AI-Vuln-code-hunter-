"""In-app settings: the Foundry connection (endpoint / key / model), editable at
runtime and persisted to the DB so it survives restarts without a redeploy."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.foundry import get_foundry_client
from app.auth import require_role
from app.db import get_session
from app.models import Role
from app.runtime_config import (
    get_foundry_config,
    get_foundry_settings_masked,
    update_foundry_settings,
)
from app.schemas import ConnectionTest, FoundrySettingsOut, FoundrySettingsUpdate, ModelsOut

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/foundry", response_model=FoundrySettingsOut)
async def get_foundry(session: AsyncSession = Depends(get_session)):
    return await get_foundry_settings_masked(session)


@router.put("/foundry", response_model=FoundrySettingsOut,
            dependencies=[Depends(require_role(Role.admin))])
async def put_foundry(body: FoundrySettingsUpdate, session: AsyncSession = Depends(get_session)):
    return await update_foundry_settings(session, body.model_dump(exclude_unset=True))


@router.get("/foundry/models", response_model=ModelsOut)
async def list_models(session: AsyncSession = Depends(get_session)):
    """Models/deployments available from the configured Foundry project."""
    cfg = await get_foundry_config(session)
    client = get_foundry_client(cfg)
    return ModelsOut(models=await client.list_models(), mock=cfg.mock)


@router.post("/foundry/test", response_model=ConnectionTest,
             dependencies=[Depends(require_role(Role.admin))])
async def test_connection(session: AsyncSession = Depends(get_session)):
    cfg = await get_foundry_config(session)
    client = get_foundry_client(cfg)
    try:
        models = await client.list_models()
        detail = "mock mode (no endpoint configured)" if cfg.mock else f"connected · deployment={cfg.deployment}"
        # Verify the configured deployment actually works
        if not cfg.mock:
            try:
                test_msgs = [{"role": "user", "content": "Reply with OK"}]
                async for _ in client.chat_stream(test_msgs, model=cfg.deployment):
                    break  # one token is enough to confirm it works
                detail += " · inference OK"
            except Exception as exc:  # noqa: BLE001
                detail += f" · inference FAILED: {exc}"
                return ConnectionTest(ok=False, detail=detail, models=models)
        return ConnectionTest(ok=True, detail=detail, models=models)
    except Exception as exc:  # noqa: BLE001
        return ConnectionTest(ok=False, detail=str(exc))
