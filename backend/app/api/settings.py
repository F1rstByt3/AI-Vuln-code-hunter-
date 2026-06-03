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
        if cfg.mock:
            return ConnectionTest(ok=True, detail="mock mode (no endpoint configured)",
                                  models=models)
        # Verify each configured role/deployment actually accepts an inference call,
        # using its effective transport (Responses for Codex / o-series).
        roles = cfg.resolve_roles()
        checks: list[tuple[str, object]] = [("chat", roles.chat)]
        checks += [(f"reviewer[{i}]", r) for i, r in enumerate(roles.reviewers)]
        if roles.judge:
            checks.append(("judge", roles.judge))

        # de-dup identical (deployment, transport) pairs to keep the test fast
        seen: set[tuple[str, str]] = set()
        results: list[str] = []
        ok = True
        for label, role in checks:
            key = (role.deployment, role.effective_transport())
            if key in seen:
                continue
            seen.add(key)
            try:
                async for _ in client.stream(
                    [{"role": "user", "content": "Reply with OK"}],
                    model=role.deployment, transport=role.effective_transport(),
                ):
                    break  # one token is enough
                results.append(f"{label}:{role.deployment}✓")
            except Exception as exc:  # noqa: BLE001
                ok = False
                results.append(f"{label}:{role.deployment}✗ ({exc})")
        return ConnectionTest(ok=ok, detail="connected · " + " · ".join(results), models=models)
    except Exception as exc:  # noqa: BLE001
        return ConnectionTest(ok=False, detail=str(exc))
