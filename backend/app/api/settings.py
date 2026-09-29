"""In-app settings: the Foundry connection (endpoint / key / model), editable at
runtime and persisted to the DB so it survives restarts without a redeploy."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.foundry import FoundryConfig, get_foundry_client
from app.auth import require_role
from app.db import get_session
from app.models import Role
from app.runtime_config import (
    activate_profile,
    build_foundry_config,
    create_profile,
    delete_profile,
    get_foundry_config,
    get_foundry_settings_masked,
    get_profile,
    get_scanner_config,
    get_scanner_settings_masked,
    list_profiles,
    profile_name_taken,
    update_foundry_settings,
    update_profile,
    update_scanner_settings,
)
from app.schemas import (
    AiProfileCreate,
    AiProfileOut,
    AiProfileUpdate,
    ConnectionTest,
    FoundrySettingsOut,
    FoundrySettingsUpdate,
    ModelsOut,
    ScannerSettingsOut,
    ScannerSettingsUpdate,
)

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
    return await _test_config(await get_foundry_config(session))


# --------------------------------------------------------------------------- profiles
@router.get("/profiles", response_model=list[AiProfileOut])
async def get_profiles(session: AsyncSession = Depends(get_session)):
    """Saved AI profiles (local / cloud / mock), secrets masked."""
    return await list_profiles(session)


@router.post("/profiles", response_model=AiProfileOut,
             dependencies=[Depends(require_role(Role.admin))])
async def post_profile(body: AiProfileCreate, session: AsyncSession = Depends(get_session)):
    if await profile_name_taken(session, body.name.strip()):
        raise HTTPException(409, f"A profile named '{body.name}' already exists")
    return await create_profile(
        session, name=body.name, description=body.description,
        from_current=body.from_current,
        patch=body.settings.model_dump(exclude_unset=True) if body.settings else None,
        activate=body.activate,
    )


@router.put("/profiles/{profile_id}", response_model=AiProfileOut,
            dependencies=[Depends(require_role(Role.admin))])
async def put_profile(profile_id: str, body: AiProfileUpdate,
                      session: AsyncSession = Depends(get_session)):
    prof = await _profile_or_404(session, profile_id)
    patch = body.model_dump(exclude_unset=True)
    if patch.get("name") and await profile_name_taken(session, patch["name"].strip(),
                                                      exclude_id=prof.id):
        raise HTTPException(409, f"A profile named '{patch['name']}' already exists")
    return await update_profile(session, prof, patch)


@router.delete("/profiles/{profile_id}", status_code=204,
               dependencies=[Depends(require_role(Role.admin))])
async def remove_profile(profile_id: str, session: AsyncSession = Depends(get_session)):
    await delete_profile(session, await _profile_or_404(session, profile_id))


@router.post("/profiles/{profile_id}/activate", response_model=FoundrySettingsOut,
             dependencies=[Depends(require_role(Role.admin))])
async def post_activate_profile(profile_id: str, session: AsyncSession = Depends(get_session)):
    """Make this profile the default for new scans (and load it into the editor)."""
    return await activate_profile(session, await _profile_or_404(session, profile_id))


@router.post("/profiles/{profile_id}/test", response_model=ConnectionTest,
             dependencies=[Depends(require_role(Role.admin))])
async def test_profile(profile_id: str, session: AsyncSession = Depends(get_session)):
    prof = await _profile_or_404(session, profile_id)
    return await _test_config(build_foundry_config(dict(prof.config or {})))


async def _profile_or_404(session: AsyncSession, profile_id: str):
    prof = await get_profile(session, profile_id)
    if prof is None:
        raise HTTPException(404, "Profile not found")
    return prof


async def _test_config(cfg: FoundryConfig) -> ConnectionTest:
    """Verify every role of *cfg* accepts an inference call."""
    try:
        client = get_foundry_client(cfg)
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
        if roles.exploit:
            checks.append(("exploit", roles.exploit))
        if roles.verifier:
            checks.append(("verifier", roles.verifier))

        # de-dup identical (deployment, transport) pairs to keep the test fast
        seen: set[tuple[str, str]] = set()
        results: list[str] = []
        ok = True
        for label, role in checks:
            key = (role.deployment, role.effective_transport(local=cfg.is_local))
            if key in seen:
                continue
            seen.add(key)
            try:
                async for _ in client.stream(
                    [{"role": "user", "content": "Reply with OK"}],
                    model=role.deployment, transport=role.effective_transport(local=cfg.is_local),
                ):
                    break  # one token is enough
                results.append(f"{label}:{role.deployment}✓")
            except Exception as exc:  # noqa: BLE001
                ok = False
                results.append(f"{label}:{role.deployment}✗ ({exc})")
        return ConnectionTest(ok=ok, detail="connected · " + " · ".join(results), models=models)
    except Exception as exc:  # noqa: BLE001
        return ConnectionTest(ok=False, detail=str(exc))


# --------------------------------------------------------------------------- scanners
@router.get("/scanners", response_model=ScannerSettingsOut)
async def get_scanners(session: AsyncSession = Depends(get_session)):
    return await get_scanner_settings_masked(session)


@router.put("/scanners", response_model=ScannerSettingsOut,
            dependencies=[Depends(require_role(Role.admin))])
async def put_scanners(body: ScannerSettingsUpdate, session: AsyncSession = Depends(get_session)):
    return await update_scanner_settings(session, body.model_dump(exclude_unset=True))


@router.post("/scanners/sonar-test", response_model=ConnectionTest,
             dependencies=[Depends(require_role(Role.admin))])
async def test_sonarqube(session: AsyncSession = Depends(get_session)):
    """Verify the SonarQube server is reachable and the token authenticates."""
    import httpx

    cfg = await get_scanner_config(session)
    if not cfg.sonarqube_url or not cfg.sonarqube_token:
        return ConnectionTest(ok=False, detail="SonarQube URL or token not set")
    try:
        async with httpx.AsyncClient(
            base_url=cfg.sonarqube_url.rstrip("/"),
            auth=(cfg.sonarqube_token, ""), timeout=15,
        ) as client:
            resp = await client.get("/api/system/status")
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "UNKNOWN")
            ok = status == "UP"
            detail = f"{data.get('id', 'server')} · status={status}"
            if ok:
                # Confirm the token actually authenticates (not just anonymous access).
                auth = await client.get("/api/authentication/validate")
                if auth.is_success and not auth.json().get("valid", False):
                    return ConnectionTest(ok=False, detail=f"{detail} · token invalid")
            return ConnectionTest(ok=ok, detail=detail)
    except Exception as exc:  # noqa: BLE001
        return ConnectionTest(ok=False, detail=str(exc))
