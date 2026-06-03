"""Runtime configuration service.

Effective config = in-app Settings (DB) layered over .env defaults. This is what
lets the Foundry endpoint / API key / selected model be changed from the UI
without a redeploy. The DB row for the API key is stored as-is in dev; in prod it
should hold a Key Vault secret reference instead (see infra/azure).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.foundry import FoundryConfig, ModelRole
from app.models import Setting

FOUNDRY_KEY = "foundry"
_SECRET_FIELDS = {"api_key"}

_STRIP_SUFFIXES = ("/openai/v1", "/openai/v1/", "/openai", "/openai/", "/v1", "/v1/")


def _normalize_endpoint(url: str | None) -> str | None:
    if not url:
        return url
    url = url.strip().rstrip("/")
    lower = url.lower()
    for suffix in _STRIP_SUFFIXES:
        if lower.endswith(suffix):
            url = url[: -len(suffix)]
            break
    return url


async def _get(session: AsyncSession, key: str) -> dict:
    row = (await session.execute(select(Setting).where(Setting.key == key))).scalar_one_or_none()
    return dict(row.value) if row else {}


async def _set(session: AsyncSession, key: str, value: dict) -> None:
    row = (await session.execute(select(Setting).where(Setting.key == key))).scalar_one_or_none()
    if row:
        row.value = value
    else:
        session.add(Setting(key=key, value=value))
    await session.commit()


async def get_foundry_config(session: AsyncSession) -> FoundryConfig:
    """Build the effective Foundry config (DB overrides win over env)."""
    cfg = FoundryConfig.from_settings()
    stored = await _get(session, FOUNDRY_KEY)
    for field in ("endpoint", "api_key", "deployment", "api_version", "api_style"):
        if stored.get(field):
            setattr(cfg, field, stored[field])
    if "use_agent_service" in stored:
        cfg.use_agent_service = bool(stored["use_agent_service"])
    roles = stored.get("roles") or {}
    if "chat" in roles:
        cfg.chat_model = ModelRole.parse(roles.get("chat"))
    if "reviewers" in roles:
        cfg.reviewer_models = [
            r for r in (ModelRole.parse(x) for x in roles.get("reviewers") or []) if r
        ]
    if "judge" in roles:
        cfg.judge_model = ModelRole.parse(roles.get("judge"))
    cfg.endpoint = _normalize_endpoint(cfg.endpoint)
    return cfg


async def get_foundry_settings_masked(session: AsyncSession) -> dict:
    """Settings for display: secrets masked, never returned in clear."""
    cfg = await get_foundry_config(session)
    return {
        "endpoint": cfg.endpoint,
        "deployment": cfg.deployment,
        "api_version": cfg.api_version,
        "api_style": cfg.api_style,
        "use_agent_service": cfg.use_agent_service,
        "api_key_set": bool(cfg.api_key),
        "mock_mode": cfg.mock,
        "auth_mode": _auth_mode(cfg),
        "roles": {
            "chat": cfg.chat_model.to_dict() if cfg.chat_model else None,
            "reviewers": [r.to_dict() for r in cfg.reviewer_models],
            "judge": cfg.judge_model.to_dict() if cfg.judge_model else None,
        },
    }


async def update_foundry_settings(session: AsyncSession, patch: dict) -> dict:
    """Apply a partial update. Empty strings clear a field; absent keys are left
    untouched. A blank api_key leaves the stored secret unchanged."""
    stored = await _get(session, FOUNDRY_KEY)
    for field in ("endpoint", "deployment", "api_version", "api_style"):
        if field in patch and patch[field] is not None:
            stored[field] = patch[field].strip()
    if "endpoint" in stored:
        stored["endpoint"] = _normalize_endpoint(stored["endpoint"]) or ""
    if "use_agent_service" in patch and patch["use_agent_service"] is not None:
        stored["use_agent_service"] = bool(patch["use_agent_service"])
    if patch.get("api_key"):  # only overwrite when a non-empty value is supplied
        stored["api_key"] = patch["api_key"]
    if "roles" in patch and patch["roles"] is not None:
        stored["roles"] = _clean_roles(patch["roles"])
    await _set(session, FOUNDRY_KEY, stored)
    return await get_foundry_settings_masked(session)


def _clean_role(data) -> dict | None:
    role = ModelRole.parse(data)
    return role.to_dict() if role else None


def _clean_roles(roles: dict) -> dict:
    out: dict = {}
    if "chat" in roles:
        out["chat"] = _clean_role(roles.get("chat"))
    if "reviewers" in roles:
        out["reviewers"] = [
            r.to_dict() for r in (ModelRole.parse(x) for x in roles.get("reviewers") or []) if r
        ]
    if "judge" in roles:
        out["judge"] = _clean_role(roles.get("judge"))
    return out


def _auth_mode(cfg: FoundryConfig) -> str:
    if cfg.api_key:
        return "api_key"
    if cfg.client_id and cfg.client_secret:
        return "service_principal"
    if cfg.endpoint:
        return "managed_identity"
    return "none"
