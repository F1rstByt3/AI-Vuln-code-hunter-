"""Runtime configuration service.

Effective config = in-app Settings (DB) layered over .env defaults. This is what
lets the Foundry endpoint / API key / selected model be changed from the UI
without a redeploy. The DB row for the API key is stored as-is in dev; in prod it
should hold a Key Vault secret reference instead (see infra/azure).

AI *profiles* are named snapshots of that same config (e.g. "Local Ollama",
"Azure prod"). Activating a profile copies it into the active ``foundry`` row;
saving the active config writes back to the active profile so the two never
drift. A scan may also pin a profile, in which case that profile's config is
used for the scan regardless of what is active.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.foundry import FoundryConfig, ModelRole
from app.config import settings
from app.models import AiProfile, Setting

FOUNDRY_KEY = "foundry"
SCANNERS_KEY = "scanners"
_SECRET_FIELDS = {"api_key"}

# Keys a profile carries (the active "foundry" row additionally holds profile_id).
PROFILE_FIELDS = (
    "endpoint", "api_key", "deployment", "api_version", "api_style",
    "use_agent_service", "roles", "context_tokens", "concurrency",
)

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


def _positive_int(v) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def build_foundry_config(stored: dict) -> FoundryConfig:
    """Layer a stored config dict (active row or profile) over .env defaults."""
    cfg = FoundryConfig.from_settings()
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
    if "exploit" in roles:
        cfg.exploit_model = ModelRole.parse(roles.get("exploit"))
    if "verifier" in roles:
        cfg.verifier_model = ModelRole.parse(roles.get("verifier"))
    cfg.context_tokens = _positive_int(stored.get("context_tokens"))
    cfg.concurrency = _positive_int(stored.get("concurrency"))
    cfg.endpoint = _normalize_endpoint(cfg.endpoint)
    return cfg


async def get_foundry_config(
    session: AsyncSession, profile_id: str | None = None,
) -> FoundryConfig:
    """Build the effective Foundry config (DB overrides win over env).

    With *profile_id*, that saved profile is used instead of the active config
    (falls back to the active config if the profile no longer exists)."""
    if profile_id:
        prof = await session.get(AiProfile, profile_id)
        if prof is not None:
            return build_foundry_config(dict(prof.config or {}))
    return build_foundry_config(await _get(session, FOUNDRY_KEY))


def config_kind(cfg: FoundryConfig) -> str:
    """mock | local | cloud — a one-word label for the UI."""
    if cfg.mock:
        return "mock"
    return "local" if cfg.is_local else "cloud"


def _masked(cfg: FoundryConfig) -> dict:
    """Display form of a config: secrets masked, never returned in clear."""
    return {
        "endpoint": cfg.endpoint,
        "deployment": cfg.deployment,
        "api_version": cfg.api_version,
        "api_style": cfg.api_style,
        "use_agent_service": cfg.use_agent_service,
        "api_key_set": bool(cfg.api_key),
        "mock_mode": cfg.mock,
        "auth_mode": _auth_mode(cfg),
        "kind": config_kind(cfg),
        "context_tokens": cfg.context_tokens,
        "concurrency": cfg.concurrency,
        "roles": {
            "chat": cfg.chat_model.to_dict() if cfg.chat_model else None,
            "reviewers": [r.to_dict() for r in cfg.reviewer_models],
            "judge": cfg.judge_model.to_dict() if cfg.judge_model else None,
            "exploit": cfg.exploit_model.to_dict() if cfg.exploit_model else None,
            "verifier": cfg.verifier_model.to_dict() if cfg.verifier_model else None,
        },
    }


async def get_foundry_settings_masked(session: AsyncSession) -> dict:
    stored = await _get(session, FOUNDRY_KEY)
    out = _masked(build_foundry_config(stored))
    pid = stored.get("profile_id")
    prof = await session.get(AiProfile, pid) if pid else None
    out["active_profile_id"] = prof.id if prof else None
    out["active_profile_name"] = prof.name if prof else None
    return out


def _apply_patch(stored: dict, patch: dict) -> dict:
    """Apply a partial update to a stored config dict. Empty strings clear a
    field; absent keys are left untouched; a blank api_key keeps the secret."""
    stored = dict(stored)
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
    # Tuning: 0 / blank / null clears back to auto.
    for field in ("context_tokens", "concurrency"):
        if field in patch:
            stored[field] = _positive_int(patch[field])
    return stored


async def update_foundry_settings(session: AsyncSession, patch: dict) -> dict:
    """Update the active config and mirror it into the active profile (if any)."""
    stored = _apply_patch(await _get(session, FOUNDRY_KEY), patch)
    pid = stored.get("profile_id")
    if pid:
        prof = await session.get(AiProfile, pid)
        if prof is not None:
            prof.config = _profile_config(stored)
        else:
            stored.pop("profile_id", None)
    await _set(session, FOUNDRY_KEY, stored)
    return await get_foundry_settings_masked(session)


def _clean_role(data) -> dict | None:
    role = ModelRole.parse(data)
    return role.to_dict() if role else None


def _clean_roles(roles: dict) -> dict:
    out: dict = {}
    for single in ("chat", "judge", "exploit", "verifier"):
        if single in roles:
            out[single] = _clean_role(roles.get(single))
    if "reviewers" in roles:
        out["reviewers"] = [
            r.to_dict() for r in (ModelRole.parse(x) for x in roles.get("reviewers") or []) if r
        ]
    return out


def _auth_mode(cfg: FoundryConfig) -> str:
    if cfg.api_key:
        return "api_key"
    if cfg.client_id and cfg.client_secret:
        return "service_principal"
    if cfg.endpoint and cfg.is_local:
        return "none"  # local OpenAI-compatible servers need no credentials
    if cfg.endpoint:
        return "managed_identity"
    return "none"


# --------------------------------------------------------------------------- profiles
def _profile_config(stored: dict) -> dict:
    return {k: stored[k] for k in PROFILE_FIELDS if k in stored}


async def _active_profile_id(session: AsyncSession) -> str | None:
    return (await _get(session, FOUNDRY_KEY)).get("profile_id")


def _profile_out(prof: AiProfile, active_id: str | None) -> dict:
    return {
        "id": prof.id,
        "name": prof.name,
        "description": prof.description,
        "active": prof.id == active_id,
        **_masked(build_foundry_config(dict(prof.config or {}))),
    }


async def list_profiles(session: AsyncSession) -> list[dict]:
    active = await _active_profile_id(session)
    rows = (await session.execute(select(AiProfile).order_by(AiProfile.name))).scalars().all()
    return [_profile_out(p, active) for p in rows]


async def get_profile(session: AsyncSession, profile_id: str) -> AiProfile | None:
    return await session.get(AiProfile, profile_id)


async def profile_name_taken(
    session: AsyncSession, name: str, exclude_id: str | None = None,
) -> bool:
    row = (await session.execute(
        select(AiProfile).where(AiProfile.name == name))).scalar_one_or_none()
    return row is not None and row.id != exclude_id


async def create_profile(
    session: AsyncSession, *, name: str, description: str | None,
    from_current: bool, patch: dict | None, activate: bool,
) -> dict:
    """Create a profile, either snapshotting the active config (incl. its
    secret, server-side) or from explicit settings, then optionally activate."""
    base = _profile_config(await _get(session, FOUNDRY_KEY)) if from_current else {}
    config = _apply_patch(base, patch or {})
    prof = AiProfile(name=name.strip(), description=description, config=config)
    session.add(prof)
    await session.commit()
    await session.refresh(prof)
    if activate:
        await activate_profile(session, prof)
    return _profile_out(prof, await _active_profile_id(session))


async def update_profile(
    session: AsyncSession, prof: AiProfile, patch: dict,
) -> dict:
    if patch.get("name"):
        prof.name = patch["name"].strip()
    if "description" in patch:
        prof.description = patch["description"]
    prof.config = _apply_patch(dict(prof.config or {}), patch)
    await session.commit()
    active = await _active_profile_id(session)
    if active == prof.id:  # keep the active row in sync with its profile
        await _set(session, FOUNDRY_KEY, {**prof.config, "profile_id": prof.id})
    return _profile_out(prof, active)


async def delete_profile(session: AsyncSession, prof: AiProfile) -> None:
    stored = await _get(session, FOUNDRY_KEY)
    if stored.get("profile_id") == prof.id:
        # Keep the active config itself; just detach it from the deleted profile.
        stored.pop("profile_id", None)
        await _set(session, FOUNDRY_KEY, stored)
    await session.delete(prof)
    await session.commit()


async def activate_profile(session: AsyncSession, prof: AiProfile) -> dict:
    """Make *prof* the active config used by default for new scans."""
    await _set(session, FOUNDRY_KEY, {**dict(prof.config or {}), "profile_id": prof.id})
    return await get_foundry_settings_masked(session)


# --------------------------------------------------------------------------- scanners
@dataclass
class ScannerConfig:
    """Effective static-scanner config (DB Settings layered over .env)."""

    semgrep_enabled: bool
    semgrep_ruleset: str
    sonarqube_enabled: bool
    sonarqube_url: str | None
    sonarqube_token: str | None


async def get_scanner_config(session: AsyncSession) -> ScannerConfig:
    stored = await _get(session, SCANNERS_KEY)
    return ScannerConfig(
        semgrep_enabled=bool(stored.get("semgrep_enabled", settings.semgrep_enabled)),
        semgrep_ruleset=stored.get("semgrep_ruleset") or settings.semgrep_ruleset,
        sonarqube_enabled=bool(stored.get("sonarqube_enabled", settings.sonarqube_enabled)),
        sonarqube_url=(stored.get("sonarqube_url") or settings.sonarqube_url) or None,
        sonarqube_token=(stored.get("sonarqube_token") or settings.sonarqube_token) or None,
    )


async def get_scanner_settings_masked(session: AsyncSession) -> dict:
    cfg = await get_scanner_config(session)
    return {
        "semgrep_enabled": cfg.semgrep_enabled,
        "semgrep_ruleset": cfg.semgrep_ruleset,
        "sonarqube_enabled": cfg.sonarqube_enabled,
        "sonarqube_url": cfg.sonarqube_url,
        "sonarqube_token_set": bool(cfg.sonarqube_token),
    }


async def update_scanner_settings(session: AsyncSession, patch: dict) -> dict:
    """Partial update. A blank sonarqube_token leaves the stored secret unchanged."""
    stored = await _get(session, SCANNERS_KEY)
    if "semgrep_enabled" in patch and patch["semgrep_enabled"] is not None:
        stored["semgrep_enabled"] = bool(patch["semgrep_enabled"])
    if "semgrep_ruleset" in patch and patch["semgrep_ruleset"] is not None:
        stored["semgrep_ruleset"] = patch["semgrep_ruleset"].strip()
    if "sonarqube_enabled" in patch and patch["sonarqube_enabled"] is not None:
        stored["sonarqube_enabled"] = bool(patch["sonarqube_enabled"])
    if "sonarqube_url" in patch and patch["sonarqube_url"] is not None:
        stored["sonarqube_url"] = patch["sonarqube_url"].strip()
    if patch.get("sonarqube_token"):  # only overwrite when non-empty
        stored["sonarqube_token"] = patch["sonarqube_token"]
    await _set(session, SCANNERS_KEY, stored)
    return await get_scanner_settings_masked(session)
