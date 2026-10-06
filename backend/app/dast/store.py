"""DAST target & credential storage service (secrets masked on the way out).

Mirrors the ``runtime_config`` pattern used for the Foundry key and Sonar token:
secrets are write-only through the API and only ever returned as booleans. The
credential secret itself is encrypted at rest (``app.secrets``) and decrypted
only in the worker at request time.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import secrets
from app.config import settings
from app.dast.modes import normalize_mode
from app.dast.scope import host_of, normalize_hosts
from app.models import DastCredential, DastTarget

_AUTH_KINDS = {"bearer", "cookie", "header", "login_form"}


def target_out(t: DastTarget, creds: list[DastCredential] | None = None) -> dict:
    return {
        "id": t.id,
        "project_id": t.project_id,
        "label": t.label,
        "base_url": t.base_url,
        "allowed_hosts": t.allowed_hosts or [],
        "active_scan_enabled": t.active_scan_enabled,
        "burp_mcp_id": t.burp_mcp_id,
        "max_rps": t.max_rps,
        "enabled": t.enabled,
        "object_seeds": t.object_seeds or {},
        "mode_config": normalize_mode(t.mode_config),
        "secrets_available": secrets.secrets_available(),
        "credentials": [cred_out(c) for c in (creds if creds is not None else t.credentials)],
    }


def cred_out(c: DastCredential) -> dict:
    """Credential for display — the secret is NEVER included, only whether set."""
    return {
        "id": c.id,
        "role_label": c.role_label,
        "auth_kind": c.auth_kind,
        "header_name": c.header_name,
        "is_privileged": c.is_privileged,
        "secret_set": bool(c.secret_enc),
    }


async def list_targets(session: AsyncSession, project_id: str) -> list[dict]:
    rows = (await session.execute(
        select(DastTarget).where(DastTarget.project_id == project_id)
        .order_by(DastTarget.label)
    )).scalars().all()
    out = []
    for t in rows:
        creds = (await session.execute(
            select(DastCredential).where(DastCredential.target_id == t.id)
            .order_by(DastCredential.role_label)
        )).scalars().all()
        out.append(target_out(t, creds))
    return out


async def create_target(session: AsyncSession, project_id: str, body: dict) -> dict:
    base_url = (body.get("base_url") or "").strip()
    if not host_of(base_url):
        raise ValueError("base_url must be an absolute URL with a host")
    t = DastTarget(
        project_id=project_id,
        label=(body.get("label") or base_url).strip()[:200],
        base_url=base_url,
        allowed_hosts=normalize_hosts(base_url, body.get("allowed_hosts")),
        active_scan_enabled=bool(body.get("active_scan_enabled")),
        burp_mcp_id=body.get("burp_mcp_id") or None,
        object_seeds=body.get("object_seeds") or {},
        max_rps=float(body.get("max_rps") or settings.dast_default_max_rps),
    )
    session.add(t)
    await session.commit()
    await session.refresh(t)
    return target_out(t, [])


async def update_target(session: AsyncSession, t: DastTarget, body: dict) -> dict:
    if body.get("label") is not None:
        t.label = body["label"].strip()[:200]
    if body.get("base_url") is not None:
        base_url = body["base_url"].strip()
        if not host_of(base_url):
            raise ValueError("base_url must be an absolute URL with a host")
        t.base_url = base_url
    if "allowed_hosts" in body:
        t.allowed_hosts = normalize_hosts(t.base_url, body.get("allowed_hosts"))
    for field in ("active_scan_enabled", "enabled"):
        if body.get(field) is not None:
            setattr(t, field, bool(body[field]))
    if body.get("burp_mcp_id") is not None:
        t.burp_mcp_id = body["burp_mcp_id"] or None
    if body.get("max_rps") is not None:
        t.max_rps = float(body["max_rps"])
    if body.get("object_seeds") is not None:
        t.object_seeds = body["object_seeds"] or {}
    if body.get("mode_config") is not None:
        t.mode_config = normalize_mode(body["mode_config"])
    await session.commit()
    await session.refresh(t)
    return target_out(t)


async def add_credential(session: AsyncSession, target_id: str, body: dict) -> dict:
    kind = (body.get("auth_kind") or "bearer").lower()
    if kind not in _AUTH_KINDS:
        raise ValueError(f"auth_kind must be one of {sorted(_AUTH_KINDS)}")
    secret = body.get("secret")
    if not secret:
        raise ValueError("secret is required")
    if not secrets.secrets_available():
        raise ValueError(
            "Credential storage is disabled: set DAST_SECRET_KEY to store secrets "
            "at rest (or supply credentials per-run instead).")
    c = DastCredential(
        target_id=target_id,
        role_label=(body.get("role_label") or "userA").strip()[:60],
        auth_kind=kind,
        header_name=(body.get("header_name") or None),
        is_privileged=bool(body.get("is_privileged")),
        secret_enc=secrets.encrypt(secret),
    )
    session.add(c)
    await session.commit()
    await session.refresh(c)
    return cred_out(c)


async def update_credential(session: AsyncSession, c: DastCredential, body: dict) -> dict:
    if body.get("role_label") is not None:
        c.role_label = body["role_label"].strip()[:60]
    if body.get("auth_kind") is not None:
        kind = body["auth_kind"].lower()
        if kind not in _AUTH_KINDS:
            raise ValueError(f"auth_kind must be one of {sorted(_AUTH_KINDS)}")
        c.auth_kind = kind
    if body.get("header_name") is not None:
        c.header_name = body["header_name"] or None
    if body.get("is_privileged") is not None:
        c.is_privileged = bool(body["is_privileged"])
    if body.get("secret"):  # only overwrite when a non-empty value is supplied
        c.secret_enc = secrets.encrypt(body["secret"])
    await session.commit()
    await session.refresh(c)
    return cred_out(c)
