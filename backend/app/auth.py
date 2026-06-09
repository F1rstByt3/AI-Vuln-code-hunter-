"""Authentication & RBAC.

Production: validates Microsoft Entra ID (Azure AD) access tokens against the
tenant JWKS. Dev: AUTH_DISABLED=true injects a deterministic admin user so the
whole app is usable without an identity provider.
"""

from __future__ import annotations

from functools import lru_cache

import jwt
from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.config import settings
from app.models import Role

_ROLE_ORDER = {Role.viewer: 0, Role.reviewer: 1, Role.admin: 2}


class CurrentUser(BaseModel):
    email: str
    name: str | None = None
    oid: str | None = None
    role: Role = Role.reviewer


DEV_USER = CurrentUser(email="dev@localhost", name="Dev Admin", oid="dev", role=Role.admin)


@lru_cache
def _jwks_client() -> jwt.PyJWKClient:
    url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
    return jwt.PyJWKClient(url)


def _verify_entra_token(token: str) -> CurrentUser:
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.entra_audience or settings.entra_client_id,
            issuer=f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0",
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc

    # Map an app role / group claim to our Role. Defaults to reviewer.
    role = Role.reviewer
    app_roles = claims.get("roles") or []
    if "admin" in app_roles:
        role = Role.admin
    elif "viewer" in app_roles:
        role = Role.viewer
    return CurrentUser(
        email=claims.get("preferred_username") or claims.get("email") or claims.get("sub", ""),
        name=claims.get("name"),
        oid=claims.get("oid"),
        role=role,
    )


async def get_current_user(authorization: str | None = Header(default=None)) -> CurrentUser:
    if settings.auth_disabled:
        return DEV_USER
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    return _verify_entra_token(authorization.split(" ", 1)[1])


def require_role(minimum: Role):
    """Dependency factory enforcing a minimum role."""

    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if _ROLE_ORDER[user.role] < _ROLE_ORDER[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return _dep
