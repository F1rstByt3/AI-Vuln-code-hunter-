"""Scripted form/API login for ``login_form`` credentials.

The credential's (encrypted) secret is a JSON spec describing how to obtain a
session for a role: where to POST, what to send, and how to turn the response
into request auth for the rest of the run. Supported extraction:

  * a cookie set by the response (session cookies) — captured into the identity;
  * a token read from the response JSON at a dotted path, applied as a bearer
    token or a named header.

The login request goes through the scoped ``LiveClient`` like everything else,
so the login URL must be inside the target's host allow-list.

Example spec (stored as the credential secret):
  {
    "url": "/api/login",                # relative to base_url, or absolute in-scope
    "method": "POST",
    "content": "json",                  # json | form
    "body": {"username": "a@x.com", "password": "..."},
    "apply": "cookie",                  # cookie | bearer | header
    "token_path": "data.token",         # for apply=bearer/header
    "header_name": "Authorization",     # for apply=header
    "cookie_names": ["session"]         # for apply=cookie (optional filter)
  }
"""

from __future__ import annotations

import json
import logging

from app.dast.identity import Identity

log = logging.getLogger(__name__)


def parse_spec(secret: str) -> dict | None:
    try:
        spec = json.loads(secret)
    except (TypeError, ValueError):
        return None
    return spec if isinstance(spec, dict) and spec.get("url") else None


def _dig(obj, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


async def perform_login(client, base_url: str, role: str, is_privileged: bool,
                        spec: dict) -> Identity:
    """Run the scripted login and return a usable Identity (or an unusable one
    with a note on failure)."""
    url = spec["url"]
    if not url.startswith(("http://", "https://")):
        url = base_url.rstrip("/") + "/" + url.lstrip("/")
    method = (spec.get("method") or "POST").upper()
    content = (spec.get("content") or "json").lower()
    body = spec.get("body") or {}
    kwargs = {"json_body": body} if content == "json" else {"data": body}

    def fail(note: str) -> Identity:
        log.info("login failed for role %s: %s", role, note)
        return Identity(role=role, is_privileged=is_privileged, usable=False, note=note)

    try:
        resp = await client.raw(method, url, Identity.anonymous(), allow_login=True, **kwargs)
    except Exception as exc:  # noqa: BLE001
        return fail(f"login request error: {type(exc).__name__}")
    if resp.status_code >= 400:
        return fail(f"login returned HTTP {resp.status_code}")

    apply = (spec.get("apply") or "cookie").lower()
    if apply == "cookie":
        wanted = set(spec.get("cookie_names") or [])
        cookies = {k: v for k, v in resp.cookies.items() if not wanted or k in wanted}
        if not cookies:
            return fail("login succeeded but set no (matching) cookies")
        return Identity(role=role, is_privileged=is_privileged, cookies=cookies)

    # token-based: read from JSON body
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return fail("login response was not JSON (needed for token extraction)")
    token = _dig(data, spec.get("token_path") or "token")
    if not token:
        return fail(f"no token at path {spec.get('token_path') or 'token'!r}")
    if apply == "bearer":
        return Identity(role=role, is_privileged=is_privileged,
                        headers={"Authorization": f"Bearer {token}"})
    if apply == "header":
        return Identity(role=role, is_privileged=is_privileged,
                        headers={spec.get("header_name") or "Authorization": str(token)})
    return fail(f"unknown apply mode {apply!r}")
