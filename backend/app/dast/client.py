"""The only path that sends live requests to a target.

Every request goes through ``LiveClient`` so the safety controls hold without
exception:
  * scope guard — the host is checked against the allow-list before sending;
  * no cross-host redirects — a redirect off the allow-list is not followed;
  * rate limit — requests are spaced to ``max_rps``;
  * request cap — a hard ceiling per run;
  * method guard — mutating methods are refused unless the run allows them.

Responses are returned as a small, evidence-safe summary (status, length,
a truncated body hash/snippet) — never the full body by default, and never the
request's auth headers.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass

import httpx

from app.config import settings
from app.dast.identity import Identity, redact_headers
from app.dast.scope import Scope, ScopeError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class LiveResponse:
    status: int
    length: int
    elapsed_ms: int
    body_hash: str
    body_snippet: str            # short, for human evidence (may be empty)
    error: str | None = None


class RequestCapExceeded(RuntimeError):
    pass


class LiveClient:
    def __init__(self, scope: Scope, *, max_rps: float, allow_mutating: bool,
                 max_requests: int | None = None, capture_bodies: bool = False,
                 log_cap: int = 3000) -> None:
        self.scope = scope
        self.allow_mutating = allow_mutating
        self._min_interval = 1.0 / max_rps if max_rps and max_rps > 0 else 0.0
        self._last = 0.0
        self._max_requests = max_requests or settings.dast_max_requests_per_run
        self._count = 0
        self._capture = capture_bodies
        # Audit trail: every outbound request (what / where / why), bounded.
        self.log: list[dict] = []
        self.by_purpose: dict[str, int] = {}
        self._log_cap = log_cap
        self._client = httpx.AsyncClient(
            follow_redirects=False,           # never auto-follow across hosts
            timeout=settings.dast_request_timeout,
            verify=True,
        )

    @property
    def count(self) -> int:
        return self._count

    def _record(self, purpose: str, method: str, url: str, role: str,
                status: int | None, ms: int, note: str = "") -> None:
        self.by_purpose[purpose] = self.by_purpose.get(purpose, 0) + 1
        if len(self.log) < self._log_cap:
            e = {"purpose": purpose, "method": method, "url": url, "identity": role,
                 "status": status, "ms": ms}
            if note:
                e["note"] = note
            self.log.append(e)

    async def __aenter__(self) -> LiveClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        if self._min_interval:
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
        self._last = time.monotonic()

    async def raw(self, method: str, url: str, identity: Identity, *,
                  json_body=None, data=None, allow_login: bool = False,
                  purpose: str = "internal"):
        """Send and return the full httpx.Response, for INTERNAL use (scripted
        login, id harvesting) where the body/cookies are needed. Never used to
        build evidence — callers must not leak the body. Same scope/rate/cap
        guards apply. ``allow_login`` permits a POST even when the run forbids
        mutating traffic (authenticating is not a target mutation)."""
        method = method.upper()
        if method not in SAFE_METHODS and not self.allow_mutating and not allow_login:
            raise RuntimeError(f"{method} requires allow_mutating")
        self.scope.check(url)
        if self._count >= self._max_requests:
            raise RequestCapExceeded(f"request cap {self._max_requests} reached")
        await self._throttle()
        self._count += 1
        started = time.monotonic()
        resp = await self._client.request(
            method, url, headers=identity.headers or None,
            cookies=identity.cookies or None, json=json_body, data=data)
        self._record(purpose, method, url, identity.role, resp.status_code,
                     int((time.monotonic() - started) * 1000))
        return resp

    async def send(self, method: str, url: str, identity: Identity,
                   *, json_body=None, purpose: str = "probe") -> LiveResponse:
        method = method.upper()
        if method not in SAFE_METHODS and not self.allow_mutating:
            self._record(purpose, method, url, identity.role, None, 0,
                         note="blocked: mutating not allowed")
            return LiveResponse(0, 0, 0, "", "",
                                error=f"blocked: {method} requires allow_mutating")
        self.scope.check(url)                 # raises ScopeError if out of scope
        if self._count >= self._max_requests:
            raise RequestCapExceeded(f"request cap {self._max_requests} reached")
        await self._throttle()
        self._count += 1
        started = time.monotonic()
        try:
            resp = await self._client.request(
                method, url, headers=identity.headers or None,
                cookies=identity.cookies or None, json=json_body,
            )
        except httpx.HTTPError as exc:
            self._record(purpose, method, url, identity.role, None,
                         int((time.monotonic() - started) * 1000),
                         note=type(exc).__name__)
            return LiveResponse(0, 0, int((time.monotonic() - started) * 1000),
                                "", "", error=f"{type(exc).__name__}: {exc}"[:200])
        self._record(purpose, method, url, identity.role, resp.status_code,
                     int((time.monotonic() - started) * 1000))
        # A redirect to another host is a scope boundary — report, don't follow.
        if resp.is_redirect:
            loc = resp.headers.get("location", "")
            if loc and not self.scope.permits(httpx.URL(resp.url).join(loc).__str__()):
                return LiveResponse(resp.status_code, 0,
                                    int((time.monotonic() - started) * 1000), "",
                                    "<redirect off-scope, not followed>")
        body = resp.content or b""
        snippet = ""
        if self._capture:
            snippet = body[:200].decode("utf-8", "replace")
        return LiveResponse(
            status=resp.status_code,
            length=len(body),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            body_hash=hashlib.sha256(body).hexdigest()[:16],
            body_snippet=snippet,
        )


async def smoke_test(base_url: str, scope: Scope,
                     identities: list[Identity]) -> dict:
    """Connectivity + credential smoke test. Sends ONE GET to the base URL per
    identity (and anonymous) and reports status — no scanning, no path probing.
    Scripted logins (login_form) are performed so their result is validated too.

    Confirms the target is reachable and the credentials are accepted at the
    transport level. It cannot prove authorization without a known-protected
    endpoint (that is what a full run does)."""
    from app.dast.login import perform_login

    results: list[dict] = []
    ok = True
    try:
        async with LiveClient(scope, max_rps=settings.dast_default_max_rps,
                              allow_mutating=False,
                              max_requests=len(identities) * 2 + 2) as client:
            # Resolve scripted logins before probing.
            for idx, ident in enumerate(identities):
                if ident.login_spec:
                    identities[idx] = await perform_login(
                        client, base_url, ident.role, ident.is_privileged, ident.login_spec)
            for ident in [Identity.anonymous(), *identities]:
                if not ident.usable and ident.role != "none":
                    results.append({"role": ident.role, "ok": False, "detail": ident.note})
                    ok = False
                    continue
                try:
                    r = await client.send("GET", base_url, ident)
                except ScopeError as exc:
                    return {"ok": False, "detail": str(exc), "roles": results}
                if r.error:
                    results.append({"role": ident.role, "ok": False, "detail": r.error})
                    ok = False
                else:
                    results.append({"role": ident.role, "ok": True,
                                    "detail": f"HTTP {r.status} · {r.length}B · {r.elapsed_ms}ms",
                                    "status": r.status,
                                    "headers_sent": list(redact_headers(ident.headers))})
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}", "roles": results}
    detail = "reachable · " + " · ".join(f"{r['role']}:{r['detail']}" for r in results)
    return {"ok": ok, "detail": detail, "roles": results}
