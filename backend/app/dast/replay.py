"""Access-control confirmation: replay one endpoint under several identities
and decide whether a finding is real.

This is the precision core. Given an ``access`` finding and the endpoint it
refers to, it sends the request as the anonymous baseline and as each configured
role, then compares outcomes to reach one of:

  confirmed_vuln  — the access control the finding predicted is genuinely missing
  enforced        — the app correctly blocks it (the finding is a false positive)
  inconclusive    — not enough signal (e.g. IDOR with no sample object to test)

It only ever performs the minimum benign action needed to show access: for
IDOR it *reads* another user's object, it does not modify it.
"""

from __future__ import annotations

import re

from app.dast.client import LiveClient, LiveResponse
from app.dast.identity import Identity, redact_headers

_PARAM_RE = re.compile(r"\{([^}/]+)\}")

# Finding rule / CWE → which probe to run.
_MISSING_AUTHN = {"access.missing-authn", "access.inconsistent-authn", "CWE-306"}
_BFLA = {"access.privileged-no-role", "access.inconsistent-authz", "CWE-285", "CWE-862"}
_IDOR = {"access.idor", "CWE-639"}


def classify(finding: dict) -> str | None:
    rule = (finding.get("rule") or (finding.get("raw") or {}).get("rule") or "")
    cwe = (finding.get("cwe") or "").split(":")[0].strip()
    keys = {rule, cwe}
    if keys & _MISSING_AUTHN:
        return "missing_authn"
    if keys & _IDOR:
        return "idor"
    if keys & _BFLA:
        return "bfla"
    return None


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _is_denied(status: int) -> bool:
    return status in (401, 403)


def fill_path(path: str, values: dict[str, str] | None) -> str:
    """Replace {param} placeholders with concrete values (default '1')."""
    values = values or {}

    def sub(m):
        return str(values.get(m.group(1), "1"))

    p = _PARAM_RE.sub(sub, path or "/")
    return p if p.startswith("/") else "/" + p


def _ev(role: str, r: LiveResponse, ident: Identity | None = None) -> dict:
    e = {"role": role, "status": r.status, "length": r.length, "ms": r.elapsed_ms}
    if r.error:
        e["error"] = r.error
    if ident is not None:
        e["headers_sent"] = list(redact_headers(ident.headers))
    return e


async def probe_missing_authn(client: LiveClient, url: str, method: str) -> tuple[str, dict]:
    """Confirmed if the anonymous request succeeds; enforced if denied."""
    anon = await client.send(method, url, Identity.anonymous())
    ev = {"requests": [_ev("none", anon)], "url": url, "method": method}
    if anon.error:
        return "inconclusive", {**ev, "reason": anon.error}
    if _is_success(anon.status):
        return "confirmed_vuln", {**ev,
            "reason": f"anonymous {method} {url} returned {anon.status} "
                      f"(expected 401/403)"}
    if _is_denied(anon.status):
        return "enforced", {**ev, "reason": f"anonymous request denied ({anon.status})"}
    return "inconclusive", {**ev, "reason": f"ambiguous status {anon.status}"}


async def probe_bfla(client: LiveClient, url: str, method: str,
                     low: list[Identity], priv: list[Identity]) -> tuple[str, dict]:
    """Confirmed if a low-privilege role succeeds on a privileged route."""
    if not low:
        return "inconclusive", {"reason": "no low-privilege role configured",
                                "url": url, "method": method}
    reqs = []
    confirmed = False
    for ident in low:
        r = await client.send(method, url, ident)
        reqs.append(_ev(ident.role, r, ident))
        if not r.error and _is_success(r.status):
            confirmed = True
    ev = {"requests": reqs, "url": url, "method": method}
    if confirmed:
        return "confirmed_vuln", {**ev,
            "reason": "a low-privilege role reached a privileged route (2xx)"}
    if any(_is_denied(x.get("status", 0)) for x in reqs):
        return "enforced", {**ev, "reason": "low-privilege role denied (401/403)"}
    return "inconclusive", {**ev, "reason": "no clear allow/deny signal"}


async def probe_idor(client: LiveClient, path: str, method: str, base_url: str,
                     id_params: list[str], seeds: dict, actors: list[Identity],
                     ) -> tuple[str, dict]:
    """Confirmed if one user can read another user's object by id.

    Needs a sample object id owned by a *different* role than the caller. Without
    seeds we cannot safely pick ids, so we report inconclusive rather than guess.
    """
    # seeds: {role_label: {param: [ids]}}
    owners = {r: v for r, v in (seeds or {}).items() if v}
    if not owners or len(actors) < 1:
        return "inconclusive", {"url": base_url + path, "method": method,
            "reason": "no sample object ids provided (set object_seeds to test IDOR)"}
    reqs = []
    for actor in actors:
        for owner_role, pmap in owners.items():
            if owner_role == actor.role:
                continue  # need someone else's object
            values = {p: (pmap.get(p) or ["1"])[0] for p in id_params}
            if not any(p in pmap for p in id_params):
                continue
            url = base_url + fill_path(path, values)
            r = await client.send(method, url, actor)
            reqs.append({**_ev(actor.role, r, actor), "owner": owner_role,
                         "target": url})
            if not r.error and _is_success(r.status):
                return "confirmed_vuln", {"requests": reqs, "method": method,
                    "reason": f"{actor.role} read {owner_role}'s object ({r.status})"}
    if not reqs:
        return "inconclusive", {"method": method,
            "reason": "no cross-user object id pair available"}
    if all(_is_denied(x.get("status", 0)) for x in reqs):
        return "enforced", {"requests": reqs, "method": method,
            "reason": "cross-user object access denied (401/403)"}
    return "inconclusive", {"requests": reqs, "method": method,
        "reason": "no successful cross-user access, but not a clean denial"}
