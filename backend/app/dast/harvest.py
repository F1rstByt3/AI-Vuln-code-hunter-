"""Object-id harvesting for IDOR testing.

IDOR confirmation needs a real object id owned by a *different* role than the
caller. Rather than fabricate ids (which risks poking at unintended objects),
we discover them: for each id-bearing endpoint, call its collection ("list")
endpoint as each role and read ids out of the JSON response. The result is a
seeds map ``{role: {param: [ids]}}`` merged with any operator-provided seeds
(operator seeds win).

Only GET list endpoints are used, so harvesting never changes state.
"""

from __future__ import annotations

import logging
import re

from app.dast.identity import Identity

log = logging.getLogger(__name__)

_ID_KEY_RE = re.compile(r"(^id$|_id$|Id$|^uuid$|^pk$|^slug$)")
_PARAM_SEG_RE = re.compile(r"\{[^}/]+\}|:[A-Za-z_]\w*|<[^>/]+>")


def collection_path(path: str) -> str | None:
    """The list path for an item path: drop the trailing id segment.
    /users/{id} -> /users ; /orgs/{oid}/members/{id} -> /orgs/{oid}/members"""
    segs = [s for s in (path or "").split("/") if s != ""]
    if not segs:
        return None
    if _PARAM_SEG_RE.search(segs[-1]):
        segs = segs[:-1]
    return "/" + "/".join(segs) if segs else "/"


def _ids_from(obj, depth: int = 0) -> list[str]:
    """Pull id-ish scalar values out of a JSON structure."""
    out: list[str] = []
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int)) and _ID_KEY_RE.search(str(k)):
                out.append(str(v))
            else:
                out.extend(_ids_from(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:50]:
            out.extend(_ids_from(item, depth + 1))
    return out


async def harvest_object_ids(client, base_url: str, endpoints: list[dict],
                             identities: list[Identity], *, per_role_cap: int = 20,
                             emit=None) -> dict:
    """Discover object ids per role and per collection.

    Returns ``{role: {collection_path: {param: [ids]}}}`` — keyed by collection
    so two endpoints that both use a param called ``id`` for different object
    types don't share an id pool (which would cross-wire IDOR probes)."""
    # Collection paths worth listing: those that have an id-param sibling.
    params_by_collection: dict[str, set[str]] = {}
    for e in endpoints:
        if not isinstance(e, dict) or not e.get("id_params"):
            continue
        coll = collection_path(e.get("path") or "")
        if coll and not _PARAM_SEG_RE.search(coll):   # a concrete list path
            params_by_collection.setdefault(coll, set()).update(e["id_params"])

    seeds: dict[str, dict[str, dict[str, list[str]]]] = {}
    for ident in identities:
        if not ident.usable:
            continue
        for coll, params in sorted(params_by_collection.items()):
            url = base_url.rstrip("/") + coll
            try:
                resp = await client.raw("GET", url, ident, purpose="harvest")
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code >= 300:
                continue
            try:
                ids = list(dict.fromkeys(_ids_from(resp.json())))[:per_role_cap]
            except Exception:  # noqa: BLE001
                continue
            if ids:
                seeds.setdefault(ident.role, {})[coll] = {p: ids for p in params}
    if emit and seeds:
        parts = []
        for role, colls in seeds.items():
            n = sum(len(next(iter(c.values()), [])) for c in colls.values())
            parts.append(f"{role}={n} across {len(colls)} collection(s)")
        await emit({"type": "log",
                    "message": "Harvested object ids for IDOR: " + ", ".join(parts)})
    return seeds


def endpoint_seeds(harvested: dict, operator: dict, collection: str | None) -> dict:
    """Resolve the ``{role: {param: [ids]}}`` usable for one endpoint.

    Endpoint-specific harvested ids win for that endpoint; operator-provided
    flat seeds (``{role: {param: [ids]}}`` on the target) act as a fallback and
    also seed roles/params nothing was harvested for. Operator seeds may also be
    nested per collection (``{role: {"/coll": {param: [ids]}}}``) to pin a
    specific endpoint; those take top precedence."""
    roles = set(harvested or {}) | set(operator or {})
    out: dict[str, dict[str, list[str]]] = {}
    for role in roles:
        op = (operator or {}).get(role, {}) or {}
        flat = {k: v for k, v in op.items() if not str(k).startswith("/")}
        op_nested = op.get(collection, {}) if isinstance(op.get(collection), dict) else {}
        harv = (harvested or {}).get(role, {}).get(collection, {}) if collection else {}
        merged = {**flat, **harv, **op_nested}
        if merged:
            out[role] = merged
    return out
