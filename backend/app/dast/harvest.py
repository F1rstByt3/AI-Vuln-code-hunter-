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
    """Return {role_label: {param: [ids]}} discovered from list endpoints."""
    # Collection paths worth listing: those that have an id-param sibling.
    collections: set[str] = set()
    params_by_collection: dict[str, set[str]] = {}
    for e in endpoints:
        if not isinstance(e, dict) or not (e.get("id_params")):
            continue
        coll = collection_path(e.get("path") or "")
        if coll and not _PARAM_SEG_RE.search(coll):   # a concrete list path
            collections.add(coll)
            params_by_collection.setdefault(coll, set()).update(e["id_params"])

    seeds: dict[str, dict[str, list[str]]] = {}
    for ident in identities:
        if not ident.usable:
            continue
        found: list[str] = []
        for coll in sorted(collections):
            if len(found) >= per_role_cap:
                break
            url = base_url.rstrip("/") + coll
            try:
                resp = await client.raw("GET", url, ident)
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code >= 300:
                continue
            try:
                found.extend(_ids_from(resp.json()))
            except Exception:  # noqa: BLE001
                continue
        uniq = list(dict.fromkeys(found))[:per_role_cap]
        if uniq:
            # Map the same id pool to every id-param name (best-effort).
            all_params = {p for ps in params_by_collection.values() for p in ps}
            seeds[ident.role] = {p: uniq for p in all_params}
    if emit and seeds:
        await emit({"type": "log", "message":
                    "Harvested object ids for IDOR: "
                    + ", ".join(f"{r}={sum(len(v) for v in d.values()) // max(1, len(d))}"
                                for r, d in seeds.items())})
    return seeds


def merge_seeds(operator: dict, harvested: dict) -> dict:
    """Operator-provided seeds take precedence over harvested ones."""
    out = {r: dict(v) for r, v in (harvested or {}).items()}
    for role, params in (operator or {}).items():
        out.setdefault(role, {})
        for param, ids in (params or {}).items():
            out[role][param] = ids
    return out
