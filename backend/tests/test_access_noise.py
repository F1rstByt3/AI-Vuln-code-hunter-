"""Access-control noise reduction: UUID-aware IDOR, systemic 'auth not located'
collapse, and an explicit AI verdict for every heuristic flag."""

from __future__ import annotations

import json

import pytest

from app.ai.checks import run_access_review
from app.ai.foundry import ModelRole
from app.scanners.access_control import _heuristic_findings


def _ep(i: int, method: str, path: str, **kw) -> dict:
    base = {
        "id": f"e{i}", "method": method, "path": path, "auth_scope": "route",
        "route_auth": [], "file_auth": [], "public_markers": [], "role_hints": [],
        "ownership_hints": [], "id_params": [], "id_kind": None,
        "state_changing": method in ("POST", "PUT", "PATCH", "DELETE"),
        "sensitive": False, "privileged": False, "likely_public": False,
        "resource": path.rsplit("/", 1)[0] or "/", "handler_file": "app.py",
        "handler_line": i + 1, "file_path": "app.py", "line": i + 1,
        "handler_source": f"def h{i}():",
    }
    base.update(kw)
    return base


def test_uuid_read_routes_not_flagged_and_numeric_ones_are():
    eps = [
        _ep(0, "GET", "/docs/{id}", id_params=["id"], id_kind="uuid"),
        _ep(1, "DELETE", "/docs/{id}", id_params=["id"], id_kind="uuid"),
        _ep(2, "GET", "/orders/{id}", id_params=["id"], id_kind="numeric"),
    ]
    out = {f["endpoint"]: f for f in _heuristic_findings(eps, False)}
    assert "GET /docs/{id}" not in out                    # unguessable, read-only
    assert out["DELETE /docs/{id}"]["severity"] == "low"  # unguessable write: low
    assert out["GET /orders/{id}"]["severity"] == "medium"
    assert "enumerable" in out["GET /orders/{id}"]["description"]
    assert all(f["flag_id"].startswith("h") for f in out.values())


def test_systemic_unlocated_auth_collapses_to_one_finding():
    eps = [_ep(i, "POST", f"/things{i}", auth_scope="none", sensitive=True)
           for i in range(30)]
    eps.append(_ep(30, "POST", "/legacy", auth_scope="public",
                   public_markers=["AllowAnonymous"], sensitive=True))
    out = _heuristic_findings(eps, False)
    rules = [f["rule"] for f in out]
    assert rules.count("access.auth-not-located") == 1
    # Per-route 'missing authn' only for the explicit opt-out, not all 30.
    assert rules.count("access.missing-authn") == 1
    sysf = next(f for f in out if f["rule"] == "access.auth-not-located")
    assert sysf["state"] == "needs_info" and len(sysf["affected_endpoints"]) == 30


class _Model:
    """Endpoint review answers flags h0/h1; leaves h2 for focused triage."""

    def __init__(self):
        self.calls: list[str] = []

    async def complete_json(self, messages, **kw):
        user = messages[-1]["content"]
        if "<<ACCESS_JSON>>" in user:
            self.calls.append("access")
            payload = json.loads(user.split("<<ACCESS_JSON>>")[1].split("<<END>>")[0])
            return {
                "endpoints": [{"id": e["id"], "authn": "unclear", "authz": "unclear",
                               "risk": "medium"} for e in payload["endpoints"]],
                "flags": [{"flag_id": "h0", "verdict": "rejected",
                           "reason": "ownership enforced by OrderPolicy"},
                          {"flag_id": "h1", "verdict": "confirmed",
                           "reason": "line 3 loads by id with no owner filter",
                           "severity": "high"}],
                "findings": [],
            }
        self.calls.append("triage")
        payload = json.loads(user.split("<<FLAGS_JSON>>")[1].split("<<END>>")[0])
        return {"flags": [{"flag_id": f["flag_id"], "verdict": "uncertain",
                           "reason": "May support staff view any ticket?"}
                          for f in payload["flags"]]}


@pytest.mark.asyncio
async def test_every_flag_gets_an_explicit_verdict():
    eps = [_ep(0, "GET", "/orders/{id}"), _ep(1, "GET", "/invoices/{id}"),
           _ep(2, "GET", "/tickets/{id}")]
    flags = [
        {"flag_id": f"h{i}", "endpoint_id": f"e{i}", "endpoint": f"GET {e['path']}",
         "rule": "access.idor", "title": f"Possible IDOR {i}", "severity": "medium",
         "confidence": 0.3, "cwe": "CWE-639", "source": "access", "state": "proposed",
         "file_path": "app.py", "line_start": i + 1, "description": "x"}
        for i, e in enumerate(eps)]
    model = _Model()
    saved: dict = {}

    async def noop(*_a, **_k):
        return None

    async def load_chunks(_phase):
        return {}

    async def save_chunk(_phase, key, items):
        saved[key] = items

    async def read_file(_p):
        return "def h():\n    return Order.get(id)\n    pass\n"

    findings, endpoints, stats = await run_access_review(
        client=model, role=ModelRole("r"),
        access_map={"endpoints": eps, "candidates": flags, "global_auth": []},
        read_file=read_file, emit=noop, stage=noop, checkpoint=noop,
        load_chunks=load_chunks, save_chunk=save_chunk, on_findings=noop, concurrency=1)

    by_flag = {f["flag_id"]: f for f in findings}
    assert "h0" not in by_flag                                  # rejected → dropped
    assert by_flag["h1"]["ai_verdict"] == "confirmed"
    assert by_flag["h1"]["severity"] == "high" and by_flag["h1"]["confidence"] >= 0.65
    assert by_flag["h2"]["state"] == "needs_info"               # via focused triage
    assert "support staff" in by_flag["h2"]["human_question"]
    assert model.calls.count("triage") == 1
    assert stats["flags_rejected"] == 1 and stats["flags_confirmed"] == 1
    assert stats["flags_uncertain"] == 1 and stats["flags_unverified"] == 0
    assert stats["rejected_flags"][0]["reason"].startswith("ownership")
    assert any(k.startswith("t") for k in saved)                # triage is resumable
