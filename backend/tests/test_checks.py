"""Verification, coverage and access-control passes (mock Foundry, no infra)."""

from __future__ import annotations

import asyncio

import pytest

from app.ai.agent import run_review
from app.ai.checks import annotate_agreement, check_evidence, unaddressed_candidates
from app.ai.foundry import MockFoundryClient, ModelRole, ReviewRoles
from app.scanners.access_control import analyze_endpoints
from app.scanners.endpoints import extract_endpoints

API_PY = '''\
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user = Depends(get_current_user)):
    return db.get(User, user_id)

@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    db.delete(User, user_id)

@router.get("/admin/stats")
async def admin_stats(current_user = Depends(get_current_user)):
    return stats()

@router.post("/login")
async def login(body: dict):
    return issue_token(body)

@router.get("/orders/{order_id}")
async def get_order(order_id: int, current_user = Depends(get_current_user)):
    return db.query(Order).filter(Order.id == order_id,
                                  Order.user_id == current_user.id).first()
'''

DB_PY = '''\
import sqlite3

def find(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE name = '" + name + "'")
    return cur.fetchall()
'''

UTIL_PY = '''\
import subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True)
'''


@pytest.fixture
def app_dir(tmp_path):
    (tmp_path / "api.py").write_text(API_PY)
    (tmp_path / "db.py").write_text(DB_PY)
    (tmp_path / "util.py").write_text(UTIL_PY)
    return tmp_path


def _reader(root):
    async def read_file(rel):
        p = root / rel
        return p.read_text() if p.is_file() else None
    return read_file


# ---------------------------------------------------------------- evidence
@pytest.mark.asyncio
async def test_evidence_check_verifies_relocates_and_rejects(app_dir):
    findings = [
        {"title": "SQLi", "file_path": "db.py", "line_start": 5, "state": "confirmed",
         "code_snippet": "cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"'\")"},
        {"title": "SQLi wrong line", "file_path": "db.py", "line_start": 40,
         "state": "confirmed", "code_snippet": "cur.execute(\"SELECT * FROM t"},
        {"title": "Ghost", "file_path": "nope/ghost.py", "line_start": 3,
         "state": "confirmed", "confidence": 0.9},
        {"title": "Paraphrased", "file_path": "db.py", "line_start": 4,
         "state": "confirmed", "confidence": 0.9,
         "code_snippet": "totally_different_code_that_is_not_there()"},
        {"title": "Wrong prefix", "file_path": "src/app/util.py", "line_start": 4,
         "code_snippet": "subprocess.run(cmd, shell=True)"},
    ]
    out, stats = await check_evidence(findings, _reader(app_dir),
                                      ["api.py", "db.py", "util.py"])
    by = {f["title"]: f for f in out}
    assert by["SQLi"]["evidence"]["status"] == "verified"
    assert by["SQLi wrong line"]["evidence"]["status"] == "relocated"
    assert by["SQLi wrong line"]["line_start"] == 5
    assert by["Ghost"]["evidence"]["status"] == "file_missing"
    assert by["Ghost"]["state"] == "dismissed"
    assert by["Paraphrased"]["evidence"]["status"] == "snippet_mismatch"
    assert by["Paraphrased"]["confidence"] <= 0.5
    assert by["Wrong prefix"]["file_path"] == "util.py"
    assert by["Wrong prefix"]["evidence"]["status"] == "verified"
    assert stats["file_missing"] == 1


def test_agreement_and_unaddressed():
    fs = [
        {"title": "SQL injection", "cwe": "CWE-89", "file_path": "a.py", "line_start": 10,
         "reviewed_by": "m1"},
        {"title": "SQLi in query", "cwe": "CWE-89", "file_path": "a.py", "line_start": 11,
         "reviewed_by": "m2"},
        {"title": "XSS", "cwe": "CWE-79", "file_path": "a.py", "line_start": 40,
         "reviewed_by": "m1"},
    ]
    annotate_agreement(fs, ["m1", "m2"])
    assert fs[0]["reviewer_agreement"] == {"count": 2, "of": 2}
    assert fs[2]["reviewer_agreement"] == {"count": 1, "of": 2}

    cands = [{"file_path": "a.py", "line_start": 12}, {"file_path": "b.py", "line_start": 3}]
    left = unaddressed_candidates(cands, fs)
    assert left == [{"file_path": "b.py", "line_start": 3}]


# ---------------------------------------------------------------- access map
@pytest.mark.asyncio
async def test_access_map_flags_real_gaps(app_dir):
    eps = await extract_endpoints(str(app_dir))
    amap = await analyze_endpoints(eps, str(app_dir))
    by = {(e["method"], e["path"]): e for e in amap["endpoints"]}

    assert by[("GET", "/users/{user_id}")]["auth_scope"] == "route"
    # The previous handler's Depends(get_current_user) must not leak into this one.
    assert by[("DELETE", "/users/{user_id}")]["auth_scope"] == "none"
    assert by[("POST", "/login")]["likely_public"] is True
    assert by[("GET", "/orders/{order_id}")]["ownership_hints"]

    rules = {(c["rule"], c["endpoint"]) for c in amap["candidates"]}
    assert ("access.inconsistent-authn", "DELETE /users/{user_id}") in rules
    assert ("access.privileged-no-role", "GET /admin/stats") in rules
    assert ("access.idor", "GET /users/{user_id}") in rules
    assert not any(ep == "GET /orders/{order_id}" for _, ep in rules)
    assert not any(ep == "POST /login" for _, ep in rules)
    assert all(c["source"] == "access" for c in amap["candidates"])


# ---------------------------------------------------------------- pipeline
@pytest.mark.asyncio
async def test_full_pipeline_with_all_checks(app_dir):
    eps = await extract_endpoints(str(app_dir))
    amap = await analyze_endpoints(eps, str(app_dir))
    candidates = [
        # Addressed by the (mock) reviewer — it echoes every candidate it's given.
        {"source": "semgrep", "title": "SQL injection", "message": "tainted query",
         "severity": "high", "cwe": "CWE-89", "file_path": "db.py", "line_start": 5,
         "code_snippet": "cur.execute("},
    ]
    files = [{"path": p, "language": "python"} for p in ("api.py", "db.py", "util.py")]
    emitted: list[dict] = []
    phases: list[str] = []

    async def emit(event):
        emitted.append(event)

    async def on_findings(phase, batch):
        phases.append(phase)

    roles = ReviewRoles(chat=ModelRole("gpt-4o"),
                        reviewers=[ModelRole("rev-a"), ModelRole("rev-b")],
                        judge=ModelRole("judge"), exploit=ModelRole("exploit"),
                        verifier=ModelRole("verifier"))
    result = await run_review(
        client=MockFoundryClient(), roles=roles, instructions=None, files=files,
        candidates=candidates, read_file=_reader(app_dir), emit=emit,
        on_findings=on_findings, access_map=amap,
    )
    findings = result["findings"]
    cov = result["summary"]["coverage"]

    # Every stage reported, including the new ones.
    stages = {e["stage"] for e in emitted if e["type"] == "stage"}
    assert {"ai_review", "ai_coverage", "ai_access", "ai_judge", "ai_verify",
            "ai_exploit"} <= stages

    # Coverage report is complete and reviewer agreement was measured.
    assert cov["files_loaded"] == 3 and cov["files_unreviewed"] == 0
    assert cov["static_candidates"] == 1 and cov["candidates_addressed_by_review"] == 1
    assert "evidence" in cov and cov["reviewer_agreement"]
    # util.py has a shell=True sink and no findings → it got a second look.
    assert cov["second_look_files"] >= 1

    # Access control: endpoint matrix + access findings flowed through judge/verify.
    assert result["endpoints"] and all("authn" in e for e in result["endpoints"])
    assert cov["endpoints"]["assessed"] == len(result["endpoints"])
    access = [f for f in findings if f["source"] == "access"]
    assert access and all(f["endpoint"] for f in access)
    assert "access" in phases

    # Verifier ran and its verdicts are recorded on findings.
    assert cov["verification"]["eligible"] > 0
    assert any((f.get("verification") or {}).get("verdict") == "true_positive"
               for f in findings)
    assert result["summary"]["models"]["verifier"] == "verifier"


@pytest.mark.asyncio
async def test_checks_can_be_disabled(app_dir):
    files = [{"path": "db.py", "language": "python"}]
    emitted: list[dict] = []

    async def emit(event):
        emitted.append(event)

    result = await run_review(
        client=MockFoundryClient(),
        roles=ReviewRoles(chat=ModelRole("c"), reviewers=[ModelRole("r")], judge=None),
        instructions=None, files=files, candidates=[], read_file=_reader(app_dir),
        emit=emit, checks={"coverage": False, "verify": False, "access_control": False},
    )
    skipped = {e["stage"] for e in emitted
               if e["type"] == "stage" and e["state"] == "skipped"}
    assert {"ai_coverage", "ai_access", "ai_verify"} <= skipped
    assert "verification" not in result["summary"]["coverage"]


NEST_TS = '''\
import { Controller, Get, Delete, UseGuards } from '@nestjs/common';

@UseGuards(JwtAuthGuard)
@Controller('users')
export class UsersController {
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.users.findById(id);
  }
}

@Controller('reports')
export class ReportsController {
  @Delete(':reportId')
  async remove(@Param('reportId') reportId: string) {
    return this.reports.delete(reportId);
  }
}
'''

FASTIFY_JS = '''\
fastify.get('/health', async () => ({ ok: true }));
fastify.route({
  method: 'POST',
  url: '/jobs/:jobId/run',
  handler: runJob,
});
'''


@pytest.mark.asyncio
async def test_nestjs_and_fastify_routes(tmp_path):
    (tmp_path / "users.controller.ts").write_text(NEST_TS)
    (tmp_path / "server.mjs").write_text(FASTIFY_JS)
    eps = await extract_endpoints(str(tmp_path))
    got = {(e["framework"], e["method"], e["path"]) for e in eps}
    assert ("nestjs", "GET", "/users/:id") in got
    assert ("nestjs", "DELETE", "/reports/:reportId") in got
    assert ("fastify", "GET", "/health") in got
    assert ("fastify", "POST", "/jobs/:jobId/run") in got

    amap = await analyze_endpoints(eps, str(tmp_path))
    by = {e["path"]: e for e in amap["endpoints"]}
    assert by["/users/:id"]["auth_scope"] == "file"        # class-level @UseGuards
    assert by["/users/:id"]["handler"] == "findOne"
    assert by["/reports/:reportId"]["auth_scope"] == "none"
    assert by["/health"]["likely_public"]


class _GarbageClient(MockFoundryClient):
    """A model that never produces the requested JSON (e.g. too small / truncated)."""

    async def complete_json(self, messages, **kw):
        return {}


@pytest.mark.asyncio
async def test_unparseable_model_output_fails_fast_instead_of_zero_findings(app_dir):
    saved: list[str] = []

    async def save_chunk(phase, key, items):
        saved.append(key)

    async def emit(_e):
        pass

    with pytest.raises(RuntimeError, match="Every review batch failed"):
        await run_review(
            client=_GarbageClient(),
            roles=ReviewRoles(chat=ModelRole("c"), reviewers=[ModelRole("r")], judge=None),
            instructions=None, files=[{"path": "db.py"}], candidates=[],
            read_file=_reader(app_dir), emit=emit, save_chunk=save_chunk,
        )
    assert saved == []  # garbage batches must not be checkpointed as "done"


@pytest.mark.asyncio
async def test_circuit_breaker_stops_after_first_failing_batches(app_dir):
    calls = {"n": 0}

    class _Counting(_GarbageClient):
        async def complete_json(self, messages, **kw):
            calls["n"] += 1
            await asyncio.sleep(0.01)  # like a real network call: yields control
            return {}

    files = [{"path": f"f{i}.py"} for i in range(40)]

    async def read_file(path):
        return "value = compute(1)\n" * 400

    async def emit(_e):
        pass

    roles = ReviewRoles(chat=ModelRole("c"), reviewers=[ModelRole("r")], judge=None,
                        context_tokens=2_500, concurrency=1)
    with pytest.raises(RuntimeError, match="Stopped early"):
        await run_review(client=_Counting(), roles=roles, instructions=None, files=files,
                         candidates=[], read_file=read_file, emit=emit)
    assert calls["n"] <= 12  # stopped after ~8 batches, not all 40 + retries


def test_parse_json_ignores_visible_reasoning():
    from app.ai.foundry import _parse_json
    out = _parse_json('<think>maybe {"findings": 1}? let me check {x}</think>\n'
                      '{"findings": [{"title": "SQLi"}]}')
    assert out == {"findings": [{"title": "SQLi"}]}
    assert _parse_json('reasoning {a} </think> {"findings": []}') == {"findings": []}
