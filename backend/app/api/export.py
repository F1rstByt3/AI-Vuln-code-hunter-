"""Export endpoints for scan results in various formats."""

from __future__ import annotations

import csv
import io
import json
import hashlib
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, tostring

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.db import get_session
from app.models import Finding, FindingState, Scan, Severity

router = APIRouter(tags=["export"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_TO_BURP = {
    Severity.critical: "High",
    Severity.high: "High",
    Severity.medium: "Medium",
    Severity.low: "Low",
    Severity.info: "Information",
}

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}


def _burp_confidence(confidence: float) -> str:
    if confidence > 0.8:
        return "Certain"
    if confidence > 0.5:
        return "Firm"
    return "Tentative"


def _cdata(text: str | None) -> str:
    return text or ""


# ---------------------------------------------------------------------------
# 1. Burp Suite XML
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/export/burp")
async def export_burp(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> Response:
    scan = await get_or_404(session, Scan, scan_id)

    result = await session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .where(Finding.state != FindingState.dismissed)
    )
    findings = result.scalars().all()

    root = Element("issues")
    root.set("burpVersion", "2024.0")
    root.set("exportTime", datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Z %Y"))

    for idx, f in enumerate(findings, start=1):
        issue = SubElement(root, "issue")

        serial = SubElement(issue, "serialNumber")
        serial.text = str(int(hashlib.md5(f.id.encode()).hexdigest()[:12], 16))

        type_el = SubElement(issue, "type")
        type_el.text = f.cwe or "134217728"

        name = SubElement(issue, "name")
        name.text = f.title

        host = SubElement(issue, "host")
        host.set("ip", "")
        host.text = "target"

        path = SubElement(issue, "path")
        path.text = f.file_path or "/"

        location = SubElement(issue, "location")
        loc_parts = []
        if f.file_path:
            loc_parts.append(f.file_path)
        if f.line_start is not None:
            loc_parts.append(str(f.line_start))
        location.text = ":".join(loc_parts) if loc_parts else "/"

        severity = SubElement(issue, "severity")
        severity.text = _SEVERITY_TO_BURP.get(f.severity, "Information")

        confidence = SubElement(issue, "confidence")
        confidence.text = _burp_confidence(f.confidence)

        bg = SubElement(issue, "issueBackground")
        bg.text = _cdata(f.description)

        rem = SubElement(issue, "remediationBackground")
        rem.text = _cdata(f.remediation)

        detail = SubElement(issue, "issueDetail")
        raw = f.raw or {}
        detail_parts: list[str] = []
        if raw.get("where_to_look"):
            detail_parts.append(f"Where to look:\n{raw['where_to_look']}")
        if raw.get("attack_scenario"):
            detail_parts.append(f"Attack scenario:\n{raw['attack_scenario']}")
        if raw.get("proof_of_concept"):
            detail_parts.append(f"Proof of concept:\n{raw['proof_of_concept']}")
        if raw.get("risk"):
            detail_parts.append(f"Risk:\n{raw['risk']}")
        if f.code_snippet:
            detail_parts.append(f"Code:\n{f.code_snippet}")
        if f.cwe:
            detail_parts.append(f"CWE: {f.cwe}")
        if f.owasp:
            detail_parts.append(f"OWASP: {f.owasp}")
        detail.text = "\n\n".join(detail_parts)

    xml_bytes = b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(root, encoding="unicode").encode("utf-8")

    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_burp.xml"'},
    )


# ---------------------------------------------------------------------------
# 2. Endpoint URL list
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/export/endpoints")
async def export_endpoints(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> Response:
    scan = await get_or_404(session, Scan, scan_id)

    raw_endpoints: list = (scan.summary or {}).get("endpoints", [])
    lines: list[str] = []
    for ep in raw_endpoints:
        if isinstance(ep, dict):
            lines.append(f"{ep.get('method', 'ANY')} {ep.get('path', '/')}")
        else:
            lines.append(str(ep))
    body = "\n".join(lines) + ("\n" if lines else "")

    return Response(
        content=body,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_endpoints.txt"'},
    )


@router.get("/scans/{scan_id}/export/access-matrix")
async def export_access_matrix(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Endpoint authorization matrix (who can call what) as CSV."""
    import csv
    import io

    scan = await get_or_404(session, Scan, scan_id)
    cols = ["method", "path", "authn", "authz", "risk", "auth_scope", "heuristic_risk",
            "file_path", "line", "handler", "handler_file", "handler_line", "notes",
            "route_auth", "file_auth", "role_hints", "ownership_hints"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for ep in (scan.summary or {}).get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        w.writerow(["; ".join(map(str, ep.get(c) or [])) if isinstance(ep.get(c), list)
                    else ("" if ep.get(c) is None else ep.get(c)) for c in cols])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="scan_{scan_id}_access_matrix.csv"'},
    )


# ---------------------------------------------------------------------------
# 3. SARIF 2.1.0
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/export/sarif")
async def export_sarif(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> Response:
    scan = await get_or_404(session, Scan, scan_id)

    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()

    # Build rules index
    rules: list[dict] = []
    rule_ids_seen: dict[str, int] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f.cwe if f.cwe else f.title.lower().replace(" ", "-")

        if rule_id not in rule_ids_seen:
            rule_ids_seen[rule_id] = len(rules)
            rule_entry: dict = {
                "id": rule_id,
                "shortDescription": {"text": f.title},
            }
            if f.description:
                rule_entry["fullDescription"] = {"text": f.description}
            if f.remediation:
                rule_entry["help"] = {"text": f.remediation, "markdown": f.remediation}
            rules.append(rule_entry)

        rule_index = rule_ids_seen[rule_id]

        # Build location
        location: dict = {}
        if f.file_path:
            physical: dict = {
                "artifactLocation": {"uri": f.file_path},
            }
            if f.line_start is not None:
                region: dict = {"startLine": f.line_start}
                if f.line_end is not None:
                    region["endLine"] = f.line_end
                physical["region"] = region
            location["physicalLocation"] = physical

        raw = f.raw or {}
        props: dict = {
            "severity": f.severity.value,
            "confidence": f.confidence,
            "state": f.state.value,
            "source": f.source.value,
        }
        for k in ("where_to_look", "attack_scenario", "proof_of_concept",
                  "risk", "recommendation"):
            if raw.get(k):
                props[k] = raw[k]

        sarif_result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.description or f.title},
            "properties": props,
        }
        if location:
            sarif_result["locations"] = [location]

        results.append(sarif_result)

    sarif: dict = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Vuln-Code-Hunter",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return Response(
        content=json.dumps(sarif, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.sarif.json"'},
    )


# ---------------------------------------------------------------------------
# 4. CSV
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "title", "severity", "confidence", "state", "source",
    "cwe", "owasp", "category", "file_path", "line_start", "line_end",
    "description", "remediation", "code_snippet",
    "where_to_look", "attack_scenario", "proof_of_concept", "risk", "recommendation",
]


@router.get("/scans/{scan_id}/export/csv")
async def export_csv(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> Response:
    scan = await get_or_404(session, Scan, scan_id)

    result = await session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .where(Finding.state != FindingState.dismissed)
    )
    findings = result.scalars().all()

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()

    for f in findings:
        raw = f.raw or {}
        writer.writerow({
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "state": f.state.value,
            "source": f.source.value,
            "cwe": f.cwe or "",
            "owasp": f.owasp or "",
            "category": f.category or "",
            "file_path": f.file_path or "",
            "line_start": f.line_start if f.line_start is not None else "",
            "line_end": f.line_end if f.line_end is not None else "",
            "description": f.description,
            "remediation": f.remediation or "",
            "code_snippet": f.code_snippet or "",
            "where_to_look": raw.get("where_to_look") or "",
            "attack_scenario": raw.get("attack_scenario") or "",
            "proof_of_concept": raw.get("proof_of_concept") or "",
            "risk": raw.get("risk") or "",
            "recommendation": raw.get("recommendation") or "",
        })

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_findings.csv"'},
    )


# ---------------------------------------------------------------------------
# OpenAPI spec for Burp (broken-access-control testing)
# ---------------------------------------------------------------------------

_OAS_PARAM_RE = None  # compiled lazily (keeps import-time cost off other exports)
_ANY_METHODS = ("get", "post")  # "ANY" routes: the two methods worth probing first
_RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def _oas_path(path: str) -> tuple[str, list[str]]:
    """Normalise framework route syntax to an OpenAPI template:
    :id / <int:pk> / [id] / {id:int} / (?P<id>...) → {id}."""
    import re

    global _OAS_PARAM_RE
    if _OAS_PARAM_RE is None:
        _OAS_PARAM_RE = re.compile(
            r"\{([A-Za-z_]\w*)(?::[^}]*)?\}|:([A-Za-z_]\w*)"
            r"|<(?:\w+:)?([A-Za-z_]\w*)>|\[\.{0,3}([A-Za-z_]\w*)\]|\(\?P<([A-Za-z_]\w*)>[^)]*\)")
    names: list[str] = []

    def sub(m):
        name = next(g for g in m.groups() if g)
        names.append(name)
        return "{" + name + "}"

    p = _OAS_PARAM_RE.sub(sub, path or "/")
    p = p.replace("^", "").replace("$", "")
    if not p.startswith("/"):
        p = "/" + p
    return p, list(dict.fromkeys(names))


def _bac_tests(ep: dict) -> list[str]:
    """What a tester should try on this endpoint for broken access control."""
    tests = []
    authn = ep.get("authn") or ep.get("auth_scope")
    if authn not in ("public",) and not ep.get("likely_public"):
        tests.append("Replay with NO session/token — expect 401/403 (missing authentication).")
    if ep.get("id_params"):
        ids = ", ".join(ep["id_params"])
        tests.append(f"As user A, request user B's object ({ids}) — expect 403/404 (IDOR/BOLA).")
    if ep.get("privileged") or ep.get("authz") in ("none", "unclear"):
        tests.append("Replay with a low-privilege user's session — expect 403 "
                     "(missing function-level authorization).")
    if ep.get("state_changing"):
        tests.append("Add privileged fields to the body (role, is_admin, owner_id, "
                     "tenant_id) — expect them ignored (mass assignment).")
    return tests


@router.get("/scans/{scan_id}/export/openapi")
async def export_openapi(
    scan_id: str,
    base_url: str = "https://target.example",
    min_risk: str = "low",
    session: AsyncSession = Depends(get_session),
) -> Response:
    """OpenAPI 3 spec of the scan's endpoints, annotated for access-control
    testing. Import into Burp (API scan / OpenAPI Parser), Postman, etc.
    Each operation carries x-access (AI/heuristic verdict), related findings,
    and concrete BAC test steps; tags group operations by risk."""
    scan = await get_or_404(session, Scan, scan_id)
    endpoints = [e for e in (scan.summary or {}).get("endpoints", []) if isinstance(e, dict)]
    cutoff = _RISK_ORDER.get(min_risk, 2)
    findings = (await session.execute(
        select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    by_endpoint: dict[str, list[str]] = {}
    for f in findings:
        label = (f.raw or {}).get("endpoint")
        if label and f.state != FindingState.dismissed:
            by_endpoint.setdefault(" ".join(label.upper().split()), []).append(
                f"[{f.severity.value}] {f.title}")

    paths: dict[str, dict] = {}
    for ep in sorted(endpoints, key=lambda e: _RISK_ORDER.get(
            e.get("risk") or e.get("heuristic_risk") or "low", 2)):
        risk = ep.get("risk") or ep.get("heuristic_risk") or "low"
        if _RISK_ORDER.get(risk, 2) > cutoff:
            continue
        path, params = _oas_path(ep.get("path") or "/")
        method = (ep.get("method") or "ANY").upper()
        methods = _ANY_METHODS if method in ("ANY", "ALL") else (method.lower(),)
        related = by_endpoint.get(f"{method} {ep.get('path')}".upper(), [])
        tests = _bac_tests(ep)
        public = (ep.get("authn") == "public") or (
            not ep.get("authn") and ep.get("auth_scope") in ("none", "public"))
        desc = "\n".join(
            [f"Handler: {ep.get('handler_file') or ep.get('file_path')}:"
             f"{ep.get('handler_line') or ep.get('line')} ({ep.get('framework')})",
             f"Auth: authn={ep.get('authn') or ep.get('auth_scope')} "
             f"authz={ep.get('authz') or 'unassessed'} risk={risk}"]
            + ([f"Notes: {ep['notes']}"] if ep.get("notes") else [])
            + (["Related findings:"] + [f"- {r}" for r in related] if related else [])
            + (["BAC tests:"] + [f"- {t}" for t in tests] if tests else []))
        for m in methods:
            op = {
                "operationId": f"{m}_{ep.get('id') or len(paths)}",
                "summary": f"[{risk.upper()}] {ep.get('handler') or path}",
                "description": desc,
                "tags": [f"risk-{risk}"] + (["has-findings"] if related else []),
                "parameters": [
                    {"name": n, "in": "path", "required": True,
                     "schema": {"type": "string"}, "example": "1"} for n in params],
                "responses": {"200": {"description": "OK"},
                              "401": {"description": "Unauthenticated"},
                              "403": {"description": "Forbidden"}},
                "security": [] if public else [{"bearerAuth": []}, {"cookieAuth": []}],
                "x-access": {k: ep.get(k) for k in (
                    "authn", "authz", "risk", "auth_scope", "heuristic_risk", "role_hints",
                    "ownership_hints", "id_params", "privileged", "state_changing")
                    if ep.get(k) not in (None, [], "")},
                "x-bac-tests": tests,
            }
            if m in ("post", "put", "patch"):
                op["requestBody"] = {"required": False, "content": {
                    "application/json": {"schema": {"type": "object"}, "example": {}}}}
            paths.setdefault(path, {})[m] = op

    spec = {
        "openapi": "3.0.3",
        "info": {"title": f"AI Vuln Code Hunter — scan {scan_id[:8]} endpoints",
                 "version": "1.0",
                 "description": "Generated from source-code analysis for broken "
                                "access control testing. Operations are tagged by "
                                "risk; see x-bac-tests on each."},
        "servers": [{"url": base_url.rstrip("/")}],
        "tags": [{"name": f"risk-{r}"} for r in ("high", "medium", "low")]
                + [{"name": "has-findings"}],
        "paths": paths,
        "components": {"securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session"}}},
    }
    return Response(
        content=json.dumps(spec, indent=2),
        media_type="application/json",
        headers={"Content-Disposition":
                 f'attachment; filename="scan_{scan_id}_openapi.json"'},
    )
