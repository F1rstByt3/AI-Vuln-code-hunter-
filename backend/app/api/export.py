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
        detail_parts: list[str] = []
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

        sarif_result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.description or f.title},
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "state": f.state.value,
                "source": f.source.value,
            },
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
        })

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_findings.csv"'},
    )
