"""Scan-to-scan diff — track remediation over time.

Compares a scan's findings against an earlier scan's and classifies each issue
as **new**, **fixed** (was open, now gone), or **still open**. Issues are
matched by a fingerprint that deliberately ignores line numbers, so ordinary
edits that shift code don't make a persistent issue look "fixed then new".

An "issue" is a (type, location) pair, not each instance — e.g. all the SQL
injections in one file track as one issue, matching how the UI groups findings.
"""

from __future__ import annotations

import re

from app.models import Finding

_WORD_RE = re.compile(r"[a-z0-9]{4,}")


def _typ(f: Finding) -> str:
    """The issue 'type' part of the fingerprint: CWE, else rule, else category,
    else a normalised title."""
    if f.cwe:
        return "cwe:" + str(f.cwe).split(":")[0].strip().lower()
    raw = f.raw or {}
    if raw.get("rule"):
        return "rule:" + str(raw["rule"]).lower()
    if f.category:
        return "cat:" + str(f.category).lower()
    words = _WORD_RE.findall((f.title or "").lower())
    return "title:" + " ".join(words[:6])


def _loc(f: Finding) -> str:
    """The location part: file path, else the endpoint, else empty."""
    if f.file_path:
        return f.file_path
    return str((f.raw or {}).get("endpoint") or "")


def fingerprint(f: Finding) -> str:
    """Stable identity for an issue across scans (line numbers excluded)."""
    return f"{_typ(f)}|{_loc(f)}"


def _is_open(f: Finding) -> bool:
    return f.state.value != "dismissed"


def _brief(f: Finding, fp: str) -> dict:
    return {
        "id": f.id, "fingerprint": fp, "title": f.title,
        "severity": f.severity.value, "state": f.state.value,
        "source": f.source.value, "cwe": f.cwe,
        "file_path": f.file_path, "line_start": f.line_start,
        "endpoint": (f.raw or {}).get("endpoint"),
    }


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def diff_findings(current: list[Finding], baseline: list[Finding]) -> dict:
    """Classify current vs baseline findings. Only open issues are tracked
    (dismissed findings don't count as present)."""
    def index(rows: list[Finding]) -> dict[str, Finding]:
        # Keep the most severe representative per fingerprint.
        out: dict[str, Finding] = {}
        for f in rows:
            if not _is_open(f):
                continue
            fp = fingerprint(f)
            cur = out.get(fp)
            if cur is None or _SEV_RANK.get(f.severity.value, 9) < _SEV_RANK.get(
                    cur.severity.value, 9):
                out[fp] = f
        return out

    cur = index(current)
    base = index(baseline)
    new_fps = [fp for fp in cur if fp not in base]
    fixed_fps = [fp for fp in base if fp not in cur]
    still_fps = [fp for fp in cur if fp in base]

    def sort_briefs(items: list[dict]) -> list[dict]:
        return sorted(items, key=lambda b: _SEV_RANK.get(b["severity"], 9))

    still: list[dict] = []
    for fp in still_fps:
        b = _brief(cur[fp], fp)
        prev, now = base[fp].severity.value, cur[fp].severity.value
        if prev != now:
            b["severity_changed_from"] = prev
        still.append(b)

    new = sort_briefs([_brief(cur[fp], fp) for fp in new_fps])
    fixed = sort_briefs([_brief(base[fp], fp) for fp in fixed_fps])
    still = sort_briefs(still)
    return {
        "counts": {"new": len(new), "fixed": len(fixed), "still_open": len(still)},
        "new": new, "fixed": fixed, "still_open": still,
    }
