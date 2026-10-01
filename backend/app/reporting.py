"""Self-contained HTML security report for a scan.

Produces one standalone HTML document (inline CSS, no external requests) that
consolidates everything a scan learned: the risk picture, coverage &
verification, each confirmed/open finding with evidence and remediation, the
access-control matrix, and live (DAST) confirmations. It is meant to be handed
to a client or team, or printed to PDF from the browser.

Security note: findings contain untrusted data (source snippets, model text,
live response bodies). EVERYTHING derived from a finding is HTML-escaped via
``esc`` before it reaches the document — the report never emits raw finding
content into markup.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from app.models import Finding, Project, Scan

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04",
              "low": "#0369a1", "info": "#64748b"}
_STATE_LABEL = {"confirmed": "Confirmed", "proposed": "Open", "needs_info": "Needs review",
                "dismissed": "Dismissed"}
# How many findings to render in full detail before summarising the tail.
_DETAIL_CAP = 500


def esc(v) -> str:
    return escape("" if v is None else str(v))


def _sev_rank(f: Finding) -> int:
    try:
        return _SEV_ORDER.index(f.severity.value)
    except (ValueError, AttributeError):
        return 9


def build_report_html(scan: Scan, project: Project | None,
                      findings: list[Finding]) -> str:
    summary = scan.summary or {}
    by_sev = summary.get("by_severity", {}) or {}
    risk = summary.get("risk_score", 0.0)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    proj_name = esc(project.name if project else "Project")

    open_f = [f for f in findings if f.state.value != "dismissed"]
    dismissed = [f for f in findings if f.state.value == "dismissed"]
    open_f.sort(key=lambda f: (_sev_rank(f), f.state.value != "confirmed"))
    confirmed_live = [f for f in findings if (f.raw or {}).get("dast", {}).get("verdict")
                      == "confirmed_vuln"]

    parts: list[str] = [_HEAD, _cover(proj_name, scan, generated, risk, len(open_f),
                                      len(confirmed_live))]
    parts.append(_exec_summary(by_sev, open_f, dismissed, summary))
    if summary.get("coverage"):
        parts.append(_coverage_section(summary["coverage"]))
    parts.append(_findings_section(open_f))
    if summary.get("endpoints"):
        parts.append(_access_matrix(summary["endpoints"]))
    if dismissed:
        parts.append(_dismissed_section(dismissed))
    parts.append(_footer(summary))
    parts.append("</body></html>")
    return "".join(parts)


def _cover(proj_name, scan, generated, risk, open_count, live_count) -> str:
    band = "#b91c1c" if risk >= 66 else "#ca8a04" if risk >= 33 else "#15803d"
    return f"""
<div class="cover">
  <div class="brand">AI Vuln Code Hunter · Security Review</div>
  <h1>{proj_name}</h1>
  <div class="meta">Scan {esc(scan.id)[:8]} · generated {generated}
    · status {esc(scan.status.value)}</div>
  <div class="riskrow">
    <div class="riskbox" style="border-color:{band}">
      <div class="riskscore" style="color:{band}">{esc(round(risk, 1))}</div>
      <div class="risklabel">risk score</div>
    </div>
    <div class="headline">
      <div><b>{open_count}</b> open findings</div>
      <div><b>{live_count}</b> confirmed against the running app</div>
    </div>
  </div>
</div>"""


def _exec_summary(by_sev, open_f, dismissed, summary) -> str:
    cells = ""
    for s in _SEV_ORDER:
        n = by_sev.get(s, 0)
        cells += (f'<div class="sevcell"><div class="sevn" style="color:{_SEV_COLOR[s]}">'
                  f'{esc(n)}</div><div class="sevl">{s}</div></div>')
    confirmed = sum(1 for f in open_f if f.state.value == "confirmed")
    needs = sum(1 for f in open_f if f.state.value == "needs_info")
    return f"""
<section>
  <h2>Executive summary</h2>
  <div class="sevgrid">{cells}</div>
  <div class="stats">
    <span><b>{esc(len(open_f))}</b> open</span>
    <span><b>{esc(confirmed)}</b> confirmed</span>
    <span><b>{esc(needs)}</b> need review</span>
    <span><b>{esc(len(dismissed))}</b> dismissed (false positives)</span>
  </div>
</section>"""


def _coverage_section(cov: dict) -> str:
    def row(label, value):
        return f"<tr><td>{esc(label)}</td><td>{esc(value)}</td></tr>"
    rows = ""
    if "files_loaded" in cov:
        rows += row("Files reviewed",
                    f"{cov.get('files_loaded', 0) - cov.get('files_unreviewed', 0)}"
                    f"/{cov.get('files_total', cov.get('files_loaded', 0))}")
    if cov.get("static_candidates") is not None:
        rows += row("Scanner hits with an AI verdict",
                    f"{cov.get('candidates_addressed_by_review', 0) + cov.get('candidates_triaged', 0)}"
                    f"/{cov.get('static_candidates', 0)}")
    if cov.get("second_look_files") is not None:
        rows += row("Sink-bearing files given a second look",
                    f"{cov.get('second_look_files')} ({cov.get('second_look_findings', 0)} new)")
    v = cov.get("verification") or {}
    if v:
        rows += row("False-positive verification",
                    f"{v.get('true_positive', 0)} confirmed · "
                    f"{v.get('false_positive', 0)} rejected · {v.get('uncertain', 0)} → human")
    ep = cov.get("endpoints") or {}
    if ep:
        rows += row("Endpoints access-assessed", f"{ep.get('assessed', 0)}/{ep.get('total', 0)}")
    if not rows:
        return ""
    return f"""
<section>
  <h2>Coverage &amp; verification</h2>
  <table class="kv">{rows}</table>
  <p class="muted">This report reflects how much of the code and attack surface was
  examined and how findings were validated.</p>
</section>"""


def _finding_card(f: Finding, idx: int) -> str:
    sev = f.severity.value
    raw = f.raw or {}
    dast = raw.get("dast") or {}
    badges = f'<span class="badge" style="background:{_SEV_COLOR.get(sev, "#64748b")}">{esc(sev)}</span>'
    badges += f'<span class="statebadge">{esc(_STATE_LABEL.get(f.state.value, f.state.value))}</span>'
    badges += f'<span class="src">{esc(f.source.value)}</span>'
    if dast.get("verdict") == "confirmed_vuln":
        badges += '<span class="live">✓ confirmed live</span>'
    loc = ""
    if raw.get("endpoint"):
        loc += f'<code>{esc(raw["endpoint"])}</code> '
    if f.file_path:
        loc += f'<code>{esc(f.file_path)}:{esc(f.line_start)}</code>'
    meta = " · ".join(x for x in [
        f"CWE {esc(f.cwe)}" if f.cwe else "",
        esc(f.owasp) if f.owasp else "",
        f"confidence {esc(round(float(f.confidence or 0), 2))}"] if x)

    body = f'<p>{esc(f.description)}</p>'
    for key, title in [("attack_scenario", "Attack scenario"),
                       ("proof_of_concept", "Proof of concept"),
                       ("risk", "Risk")]:
        if raw.get(key):
            pre = key == "proof_of_concept"
            content = f'<pre>{esc(raw[key])}</pre>' if pre else f'<p>{esc(raw[key])}</p>'
            body += f'<div class="sub"><b>{title}</b>{content}</div>'
    if dast.get("evidence"):
        body += _evidence_block(dast)
    if f.code_snippet and not raw.get("proof_of_concept"):
        body += f'<div class="sub"><b>Evidence</b><pre>{esc(f.code_snippet)}</pre></div>'
    remediation = raw.get("recommendation") or f.remediation
    if remediation:
        body += f'<div class="fix"><b>Remediation</b><p>{esc(remediation)}</p></div>'
    if f.human_question:
        body += f'<div class="q"><b>Question for the team</b><p>{esc(f.human_question)}</p></div>'
    if f.triage_note:
        body += f'<p class="muted">Triage: {esc(f.triage_note)}</p>'

    return f"""
<div class="finding" style="border-left-color:{_SEV_COLOR.get(sev, '#64748b')}">
  <div class="fhead"><span class="fnum">#{idx}</span>
    <span class="ftitle">{esc(f.title)}</span>{badges}</div>
  <div class="floc">{loc}{' · ' if loc and meta else ''}<span class="muted">{meta}</span></div>
  {body}
</div>"""


def _evidence_block(dast: dict) -> str:
    ev = dast.get("evidence") or {}
    rows = ""
    for r in ev.get("requests", []) or []:
        status = r.get("error") or f"HTTP {r.get('status')}"
        extra = f" · owner {esc(r.get('owner'))}" if r.get("owner") else ""
        base = " (baseline)" if r.get("baseline") else ""
        rows += (f"<tr><td>{esc(r.get('role'))}{base}</td><td>{esc(status)}</td>"
                 f"<td>{esc(r.get('target') or '')}{extra}</td></tr>")
    table = f'<table class="ev"><tr><th>identity</th><th>result</th><th>request</th></tr>{rows}</table>' if rows else ""
    return (f'<div class="sub"><b>Live test ({esc(dast.get("by", "dast"))})</b>'
            f'<p>{esc(ev.get("reason"))}</p>{table}</div>')


def _findings_section(open_f: list[Finding]) -> str:
    if not open_f:
        return ('<section><h2>Findings</h2><p class="good">No open findings — '
                'nothing required action at this scan.</p></section>')
    shown = open_f[:_DETAIL_CAP]
    cards = "".join(_finding_card(f, i + 1) for i, f in enumerate(shown))
    tail = ""
    if len(open_f) > _DETAIL_CAP:
        tail = (f'<p class="muted">…and {len(open_f) - _DETAIL_CAP} more open findings '
                f'(showing the {_DETAIL_CAP} highest-severity). Use the CSV/SARIF export '
                f'for the full set.</p>')
    return f'<section><h2>Findings ({len(open_f)})</h2>{cards}{tail}</section>'


def _access_matrix(endpoints: list) -> str:
    eps = [e for e in endpoints if isinstance(e, dict) and (e.get("authn") or e.get("auth_scope"))]
    if not eps:
        return ""
    rank = {"high": 0, "medium": 1, "low": 2}
    eps.sort(key=lambda e: rank.get(e.get("risk") or e.get("heuristic_risk") or "low", 3))
    rows = ""
    for e in eps[:400]:
        rk = e.get("risk") or e.get("heuristic_risk") or "low"
        color = {"high": "#b91c1c", "medium": "#ca8a04"}.get(rk, "#64748b")
        rows += (f"<tr><td><code>{esc(e.get('method'))}</code></td>"
                 f"<td><code>{esc(e.get('path'))}</code></td>"
                 f"<td>{esc(e.get('authn') or e.get('auth_scope'))}</td>"
                 f"<td>{esc(e.get('authz') or '—')}</td>"
                 f"<td style='color:{color}'>{esc(rk)}</td></tr>")
    return f"""
<section>
  <h2>Access-control matrix</h2>
  <table class="matrix"><tr><th>Method</th><th>Path</th><th>Authn</th>
    <th>Authz</th><th>Risk</th></tr>{rows}</table>
</section>"""


def _dismissed_section(dismissed: list[Finding]) -> str:
    items = "".join(f"<li>{esc(f.title)} "
                    f'<span class="muted">({esc(f.severity.value)}'
                    f'{" · " + esc(f.triage_note) if f.triage_note else ""})</span></li>'
                    for f in dismissed[:200])
    more = (f"<li class='muted'>…and {len(dismissed) - 200} more</li>"
            if len(dismissed) > 200 else "")
    return f"""
<section class="dismissed">
  <h2>Dismissed ({len(dismissed)})</h2>
  <p class="muted">Findings ruled out during validation (false positives, or the
  application was shown to enforce the control).</p>
  <ul>{items}{more}</ul>
</section>"""


def _footer(summary: dict) -> str:
    models = summary.get("models") or {}
    reviewers = ", ".join(models.get("reviewers", []) or []) if models else ""
    line = f"Reviewers: {esc(reviewers)}" if reviewers else ""
    return f"""
<footer>
  <p>Generated by AI Vuln Code Hunter — static analysis, AI review, and live
  confirmation. {line}</p>
  <p class="muted">Findings marked "confirmed live" were verified against the
  running application; others are static findings pending confirmation.</p>
</footer>"""


_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security review report</title>
<style>
:root{--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#fff;--panel:#f8fafc}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg);background:var(--bg);margin:0;padding:0 24px 64px}
.cover{max-width:900px;margin:0 auto;padding:40px 0 24px;border-bottom:3px solid var(--fg)}
.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font-size:34px;margin:8px 0 4px}
.meta{color:var(--muted);font-size:13px}
.riskrow{display:flex;gap:24px;align-items:center;margin-top:24px}
.riskbox{border:3px solid;border-radius:12px;padding:16px 24px;text-align:center;min-width:120px}
.riskscore{font-size:44px;font-weight:800;line-height:1}
.risklabel{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.headline div{font-size:18px;margin:4px 0}
section,footer{max-width:900px;margin:32px auto 0}
h2{font-size:20px;border-bottom:1px solid var(--line);padding-bottom:6px;margin:0 0 16px}
.sevgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}
.sevcell{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;text-align:center}
.sevn{font-size:26px;font-weight:800}
.sevl{font-size:11px;text-transform:uppercase;color:var(--muted)}
.stats{display:flex;gap:20px;flex-wrap:wrap;color:var(--muted)}
.stats b{color:var(--fg)}
table{border-collapse:collapse;width:100%;font-size:14px}
.kv td{padding:6px 8px;border-bottom:1px solid var(--line)}
.kv td:first-child{color:var(--muted);width:60%}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:5px;
  border-radius:8px;padding:14px 16px;margin-bottom:14px;page-break-inside:avoid}
.fhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fnum{color:var(--muted);font-weight:700}
.ftitle{font-weight:700;font-size:16px;flex:1;min-width:200px}
.badge{color:#fff;font-size:11px;font-weight:700;text-transform:uppercase;
  padding:2px 8px;border-radius:10px}
.statebadge{font-size:11px;border:1px solid var(--line);border-radius:10px;padding:2px 8px}
.src{font-size:11px;color:var(--muted);text-transform:uppercase}
.live{font-size:11px;font-weight:700;color:#166534;background:#dcfce7;padding:2px 8px;border-radius:10px}
.floc{margin:6px 0;font-size:13px}
code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12px}
.finding p{margin:8px 0}
.sub,.fix,.q{margin:10px 0;padding:10px 12px;border-radius:6px;background:#fff;border:1px solid var(--line)}
.fix{background:#f0fdf4;border-color:#bbf7d0}
.q{background:#fdf4ff;border-color:#f5d0fe}
.sub b,.fix b,.q b{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);margin-bottom:4px}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;
  font-size:12px;white-space:pre-wrap;word-break:break-word;margin:4px 0}
.ev{margin-top:6px;font-size:12px}
.ev th,.ev td,.matrix th,.matrix td{border:1px solid var(--line);padding:4px 8px;text-align:left}
.matrix th{background:var(--panel)}
.muted{color:var(--muted)}
.good{color:#166534;font-weight:600}
.dismissed ul{columns:2;font-size:13px}
footer{border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:13px}
@media print{body{padding:0}.finding{background:#fff}}
</style></head><body>"""
