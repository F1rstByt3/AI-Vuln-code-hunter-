"""Hand-off to Burp for manual testing: Repeater / Intruder-ready requests.

Builds raw HTTP/1.1 requests for the scan's endpoints with Burp Intruder
payload markers (``§…§``) around object identifiers, so a tester can paste a
request straight into Intruder (positions pre-set) or Repeater — or have it
pushed there directly through the Burp MCP server.

Credentials are never embedded: requests carry an ``Authorization`` header
placeholder for the tester to fill in (or for a Burp session-handling rule /
Autorize to replace). Stored DAST secrets stay server-side.
"""

from __future__ import annotations

import io
import re
import zipfile
from urllib.parse import urlparse

MARK = "§"  # Burp Intruder payload-position marker: §
AUTH_PLACEHOLDER = "Bearer REPLACE_WITH_YOUR_TOKEN"
_UUID_SAMPLE = "00000000-0000-0000-0000-000000000001"
_BODY_METHODS = {"POST", "PUT", "PATCH"}
_RISK = {"high": 0, "medium": 1, "low": 2}

_PARAM_RE = re.compile(
    r"\{([A-Za-z_]\w*)(?::[^}]*)?\}|:([A-Za-z_]\w*)"
    r"|<(?:\w+:)?([A-Za-z_]\w*)>|\[\.{0,3}([A-Za-z_]\w*)\]|\(\?P<([A-Za-z_]\w*)>[^)]*\)")


def _sample(name: str, id_kind: str | None) -> str:
    n = name.lower()
    if id_kind == "uuid" or any(t in n for t in ("uuid", "guid")):
        return _UUID_SAMPLE
    if "slug" in n or "name" in n:
        return "example"
    return "1"


def concrete_path(path: str, id_params: list[str] | None = None,
                  id_kind: str | None = None, mark: bool = True) -> str:
    """Framework route → concrete path. Id params are wrapped in § markers
    (Intruder positions); other params get a plain sample value."""
    ids = {p.lower() for p in (id_params or [])}

    def sub(m: re.Match) -> str:
        name = next(g for g in m.groups() if g)
        val = _sample(name, id_kind)
        is_id = name.lower() in ids or name.lower() == "id" or name.lower().endswith("id")
        return f"{MARK}{val}{MARK}" if (mark and is_id) else val

    p = _PARAM_RE.sub(sub, path or "/").replace("^", "").replace("$", "")
    return p if p.startswith("/") else "/" + p


def raw_request(ep: dict, base_url: str, *, mark: bool = True,
                note: str | None = None) -> str:
    """One raw HTTP/1.1 request (CRLF line endings, as Burp expects)."""
    u = urlparse(base_url if "://" in base_url else "https://" + base_url)
    host = u.hostname or "target.example"
    if u.port:
        host = f"{host}:{u.port}"
    prefix = (u.path or "").rstrip("/")
    method = (ep.get("method") or "GET").upper()
    if method in ("ANY", "ALL", "*"):
        method = "GET"
    path = prefix + concrete_path(ep.get("path") or "/", ep.get("id_params"),
                                  ep.get("id_kind"), mark)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: ai-vuln-code-hunter (manual testing)",
             "Accept: application/json, */*", f"Authorization: {AUTH_PLACEHOLDER}"]
    if note:
        # Harmless custom header so the tester can see why it was exported.
        lines.append(f"X-Hunter-Note: {re.sub(r'[^ -~]', '', note)[:180]}")
    body = ""
    if method in _BODY_METHODS:
        body = "{}"
        lines += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    lines.append("Connection: close")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def target_parts(base_url: str) -> tuple[str, int, bool]:
    u = urlparse(base_url if "://" in base_url else "https://" + base_url)
    https = u.scheme != "http"
    return (u.hostname or "target.example"), (u.port or (443 if https else 80)), https


def endpoint_for_label(endpoints: list[dict], label: str | None) -> dict | None:
    """Find the endpoint dict a finding's "METHOD /path" label refers to."""
    if not label:
        return None
    want = " ".join(label.upper().split())
    for ep in endpoints:
        if f"{(ep.get('method') or '').upper()} {(ep.get('path') or '').upper()}" == want:
            return ep
    method, _, path = want.partition(" ")
    return {"method": method or "GET", "path": path or label, "id_params": []}


_README = """\
AI Vuln Code Hunter - Burp manual-testing pack
================================================

requests/        One raw HTTP request per endpoint, ordered by risk.
all-requests.txt All of the above, separated by blank lines.
payloads/        Intruder payload lists for object identifiers.

Authorization is a placeholder (REPLACE_WITH_YOUR_TOKEN). Either edit it, or
add a Burp session-handling rule / use the Autorize extension so Burp swaps
in real sessions. No stored credentials are included in this pack.

Repeater
  Open a request file, copy everything, then in Burp: Repeater -> new tab ->
  paste into the request editor. Set the target host/port/HTTPS from the
  Host header (the tab's "Target" field).

Intruder (IDOR / BOLA)
  Copy a request -> Intruder -> new attack -> paste. Object ids are already
  wrapped in section markers (the "§" character), so the payload positions
  are set. Sniper attack, payload type "Simple list", load
  payloads/numeric-ids.txt (or uuids-sample.txt). Compare response length /
  status: as user A, any 200 for another user's id is a finding.

Intruder (swap identity)
  Put markers around the Authorization value instead and use a Pitchfork /
  Cluster bomb attack with one token per role (anonymous, user A, user B,
  admin) to test missing authentication and function-level authorisation.

Whole API at once
  Use the scan's "OpenAPI (Burp)" export with Burp's API scanning, or send
  requests straight to Repeater/Intruder from the scan page when the Burp MCP
  server is registered (Settings -> Integrations).
"""


def build_pack(endpoints: list[dict], base_url: str, *,
               findings_by_label: dict[str, list[str]] | None = None) -> bytes:
    """ZIP: per-endpoint raw requests, a combined file, payload lists, README."""
    fbl = findings_by_label or {}
    eps = sorted(endpoints, key=lambda e: (
        _RISK.get(e.get("risk") or e.get("heuristic_risk") or "low", 2),
        e.get("path") or ""))
    buf = io.BytesIO()
    combined: list[str] = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, ep in enumerate(eps, 1):
            label = f"{(ep.get('method') or 'GET').upper()} {ep.get('path') or '/'}"
            related = fbl.get(" ".join(label.upper().split()), [])
            risk = ep.get("risk") or ep.get("heuristic_risk") or "low"
            req = raw_request(ep, base_url, note=f"risk={risk}"
                              + (f"; {related[0]}" if related else ""))
            slug = re.sub(r"[^A-Za-z0-9]+", "_", label).strip("_")[:80]
            z.writestr(f"requests/{n:03d}_{risk}_{slug}.txt", req)
            combined.append(f"### {label}  [risk={risk}]"
                            + "".join(f"\n### finding: {r}" for r in related[:5])
                            + "\n" + req.replace("\r\n", "\n"))
        z.writestr("all-requests.txt", "\n\n".join(combined))
        z.writestr("payloads/numeric-ids.txt",
                   "\n".join(str(i) for i in range(0, 501)) + "\n-1\n99999999\n")
        z.writestr("payloads/uuids-sample.txt",
                   "\n".join(f"00000000-0000-0000-0000-{i:012d}" for i in range(1, 51)) + "\n")
        z.writestr("README.txt", _README)
    return buf.getvalue()
