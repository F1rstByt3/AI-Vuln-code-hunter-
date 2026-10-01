"""Burp Suite integration over MCP — active scanning for a DAST run.

The app owns access-control confirmation (``replay``); Burp owns broad active
scanning (injection, XSS, SSRF, …). Burp is driven through its official MCP
Server extension, registered like any other MCP server (``McpServer``).

Burp's MCP tool names and argument shapes differ across versions, so this
client *discovers* tools by name and maps them by capability, with overrides in
``server.config``. What it does, in order of reliability:

1. **Seed** the discovered, authenticated request surface into Burp (so Burp's
   proxy history / site map holds the real requests). Reliable — needs only a
   "send HTTP request" tool.
2. **Active scan** those URLs, if the server exposes a scan tool, then poll and
   ingest issues as ``dast`` findings. Best-effort — skipped (with a clear log)
   when the running Burp/extension doesn't expose scanning over MCP, in which
   case the surface is still seeded for the operator to scan in Burp.

Everything is gated by the run's scope + mutating rules: seeding reuses the
same ``Scope`` host allow-list, and non-idempotent requests are only seeded
when the run allows mutating traffic.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

import httpx

from app.models import McpServer

log = logging.getLogger(__name__)

# Capability → substrings matched (lower-cased) against discovered tool names.
_CAP_PATTERNS = {
    "send": ("send_http1_request", "send_http_request", "send_request", "send_http2"),
    "scan": ("active_scan", "start_scan", "create_scan", "scan_url", "audit", "new_scan"),
    "issues": ("scan_issues", "get_issues", "get_scan_issues", "list_issues", "issues"),
    "history": ("proxy_http_history", "get_proxy_history", "http_history"),
    "scan_status": ("scan_status", "get_scan", "scan_progress"),
    # Manual-testing hand-off (PortSwigger MCP: create_repeater_tab, send_to_intruder).
    "repeater": ("create_repeater_tab", "send_to_repeater", "repeater"),
    "intruder": ("send_to_intruder", "create_intruder", "intruder"),
}

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class BurpClient:
    """MCP client specialised for the Burp MCP server."""

    def __init__(self, server: McpServer) -> None:
        self.server = server
        self.cfg = dict(server.config or {})
        self._id = 0
        self._tools: list[dict] | None = None
        # config: {"tools": {"send": "send_http1_request", ...}, "token": "..."}
        self._overrides = self.cfg.get("tools") or {}

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    async def _rpc(self, method: str, params: dict | None = None, timeout: float = 120) -> dict:
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method,
                   "params": params or {}}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = self.cfg.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(self.server.url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        if "error" in data:
            raise RuntimeError(f"Burp MCP error: {data['error']}")
        return data.get("result", {})

    async def list_tools(self) -> list[dict]:
        if self._tools is None:
            self._tools = (await self._rpc("tools/list")).get("tools", [])
        return self._tools

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})

    async def tool_for(self, cap: str) -> str | None:
        """Resolve a capability to a concrete tool name (override or discovery)."""
        if cap in self._overrides:
            return self._overrides[cap]
        names = [t.get("name", "") for t in await self.list_tools()]
        for pat in _CAP_PATTERNS.get(cap, ()):
            for n in names:
                if pat in n.lower():
                    return n
        return None

    async def capabilities(self) -> dict:
        return {cap: (await self.tool_for(cap)) for cap in _CAP_PATTERNS}

    # ----------------------------------------------------------------- seeding
    async def seed_request(self, method: str, url: str, headers: dict) -> bool:
        """Send one request through Burp so it lands in its history/site map."""
        tool = await self.tool_for("send")
        if not tool:
            return False
        try:
            await self.call_tool(tool, _send_args(tool, method, url, headers))
            return True
        except Exception as exc:  # noqa: BLE001
            log.info("burp seed failed for %s %s: %s", method, url, exc)
            return False

    # ----------------------------------------------------------- manual hand-off
    async def send_to_tool(self, tool_cap: str, raw: str, host: str, port: int,
                           https: bool, tab_name: str) -> None:
        """Open *raw* in Burp Repeater or Intruder. Raises if unsupported."""
        tool = await self.tool_for(tool_cap)
        if not tool:
            raise RuntimeError(
                f"This Burp MCP server exposes no {tool_cap} tool — update the Burp MCP "
                f"Server extension, or use 'Copy for Burp' / the request pack instead")
        await self.call_tool(tool, {
            "tabName": tab_name[:60], "content": raw, "request": raw,
            "targetHostname": host, "host": host, "targetPort": port, "port": port,
            "usesHttps": https, "https": https, "secure": https,
        })

    # ----------------------------------------------------------------- scanning
    async def active_scan(self, urls: list[str]) -> str | None:
        """Start an active scan of *urls*. Returns a task id/handle, or None if
        the server exposes no scan tool."""
        tool = await self.tool_for("scan")
        if not tool:
            return None
        res = await self.call_tool(tool, {"urls": urls, "url": urls[0] if urls else None})
        # task id may come back under various keys
        for k in ("task_id", "scan_id", "id", "handle"):
            if isinstance(res, dict) and res.get(k):
                return str(res[k])
        return "started"

    async def fetch_issues(self) -> list[dict]:
        tool = await self.tool_for("issues")
        if not tool:
            return []
        res = await self.call_tool(tool, {})
        return _issues_from(res)


def _send_args(tool: str, method: str, url: str, headers: dict) -> dict:
    """Best-effort arguments for a 'send request' tool across Burp versions.

    Covers the common shapes: a raw-request form (content + target host/port)
    and a structured form (method/url/headers)."""
    parsed = urlparse(url)
    https = parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    hdr_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = (f"{method} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
           f"{hdr_lines}\r\nConnection: close\r\n\r\n")
    # Provide several key spellings; unknown ones are ignored by the server.
    return {
        "content": raw, "request": raw,
        "targetHostname": parsed.hostname, "host": parsed.hostname,
        "targetPort": port, "port": port,
        "usesHttps": https, "secure": https, "https": https,
        "method": method, "url": url,
        "headers": [{"name": k, "value": v} for k, v in headers.items()],
    }


def _issues_from(result: dict) -> list[dict]:
    if isinstance(result, dict):
        for key in ("issues", "findings", "scan_issues"):
            if isinstance(result.get(key), list):
                return result[key]
        for block in result.get("content", []):
            if isinstance(block, dict) and isinstance(block.get("json"), dict):
                j = block["json"]
                for key in ("issues", "findings"):
                    if isinstance(j.get(key), list):
                        return j[key]
    return result if isinstance(result, list) else []


# Burp severity/confidence → our severity.
_SEV = {"high": "high", "medium": "medium", "low": "low",
        "information": "info", "info": "info"}


def issue_to_finding(scan_id: str, issue: dict) -> dict:
    """Normalise a Burp issue into a finding dict (source='dast')."""
    name = issue.get("name") or issue.get("issue_name") or issue.get("type") or "Burp issue"
    sev = _SEV.get(str(issue.get("severity", "medium")).lower(), "medium")
    url = issue.get("url") or issue.get("origin") or ""
    detail = (issue.get("issue_detail") or issue.get("detail")
              or issue.get("description") or "")
    conf = str(issue.get("confidence", "")).lower()
    return {
        "title": str(name)[:300],
        "description": _strip_html(detail)[:4000],
        "severity": sev,
        "confidence": {"certain": 0.95, "firm": 0.8, "tentative": 0.5}.get(conf, 0.7),
        "source": "dast",
        "state": "proposed",
        "cwe": _first_cwe(issue),
        "category": "dynamic",
        "file_path": None,
        "remediation": _strip_html(issue.get("remediation")
                                   or issue.get("remediation_detail") or "")[:2000] or None,
        "endpoint": url,
        "code_snippet": _evidence(issue),
        "rule": issue.get("type_index") or issue.get("serial_number"),
        "origin": "burp",
        "raw_issue_url": url,
    }


def _first_cwe(issue: dict):
    v = issue.get("cwe") or issue.get("vulnerability_classifications")
    if isinstance(v, list):
        return str(v[0]) if v else None
    return str(v) if v else None


def _evidence(issue: dict) -> str | None:
    for k in ("evidence", "request_response", "proof", "request"):
        val = issue.get(k)
        if isinstance(val, str) and val.strip():
            return val[:1000]
    return None


def _strip_html(text) -> str:
    import re
    if not isinstance(text, str):
        return ""
    return re.sub(r"<[^>]+>", "", text).replace("&amp;", "&").replace("&lt;", "<").strip()


async def wait_and_fetch_issues(client: BurpClient, *, poll_seconds: float = 10,
                                max_wait: float = 900, is_canceled=None) -> list[dict]:
    """Poll the issues endpoint until it stops growing or max_wait elapses.

    Burp scan-status tools are inconsistent across versions, so rather than
    depend on a status API we watch the issue count settle."""
    waited = 0.0
    last = -1
    stable = 0
    while waited < max_wait:
        if is_canceled and await is_canceled():
            break
        issues = await client.fetch_issues()
        if len(issues) == last:
            stable += 1
            if stable >= 3:            # unchanged across 3 polls → assume done
                return issues
        else:
            stable = 0
        last = len(issues)
        await asyncio.sleep(poll_seconds)
        waited += poll_seconds
    return await client.fetch_issues()
