"""Minimal MCP client.

Lets the platform call tools exposed by registered MCP servers (e.g. the Semgrep
MCP server, a SonarQube MCP bridge, or custom ones). HTTP/SSE JSON-RPC transport
is implemented; stdio is stubbed for the worker to launch locally.

This is intentionally small — enough to list and invoke tools and fold their
output into the same Candidate shape the agent consumes.
"""

from __future__ import annotations

import httpx

from app.models import McpServer
from app.scanners.base import Candidate


class McpError(RuntimeError):
    pass


class McpClient:
    def __init__(self, server: McpServer) -> None:
        self.server = server
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    async def _rpc(self, method: str, params: dict | None = None) -> dict:
        if self.server.transport not in ("http", "sse"):
            raise McpError(f"transport '{self.server.transport}' not supported by HTTP client")
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params or {}}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = self.server.config.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(self.server.url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        if "error" in data:
            raise McpError(str(data["error"]))
        return data.get("result", {})

    async def list_tools(self) -> list[dict]:
        return (await self._rpc("tools/list")).get("tools", [])

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})

    async def scan(self, workdir: str) -> list[Candidate]:
        """Convention: server exposes a 'scan' tool returning findings we normalise."""
        try:
            result = await self.call_tool("scan", {"path": workdir})
        except (McpError, httpx.HTTPError):
            return []
        return [self._normalise(item) for item in _extract_findings(result)]

    def _normalise(self, item: dict) -> Candidate:
        return Candidate(
            source=self.server.name,
            rule=item.get("rule", item.get("check_id", "")),
            title=item.get("title", item.get("message", ""))[:200],
            message=item.get("message", ""),
            severity=str(item.get("severity", "medium")).lower(),
            cwe=item.get("cwe"),
            owasp=item.get("owasp"),
            category=item.get("category", self.server.kind),
            file_path=item.get("file_path", item.get("path", "")),
            line_start=item.get("line_start", item.get("line")),
            line_end=item.get("line_end"),
            code_snippet=item.get("code_snippet"),
        )


def _extract_findings(result: dict) -> list[dict]:
    """MCP tool results vary; accept a few common shapes."""
    if isinstance(result.get("findings"), list):
        return result["findings"]
    for block in result.get("content", []):
        if block.get("type") == "json" and isinstance(block.get("json"), dict):
            return block["json"].get("findings", [])
    return []
