"""SonarQube adapter.

Unlike Semgrep (a self-contained CLI), SonarQube analysis is a two-phase dance:
  1. `sonar-scanner` uploads the code to a SonarQube *server*, which queues a
     background Compute Engine (CE) task to analyse it;
  2. once that task finishes we pull the issues back over the Web API and map
     them into our `Candidate` shape.

The server is configured via `SONARQUBE_URL` / `SONARQUBE_TOKEN`. Point these at
a local container (see the `sonar` compose profile) or any SonarQube instance.
The scan degrades gracefully: any error here is logged by the worker and the
review continues with the other scanners.
"""

from __future__ import annotations

import asyncio
import re
import uuid

import httpx

from app.config import settings
from app.scanners.base import Candidate

# SonarQube severities -> our scale.
_SEV_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "high",
    "MAJOR": "medium",
    "MINOR": "low",
    "INFO": "info",
}

# CWE references show up in issue tags like "cwe-89".
_CWE_TAG = re.compile(r"cwe-(\d+)", re.IGNORECASE)
_OWASP_TAG = re.compile(r"owasp-(a\d+)", re.IGNORECASE)


class SonarScanner:
    name = "sonarqube"

    def __init__(self) -> None:
        self.host = (settings.sonarqube_url or "").rstrip("/")
        self.token = settings.sonarqube_token or ""

    async def scan(self, workdir: str) -> list[Candidate]:
        if not self.host or not self.token:
            return []

        project_key = f"hunter-{uuid.uuid4().hex[:12]}"
        await self._run_scanner(workdir, project_key)
        # The CE task analyses asynchronously; wait for it before querying issues.
        await self._await_analysis(project_key)
        return await self._fetch_issues(project_key)

    # -- phase 1: upload + analyse -----------------------------------------
    async def _run_scanner(self, workdir: str, project_key: str) -> None:
        cmd = [
            "sonar-scanner",
            f"-Dsonar.host.url={self.host}",
            f"-Dsonar.token={self.token}",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.projectName={project_key}",
            "-Dsonar.sources=.",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.exclusions=**/node_modules/**,**/vendor/**,**/dist/**,**/build/**,**/*.min.js",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=workdir,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            tail = (stderr or b"").decode("utf-8", "replace")[-500:]
            raise RuntimeError(f"sonar-scanner failed (rc={proc.returncode}): {tail}")

    async def _await_analysis(self, project_key: str, timeout_s: int = 300) -> None:
        """Poll the most recent CE task for this project until it completes."""
        deadline = asyncio.get_event_loop().time() + timeout_s
        async with self._client() as client:
            while asyncio.get_event_loop().time() < deadline:
                resp = await client.get(
                    "/api/ce/component", params={"component": project_key}
                )
                resp.raise_for_status()
                data = resp.json()
                tasks = data.get("queue", [])
                current = data.get("current")
                if not tasks and current and current.get("status") in {
                    "SUCCESS", "FAILED", "CANCELED"
                }:
                    if current["status"] != "SUCCESS":
                        raise RuntimeError(f"SonarQube analysis {current['status']}")
                    return
                await asyncio.sleep(3)
        raise TimeoutError("SonarQube analysis did not finish in time")

    # -- phase 2: pull issues ----------------------------------------------
    async def _fetch_issues(self, project_key: str) -> list[Candidate]:
        candidates: list[Candidate] = []
        page = 1
        async with self._client() as client:
            while True:
                resp = await client.get("/api/issues/search", params={
                    "componentKeys": project_key,
                    "resolved": "false",
                    "ps": 500,
                    "p": page,
                })
                resp.raise_for_status()
                data = resp.json()
                for issue in data.get("issues", []):
                    candidates.append(self._to_candidate(issue, project_key))
                total = data.get("total", 0)
                if page * 500 >= total or not data.get("issues"):
                    break
                page += 1
        return candidates

    def _to_candidate(self, issue: dict, project_key: str) -> Candidate:
        sev = _SEV_MAP.get(issue.get("severity", "MAJOR"), "medium")
        component = issue.get("component", "")
        # component is "projectKey:relative/path" — strip the key prefix.
        rel = component.split(":", 1)[1] if ":" in component else component
        tags = issue.get("tags", [])
        cwe = next((f"CWE-{m.group(1)}" for t in tags
                    if (m := _CWE_TAG.match(t))), None)
        owasp = next((m.group(1).upper() for t in tags
                      if (m := _OWASP_TAG.match(t))), None)
        line = issue.get("line")
        return Candidate(
            source="sonarqube",
            rule=issue.get("rule", ""),
            title=(issue.get("message") or issue.get("rule", "")).split("\n")[0][:200],
            message=issue.get("message", ""),
            severity=sev,
            cwe=cwe,
            owasp=owasp,
            category=issue.get("type", "CODE_SMELL").lower(),
            file_path=rel,
            line_start=line,
            line_end=line,
            code_snippet=None,
        )

    def _client(self) -> httpx.AsyncClient:
        # SonarQube accepts the token as the basic-auth username (empty password).
        return httpx.AsyncClient(
            base_url=self.host, auth=(self.token, ""), timeout=60
        )
