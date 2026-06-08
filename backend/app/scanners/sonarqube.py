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
import logging
import re
import shutil
import uuid

import httpx

logger = logging.getLogger(__name__)

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

    def __init__(self, url: str | None = None, token: str | None = None) -> None:
        # Explicit args (from in-app Settings) win over .env defaults.
        self.host = (url or settings.sonarqube_url or "").rstrip("/")
        self.token = token or settings.sonarqube_token or ""

    # OWASP tags to activate in security-focused quality profiles.
    _SECURITY_RULE_TAGS = (
        "cwe",
        "owasp-a1",
        "owasp-a2",
        "owasp-a3",
        "owasp-a4",
        "owasp-a5",
        "owasp-a6",
        "owasp-a7",
        "owasp-a8",
        "owasp-a9",
        "owasp-a10",
        "sans-top25-insecure",
        "sans-top25-porous",
        "sans-top25-risky",
        "security",
    )

    _SECURITY_PROFILE_NAME = "Hunter Security"

    async def scan(self, workdir: str) -> list[Candidate]:
        if not self.host or not self.token:
            return []

        await self._wait_ready()
        project_key = f"hunter-{uuid.uuid4().hex[:12]}"
        await self._run_scanner(workdir, project_key)
        # The CE task analyses asynchronously; wait for it before querying issues.
        await self._await_analysis(project_key)
        # After analysis completes, try to assign a security-focused quality
        # profile so subsequent analyses (and the issue set we pull) emphasise
        # security rules.  Failures here are non-fatal.
        await self._ensure_security_profile(project_key)
        return await self._fetch_issues(project_key)

    async def _wait_ready(self, timeout_s: int = 180) -> None:
        """Block until SonarQube reports UP, so we don't scan a half-booted server."""
        deadline = asyncio.get_event_loop().time() + timeout_s
        async with self._client() as client:
            while asyncio.get_event_loop().time() < deadline:
                try:
                    resp = await client.get("/api/system/status", timeout=10)
                    if resp.status_code == 200 and resp.json().get("status") == "UP":
                        return
                except Exception:
                    pass
                await asyncio.sleep(5)
        logger.warning("SonarQube did not become ready in %ds; attempting scan anyway", timeout_s)

    # -- phase 1: upload + analyse -----------------------------------------
    async def _run_scanner(self, workdir: str, project_key: str, retries: int = 2) -> None:
        cmd = [
            "sonar-scanner",
            f"-Dsonar.host.url={self.host}",
            f"-Dsonar.token={self.token}",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.projectName={project_key}",
            "-Dsonar.sources=.",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.exclusions=**/node_modules/**,**/vendor/**,**/dist/**,**/build/**,**/*.min.js",
            "-Dsonar.security.hotspots.report=true",
            "-Dsonar.issue.ignore.allfile=",
        ]
        node = shutil.which("node")
        if node:
            cmd.append(f"-Dsonar.nodejs.executable={node}")
        last_err = ""
        for attempt in range(1 + retries):
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=workdir,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return
            last_err = (stderr or b"").decode("utf-8", "replace")[-500:]
            if attempt < retries:
                wait = 10 * (attempt + 1)
                logger.warning("sonar-scanner failed (rc=%d, attempt %d/%d); "
                               "retrying in %ds", proc.returncode, attempt + 1,
                               1 + retries, wait)
                await asyncio.sleep(wait)
        raise RuntimeError(f"sonar-scanner failed (rc={proc.returncode}): {last_err}")

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
        async with self._client() as client:
            # Fetch standard issues (VULNERABILITY, BUG, CODE_SMELL).
            # Newer SonarQube versions don't accept SECURITY_HOTSPOT here.
            candidates.extend(await self._fetch_paged_issues(client, project_key))
            # Fetch security hotspots via the dedicated endpoint.
            candidates.extend(await self._fetch_hotspots(client, project_key))
        return candidates

    async def _fetch_paged_issues(
        self, client: httpx.AsyncClient, project_key: str,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        page = 1
        # Try the newer issue types first; fall back to legacy if 400.
        types_options = [
            "VULNERABILITY,BUG,CODE_SMELL",
            "VULNERABILITY,BUG",
            "VULNERABILITY",
        ]
        chosen_types = types_options[0]
        while True:
            resp = await client.get("/api/issues/search", params={
                "componentKeys": project_key,
                "resolved": "false",
                "types": chosen_types,
                "ps": 500,
                "p": page,
            })
            if resp.status_code == 400 and page == 1 and types_options:
                types_options.pop(0)
                if types_options:
                    chosen_types = types_options[0]
                    logger.warning("SonarQube issues API rejected types=%s; "
                                   "trying %s", chosen_types, types_options[0])
                    continue
                else:
                    logger.warning("SonarQube issues API rejected all type "
                                   "combinations; skipping issues")
                    break
            resp.raise_for_status()
            data = resp.json()
            for issue in data.get("issues", []):
                candidates.append(self._to_candidate(issue, project_key))
            total = data.get("total", 0)
            if page * 500 >= total or not data.get("issues"):
                break
            page += 1
        return candidates

    async def _fetch_hotspots(
        self, client: httpx.AsyncClient, project_key: str,
    ) -> list[Candidate]:
        """Fetch security hotspots via the dedicated /api/hotspots/search endpoint."""
        candidates: list[Candidate] = []
        page = 1
        try:
            while True:
                resp = await client.get("/api/hotspots/search", params={
                    "projectKey": project_key,
                    "ps": 500,
                    "p": page,
                })
                if resp.status_code == 404:
                    break
                resp.raise_for_status()
                data = resp.json()
                for hotspot in data.get("hotspots", []):
                    candidates.append(self._hotspot_to_candidate(hotspot, project_key))
                paging = data.get("paging", {})
                total = paging.get("total", 0)
                if page * 500 >= total or not data.get("hotspots"):
                    break
                page += 1
        except Exception as exc:
            logger.warning("Failed to fetch hotspots for %s: %s", project_key, exc)
        return candidates

    # -- security quality-profile management ---------------------------------

    async def _ensure_security_profile(self, project_key: str) -> None:
        """Create (if needed) and associate a security-focused quality profile.

        The method is best-effort: any failure is logged as a warning and the
        scan continues with whatever default profile the server already has.
        """
        try:
            async with self._client() as client:
                # Discover which languages the server knows about so we can
                # create / assign a profile per language.
                lang_resp = await client.get("/api/languages/list")
                lang_resp.raise_for_status()
                languages = [
                    lang["key"]
                    for lang in lang_resp.json().get("languages", [])
                ]
                if not languages:
                    logger.warning("SonarQube returned no languages; skipping profile setup")
                    return

                for language in languages:
                    await self._ensure_security_profile_for_language(
                        client, project_key, language
                    )
        except Exception:
            logger.warning(
                "Failed to set up security quality profile for %s; "
                "continuing with server defaults",
                project_key,
                exc_info=True,
            )

    async def _ensure_security_profile_for_language(
        self,
        client: httpx.AsyncClient,
        project_key: str,
        language: str,
    ) -> None:
        """Ensure the *Hunter Security* profile exists for *language* and
        associate it with the given project."""

        profile_key: str | None = None

        # 1. Search for an existing profile with our name.
        search_resp = await client.get(
            "/api/qualityprofiles/search",
            params={"qualityProfile": self._SECURITY_PROFILE_NAME, "language": language},
        )
        search_resp.raise_for_status()
        for profile in search_resp.json().get("profiles", []):
            if profile.get("name") == self._SECURITY_PROFILE_NAME:
                profile_key = profile["key"]
                break

        # 2. If it doesn't exist, create one that inherits from the default.
        if profile_key is None:
            profile_key = await self._create_security_profile(client, language)
            if profile_key is None:
                # Creation failed (logged inside); skip this language.
                return

        # 3. Associate the profile with the project.
        assoc_resp = await client.post(
            "/api/qualityprofiles/add_project",
            data={
                "qualityProfile": self._SECURITY_PROFILE_NAME,
                "language": language,
                "project": project_key,
            },
        )
        # 404 is returned when the project has no files in this language — that
        # is perfectly fine; ignore it.
        if assoc_resp.status_code not in (200, 204, 404):
            assoc_resp.raise_for_status()

    async def _create_security_profile(
        self,
        client: httpx.AsyncClient,
        language: str,
    ) -> str | None:
        """Create the *Hunter Security* quality profile for the given language.

        The new profile copies all rules from the built-in default and then
        activates additional security / vulnerability rules on top.

        Returns the profile key on success, or ``None`` on failure.
        """
        try:
            # Find the current default profile for this language so we can
            # copy its active rules.
            defaults_resp = await client.get(
                "/api/qualityprofiles/search",
                params={"defaults": "true", "language": language},
            )
            defaults_resp.raise_for_status()
            default_profiles = defaults_resp.json().get("profiles", [])
            parent_profile_name: str | None = None
            if default_profiles:
                parent_profile_name = default_profiles[0].get("name")

            # Create the new profile.  If there is a default we can copy from,
            # we use the copy endpoint; otherwise create an empty profile.
            if parent_profile_name:
                copy_resp = await client.post(
                    "/api/qualityprofiles/copy",
                    data={
                        "fromKey": default_profiles[0]["key"],
                        "toName": self._SECURITY_PROFILE_NAME,
                    },
                )
                copy_resp.raise_for_status()
                profile_key = copy_resp.json().get("key")
            else:
                create_resp = await client.post(
                    "/api/qualityprofiles/create",
                    data={
                        "name": self._SECURITY_PROFILE_NAME,
                        "language": language,
                    },
                )
                create_resp.raise_for_status()
                profile_key = (
                    create_resp.json().get("profile", {}).get("key")
                )

            if not profile_key:
                logger.warning(
                    "Could not determine profile key after creating "
                    "'%s' for language %s",
                    self._SECURITY_PROFILE_NAME,
                    language,
                )
                return None

            # Activate all security-related rules on the new profile.
            await client.post(
                "/api/qualityprofiles/activate_rules",
                data={
                    "targetKey": profile_key,
                    "types": "VULNERABILITY,SECURITY_HOTSPOT",
                },
            )
            # Also activate rules matching well-known security tags.
            await client.post(
                "/api/qualityprofiles/activate_rules",
                data={
                    "targetKey": profile_key,
                    "tags": ",".join(self._SECURITY_RULE_TAGS),
                },
            )

            logger.info(
                "Created security quality profile '%s' for language %s (key=%s)",
                self._SECURITY_PROFILE_NAME,
                language,
                profile_key,
            )
            return profile_key

        except Exception:
            logger.warning(
                "Failed to create security quality profile for language %s; "
                "skipping",
                language,
                exc_info=True,
            )
            return None

    def _hotspot_to_candidate(self, hotspot: dict, project_key: str) -> Candidate:
        component = hotspot.get("component", "")
        rel = component.split(":", 1)[1] if ":" in component else component
        vuln_prob = hotspot.get("vulnerabilityProbability", "MEDIUM")
        sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        line = hotspot.get("line")
        return Candidate(
            source="sonarqube",
            rule=hotspot.get("ruleKey", hotspot.get("key", "")),
            title=(hotspot.get("message") or "Security Hotspot")[:200],
            message=hotspot.get("message", ""),
            severity=sev_map.get(vuln_prob, "medium"),
            cwe=None,
            owasp=None,
            category="security_hotspot",
            file_path=rel,
            line_start=line,
            line_end=line,
            code_snippet=None,
        )

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
