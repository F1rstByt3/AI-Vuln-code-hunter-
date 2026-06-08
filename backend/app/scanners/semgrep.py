"""Semgrep adapter — runs Semgrep over the extracted code and normalises results
into Candidate dicts. Runs both the standard ruleset AND our custom hunter rules
for deeper security coverage."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from app.config import settings
from app.scanners.base import Candidate

logger = logging.getLogger(__name__)

_SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_EXCLUDES = ["node_modules", "vendor", ".git", "dist", "build", "*.min.js", "*.lock"]
_RULES_DIR = str(Path(__file__).parent / "rules")


class SemgrepScanner:
    name = "semgrep"

    async def scan(self, workdir: str) -> list[Candidate]:
        configs = [settings.semgrep_ruleset]
        if os.path.isdir(_RULES_DIR) and os.listdir(_RULES_DIR):
            configs.append(_RULES_DIR)

        cmd = ["semgrep", "scan"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd += [
            "--json", "--quiet", "--no-git-ignore",
            "--max-target-bytes", str(settings.max_file_bytes_for_ai * 5),
            "--timeout", "120",
            "--severity", "INFO",
            "--severity", "WARNING",
            "--severity", "ERROR",
        ]
        for ex in _EXCLUDES:
            cmd += ["--exclude", ex]
        cmd.append(".")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        stderr_text = (stderr or b"").decode("utf-8", "replace").strip()
        if stderr_text:
            logger.info("semgrep stderr (rc=%d): %s", proc.returncode,
                        stderr_text[-1000:])
        if not stdout:
            logger.warning("semgrep returned no stdout (rc=%d)", proc.returncode)
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("semgrep returned invalid JSON (rc=%d)", proc.returncode)
            return []
        results = data.get("results", [])
        errors = data.get("errors", [])
        if errors:
            logger.warning("semgrep reported %d errors: %s", len(errors),
                           json.dumps(errors[:3])[:500])
        logger.info("semgrep: %d results, %d errors, rc=%d",
                    len(results), len(errors), proc.returncode)
        return [self._to_candidate(r, workdir) for r in results]

    def _to_candidate(self, r: dict, workdir: str) -> Candidate:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        sev = _SEV_MAP.get(extra.get("severity", "WARNING"), "medium")
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        owasp = meta.get("owasp")
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else None
        rel = os.path.relpath(r.get("path", ""), workdir)
        return Candidate(
            source="semgrep",
            rule=r.get("check_id", ""),
            title=(meta.get("shortDescription") or r.get("check_id", "")).split("\n")[0][:200],
            message=extra.get("message", ""),
            severity=sev,
            cwe=str(cwe) if cwe else None,
            owasp=str(owasp) if owasp else None,
            category=meta.get("category", "security"),
            file_path=rel,
            line_start=r.get("start", {}).get("line"),
            line_end=r.get("end", {}).get("line"),
            code_snippet=extra.get("lines"),
        )
