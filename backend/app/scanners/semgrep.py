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
        ruleset = settings.semgrep_ruleset
        # "auto" requires `semgrep login`; fall back to p/default if not logged in.
        if ruleset == "auto":
            logged_in = await self._check_semgrep_login()
            if not logged_in:
                logger.info("semgrep not logged in — using p/default instead of auto")
                ruleset = "p/default"

        configs = [ruleset]
        if os.path.isdir(_RULES_DIR) and os.listdir(_RULES_DIR):
            configs.append(_RULES_DIR)

        cmd = ["semgrep", "scan", "--metrics=off"]
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
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
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

    @staticmethod
    async def _check_semgrep_login() -> bool:
        """Return True if semgrep is logged in (can use --config auto)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "whoami",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _read_context(filepath: str, centre: int, radius: int = 3) -> str | None:
        """Read a small window around *centre* from *filepath*."""
        try:
            with open(filepath, encoding="utf-8", errors="replace") as fh:
                all_lines = fh.readlines()
        except OSError:
            return None
        if not all_lines:
            return None
        start = max(0, centre - 1 - radius)
        end = min(len(all_lines), centre + radius)
        numbered = [
            f"{start + i + 1:>5} | {line.rstrip()}"
            for i, line in enumerate(all_lines[start:end])
        ]
        return "\n".join(numbered)

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
        snippet = extra.get("lines", "")
        # Semgrep "lines" is just the matched text — try to read a few lines of
        # context from the actual file so the snippet is more useful.
        line_start = r.get("start", {}).get("line")
        if line_start and r.get("path"):
            snippet = self._read_context(r["path"], line_start, radius=3) or snippet
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
            line_start=line_start,
            line_end=r.get("end", {}).get("line"),
            code_snippet=snippet,
        )
