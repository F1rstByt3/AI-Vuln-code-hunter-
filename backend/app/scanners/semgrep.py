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


_OOM_MARKERS = ("engine was killed", "used too much memory", "out of memory",
                "maximum memory", "oom")
_OOM_HELP = (
    "⚠ Semgrep ran out of memory and skipped rules/files — its findings are "
    "incomplete (the AI review still ran). Give Docker more RAM (Docker Desktop "
    "→ Settings → Resources, 8GB+), or lower SEMGREP_MAX_MEMORY_MB / keep "
    "SEMGREP_JOBS=1 in .env. The AI reviewers cover what Semgrep missed.")


class SemgrepScanner:
    name = "semgrep"

    async def scan(self, workdir: str, emit=None) -> list[Candidate]:
        async def _note(msg: str) -> None:
            if emit:
                await emit({"type": "log", "message": msg})

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
            # Memory bounds so the engine isn't OOM-killed on big repos / low RAM.
            "--jobs", str(max(1, settings.semgrep_jobs)),
            "--severity", "INFO",
            "--severity", "WARNING",
            "--severity", "ERROR",
        ]
        if settings.semgrep_max_memory_mb and settings.semgrep_max_memory_mb > 0:
            cmd += ["--max-memory", str(settings.semgrep_max_memory_mb)]
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
        try:
            stdout, stderr = await proc.communicate()
        except asyncio.CancelledError:
            proc.kill()  # scan canceled: don't leave the scanner running
            await proc.wait()
            raise
        stderr_text = (stderr or b"").decode("utf-8", "replace").strip()
        if stderr_text:
            logger.info("semgrep stderr (rc=%d): %s", proc.returncode,
                        stderr_text[-1000:])
        if not stdout:
            logger.warning("semgrep returned no stdout (rc=%d)", proc.returncode)
            if any(m in stderr_text.lower() for m in _OOM_MARKERS):
                await _note(_OOM_HELP)
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
            blob = (json.dumps(errors) + " " + stderr_text).lower()
            if any(m in blob for m in _OOM_MARKERS):
                # Partial run: some rules/files were skipped for memory.
                await _note(_OOM_HELP)
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
        # Semgrep runs with cwd=workdir on ".", so paths come back relative to
        # the workdir — resolve them there, not against the worker's own cwd
        # (which produced "../../../app/..." paths nothing could open).
        raw_path = r.get("path", "")
        full = raw_path if os.path.isabs(raw_path) else os.path.join(workdir, raw_path)
        rel = os.path.relpath(full, workdir)
        snippet = extra.get("lines", "")
        if snippet.strip() == "requires login":  # Semgrep's placeholder when logged out
            snippet = ""
        # Semgrep "lines" is just the matched text — read a few lines of real
        # context from the file so the snippet is useful.
        line_start = r.get("start", {}).get("line")
        if line_start and raw_path:
            snippet = self._read_context(full, line_start, radius=3) or snippet
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
