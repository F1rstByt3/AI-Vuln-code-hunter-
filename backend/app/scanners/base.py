"""Common scanner contract. A scanner turns a working directory into a list of
candidate dicts that the AI agent will triage."""

from __future__ import annotations

from typing import Protocol, TypedDict


class Candidate(TypedDict, total=False):
    source: str          # semgrep | sonarqube | <mcp name>
    rule: str
    title: str
    message: str
    severity: str        # critical|high|medium|low|info
    cwe: str | None
    owasp: str | None
    category: str | None
    file_path: str       # relative to workdir
    line_start: int | None
    line_end: int | None
    code_snippet: str | None


class Scanner(Protocol):
    name: str

    async def scan(self, workdir: str) -> list[Candidate]: ...
