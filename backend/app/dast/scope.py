"""Scope enforcement — the guard that keeps live testing on authorized hosts.

Every outbound request in a DAST run passes ``check_host`` before it is sent.
A request whose resolved host is not in the run's allow-list is refused here,
in one place, so there is no code path that can contact an unintended host.
"""

from __future__ import annotations

from urllib.parse import urlparse


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def normalize_hosts(base_url: str, allowed: list[str] | None) -> list[str]:
    """The effective allow-list: whatever the operator declared, plus the base
    URL's own host. Lower-cased, de-duplicated, empties dropped."""
    hosts = {host_of(base_url)} if base_url else set()
    for h in allowed or []:
        h = (h or "").strip().lower()
        if h:
            # Accept a full URL or a bare host.
            hosts.add(host_of(h) if "//" in h else h.split("/")[0].split(":")[0])
    return sorted(h for h in hosts if h)


class ScopeError(RuntimeError):
    """Raised when a request would leave the authorized host allow-list."""


class Scope:
    """Immutable allow-list checked on every request of a run."""

    def __init__(self, allowed_hosts: list[str]) -> None:
        self.allowed = set(allowed_hosts)

    def permits(self, url: str) -> bool:
        h = host_of(url)
        return bool(h) and h in self.allowed

    def check(self, url: str) -> None:
        if not self.permits(url):
            raise ScopeError(
                f"refusing to contact out-of-scope host {host_of(url)!r}; "
                f"allowed: {sorted(self.allowed)}")
