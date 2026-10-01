"""Per-target DAST *mode*: how runs against a target are initiated.

This is the policy layer around launching — distinct from the live, in-flight
control (:mod:`app.dast.live_control`). It is editable at any time and only ever
affects the *next* run, never one already in flight. Everything here keeps to
the project's safety stance: automation is restricted to the safe subset
(access-control confirmation, non-mutating) unless a human explicitly widens it.
"""

from __future__ import annotations

DEFAULT_DAST_MODE: dict = {
    # Queue a run automatically when a scan on this target's project completes.
    "auto_run": False,
    # Auto-runs use only this safe subset — never mutating, never active scan,
    # unless auto_run_active is turned on deliberately.
    "auto_run_active": False,
    # New runs wait in pending_approval for a second admin to approve before any
    # traffic is sent (separates "request a run" from "authorise a run").
    "require_approval": False,
    # The checks any run against this target may use. active_scan must be listed
    # here AND enabled on the target before a run can scan actively.
    "allowed_checks": ["access_control"],
}

_ALLOWED_CHECK_NAMES = {"access_control", "active_scan"}


def normalize_mode(raw: dict | None) -> dict:
    m = {**DEFAULT_DAST_MODE, **(raw or {})}
    m["auto_run"] = bool(m.get("auto_run"))
    m["auto_run_active"] = bool(m.get("auto_run_active"))
    m["require_approval"] = bool(m.get("require_approval"))
    checks = [c for c in (m.get("allowed_checks") or []) if c in _ALLOWED_CHECK_NAMES]
    m["allowed_checks"] = checks or ["access_control"]
    return m


def check_allowed(mode: dict, check: str) -> bool:
    return check in normalize_mode(mode)["allowed_checks"]
