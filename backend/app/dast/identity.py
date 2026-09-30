"""Turn a stored credential into request authentication, and smoke-test it.

An ``Identity`` knows how to authenticate one role. It produces the headers and
cookies to attach to a live request, and — importantly — it can redact itself so
auth material never lands in captured evidence, logs or AI prompts.

Phase 1 supports static ``bearer`` / ``header`` / ``cookie`` credentials and a
connectivity smoke test. Scripted ``login_form`` (POST creds, capture session)
is stubbed for a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app import secrets
from app.models import DastCredential

# Header names whose values must never appear in evidence/logs.
SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token",
                     "api-key", "x-access-token", "proxy-authorization"}


@dataclass
class Identity:
    role: str
    is_privileged: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    usable: bool = True
    note: str = ""

    @classmethod
    def anonymous(cls) -> Identity:
        return cls(role="none")

    @classmethod
    def from_credential(cls, c: DastCredential) -> Identity:
        """Build an identity from a stored credential, decrypting its secret."""
        secret = secrets.try_decrypt(c.secret_enc)
        if secret is None:
            return cls(role=c.role_label, is_privileged=c.is_privileged,
                       usable=False, note="secret unavailable (key missing/rotated)")
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        kind = c.auth_kind
        if kind == "bearer":
            headers["Authorization"] = f"Bearer {secret}"
        elif kind == "header":
            headers[c.header_name or "Authorization"] = secret
        elif kind == "cookie":
            if c.header_name:            # a single named cookie
                cookies[c.header_name] = secret
            else:                        # a raw Cookie header value ("a=1; b=2")
                headers["Cookie"] = secret
        elif kind == "login_form":
            return cls(role=c.role_label, is_privileged=c.is_privileged,
                       usable=False, note="login_form not yet supported")
        else:
            return cls(role=c.role_label, is_privileged=c.is_privileged,
                       usable=False, note=f"unknown auth_kind {kind!r}")
        return cls(role=c.role_label, is_privileged=c.is_privileged,
                   headers=headers, cookies=cookies)


def redact_headers(headers: dict) -> dict:
    """Copy of *headers* with sensitive values masked — safe for evidence."""
    out = {}
    for k, v in (headers or {}).items():
        out[k] = "<redacted>" if k.lower() in SENSITIVE_HEADERS else v
    return out
