"""Native active scanner — real DAST checks without requiring Burp.

Covers the high-value, low-false-positive checks against the discovered
endpoints, so a run produces injection/XSS/header findings on its own; Burp (if
attached) adds deeper, parameter-aware coverage on top.

What it does, all through the scoped ``LiveClient`` (host allow-list, rate
limit, request cap):

  * **Passive** (zero added risk, no attack payloads): missing/weak security
    headers, insecure cookie flags, and verbose server errors / stack traces in
    responses.
  * **Active path-parameter probes** (safe GET requests that substitute a
    benign detection payload into a ``{id}`` slot): error-based SQL injection
    and reflected XSS (a unique marker reflected unencoded). Detection payloads
    only — nothing destructive.

Parameters beyond the path aren't known from source analysis, so query/body
injection — and path-traversal, which needs an injectable file/path parameter
that HTTP clients don't let you smuggle through a ``{id}`` segment — are Burp's
job; this scanner is honest about that boundary.
"""

from __future__ import annotations

import re
import uuid

from app.dast import replay
from app.dast.client import RequestCapExceeded
from app.dast.identity import Identity

# --- response signatures ----------------------------------------------------
_SQL_ERR = re.compile(
    r"(SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"SQLSTATE|SQLite3?::|sqlite3\.OperationalError|Unclosed quotation mark|"
    r"quoted string not properly terminated|psycopg2\.|pg_query\(\)|"
    r"You have an error in your SQL syntax)", re.I)
_SERVER_ERR = re.compile(
    r"Traceback \(most recent call last\)|Exception in thread|"
    r"at [\w.$]+\([\w.]+\.(java|kt):\d+\)|System\.Web\.HttpException|"
    r"org\.springframework|Werkzeug Debugger|<b>Fatal error</b>|"
    r"Microsoft OLE DB Provider|ThreadPoolExecutor", re.I)

# Security headers every app should set (HSTS only checked on https).
_WANT_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options (nosniff)",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

_SQLI_PAYLOADS = ["'", "1'\"", "1' OR '1'='1' -- "]


def _f(title, severity, cwe, owasp, desc, endpoint, *, remediation=None,
       evidence=None, rule=None) -> dict:
    return {"title": title[:300], "severity": severity, "confidence": 0.6,
            "source": "dast", "state": "proposed", "cwe": cwe, "owasp": owasp,
            "category": "dynamic", "description": desc, "endpoint": endpoint,
            "remediation": remediation, "code_snippet": evidence,
            "rule": rule, "origin": "native-dast"}


async def native_active_scan(client, base_url: str, endpoints: list[dict],
                             identity: Identity, emit=None, *, is_canceled=None,
                             max_endpoints: int = 300) -> list[dict]:
    """Return a list of finding dicts (source='dast')."""
    findings: list[dict] = []
    base = base_url.rstrip("/")

    # ---- passive: security headers + cookie flags on the base response ----
    try:
        r = await client.raw("GET", base + "/", identity, purpose="passive:headers")
        findings += _passive_headers(base, r)
    except RequestCapExceeded:
        raise
    except Exception:  # noqa: BLE001
        pass

    # ---- per-endpoint: passive error detection + path-param active probes ----
    seen_param_targets: set[str] = set()
    checked = 0
    for e in endpoints:
        if is_canceled and await is_canceled():
            break
        if checked >= max_endpoints:
            break
        if not isinstance(e, dict):
            continue
        method = (e.get("method") or "GET").upper()
        if method in ("ANY", "ALL"):
            method = "GET"
        if method not in ("GET", "HEAD"):
            continue  # active probing stays on safe, idempotent methods
        path = e.get("path") or "/"
        url = base + replay.fill_path(path, None)
        checked += 1

        # passive: does a normal request leak a stack trace?
        try:
            r = await client.raw("GET", url, identity, purpose="passive:errors")
            body = (r.text or "")[:20000]
        except RequestCapExceeded:
            raise
        except Exception:  # noqa: BLE001
            continue
        if r.status_code >= 500 and _SERVER_ERR.search(body):
            findings.append(_f(
                f"Verbose server error on {method} {path}", "medium", "CWE-209",
                "A05:2021 - Security Misconfiguration",
                "The endpoint returned a stack trace / internal error detail to the client.",
                f"{method} {path}", rule="dast.error-disclosure",
                remediation="Return a generic error; log details server-side.",
                evidence=_snip(body, _SERVER_ERR)))

        # active path-param probes (one param per endpoint, deduped by location)
        id_params = e.get("id_params") or _implicit_params(path)
        for param in id_params[:1]:
            loc = f"{method} {path}#{param}"
            if loc in seen_param_targets:
                continue
            seen_param_targets.add(loc)
            findings += await _probe_param(client, base, path, method, param,
                                           identity, is_canceled)
    if emit:
        await emit({"type": "log", "message":
                    f"Native active scan: checked {checked} endpoint(s), "
                    f"{len(findings)} finding(s)"})
    return findings


async def _probe_param(client, base, path, method, param, identity,
                       is_canceled) -> list[dict]:
    found: list[dict] = []
    label = f"{method} {path}"

    async def send(payload, purpose):
        url = base + replay.fill_path(path, {param: payload})
        try:
            r = await client.raw(method, url, identity, purpose=purpose)
            return r, (r.text or "")[:20000]
        except RequestCapExceeded:
            raise
        except Exception:  # noqa: BLE001
            return None, ""

    # SQL injection (error-based)
    for p in _SQLI_PAYLOADS:
        if is_canceled and await is_canceled():
            return found
        r, body = await send(p, "active:sqli")
        if r is not None and _SQL_ERR.search(body):
            found.append(_f(
                f"SQL injection on {label} (param {param})", "high", "CWE-89",
                "A03:2021 - Injection",
                f"A database error surfaced when injecting into `{param}`, indicating "
                f"the value reaches a SQL query unsafely.", label,
                rule="dast.sqli", remediation="Use parameterized queries.",
                evidence=_snip(body, _SQL_ERR)))
            break

    # Reflected XSS: a slash-free angle-bracket marker reflected unencoded in an
    # HTML response. (A payload with '/' would split the path segment.)
    marker = "xss" + uuid.uuid4().hex[:8]
    payload = f"<{marker}>"
    r, body = await send(payload, "active:xss")
    if r is not None and payload in body \
            and "html" in (r.headers.get("content-type", "").lower()):
        found.append(_f(
            f"Reflected XSS on {label} (param {param})", "medium", "CWE-79",
            "A03:2021 - Injection",
            f"A marker injected into `{param}` was reflected unencoded (raw `<` `>`) "
            f"in an HTML response — a reflected-XSS indicator.", label,
            rule="dast.reflected-xss",
            remediation="Context-encode output; set a restrictive Content-Security-Policy.",
            evidence=f"reflected {payload} unencoded in HTML"))
    return found


def _passive_headers(base: str, r) -> list[dict]:
    findings: list[dict] = []
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    missing = [name for key, name in _WANT_HEADERS.items() if key not in hdrs]
    if base.startswith("https://") and "strict-transport-security" not in hdrs:
        missing.append("Strict-Transport-Security")
    if missing:
        findings.append(_f(
            "Missing security headers", "low", "CWE-693",
            "A05:2021 - Security Misconfiguration",
            "The application does not set: " + ", ".join(missing) + ".",
            base, rule="dast.missing-headers",
            remediation="Add the listed response headers at the edge/framework level."))
    # cookie flags
    setcookie = r.headers.get("set-cookie", "")
    if setcookie:
        low = setcookie.lower()
        flags = [f for f, tok in [("Secure", "secure"), ("HttpOnly", "httponly"),
                                  ("SameSite", "samesite")] if tok not in low]
        if flags:
            findings.append(_f(
                "Cookie without " + "/".join(flags), "low", "CWE-614",
                "A05:2021 - Security Misconfiguration",
                "A Set-Cookie response is missing: " + ", ".join(flags) + ".",
                base, rule="dast.cookie-flags",
                remediation="Set Secure, HttpOnly and SameSite on session cookies."))
    return findings


def _implicit_params(path: str) -> list[str]:
    return [m for m in re.findall(r"\{([^}/]+)\}|:([A-Za-z_]\w*)", path) for m in m if m][:1]


def _snip(body: str, pat: re.Pattern) -> str:
    m = pat.search(body)
    if not m:
        return body[:200]
    start = max(0, m.start() - 60)
    return body[start:m.end() + 60].strip()[:300]
