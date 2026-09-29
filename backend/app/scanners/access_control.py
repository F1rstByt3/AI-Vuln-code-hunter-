"""Endpoint access-control analysis (deterministic, no AI).

Turns the raw route list from ``endpoints.py`` into an access-control map:

* where authentication is enforced for each route — on the route itself
  (decorator / attribute / middleware argument / handler signature), at the
  file or controller level (router ``dependencies``, ``router.use(auth)``,
  ``before_action``, class-level ``[Authorize]``), or globally (Spring
  ``SecurityFilterChain``, DRF ``DEFAULT_PERMISSION_CLASSES``, ASP.NET
  fallback policy, Nest ``APP_GUARD`` …);
* role / permission checks and object-ownership checks near the handler;
* id-bearing path params (IDOR / BOLA candidates), state-changing methods,
  sensitive and privileged paths, and routes that are public by design.

Handlers that live away from the route table (Django ``urls.py`` → views,
Rails ``routes.rb`` → controllers, Laravel routes → controllers) are resolved
by framework convention so their decorators and bodies are inspected too.

From the map it derives *heuristic* findings — missing authentication on
state-changing/sensitive routes, possible IDOR, privileged routes without a
role check, and inconsistent protection between sibling routes on the same
resource. These are hints: the AI access-control review confirms or rejects
each one, and they stand on their own for static-only scans.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import Counter

logger = logging.getLogger(__name__)

_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__", ".venv",
              "venv", "target", "bin", "obj", ".next", "coverage"}
_SRC_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".kt",
             ".cs", ".go", ".rb", ".php"}
_MAX_FILE = 2 * 1024 * 1024
_MAX_GLOBAL_ENTRIES = 200
_MAX_HEURISTIC_FINDINGS = 600

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Authentication enforced at/near a route or inside its handler.
_AUTHN_RE = re.compile(r"""(?ix)
    login_required | jwt_required | auth_required | token_required
  | requires?_?auth\w* | require_?(?:user|login|role|roles|admin|permission|scope)\w*
  | is_?authenticated | \bauthenticated\b | passport\.authenticate | \bauthenticate\b
  | \[\s*authorize | @authorize\b | preauthorize | @secured | rolesallowed
  | permission_classes | permission_required | has_?(?:role|permission|perm|authority)\w*
  | current_?user | get_current_\w+ | authenticationprincipal
  | verify_?(?:token|jwt|auth)\w* | ensure_?(?:auth|login|logged)\w* | is_?logged_?in
  | useguards | \w*authguard | \w*auth(?:entication|orization)?_?middleware
  | requireauth\w* | withauth | isauth\w*
  | before_action\s+:\w*(?:auth|login|user)\w*
  | middleware\(\s*\[?\s*['"](?:auth|jwt|sanctum|verified)
  | \bprotect\b
""")

# Explicitly anonymous / opted out of auth.
_PUBLIC_MARK_RE = re.compile(r"""(?ix)
    allowanonymous | @permitall | permitall\(\) | csrf_exempt | @public\b
  | skip_before_action\s+:\w*(?:auth|login) | withoutmiddleware\(.{0,30}auth
  | security\s*=\s*\[\s*\] | auth\s*[:=]\s*false
""")

# Role / permission (function-level authorization).
_ROLE_RE = re.compile(r"""(?ix)
    require_?(?:role|roles|admin|permission|permissions|scope|scopes)\w*
  | has_?(?:role|any_?role|permission|perm|authority|any_?authority)\w*
  | rolesallowed | preauthorize | @secured | roles\s*=\s*['"] | policy\s*=\s*['"]
  | is_?admin | admin_required | is_?superuser | is_staff | permission_classes
  | permission_required | authorize\(\s*\w | can\?\s*\( | cannot\?\s*\( | abilit(?:y|ies)
  | check_?(?:permission|role|access)\w* | user\.role
  | \.roles?\s*(?:==|\bin\b|\.includes|\.contains)
  | middleware\(.{0,40}(?:can:|role:|admin)
""")

# Object-ownership / tenant scoping (object-level authorization).
_OWNERSHIP_RE = re.compile(r"""(?ix)
    \bowner(?:_?id)?\b | user_?id\s*(?:==|===|!=|!==)
  | (?:==|===)\s*(?:current_?user|req\.user|request\.user)
  | current_?user\.id | req\.user\.id | request\.user\.id | tenant_?id | org(?:anization)?_?id
  | filter(?:_by)?\(.{0,60}\b(?:user|owner|tenant)
  | where\(.{0,60}\b(?:user|owner|tenant) | \.for_user\( | belongs_?to | current_user\.\w+\.find
  | authorize\(\s*\w | can\?\(
""")

# Path params: {id} :id <int:id> [id] (?P<id>...)
_PARAM_RE = re.compile(
    r"\{([^}/]+)\}|:([A-Za-z_]\w*)|<(?:\w+:)?([A-Za-z_]\w*)>|\[\.{0,3}([A-Za-z_]\w*)\]"
    r"|\(\?P<([A-Za-z_]\w*)>"
)

_SENSITIVE_RE = re.compile(
    r"(?i)(admin|internal|debug|manage|config|setting|user|account|role|permission|"
    r"privilege|token|secret|apikey|api-key|api_key|password|billing|payment|invoice|"
    r"order|export|import|upload|delete|remove|impersonat|sudo|tenant|org|audit|report|"
    r"backup|actuator|graphql|console|webhook|profile|wallet|transfer)"
)
_PRIVILEGED_RE = re.compile(
    r"(?i)(^|[/_.-])(admin|administrator|internal|debug|manage|management|sudo|"
    r"impersonat\w*|actuator|console|superuser|staff|backoffice|root|ops)([/_.-]|$)"
)
_PUBLIC_PATH_RE = re.compile(
    r"(?i)(^|/)(login|logout|signin|sign-in|signup|sign-up|register|forgot\w*|"
    r"reset-password|password-reset|verify-email|oauth2?|callback|sso|saml|"
    r"health|healthz|healthcheck|ready|readyz|live|livez|ping|version|docs|swagger\w*|"
    r"openapi\w*|redoc|static|assets|public|favicon\w*|robots\.txt|sitemap\w*)(/|$|\.|\{|:)"
)

# Global / app-wide auth context (security config, global middleware).
_GLOBAL_PRESCREEN = (
    b"SecurityFilterChain", b"authorizeRequests", b"authorizeHttpRequests",
    b"EnableWebSecurity", b"permitAll", b"DEFAULT_PERMISSION_CLASSES",
    b"LoginRequiredMiddleware", b"UseAuthentication", b"UseAuthorization",
    b"RequireAuthorization", b"FallbackPolicy", b"APP_GUARD", b"useGlobalGuards",
    b"app.use(", b".Use(", b"before_action", b"FastAPI(", b"middleware(",
)
_GLOBAL_LINE_RE = re.compile(r"""(?ix)
    securityfilterchain | authorize(?:http)?requests | anyrequest\(\)\s*\.\s*authenticated
  | (?:ant|mvc|request)matchers\( | permitall | enablewebsecurity
  | default_permission_classes | default_authentication_classes | loginrequiredmiddleware
  | useauthentication | useauthorization | requireauthorization | fallbackpolicy
  | app_guard | useglobalguards
  | app\.use\(.{0,80}(?:auth|passport|jwt|session|guard|protect|login)
  | \.use\(.{0,60}(?:auth|jwt|guard|protect)
  | before_action\s+:\w*(?:auth|login|user)
  | fastapi\(.{0,160}dependencies
  | middleware\(.{0,40}(?:auth|sanctum|jwt)
""")
# The subset of global lines that *enforce* auth by default for every route.
# app.use(...) only counts when an auth-ish *middleware identifier* is mounted —
# not when auth *routes* are mounted (app.use('/auth', authRoutes)).
_GLOBAL_ENFORCE_RE = re.compile(r"""(?ix)
    anyrequest\(\)\s*\.\s*authenticated | loginrequiredmiddleware
  | default_permission_classes.{0,80}isauthenticated | fallbackpolicy | requireauthorization\(\)
  | app_guard | useglobalguards | fastapi\(.{0,160}dependencies
  | before_action\s+:authenticate
  | app\.use\(\s*(?:['"][^'"]*['"]\s*,\s*)?(?!\w*(?:route|controller))
        (?:\w+\.)*\w*(?:auth|jwt|guard|protect)\w*
""")

# File/controller-level auth that covers routes declared *after* it.
_FILE_AUTH_RE = re.compile(r"""(?ix)
    apirouter\(.{0,200}dependencies\s*=
  | \b(?:router|app|api|group|r|g|e|\w+Router)\.use\(\s*(?:['"][^'"]*['"]\s*,\s*)?
        (?!\w*(?:route|controller))(?:\w+\.)*\w*(?:auth|jwt|passport|guard|protect|login)\w*
  | before_action\s+:\w*(?:auth|login|user|admin)
  | ->middleware\(.{0,40}(?:auth|sanctum|jwt|can:) | route::middleware\(.{0,40}(?:auth|sanctum|jwt)
  | loginrequiredmixin | permissionrequiredmixin | userpassestestmixin
  | permission_classes\s*=
""")
# Attribute-style markers only count file-wide when they decorate the class.
_CLASS_ATTR_RE = re.compile(r"(?i)\[\s*authorize|@preauthorize|@secured|@rolesallowed|@useguards")
_CLASS_DECL_RE = re.compile(r"^\s*(?:export\s+)?(?:public\s+|abstract\s+|final\s+|sealed\s+)*"
                            r"(?:partial\s+)?class\s+\w+")

_DEF_TEMPLATE = (r"(?:\bdef|\bfunction|\bfunc|\bclass|\bpublic|\bprivate|\bprotected|"
                 r"\basync|\bconst|\blet|\bvar)\s+(?:[\w<>\[\],?]+\s+)*{name}\b")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def analyze_endpoints(endpoints: list[dict], workdir: str) -> dict:
    """Build the access-control map + heuristic findings (runs in a thread)."""
    return await asyncio.to_thread(_analyze_sync, endpoints, workdir)


def _analyze_sync(endpoints: list[dict], workdir: str) -> dict:
    all_paths, global_auth = _scan_tree(workdir)
    global_enforced = any(e["enforces"] for e in global_auth)
    cache: dict[str, list[str] | None] = {}
    fa_cache: dict[str, list[tuple[int, str]]] = {}

    def lines_of(rel: str | None) -> list[str] | None:
        if not rel:
            return None
        if rel not in cache:
            cache[rel] = _read_lines(workdir, rel)
        return cache[rel]

    def file_auth_of(rel: str, before_line: int) -> list[str]:
        if rel not in fa_cache:
            fa_cache[rel] = _file_auth_index(lines_of(rel) or [])
        return _uniq(h for n, h in fa_cache[rel] if n < before_line)

    # Route lines per file, so a handler window stops at the next route.
    routes_by_file: dict[str, list[int]] = {}
    for ep in endpoints:
        routes_by_file.setdefault(ep.get("file_path") or "", []).append(int(ep.get("line") or 1))
    for v in routes_by_file.values():
        v.sort()

    enriched: list[dict] = []
    for i, ep in enumerate(endpoints):
        enriched.append(_enrich(dict(ep), i, lines_of, file_auth_of, all_paths,
                                routes_by_file, global_enforced))

    candidates = _heuristic_findings(enriched, bool(global_auth))
    mechanisms = Counter(h.lower() for ep in enriched
                         for h in ep["route_auth"] + ep["file_auth"])
    scopes = Counter(ep["auth_scope"] for ep in enriched)
    stats = {
        "endpoints": len(enriched),
        "by_scope": dict(scopes),
        "state_changing": sum(1 for e in enriched if e["state_changing"]),
        "with_id_params": sum(1 for e in enriched if e["id_params"]),
        "privileged": sum(1 for e in enriched if e["privileged"]),
        "heuristic_findings": len(candidates),
        "global_auth_enforced": global_enforced,
    }
    logger.info("access-control map: %d endpoints, %d heuristic findings, scopes=%s",
                len(enriched), len(candidates), dict(scopes))
    return {
        "endpoints": enriched,
        "candidates": candidates,
        "global_auth": global_auth,
        "mechanisms": [m for m, _ in mechanisms.most_common(25)],
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Tree scan: file list + global auth context
# ---------------------------------------------------------------------------


def _scan_tree(workdir: str) -> tuple[list[str], list[dict]]:
    paths: list[str] = []
    global_auth: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(workdir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _SRC_EXTS:
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, workdir)
            paths.append(rel)
            if len(global_auth) >= _MAX_GLOBAL_ENTRIES:
                continue
            try:
                if os.path.getsize(full) > _MAX_FILE:
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"\x00" in raw[:1024] or not any(t in raw for t in _GLOBAL_PRESCREEN):
                continue
            for n, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                if _GLOBAL_LINE_RE.search(line):
                    global_auth.append({
                        "file_path": rel, "line": n, "text": line.strip()[:200],
                        "enforces": bool(_GLOBAL_ENFORCE_RE.search(line)),
                    })
                    if len(global_auth) >= _MAX_GLOBAL_ENTRIES:
                        break
    return paths, global_auth


def _read_lines(workdir: str, rel: str) -> list[str] | None:
    target = os.path.realpath(os.path.join(workdir, rel))
    if not target.startswith(os.path.realpath(workdir) + os.sep):
        return None
    try:
        if os.path.getsize(target) > _MAX_FILE:
            return None
        with open(target, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Per-endpoint enrichment
# ---------------------------------------------------------------------------


def _enrich(ep: dict, idx: int, lines_of, file_auth_of, all_paths: list[str],
            routes_by_file: dict[str, list[int]], global_enforced: bool) -> dict:
    method = (ep.get("method") or "ANY").upper()
    path = ep.get("path") or "/"
    route_file = ep.get("file_path") or ""
    route_line = int(ep.get("line") or 1)
    route_lines = lines_of(route_file) or []
    lang = os.path.splitext(route_file)[1].lower()

    # Handler: same file right below the route, or resolved by convention.
    h_file, h_line = _resolve_handler(ep, route_file, route_line, route_lines,
                                      lines_of, all_paths)
    h_lines = lines_of(h_file) or []
    if h_file == route_file:
        # Decorators/attributes stacked on this route, through the end of its
        # handler body — never spilling into the neighbouring routes.
        h_start = _decorators_above(route_lines, route_line)
        h_end = _block_end(route_lines, h_line, lang)
        nxt = [ln for ln in routes_by_file.get(route_file, []) if ln > route_line]
        if nxt:
            h_end = min(h_end, _decorators_above(route_lines, nxt[0]) - 1)
        h_end = max(h_end, route_line)
        route_window: list[str] = []
    else:
        h_start = _decorators_above(h_lines, h_line)
        h_end = _block_end(h_lines, h_line, os.path.splitext(h_file)[1].lower())
        # The route statement itself (e.g. Laravel ->middleware('auth') chains).
        route_window = route_lines[max(0, route_line - 1): route_line + 2]
    handler_window = h_lines[h_start - 1: h_end] if h_lines else []

    route_text = "\n".join(route_window)
    handler_text = "\n".join(handler_window)
    both = route_text + "\n" + handler_text

    route_auth = _uniq(m.group(0).strip() for m in _AUTHN_RE.finditer(both))
    public_markers = _uniq(m.group(0).strip() for m in _PUBLIC_MARK_RE.finditer(both))
    role_hints = _uniq(m.group(0).strip() for m in _ROLE_RE.finditer(both))
    ownership_hints = _uniq(m.group(0).strip() for m in _OWNERSHIP_RE.finditer(handler_text))
    file_auth = file_auth_of(route_file, route_line)
    if h_file != route_file:
        file_auth = _uniq(file_auth + file_auth_of(h_file, h_line))

    if public_markers and not route_auth:
        scope = "public"
    elif route_auth:
        scope = "route"
    elif file_auth:
        scope = "file"
    elif global_enforced:
        scope = "global"
    else:
        scope = "none"

    params = _path_params(path)
    id_params = [p for p in params if _is_id_param(p)]
    haystack = f"{path} {ep.get('handler') or ''}"
    sensitive = bool(_SENSITIVE_RE.search(haystack))
    privileged = bool(_PRIVILEGED_RE.search(path)) or bool(
        re.search(r"(?i)admin|impersonat|sudo", ep.get("handler") or ""))
    likely_public = bool(_PUBLIC_PATH_RE.search(path)) and not privileged
    state_changing = method in _STATE_CHANGING

    unauth = scope in ("none", "public") and not likely_public
    if unauth and (state_changing or privileged):
        risk = "high"
    elif privileged and not role_hints and not likely_public:
        risk = "high"
    elif (unauth and sensitive) or (id_params and not ownership_hints and not likely_public):
        risk = "medium"
    else:
        risk = "low"

    route_src = route_lines[route_line - 1].strip() if 0 < route_line <= len(route_lines) else ""
    ep.update({
        "id": f"e{idx}",
        "method": method,
        "auth_hints": _uniq(list(ep.get("auth_hints") or []) + route_auth + file_auth),
        "route_auth": route_auth,
        "file_auth": file_auth,
        "public_markers": public_markers,
        "role_hints": role_hints,
        "ownership_hints": ownership_hints,
        "auth_scope": scope,
        "path_params": params,
        "id_params": id_params,
        "state_changing": state_changing,
        "sensitive": sensitive,
        "privileged": privileged,
        "likely_public": likely_public,
        "heuristic_risk": risk,
        "resource": _family(path),
        "handler_file": h_file,
        "handler_line": h_line,
        "handler_start": h_start,
        "handler_end": h_end,
        "route_source": route_src[:240],
    })
    return ep


def _resolve_handler(ep: dict, route_file: str, route_line: int, route_lines: list[str],
                     lines_of, all_paths: list[str]) -> tuple[str, int]:
    """Locate the handler definition. Same file by default; framework
    conventions for route tables that point elsewhere."""
    handler = (ep.get("handler") or "").strip()
    fw = (ep.get("framework") or "").lower()
    if not handler:
        return route_file, route_line

    candidates: list[str] = []
    symbol = handler
    if fw == "rails":
        if "#" in handler:
            ctrl, symbol = handler.split("#", 1)
        else:  # `resources :users` → UsersController; point at its first action
            ctrl, symbol = handler, r"\w+"
        suffix = f"controllers/{ctrl}_controller.rb"
        candidates = [p for p in all_paths if p.replace(os.sep, "/").endswith(suffix)]
        for rel in candidates[:3]:
            lines = lines_of(rel) or []
            for n, line in enumerate(lines, 1):
                if re.match(rf"\s*def\s+{symbol}\b", line):
                    return rel, n
        return route_file, route_line
    elif fw == "laravel" and "@" in handler:
        ctrl, symbol = handler.split("@", 1)
        candidates = [p for p in all_paths if os.path.basename(p) == f"{ctrl}.php"]
    elif fw == "django":
        name = handler.replace(".as_view", "").split(".")[-1]
        symbol = name
        base = os.path.dirname(route_file)
        dirs = (base, os.path.join(base, "views"))
        candidates = [p for p in all_paths
                      if p.endswith(".py") and os.path.dirname(p) in dirs
                      and ("views" in p or "api" in p)]
    else:
        symbol = handler.split(".")[-1]

    if not re.fullmatch(r"\w+", symbol or ""):
        return route_file, route_line
    def_re = re.compile(_DEF_TEMPLATE.format(name=re.escape(symbol)))

    # Same file first (below the route for decorator styles, anywhere otherwise).
    if route_lines and fw not in ("rails", "laravel", "django"):
        for n in range(route_line - 1, min(len(route_lines), route_line + 8)):
            if def_re.search(route_lines[n]):
                return route_file, n + 1
        return route_file, route_line
    for rel in candidates[:12]:
        lines = lines_of(rel) or []
        for n, line in enumerate(lines, 1):
            if def_re.search(line):
                return rel, n
    return route_file, route_line


_ANNOTATION_PREFIXES = ("@", "[", "#[", "#", "//", "/*", "*")


def _decorators_above(lines: list[str], line: int) -> int:
    """First line (1-based) of the decorator/attribute/comment block directly
    above *line*; *line* itself when there is none. Stops at a blank line or
    ordinary code, so the previous handler's body is never included."""
    start = line
    k = line - 2
    while k >= 0 and line - k <= 12:
        s = lines[k].strip()
        if not s or not s.startswith(_ANNOTATION_PREFIXES):
            break
        start = k + 1
        k -= 1
    return start


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip())


def _block_end(lines: list[str], line: int, ext: str, cap: int = 80) -> int:
    """Last line (1-based) of the definition starting at *line*."""
    n = len(lines)
    if not n or line > n:
        return min(line, n)
    last = min(n, line + cap)
    if ext == ".py":
        # Skip down to the def (decorator lines precede it), then run to dedent.
        k = line - 1
        while k < last - 1 and not re.match(r"\s*(async\s+)?(def|class)\s", lines[k]):
            k += 1
        base = _indent(lines[k])
        end = k + 1
        for j in range(k + 1, last):
            s = lines[j]
            if not s.strip():
                continue
            if _indent(s) <= base and not s.strip().startswith((")", "]", "}")):
                break
            end = j + 1
        return end
    if ext == ".rb":
        base = _indent(lines[line - 1])
        for j in range(line, last):
            if lines[j].strip() == "end" and _indent(lines[j]) <= base:
                return j + 1
        return last
    # Brace languages: match braces from the route/def line; a statement that
    # never opens a block (app.get('/x', auth, handler);) ends at its ';'.
    depth = 0
    opened = False
    for j in range(line - 1, last):
        s = lines[j]
        depth += s.count("{") - s.count("}")
        if depth > 0:
            opened = True
        if opened and depth <= 0:
            return j + 1
        if not opened and s.rstrip().endswith(";"):
            return j + 1
    return last


def _file_auth_index(lines: list[str]) -> list[tuple[int, str]]:
    """(line, hint) for auth applied to every route declared after it in this
    file/controller: router deps, router.use(auth), before_action, mixins, and
    attribute markers that decorate the *class* (not a single method)."""
    out: list[tuple[int, str]] = []
    for n, line in enumerate(lines, 1):
        m = _FILE_AUTH_RE.search(line)
        if m:
            out.append((n, m.group(0).strip()[:80]))
            continue
        m = _CLASS_ATTR_RE.search(line)
        if m and any(_CLASS_DECL_RE.search(lines[k]) for k in range(n, min(len(lines), n + 4))):
            out.append((n, m.group(0).strip()[:80]))
    return out


def _path_params(path: str) -> list[str]:
    out = []
    for m in _PARAM_RE.finditer(path):
        name = next(g for g in m.groups() if g)
        out.append(name.split(":")[0])
    return out


def _is_id_param(name: str) -> bool:
    n = name.lower()
    return (n in {"id", "pk", "uuid", "guid", "slug", "number", "no"}
            or n.endswith("id") or n.endswith("_uuid") or n.endswith("_pk"))


def _family(path: str) -> str:
    """Resource family: params normalised, trailing params stripped, so
    /users, /users/{id} and /users/:id land in the same group."""
    p = _PARAM_RE.sub(":p", path.lower()).rstrip("/") or "/"
    segs = p.split("/")
    while len(segs) > 2 and segs[-1] == ":p":
        segs.pop()
    return "/".join(segs) or "/"


def _uniq(items) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        if it and it not in seen:
            seen[it] = None
    return list(seen)


# ---------------------------------------------------------------------------
# Heuristic findings
# ---------------------------------------------------------------------------


def _heuristic_findings(eps: list[dict], has_global_context: bool) -> list[dict]:
    by_family: dict[str, list[dict]] = {}
    for ep in eps:
        by_family.setdefault(ep["resource"], []).append(ep)

    per_ep: dict[str, list[dict]] = {}

    def add(ep: dict, f: dict) -> None:
        bucket = per_ep.setdefault(ep["id"], [])
        if len(bucket) < 2:  # keep noise bounded: at most two hints per route
            bucket.append(f)

    # 1. Inconsistent protection between sibling routes of the same resource.
    for family, group in by_family.items():
        protected = [e for e in group if e["auth_scope"] in ("route", "file")]
        exposed = [e for e in group
                   if e["auth_scope"] in ("none", "public") and not e["likely_public"]]
        if protected and exposed:
            peers = ", ".join(sorted({f"{e['method']} {e['path']}" for e in protected}))[:300]
            for e in exposed:
                add(e, _finding(
                    e, "access.inconsistent-authn",
                    f"Inconsistent access control: {e['method']} {e['path']} lacks the "
                    f"authentication its sibling routes enforce",
                    f"Other routes on the '{family}' resource enforce authentication "
                    f"({peers}), but {e['method']} {e['path']} has no authentication "
                    f"detected at the route, controller or global level. Inconsistent "
                    f"protection across one resource is a classic broken-access-control "
                    f"pattern (a forgotten decorator/middleware).",
                    "high" if e["state_changing"] or e["privileged"] else "medium",
                    0.5, "CWE-862",
                    "Apply the same authentication (and authorization) used by the "
                    "sibling routes, ideally at the router/controller level so new routes "
                    "inherit it."))
        # Same resource, authenticated everywhere, but role checks on only some.
        roled = [e for e in protected if e["role_hints"]]
        unroled = [e for e in protected if not e["role_hints"]
                   and (e["state_changing"] or e["privileged"])]
        if roled and unroled:
            peers = ", ".join(sorted({f"{e['method']} {e['path']}" for e in roled}))[:300]
            for e in unroled:
                add(e, _finding(
                    e, "access.inconsistent-authz",
                    f"Inconsistent authorization: {e['method']} {e['path']} has no role "
                    f"check while sibling routes do",
                    f"Sibling routes on '{family}' check roles/permissions ({peers}) but "
                    f"{e['method']} {e['path']} only requires authentication — any "
                    f"logged-in user may be able to perform this action (vertical "
                    f"privilege escalation).",
                    "high" if e["privileged"] else "medium", 0.4, "CWE-863",
                    "Enforce the same role/permission policy as the sibling routes."))

    flagged = set(per_ep)
    for e in eps:
        if e["likely_public"]:
            continue
        label = f"{e['method']} {e['path']}"
        exposed = e["auth_scope"] in ("none", "public")
        # 2. Missing authentication on state-changing / sensitive routes.
        if exposed and e["id"] not in flagged and (e["state_changing"] or e["sensitive"]
                                                   or e["privileged"]):
            why = ("explicitly marked anonymous (" + ", ".join(e["public_markers"]) + ")"
                   if e["auth_scope"] == "public" else
                   "no authentication detected at the route, controller or global level")
            ctx = (" Global security configuration exists — confirm whether it "
                   "covers this route." if has_global_context else "")
            add(e, _finding(
                e, "access.missing-authn", f"Endpoint without authentication: {label}",
                f"{label} is {'state-changing' if e['state_changing'] else 'sensitive'} "
                f"and {why}.{ctx}",
                "high" if (e["state_changing"] and (e["sensitive"] or e["privileged"]))
                else "medium",
                0.35, "CWE-306",
                "Require authentication for this route (decorator/attribute/middleware) "
                "unless it is intentionally public; document intentionally public routes."))
        # 3. Privileged route without a role/permission check.
        if e["privileged"] and not e["role_hints"]:
            add(e, _finding(
                e, "access.privileged-no-role",
                f"Privileged endpoint without a role check: {label}",
                f"{label} looks administrative/privileged but no role or permission "
                f"check was detected — authentication alone lets any user reach it.",
                "high", 0.35, "CWE-285",
                "Restrict the route to the privileged role (e.g. require_role('admin'), "
                "@PreAuthorize(\"hasRole('ADMIN')\"), [Authorize(Roles=\"Admin\")])."))
        # 4. Object id in the path with no ownership check (IDOR / BOLA).
        if e["id_params"] and not e["ownership_hints"] and not e["role_hints"]:
            add(e, _finding(
                e, "access.idor",
                f"Possible IDOR / missing object-level authorization: {label}",
                f"{label} takes an object identifier ({', '.join(e['id_params'])}) from "
                f"the client, but the handler shows no ownership or tenant check — a "
                f"user may read or modify another user's object by changing the id.",
                "high" if e["state_changing"] else "medium", 0.3, "CWE-639",
                "Scope the lookup to the caller (e.g. WHERE id = :id AND owner_id = "
                ":current_user) or enforce an object-level policy before returning or "
                "mutating it."))

    out = [f for fs in per_ep.values() for f in fs]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: (rank.get(f["severity"], 9), -f["confidence"]))
    return out[:_MAX_HEURISTIC_FINDINGS]


def _finding(ep: dict, rule: str, title: str, description: str, severity: str,
             confidence: float, cwe: str, remediation: str) -> dict:
    return {
        "title": title[:300],
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": "A01:2021 - Broken Access Control",
        "category": "access-control",
        "file_path": ep.get("handler_file") or ep.get("file_path"),
        "line_start": ep.get("handler_line") or ep.get("line"),
        "line_end": ep.get("handler_line") or ep.get("line"),
        "code_snippet": ep.get("route_source") or None,
        "remediation": remediation,
        "source": "access",
        "state": "proposed",
        "rule": rule,
        "origin": "heuristic",
        "endpoint": f"{ep['method']} {ep['path']}",
        "endpoint_id": ep["id"],
    }
