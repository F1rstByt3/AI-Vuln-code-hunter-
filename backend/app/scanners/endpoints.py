"""Scanner that extracts API endpoints / route definitions from source code.

Supports: FastAPI, Flask, Django, Express, Next.js, Spring, ASP.NET,
Go net/http, Gin, Rails, and Laravel.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Directories and size limits
# ---------------------------------------------------------------------------

_SKIP_DIRS: set[str] = {
    "node_modules",
    "vendor",
    ".git",
    "dist",
    "build",
    "__pycache__",
    ".venv",
}

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# ---------------------------------------------------------------------------
# Auth-hint patterns (scanned in the 5 lines preceding a route decorator)
# ---------------------------------------------------------------------------

_AUTH_PATTERN = re.compile(
    r"(?i)"
    r"(?:require_role|login_required|jwt_required|Authorize|authenticate"
    r"|IsAuthenticated|AllowAnonymous|protect|permission|auth)"
)

# ---------------------------------------------------------------------------
# Framework regex patterns
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, framework_name, method_group, path_group,
#                handler_group).
# Groups that don't exist for a pattern should be set to None; the extractor
# will fall back to sensible defaults.

_METHOD_MAP = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "head": "HEAD",
    "options": "OPTIONS",
}

# -- Python: FastAPI / Flask ------------------------------------------------
_PY_DECORATOR = re.compile(
    r"""@(?:app|router)\."""
    r"""(get|post|put|delete|patch|head|options)"""
    r"""\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_FLASK_ROUTE = re.compile(
    r"""@(?:app|blueprint|bp)\."""
    r"""route\(\s*["']([^"']+)["']"""
    r"""(?:.*?methods\s*=\s*\[([^\]]*)\])?""",
    re.IGNORECASE,
)

# -- Python: Django ---------------------------------------------------------
_DJANGO_PATH = re.compile(
    r"""(?:path|re_path|url)\(\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*(\w[\w.]*))?""",
    re.IGNORECASE,
)

# -- JS/TS: Express --------------------------------------------------------
_EXPRESS = re.compile(
    r"""(?:app|router)\."""
    r"""(get|post|put|delete|patch|head|options|all)"""
    r"""\(\s*["'`]([^"'`]+)["'`]"""
    r"""(?:\s*,\s*(\w+))?""",
    re.IGNORECASE,
)

# -- Java: Spring -----------------------------------------------------------
_SPRING_MAPPING = re.compile(
    r"""@(Get|Post|Put|Delete|Patch|Request)Mapping"""
    r"""(?:\(\s*(?:value\s*=\s*)?["']([^"']+)["']\s*\)|\b)""",
    re.IGNORECASE,
)

# -- C#/.NET: ASP.NET attribute routing -------------------------------------
_ASPNET_HTTP = re.compile(
    r"""\[Http(Get|Post|Put|Delete|Patch)"""
    r"""(?:\(\s*["']([^"']+)["']\s*\))?\]""",
    re.IGNORECASE,
)

_ASPNET_ROUTE = re.compile(
    r"""\[Route\(\s*["']([^"']+)["']\s*\)\]""",
    re.IGNORECASE,
)

_ASPNET_MAP = re.compile(
    r"""\.Map(Get|Post|Put|Delete|Patch)"""
    r"""\(\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*(\w+))?""",
    re.IGNORECASE,
)

# -- Go: net/http, gorilla mux, gin ----------------------------------------
_GO_HANDLE = re.compile(
    r"""(?:http|mux)\.HandleFunc\(\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*(\w+))?""",
)

_GIN_ROUTE = re.compile(
    r"""(?:r|router|g|group)\."""
    r"""(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"""
    r"""\(\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*(\w+))?""",
    re.IGNORECASE,
)

# -- Ruby: Rails routes -----------------------------------------------------
_RAILS_ROUTE = re.compile(
    r"""^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']"""
    r"""(?:.*?(?:to:|=>)\s*["']?(\w+#\w+)["']?)?""",
    re.IGNORECASE | re.MULTILINE,
)

_RAILS_RESOURCES = re.compile(
    r"""^\s*resources?\s+:(\w+)""",
    re.IGNORECASE | re.MULTILINE,
)

# -- PHP: Laravel -----------------------------------------------------------
_LARAVEL = re.compile(
    r"""Route::(get|post|put|delete|patch|match|any)"""
    r"""\(\s*["']([^"']+)["']"""
    r"""(?:.*?(\w+)@(\w+))?""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# File extension -> language hint
# ---------------------------------------------------------------------------

_LANG_EXTS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}

# Quick byte-level indicators per language. If none of these substrings appear
# in the file, it cannot contain a route definition we'd match, so we skip it
# entirely. This avoids full line-by-line regex on ~95% of source files.
_PRESCREEN: dict[str, tuple[bytes, ...]] = {
    "python": (b"@app.", b"@router.", b"@blueprint.", b"@bp.", b"path(", b"re_path(", b"url("),
    "javascript": (b"app.", b"router.", b"Route", b"export", b"pages/api"),
    "typescript": (b"app.", b"router.", b"Route", b"export", b"pages/api"),
    "java": (b"Mapping",),
    "csharp": (b"Http", b"[Route", b".Map"),
    "go": (b"HandleFunc", b".GET", b".POST", b".PUT", b".DELETE", b".PATCH"),
    "ruby": (b"get ", b"post ", b"put ", b"patch ", b"delete ", b"resources", b"resource "),
    "php": (b"Route::"),
}

# ---------------------------------------------------------------------------
# Next.js file-based routing detection
# ---------------------------------------------------------------------------

_NEXTJS_API_RE = re.compile(
    r"(?:pages/api/|app/(?:.*/)?)(?:route)\.[jt]sx?$"
    r"|pages/api/.*\.[jt]sx?$"
)

# HTTP method exports in Next.js App Router route files
_NEXTJS_EXPORT = re.compile(
    r"""export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"""
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_auth_hints(lines: list[str], line_idx: int) -> list[str]:
    """Return auth-related hints found in the 5 lines before *line_idx*."""
    start = max(0, line_idx - 5)
    hints: list[str] = []
    for i in range(start, line_idx):
        for m in _AUTH_PATTERN.finditer(lines[i]):
            hints.append(m.group(0))
    return hints


def _norm_method(raw: str) -> str:
    """Normalize an HTTP method string to upper-case standard form."""
    return _METHOD_MAP.get(raw.lower(), raw.upper())


def _is_binary(chunk: bytes) -> bool:
    """Quick heuristic: if the first 1024 bytes contain a null, treat as binary."""
    return b"\x00" in chunk[:1024]


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------


async def extract_endpoints(workdir: str) -> list[dict]:
    """Walk *workdir* and return a list of endpoint descriptors.

    Runs the I/O-heavy walk in a thread so the event loop stays responsive.
    """
    return await asyncio.to_thread(_extract_endpoints_sync, workdir)


def _extract_endpoints_sync(workdir: str) -> list[dict]:
    results: list[dict] = []
    files_checked = 0
    files_read = 0

    for dirpath, dirnames, filenames in os.walk(workdir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            lang = _LANG_EXTS.get(ext)
            if lang is None:
                continue

            full_path = os.path.join(dirpath, fname)
            files_checked += 1

            try:
                size = os.path.getsize(full_path)
                if size > _MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            # Pre-screen: read first 8KB and check for route indicator strings.
            # Skips files that can't possibly match any framework pattern.
            indicators = _PRESCREEN.get(lang)
            if indicators and size > 512:
                try:
                    with open(full_path, "rb") as fh:
                        head = fh.read(min(size, 8192))
                except OSError:
                    continue
                if _is_binary(head):
                    continue
                if not any(ind in head for ind in indicators):
                    # For files > 8KB, the indicator might be deeper — read the rest.
                    if size <= 8192:
                        continue
                    try:
                        with open(full_path, "rb") as fh:
                            fh.seek(8192)
                            tail = fh.read()
                    except OSError:
                        continue
                    if not any(ind in tail for ind in indicators):
                        continue

            # Full read for files that passed pre-screen
            try:
                with open(full_path, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue

            if _is_binary(raw):
                continue

            files_read += 1
            text = raw.decode("utf-8", errors="replace")
            lines = text.splitlines()
            rel_path = os.path.relpath(full_path, workdir)

            # --- Next.js file-based API routes ----------------------------
            if lang in ("javascript", "typescript") and _NEXTJS_API_RE.search(rel_path):
                # App Router route files: look for exported HTTP methods
                found_export = False
                for line_idx, line in enumerate(lines):
                    m = _NEXTJS_EXPORT.search(line)
                    if m:
                        found_export = True
                        method = m.group(1).upper()
                        # Derive path from file location
                        api_path = "/" + rel_path
                        api_path = re.sub(r"/route\.[jt]sx?$", "", api_path)
                        api_path = api_path.replace("app/", "", 1)
                        # Convert [param] to {param}
                        api_path = re.sub(r"\[([^\]]+)\]", r"{\1}", api_path)
                        results.append({
                            "method": method,
                            "path": api_path,
                            "file_path": rel_path,
                            "line": line_idx + 1,
                            "framework": "nextjs",
                            "handler": method,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })

                if not found_export and "pages/api/" in rel_path:
                    # Pages Router: the file itself is the route
                    api_path = "/" + rel_path
                    api_path = re.sub(r"\.[jt]sx?$", "", api_path)
                    api_path = api_path.replace("pages/", "", 1)
                    api_path = re.sub(r"/index$", "", api_path) or "/"
                    api_path = re.sub(r"\[([^\]]+)\]", r"{\1}", api_path)
                    results.append({
                        "method": "ANY",
                        "path": api_path,
                        "file_path": rel_path,
                        "line": 1,
                        "framework": "nextjs",
                        "handler": fname,
                        "auth_hints": [],
                    })

            # --- Line-by-line regex matching ------------------------------
            for line_idx, line in enumerate(lines):
                lineno = line_idx + 1

                # Python: FastAPI / Flask decorator style
                if lang == "python":
                    m = _PY_DECORATOR.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        path = m.group(2)
                        handler = _extract_handler_below(lines, line_idx)
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "fastapi",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                    m = _FLASK_ROUTE.search(line)
                    if m:
                        path = m.group(1)
                        raw_methods = m.group(2)
                        if raw_methods:
                            methods = [
                                s.strip().strip("'\"").upper()
                                for s in raw_methods.split(",")
                            ]
                        else:
                            methods = ["GET"]
                        handler = _extract_handler_below(lines, line_idx)
                        for method in methods:
                            results.append({
                                "method": method,
                                "path": path,
                                "file_path": rel_path,
                                "line": lineno,
                                "framework": "flask",
                                "handler": handler,
                                "auth_hints": _get_auth_hints(lines, line_idx),
                            })
                        continue

                    m = _DJANGO_PATH.search(line)
                    if m:
                        path = m.group(1)
                        handler = m.group(2) or None
                        results.append({
                            "method": "ANY",
                            "path": path if path.startswith("/") else "/" + path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "django",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # JavaScript/TypeScript: Express
                if lang in ("javascript", "typescript"):
                    m = _EXPRESS.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        if method == "ALL":
                            method = "ANY"
                        path = m.group(2)
                        handler = m.group(3) or None
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "express",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # Java: Spring
                if lang == "java":
                    m = _SPRING_MAPPING.search(line)
                    if m:
                        kind = m.group(1).lower()
                        path = m.group(2) or "/"
                        if kind == "request":
                            method = "ANY"
                        else:
                            method = _norm_method(kind)
                        handler = _extract_handler_below(lines, line_idx)
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "spring",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # C# / .NET
                if lang == "csharp":
                    m = _ASPNET_HTTP.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        path = m.group(2) or None
                        handler = _extract_handler_below(lines, line_idx)
                        results.append({
                            "method": method,
                            "path": path or "/",
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "aspnet",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                    m = _ASPNET_ROUTE.search(line)
                    if m:
                        path = m.group(1)
                        results.append({
                            "method": "ANY",
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "aspnet",
                            "handler": None,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                    m = _ASPNET_MAP.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        path = m.group(2)
                        handler = m.group(3) or None
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "aspnet",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # Go
                if lang == "go":
                    m = _GO_HANDLE.search(line)
                    if m:
                        path = m.group(1)
                        handler = m.group(2) or None
                        results.append({
                            "method": "ANY",
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "go-net-http",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                    m = _GIN_ROUTE.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        path = m.group(2)
                        handler = m.group(3) or None
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "gin",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # Ruby: Rails
                if lang == "ruby":
                    m = _RAILS_ROUTE.search(line)
                    if m:
                        method = _norm_method(m.group(1))
                        path = m.group(2)
                        handler = m.group(3) or None
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "rails",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                    m = _RAILS_RESOURCES.search(line)
                    if m:
                        resource = m.group(1)
                        results.append({
                            "method": "ANY",
                            "path": f"/{resource}",
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "rails",
                            "handler": resource,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

                # PHP: Laravel
                if lang == "php":
                    m = _LARAVEL.search(line)
                    if m:
                        raw = m.group(1).lower()
                        if raw in ("match", "any"):
                            method = "ANY"
                        else:
                            method = _norm_method(raw)
                        path = m.group(2)
                        controller = m.group(3)
                        action = m.group(4)
                        handler = f"{controller}@{action}" if controller and action else None
                        results.append({
                            "method": method,
                            "path": path,
                            "file_path": rel_path,
                            "line": lineno,
                            "framework": "laravel",
                            "handler": handler,
                            "auth_hints": _get_auth_hints(lines, line_idx),
                        })
                        continue

    logger.info("endpoint extraction: checked %d files, read %d, found %d endpoints",
                files_checked, files_read, len(results))
    return results


def _extract_handler_below(lines: list[str], decorator_idx: int) -> str | None:
    """Look at lines immediately following a decorator for a function/method name."""
    func_re = re.compile(
        r"(?:def|function|public|private|protected|async)\s+(\w+)"
    )
    for i in range(decorator_idx + 1, min(decorator_idx + 5, len(lines))):
        m = func_re.search(lines[i])
        if m:
            return m.group(1)
    return None
