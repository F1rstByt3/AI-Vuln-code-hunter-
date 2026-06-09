"""Artifact ingestion: turn an uploaded archive / git repo / local path into a
materialised working tree plus an indexed 'analyzable surface'.

Built for big inputs:
  * uploads stream from object storage to disk (never fully into RAM);
  * archive extraction is guarded against zip-bombs and path traversal;
  * binaries, vendored deps and oversized files are flagged out of the AI surface
    (static tools still see them) so we never feed 10GB to the model.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tarfile
import zipfile
from dataclasses import dataclass, field

from app.config import settings
from app.storage import ObjectStorage

logger = logging.getLogger(__name__)

WORKROOT = os.environ.get("SCAN_WORKDIR", "/scan-workdir")

_VENDOR_MARKERS = (
    "/node_modules/", "/vendor/", "/.git/", "/dist/", "/build/",
    "/site-packages/", "/.venv/", "/venv/", "/target/", "/.gradle/",
    "/bower_components/", "/jspm_packages/", "/.next/", "/.nuxt/",
    "/out/", "/coverage/", "/__pycache__/", "/.tox/", "/.mypy_cache/",
    "/.pytest_cache/", "/.terraform/", "/Pods/", "/Carthage/",
    "/storybook-static/",
)

# Heavy/vendored dirs pruned during the walk entirely (never indexed) — pure
# speed: we don't want to stat millions of dependency files.
_PRUNE_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", ".venv", "venv",
    "site-packages", "target", ".gradle", "bower_components", "jspm_packages",
    ".next", ".nuxt", "out", "coverage", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".terraform", "Pods", "Carthage", "storybook-static",
    ".idea", ".vscode",
}

# Non-product code: indexed (so it shows in the file tree and can be opted into
# via scope selection) but kept OUT of the default AI surface. Tests/fixtures/
# generated migrations rarely hold the vulnerabilities worth a manual review and
# they dominate token budget on large repos.
_NOISE_MARKERS = (
    "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/testdata/",
    "/fixtures/", "/__mocks__/", "/e2e/", "/migrations/", "/examples/",
    "/example/", "/samples/", "/.storybook/",
)

# Generated / minified / lock artifacts — excluded by filename, no real review value.
_GENERATED_SUFFIXES = (
    ".min.js", ".min.css", ".bundle.js", ".bundle.css", "-min.js", ".map",
    ".pb.go", ".pb.cc", ".pb.h", "_pb2.py", "_pb2_grpc.py", ".g.dart",
    ".generated.ts", ".generated.js", ".d.ts",
)
_GENERATED_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "gemfile.lock", "poetry.lock", "cargo.lock", "go.sum", "go.mod",
    "pipfile.lock", "packages.lock.json",
}
_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp", ".rs": "rust",
    ".kt": "kotlin", ".swift": "swift", ".scala": "scala", ".sh": "shell", ".sql": "sql",
    ".yaml": "yaml", ".yml": "yaml", ".tf": "terraform", ".json": "json", ".html": "html",
}
_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2")


def _is_archive(path: str) -> bool:
    """Detect archives by extension AND by content (magic bytes)."""
    if path.lower().endswith(_ARCHIVE_EXTS):
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        if header[:4] == b"PK\x03\x04":
            return True
        if header[:6] in (b"7z\xbc\xaf\x27\x1c",):
            return True
        if tarfile.is_tarfile(path):
            return True
    except Exception:
        pass
    return False


@dataclass
class FileEntry:
    path: str
    size_bytes: int
    language: str | None
    sha256: str | None
    is_binary: bool
    is_vendored: bool
    included: bool


@dataclass
class IngestResult:
    workdir: str
    files: list[FileEntry] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def analyzable(self) -> int:
        return sum(1 for f in self.files if f.included)


async def materialize(artifact, storage: ObjectStorage) -> str:
    """Produce a local working tree for the artifact. Returns the workdir path."""
    workdir = os.path.join(WORKROOT, artifact.id)
    os.makedirs(workdir, exist_ok=True)

    if artifact.kind.value == "local":
        if not artifact.source_ref or not os.path.isdir(artifact.source_ref):
            raise ValueError("local artifact requires an existing source_ref directory")
        return artifact.source_ref

    if artifact.kind.value == "git":
        await _git_clone(artifact.source_ref, workdir)
        return workdir

    # upload: pull the stored object to disk, then extract if it's an archive.
    raw_name = (artifact.meta or {}).get("filename", "upload.bin")
    raw_path = os.path.join(workdir, "__raw__", raw_name)
    os.makedirs(os.path.dirname(raw_path), exist_ok=True)
    await storage.download_to_path(artifact.storage_key, raw_path)

    dest = os.path.join(workdir, "src")
    os.makedirs(dest, exist_ok=True)
    raw_size = os.path.getsize(raw_path)
    is_arch = _is_archive(raw_path)
    logger.info("materialize: raw=%s size=%d archive=%s dest=%s",
                raw_name, raw_size, is_arch, dest)
    if is_arch:
        _safe_extract(raw_path, dest)
        extracted = sum(1 for _, _, fs in os.walk(dest) for _ in fs)
        logger.info("materialize: extracted %d files into %s", extracted, dest)
        if extracted == 0:
            logger.warning("materialize: archive extracted 0 files! "
                           "raw_path=%s raw_size=%d", raw_path, raw_size)
    else:
        os.replace(raw_path, os.path.join(dest, raw_name))
    return dest


async def _git_clone(source_ref: str | None, workdir: str) -> None:
    import asyncio

    if not source_ref:
        raise ValueError("git artifact requires source_ref (url[#ref])")
    url, _, ref = source_ref.partition("#")
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", *( ["--branch", ref] if ref else [] ), url, workdir,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {err.decode(errors='ignore')[:500]}")


def _safe_extract(archive_path: str, dest: str) -> None:
    """Extract with zip-bomb and path-traversal guards."""
    total = 0
    count = 0

    def _check(member_name: str, member_size: int) -> str:
        nonlocal total, count
        count += 1
        total += member_size
        if count > settings.max_extract_files:
            raise RuntimeError("archive exceeds max file count")
        if total > settings.max_extract_bytes:
            raise RuntimeError("archive exceeds max extracted size (zip-bomb guard)")
        target = os.path.realpath(os.path.join(dest, member_name))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            raise RuntimeError(f"path traversal blocked: {member_name}")
        return target

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = _check(info.filename, info.file_size)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    _stream_copy(src, out)
    else:
        with tarfile.open(archive_path) as tf:
            for member in tf.getmembers():
                if not member.isfile() or member.issym() or member.islnk():
                    continue
                target = _check(member.name, member.size)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                with open(target, "wb") as out:
                    _stream_copy(extracted, out)


def _stream_copy(src, dst, chunk: int = 1 << 20) -> None:
    while data := src.read(chunk):
        dst.write(data)


def index_files(workdir: str) -> IngestResult:
    """Walk the tree and classify each file into the analyzable surface."""
    result = IngestResult(workdir=workdir)
    for root, dirs, files in os.walk(workdir):
        # prune common heavy/vendored dirs early for speed
        dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS]
        for name in files:
            abs_path = os.path.join(root, name)
            if os.path.islink(abs_path):
                continue
            rel = os.path.relpath(abs_path, workdir)
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            ext = os.path.splitext(name)[1].lower()
            language = _LANG_BY_EXT.get(ext)
            is_binary = _looks_binary(abs_path)
            rel_padded = f"/{rel.lower()}/"
            is_vendored = any(m in rel_padded for m in _VENDOR_MARKERS)
            is_noise = any(m in rel_padded for m in _NOISE_MARKERS)
            lname = name.lower()
            is_generated = lname in _GENERATED_NAMES or lname.endswith(_GENERATED_SUFFIXES)
            included = (
                not is_binary
                and not is_vendored
                and not is_noise
                and not is_generated
                and language is not None
                and size <= settings.max_file_bytes_for_ai
            )
            result.files.append(
                FileEntry(
                    path=rel,
                    size_bytes=size,
                    language=language,
                    sha256=_sha256(abs_path) if included else None,
                    is_binary=is_binary,
                    is_vendored=is_vendored,
                    included=included,
                )
            )
            result.total_bytes += size
    return result


def _looks_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while data := fh.read(1 << 20):
            h.update(data)
    return h.hexdigest()
