"""Symmetric encryption for at-rest secrets (DAST test-account credentials).

Credentials for live testing are the most sensitive data the app stores: they
grant access to the operator's own running systems. They are encrypted with a
key that lives *outside* the database (env / secret manager), so a database
dump alone never yields usable credentials.

Key source, in order:
  1. DAST_SECRET_KEY  — a urlsafe-base64 32-byte Fernet key (recommended; in
     prod this comes from Key Vault).
  2. derived from SECRET_KEY / a stable app secret, if one is set.
If neither is configured, credential *storage* is disabled and the API says so;
access-control replay can still run with per-run, in-memory credentials that are
never written to disk.

The ciphertext is versioned ("v1:") so the scheme can evolve.
"""

from __future__ import annotations

import base64
import hashlib
import logging

log = logging.getLogger(__name__)

_PREFIX = "v1:"


class SecretsDisabled(RuntimeError):
    """Raised when encryption is requested but no key is configured."""


def _load_key() -> bytes | None:
    """Return a 32-byte urlsafe-base64 Fernet key, or None if not configured."""
    import os

    from app.config import settings

    # Read the env directly first: the key can be set/rotated without rebuilding
    # the cached Settings object, and tests set it after import.
    raw = os.getenv("DAST_SECRET_KEY") or getattr(settings, "dast_secret_key", None)
    if raw:
        raw = raw.strip()
        try:
            # Accept a ready-made Fernet key…
            if len(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))) == 32:
                return raw.encode() if len(raw) == 44 else _to_fernet_key(raw)
        except Exception:  # noqa: BLE001
            pass
        return _to_fernet_key(raw)  # treat as a passphrase
    fallback = os.getenv("SECRET_KEY") or getattr(settings, "secret_key", None)
    if fallback:
        return _to_fernet_key(fallback)
    return None


def _to_fernet_key(material: str) -> bytes:
    """Derive a valid Fernet key from arbitrary secret material."""
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def secrets_available() -> bool:
    return _load_key() is not None


def _fernet():
    from cryptography.fernet import Fernet

    key = _load_key()
    if key is None:
        raise SecretsDisabled(
            "No encryption key configured. Set DAST_SECRET_KEY to store live-test "
            "credentials at rest.")
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a secret for storage. Returns a versioned token string."""
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt(token: str) -> str:
    """Decrypt a stored secret. Raises on a missing key or tampered ciphertext."""
    if not token.startswith(_PREFIX):
        raise ValueError("unrecognized secret format")
    return _fernet().decrypt(token[len(_PREFIX):].encode("ascii")).decode("utf-8")


def try_decrypt(token: str | None) -> str | None:
    """Best-effort decrypt; returns None on any failure (missing key, bad data)."""
    if not token:
        return None
    try:
        return decrypt(token)
    except Exception:  # noqa: BLE001
        log.warning("could not decrypt a stored secret (key rotated or missing?)")
        return None
