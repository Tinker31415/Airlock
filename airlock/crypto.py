"""Encryption at rest + per-subproject key isolation.

Design
------
* A single 32-byte *master key* is generated once and stored in keys/master.key
  with restricted permissions. This is the root secret of the system.
* Each subproject gets its own key, *derived* from the master key via HKDF with
  the subproject name as the info/salt. A subproject task is only ever handed its
  own derived key, so holding it lets you decrypt that subproject's files and no
  others. The master key never leaves the ingestion host.
* Files are encrypted with Fernet (AES-128-CBC + HMAC-SHA256, authenticated).

Trust boundary (be honest): because the master key lives on the same always-on
machine, isolation is defence-in-depth, not a cryptographic guarantee against
someone who already has root on that box. It does mean a leaked *subproject* key,
a stolen vault file, or a compromised subproject process cannot read other
subprojects' data.
"""
from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_BYTES = 32
# Fixed salt keeps derivation deterministic across restarts; per-subproject
# separation comes from the `info` parameter, not the salt.
_HKDF_SALT = b"secure-ingest/v1/hkdf-salt"


def _restrict_perms(path: Path) -> None:
    """Best-effort lock-down of a secret file to the owner only."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 (POSIX)
    except (PermissionError, NotImplementedError, OSError):
        # On Windows chmod is limited; rely on NTFS ACLs / user profile perms.
        pass


def load_or_create_master_key(master_key_path: Path) -> bytes:
    if master_key_path.exists():
        raw = master_key_path.read_bytes()
        if len(raw) != MASTER_KEY_BYTES:
            raise ValueError(
                f"Master key at {master_key_path} is corrupt (expected {MASTER_KEY_BYTES} bytes)."
            )
        return raw
    master_key_path.parent.mkdir(parents=True, exist_ok=True)
    raw = os.urandom(MASTER_KEY_BYTES)
    master_key_path.write_bytes(raw)
    _restrict_perms(master_key_path)
    return raw


def derive_subproject_key(master_key: bytes, subproject: str) -> bytes:
    """Deterministically derive a 32-byte key for a subproject."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=f"subproject:{subproject}".encode("utf-8"),
    )
    return hkdf.derive(master_key)


def _fernet_for_key(key32: bytes) -> Fernet:
    # Fernet wants a urlsafe base64-encoded 32-byte key.
    return Fernet(base64.urlsafe_b64encode(key32))


def encrypt_bytes(key32: bytes, plaintext: bytes) -> bytes:
    return _fernet_for_key(key32).encrypt(plaintext)


def decrypt_bytes(key32: bytes, token: bytes) -> bytes:
    return _fernet_for_key(key32).decrypt(token)


def encrypt_file_to(key32: bytes, src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(encrypt_bytes(key32, src.read_bytes()))
    _restrict_perms(dst)


def decrypt_file_to(key32: bytes, src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(decrypt_bytes(key32, src.read_bytes()))
