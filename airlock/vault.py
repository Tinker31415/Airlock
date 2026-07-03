"""The encrypted vault: where cleared files live, isolated per subproject.

A cleared file is encrypted with its subproject's derived key and stored under
    vault/<subproject>/<file_id>.enc
Only a process holding that subproject's key can decrypt it. The plaintext never
touches disk inside the vault.
"""
from __future__ import annotations

from pathlib import Path

from . import crypto
from .config import Config

UNASSIGNED = "_unassigned"


def _safe_subproject(name: str | None) -> str:
    if not name:
        return UNASSIGNED
    # Prevent path traversal / weird chars in the folder name.
    keep = "".join(ch if (ch.isalnum() or ch in " -_") else "_" for ch in name)
    return keep.strip() or UNASSIGNED


def store_clean_file(cfg: Config, master_key: bytes, file_id: str,
                     subproject: str | None, plaintext_path: Path) -> str:
    """Encrypt plaintext_path into the vault.

    Returns the path relative to storage_dir (e.g. "vault/<subproject>/<id>.enc").
    Every stored path in the manifest is storage_dir-relative so the janitor,
    review console and clients all resolve it the same way.
    """
    sp = _safe_subproject(subproject)
    key = crypto.derive_subproject_key(master_key, sp)
    dst = cfg.vault_dir / sp / f"{file_id}.enc"
    crypto.encrypt_file_to(key, plaintext_path, dst)
    return str(dst.relative_to(cfg.storage_dir)).replace("\\", "/")


def decrypt_from_vault(cfg: Config, master_key: bytes, subproject: str,
                       storage_rel_path: str, dst: Path) -> None:
    """Decrypt one vault file (path relative to storage_dir) into dst."""
    sp = _safe_subproject(subproject)
    key = crypto.derive_subproject_key(master_key, sp)
    src = cfg.storage_dir / storage_rel_path
    crypto.decrypt_file_to(key, src, dst)
