"""Central configuration loader for the secure-ingest service.

All paths, secrets and the subproject registry live in config.yaml.
Nothing else in the codebase hard-codes a path or a secret.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Repo root = parent of the /src directory this file lives in.
ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    # Where the on-disk state lives (quarantine, vault, keys, logs, db).
    storage_dir: Path
    # Upload access secret. Anyone with this can POST files. Keep it private.
    upload_token: str
    # Bind address for the local ingress server (Cloudflare Tunnel points here).
    host: str
    port: int
    # Max upload size in bytes (defence against disk-fill).
    max_upload_bytes: int
    # Registered subprojects a file can be addressed to.
    subprojects: list[str]
    # ClamAV: how we talk to it. mode = "clamd" (daemon socket) or "clamscan" (cli).
    clam_mode: str
    clamd_host: str
    clamd_port: int
    clamscan_path: str
    # If the scanner cannot run, hold the file for review instead of releasing it.
    fail_closed: bool = True
    # Extensions we never auto-release even if a scanner reports clean.
    always_hold_extensions: list[str] = field(default_factory=list)
    # Files left in the review queue longer than this are permanently purged.
    held_retention_days: int = 15

    # ---- derived paths -------------------------------------------------
    @property
    def incoming_dir(self) -> Path:
        return self.storage_dir / "quarantine" / "incoming"

    @property
    def working_dir(self) -> Path:
        return self.storage_dir / "quarantine" / "working"

    @property
    def held_dir(self) -> Path:
        return self.storage_dir / "quarantine" / "held"

    @property
    def vault_dir(self) -> Path:
        return self.storage_dir / "vault"

    @property
    def keys_dir(self) -> Path:
        return self.storage_dir / "keys"

    @property
    def logs_dir(self) -> Path:
        return self.storage_dir / "logs"

    @property
    def db_path(self) -> Path:
        return self.storage_dir / "manifest.db"

    @property
    def master_key_path(self) -> Path:
        return self.keys_dir / "master.key"

    def ensure_dirs(self) -> None:
        for d in (
            self.incoming_dir,
            self.working_dir,
            self.held_dir,
            self.vault_dir,
            self.keys_dir,
            self.logs_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


def _resolve(base: Path, value: str) -> Path:
    p = Path(os.path.expanduser(value))
    return p if p.is_absolute() else (base / p).resolve()


def load_config(path: str | os.PathLike | None = None) -> Config:
    cfg_path = Path(path) if path else (ROOT / "config.yaml")
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Config not found at {cfg_path}. Copy config.example.yaml to config.yaml first."
        )
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    storage = _resolve(ROOT, data.get("storage_dir", "storage"))
    clam = data.get("clamav", {}) or {}

    cfg = Config(
        storage_dir=storage,
        upload_token=str(data.get("upload_token", "")).strip(),
        host=str(data.get("host", "127.0.0.1")),
        port=int(data.get("port", 8080)),
        max_upload_bytes=int(data.get("max_upload_mb", 512)) * 1024 * 1024,
        subprojects=list(data.get("subprojects", [])),
        clam_mode=str(clam.get("mode", "clamscan")),
        clamd_host=str(clam.get("host", "127.0.0.1")),
        clamd_port=int(clam.get("port", 3310)),
        clamscan_path=str(clam.get("clamscan_path", "clamscan")),
        fail_closed=bool(data.get("fail_closed", True)),
        always_hold_extensions=[e.lower() for e in data.get("always_hold_extensions", [])],
        held_retention_days=int(data.get("held_retention_days", 15)),
    )
    if not cfg.upload_token or cfg.upload_token in ("CHANGE_ME", "changeme"):
        raise ValueError("Set a strong 'upload_token' in config.yaml before starting.")
    return cfg
