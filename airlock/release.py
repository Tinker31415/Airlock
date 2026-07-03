"""Subproject access layer.

This is what a subproject's background task uses to get *its own* cleared files
and nothing else. A subproject is identified by name; its files are decrypted
with the key derived for that name. Ask for another subproject's files and the
decryption simply fails (wrong key), so isolation is enforced by cryptography,
not by convention.

CLI:
    python -m src.release list  "<subproject>"
    python -m src.release fetch "<subproject>" --dest <dir> [--id <file_id>] [--keep-name]

Library (use inside a subproject's task):
    from src.release import list_files, fetch_all
    for meta in list_files("BLR - open data mining"):
        ...
    paths = fetch_all("BLR - open data mining", dest="./_inbox")
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from . import crypto, vault
from .config import Config, load_config
from .manifest import Manifest


def _ctx(config_path: Optional[str] = None):
    cfg = load_config(config_path)
    cfg.ensure_dirs()
    master_key = crypto.load_or_create_master_key(cfg.master_key_path)
    manifest = Manifest(cfg.db_path)
    return cfg, master_key, manifest


def list_files(subproject: str, config_path: Optional[str] = None) -> list[dict]:
    _, _, manifest = _ctx(config_path)
    return [
        {"id": r["id"], "name": r["original_name"], "sha256": r["sha256"],
         "size_bytes": r["size_bytes"], "vault_path": r["vault_path"]}
        for r in manifest.released_for(subproject)
    ]


def fetch_all(subproject: str, dest: str | Path, file_id: Optional[str] = None,
              keep_name: bool = False, config_path: Optional[str] = None) -> list[Path]:
    """Decrypt this subproject's released files into `dest`. Returns written paths."""
    cfg, master_key, manifest = _ctx(config_path)
    dest_dir = Path(dest)
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for r in manifest.released_for(subproject):
        if file_id and r["id"] != file_id:
            continue
        if not r["vault_path"]:
            continue
        if keep_name:
            out = dest_dir / f"{r['id']}_{r['original_name']}"
        else:
            out = dest_dir / f"{r['id']}.bin"
        vault.decrypt_from_vault(cfg, master_key, subproject, r["vault_path"], out)
        written.append(out)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description="secure-ingest subproject access")
    ap.add_argument("--config", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    lp = sub.add_parser("list"); lp.add_argument("subproject")
    fp = sub.add_parser("fetch")
    fp.add_argument("subproject")
    fp.add_argument("--dest", required=True)
    fp.add_argument("--id", default=None)
    fp.add_argument("--keep-name", action="store_true")
    args = ap.parse_args()

    if args.cmd == "list":
        files = list_files(args.subproject, args.config)
        if not files:
            print("No released files for this subproject.")
            return
        for f in files:
            print(f"  {f['id']}  {f['size_bytes']:>10}  {f['name']}")
    elif args.cmd == "fetch":
        paths = fetch_all(args.subproject, args.dest, args.id, args.keep_name, args.config)
        print(f"Decrypted {len(paths)} file(s) into {args.dest}")
        for p in paths:
            print(f"  {p}")


if __name__ == "__main__":
    main()
