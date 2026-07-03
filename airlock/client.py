"""The Airlock client — how a subproject uses the shared infra *by name*.

    from airlock import Airlock

    drop = Airlock("BLR - open data mining")

    # Scheduled job (daily/weekly/monthly): grab only newly-cleared files.
    for path in drop.pull_new(dest="./data"):
        process(path)

    # Or list / inspect without consuming:
    for meta in drop.peek_new():
        print(meta["name"])

A subproject only ever sees files that were (a) cleared by the scanner and
(b) addressed to that subproject. Decryption uses the subproject's derived key,
so even direct access to another subproject's vault files yields nothing.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from . import crypto, vault
from .config import load_config
from .manifest import Manifest


def _row_meta(r) -> dict:
    return {"id": r["id"], "name": r["original_name"], "sha256": r["sha256"],
            "size_bytes": r["size_bytes"], "subproject": r["subproject"],
            "received_at": r["received_at"], "vault_path": r["vault_path"]}


class Airlock:
    def __init__(self, subproject: str, config_path: Optional[str] = None):
        if not subproject:
            raise ValueError("subproject name is required")
        self.subproject = subproject
        self.cfg = load_config(config_path)
        self.cfg.ensure_dirs()
        self._master = crypto.load_or_create_master_key(self.cfg.master_key_path)
        self.manifest = Manifest(self.cfg.db_path)

    # ---- inspection ----------------------------------------------------
    def list(self) -> list[dict]:
        """All cleared files addressed to this subproject."""
        return [_row_meta(r) for r in self.manifest.released_for(self.subproject)]

    def peek_new(self) -> list[dict]:
        """Cleared files newer than the consumption cursor (does not advance it)."""
        cur = self.manifest.get_cursor(self.subproject)
        return [_row_meta(r) for r in
                self.manifest.released_since(self.subproject, cur)]

    def pending_count(self) -> int:
        return len(self.peek_new())

    def stats(self) -> dict:
        rows = self.manifest.released_for(self.subproject)
        return {
            "subproject": self.subproject,
            "total_released": len(rows),
            "new_since_cursor": len(self.peek_new()),
            "cursor_ts": self.manifest.get_cursor(self.subproject),
            "bytes_released": sum((r["size_bytes"] or 0) for r in rows),
        }

    # ---- consumption ---------------------------------------------------
    def _decrypt_rows(self, rows, dest: Path, keep_name: bool) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        out: list[Path] = []
        for r in rows:
            if not r["vault_path"]:
                continue
            name = f"{r['id']}_{r['original_name']}" if keep_name else f"{r['id']}.bin"
            target = dest / name
            vault.decrypt_from_vault(self.cfg, self._master, self.subproject,
                                     r["vault_path"], target)
            self.manifest.audit(r["id"], "consumed",
                                f"subproject={self.subproject} -> {target.name}")
            out.append(target)
        return out

    def pull(self, dest: str | Path, keep_name: bool = True) -> list[Path]:
        """Decrypt ALL cleared files for this subproject into dest."""
        rows = self.manifest.released_for(self.subproject)
        return self._decrypt_rows(rows, Path(dest), keep_name)

    def pull_new(self, dest: str | Path, keep_name: bool = True) -> list[Path]:
        """Decrypt only files cleared since the last pull, then advance the cursor.

        This is the call a scheduled 'once a day/week/month' job should use:
        each run picks up exactly what arrived since it last ran.
        """
        cur = self.manifest.get_cursor(self.subproject)
        rows = self.manifest.released_since(self.subproject, cur)
        paths = self._decrypt_rows(rows, Path(dest), keep_name)
        if rows:
            newest = max(r["received_at"] for r in rows)
            self.manifest.set_cursor(self.subproject, newest)
        return paths

    def reset_cursor(self) -> None:
        """Forget what has been consumed; next pull_new returns everything again."""
        self.manifest.set_cursor(self.subproject, 0.0)
