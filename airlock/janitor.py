"""Retention janitor: permanently purge files stuck in the review queue.

Anything left in the 'held' (waiting-for-clearance) state longer than
config.held_retention_days (default 15) is securely deleted and its manifest
row is marked 'purged'. This bounds how long potentially-malicious or
unreviewed content can sit on disk.

Runs three ways:
  * automatically, once per hour, inside the scanner loop (pipeline.py);
  * on demand:      python -m airlock janitor
  * scheduled:      via the OS scheduler / Cowork scheduled task (see docs).
"""
from __future__ import annotations

import time
from pathlib import Path

from .config import Config, load_config
from .manifest import Manifest
from .securedelete import secure_delete


def purge_expired(cfg: Config, manifest: Manifest, retention_days: int | None = None,
                  log=print) -> list[str]:
    days = cfg.held_retention_days if retention_days is None else retention_days
    cutoff = time.time() - days * 86400
    purged: list[str] = []
    for r in manifest.held_older_than(cutoff):
        if r["vault_path"]:
            secure_delete(cfg.storage_dir / r["vault_path"])
        age_days = (time.time() - r["received_at"]) / 86400
        manifest.update(r["id"], status="purged", vault_path=None,
                        reason=f"auto-purged after {age_days:.1f}d in review queue "
                               f"(limit {days}d)")
        manifest.audit(r["id"], "purged",
                       f"retention {days}d exceeded; securely deleted")
        log(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  PURGE {r['id']}  "
            f"{r['original_name']}  (held {age_days:.1f}d)")
        purged.append(r["id"])
    return purged


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="airlock retention janitor")
    ap.add_argument("--config", default=None)
    ap.add_argument("--days", type=int, default=None,
                    help="override retention days (default from config)")
    args = ap.parse_args()
    cfg = load_config(args.config)
    cfg.ensure_dirs()
    manifest = Manifest(cfg.db_path)
    purged = purge_expired(cfg, manifest, args.days)
    print(f"Purged {len(purged)} expired file(s).")


if __name__ == "__main__":
    main()
