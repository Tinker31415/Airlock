"""The quarantine pipeline: scan incoming files and route them.

Clean  -> encrypted into the vault, tagged to its subproject, status=released.
Held   -> encrypted into quarantine/held, status=held, awaiting your review.

Run continuously with:  python -m src.pipeline --watch
Or one pass with:       python -m src.pipeline
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from . import crypto, vault
from .config import Config, load_config
from .janitor import purge_expired
from .manifest import Manifest
from .scanner import ScanResult, load_bad_hashes, scan_file

HELD_KEY_LABEL = "_held"
POLL_SECONDS = 3


def _log(cfg: Config, msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    try:
        (cfg.logs_dir / "pipeline.log").open("a", encoding="utf-8").write(line + "\n")
    except OSError:
        pass


def _hold(cfg: Config, master_key: bytes, manifest: Manifest, file_id: str,
          plaintext: Path, res: ScanResult) -> None:
    key = crypto.derive_subproject_key(master_key, HELD_KEY_LABEL)
    dst = cfg.held_dir / f"{file_id}.enc"
    crypto.encrypt_file_to(key, plaintext, dst)
    plaintext.unlink(missing_ok=True)
    rel = str(dst.relative_to(cfg.storage_dir)).replace("\\", "/")
    manifest.update(file_id, status="held", verdict=res.reason, reason=res.detail,
                    vault_path=rel)
    manifest.audit(file_id, "held", f"{res.reason} :: {res.detail}")
    _log(cfg, f"HELD  {file_id}  [{res.reason}] {res.detail}")


def _release(cfg: Config, master_key: bytes, manifest: Manifest, file_id: str,
             subproject: str | None, plaintext: Path, res: ScanResult) -> None:
    rel = vault.store_clean_file(cfg, master_key, file_id, subproject, plaintext)
    plaintext.unlink(missing_ok=True)
    manifest.update(file_id, status="released", verdict=res.reason,
                    vault_path=rel, reason="auto-released: clean")
    manifest.audit(file_id, "released", f"vault={rel} subproject={subproject}")
    _log(cfg, f"CLEAN {file_id}  -> {rel}  (subproject={subproject})")


def process_one(cfg: Config, master_key: bytes, manifest: Manifest,
                bad_hashes: set[str], bin_path: Path) -> None:
    file_id = bin_path.stem
    sidecar = cfg.incoming_dir / f"{file_id}.json"
    meta = {}
    if sidecar.exists():
        try:
            meta = json.loads(sidecar.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            meta = {}

    row = manifest.get(file_id)
    original = meta.get("original_name") or (row["original_name"] if row else file_id)
    sha256 = meta.get("sha256") or (row["sha256"] if row else "")
    subproject = meta.get("subproject") if meta else (row["subproject"] if row else None)

    manifest.update(file_id, status="scanning")
    manifest.audit(file_id, "scanning", f"name={original}")

    # Move to working/ so a re-scan pass won't pick it up again mid-flight.
    working = cfg.working_dir / f"{file_id}.bin"
    cfg.working_dir.mkdir(parents=True, exist_ok=True)
    bin_path.rename(working)

    try:
        res = scan_file(cfg, working, original, sha256, bad_hashes)
        if res.clean:
            _release(cfg, master_key, manifest, file_id, subproject, working, res)
        else:
            _hold(cfg, master_key, manifest, file_id, working, res)
    finally:
        working.unlink(missing_ok=True)
        sidecar.unlink(missing_ok=True)


def run_pass(cfg: Config, master_key: bytes, manifest: Manifest) -> int:
    bad_hashes = load_bad_hashes(cfg)
    count = 0
    for bin_path in sorted(cfg.incoming_dir.glob("*.bin")):
        if bin_path.name.startswith("."):
            continue
        process_one(cfg, master_key, manifest, bad_hashes, bin_path)
        count += 1
    return count


def main() -> None:
    ap = argparse.ArgumentParser(description="secure-ingest quarantine pipeline")
    ap.add_argument("--watch", action="store_true", help="run continuously")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    cfg = load_config(args.config)
    cfg.ensure_dirs()
    master_key = crypto.load_or_create_master_key(cfg.master_key_path)
    manifest = Manifest(cfg.db_path)

    _log(cfg, f"pipeline starting (watch={args.watch}, clam_mode={cfg.clam_mode}, "
              f"fail_closed={cfg.fail_closed}, retention={cfg.held_retention_days}d)")
    if args.watch:
        last_janitor = 0.0
        while True:
            try:
                run_pass(cfg, master_key, manifest)
                # Run the retention janitor at most once an hour.
                if time.time() - last_janitor > 3600:
                    purge_expired(cfg, manifest, log=lambda m: _log(cfg, m))
                    last_janitor = time.time()
            except Exception as e:  # keep the daemon alive
                _log(cfg, f"ERROR in pass: {e!r}")
            time.sleep(POLL_SECONDS)
    else:
        n = run_pass(cfg, master_key, manifest)
        purge_expired(cfg, manifest, log=lambda m: _log(cfg, m))
        _log(cfg, f"processed {n} file(s)")


if __name__ == "__main__":
    main()
