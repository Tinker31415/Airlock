"""Human review console for held files.

    python -m src.review list                 # show the held queue
    python -m src.review show   <file_id>      # full metadata + verdict
    python -m src.review approve <file_id>     # release to the vault for its subproject
    python -m src.review delete  <file_id>     # PERMANENT secure deletion
    python -m src.review released [subproject] # what has been released

Held files are stored encrypted. 'approve' decrypts and re-encrypts under the
target subproject's key; 'delete' securely overwrites and removes the ciphertext.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

from . import crypto, vault
from .config import Config, load_config
from .manifest import Manifest
from .pipeline import HELD_KEY_LABEL
from .securedelete import secure_delete


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def cmd_list(cfg: Config, manifest: Manifest, _args) -> None:
    rows = manifest.by_status("held")
    if not rows:
        print("Review queue is empty.")
        return
    print(f"{len(rows)} file(s) held for review:\n")
    for r in rows:
        print(f"  id={r['id']}")
        print(f"     name      : {r['original_name']}")
        print(f"     subproject: {r['subproject'] or '(unassigned)'}")
        print(f"     verdict   : {r['verdict']}")
        print(f"     reason    : {r['reason']}")
        print(f"     uploader  : {r['uploader']}   received: {_fmt_ts(r['received_at'])}")
        print(f"     sha256    : {r['sha256']}\n")


def cmd_show(cfg: Config, manifest: Manifest, args) -> None:
    r = manifest.get(args.file_id)
    if not r:
        print("No such file id.")
        return
    for k in r.keys():
        val = r[k]
        if k in ("received_at", "updated_at"):
            val = _fmt_ts(val)
        print(f"  {k:12}: {val}")


def cmd_approve(cfg: Config, master_key: bytes, manifest: Manifest, args) -> None:
    r = manifest.get(args.file_id)
    if not r or r["status"] != "held":
        print("File is not in the held state.")
        return
    held_enc = cfg.storage_dir / r["vault_path"]
    if not held_enc.exists():
        print(f"Ciphertext missing: {held_enc}")
        return
    held_key = crypto.derive_subproject_key(master_key, HELD_KEY_LABEL)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "plain.bin"
        crypto.decrypt_file_to(held_key, held_enc, tmp)
        rel = vault.store_clean_file(cfg, master_key, r["id"], r["subproject"], tmp)
        secure_delete(tmp)
    secure_delete(held_enc)
    manifest.update(r["id"], status="released", vault_path=rel,
                    reason="approved by reviewer")
    manifest.audit(r["id"], "approved", f"released to vault/{rel}")
    print(f"Approved. Released to vault/{rel} for subproject "
          f"'{r['subproject'] or '(unassigned)'}'.")


def cmd_delete(cfg: Config, master_key: bytes, manifest: Manifest, args) -> None:
    r = manifest.get(args.file_id)
    if not r:
        print("No such file id.")
        return
    if r["vault_path"]:
        target = cfg.storage_dir / r["vault_path"]
        secure_delete(target)
    if not args.yes:
        ans = input(f"Permanently destroy '{r['original_name']}' ({r['id']})? "
                    f"This cannot be undone [type DELETE]: ")
        if ans.strip() != "DELETE":
            print("Aborted.")
            return
    manifest.update(r["id"], status="deleted", vault_path=None,
                    reason=(args.reason or "securely deleted by reviewer"))
    manifest.audit(r["id"], "deleted", args.reason or "secure delete")
    print(f"Permanently deleted {r['id']} ({r['original_name']}).")


def cmd_released(cfg: Config, manifest: Manifest, args) -> None:
    if args.subproject:
        rows = manifest.released_for(args.subproject)
    else:
        rows = manifest.by_status("released")
    if not rows:
        print("Nothing released.")
        return
    for r in rows:
        print(f"  {r['id']}  {r['subproject'] or '(unassigned)':22}  "
              f"{r['original_name']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="secure-ingest review console")
    ap.add_argument("--config", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sp = sub.add_parser("show"); sp.add_argument("file_id")
    sp = sub.add_parser("approve"); sp.add_argument("file_id")
    sp = sub.add_parser("delete")
    sp.add_argument("file_id"); sp.add_argument("--yes", action="store_true")
    sp.add_argument("--reason", default="")
    sp = sub.add_parser("released"); sp.add_argument("subproject", nargs="?")
    args = ap.parse_args()

    cfg = load_config(args.config)
    cfg.ensure_dirs()
    manifest = Manifest(cfg.db_path)
    master_key = crypto.load_or_create_master_key(cfg.master_key_path)

    if args.cmd == "list":
        cmd_list(cfg, manifest, args)
    elif args.cmd == "show":
        cmd_show(cfg, manifest, args)
    elif args.cmd == "approve":
        cmd_approve(cfg, master_key, manifest, args)
    elif args.cmd == "delete":
        cmd_delete(cfg, master_key, manifest, args)
    elif args.cmd == "released":
        cmd_released(cfg, manifest, args)
    else:
        ap.print_help(); sys.exit(1)


if __name__ == "__main__":
    main()
