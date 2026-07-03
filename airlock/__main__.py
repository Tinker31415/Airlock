"""Unified command line:  python -m airlock <command> [args]

Commands
  serve                       start the upload server (localhost)
  scan [--watch]              run the quarantine scanner (screens uploads)
  status                      operational snapshot
  janitor [--days N]          purge files held past the retention limit
  review <list|show|approve|delete|released> ...
  list  "<subproject>"        list cleared files for a subproject
  pull  "<subproject>" --dest DIR [--all]     decrypt files (default: new only)
  pull-new "<subproject>" --dest DIR          decrypt only newly-cleared files

Subprojects will more often import the client instead of shelling out:
  from airlock import Airlock
  Airlock("<subproject>").pull_new(dest="./data")
"""
from __future__ import annotations

import sys


def _client_pull(argv: list[str], only_new: bool) -> int:
    import argparse
    from .client import Airlock
    ap = argparse.ArgumentParser(prog="airlock pull")
    ap.add_argument("subproject")
    ap.add_argument("--dest", required=True)
    ap.add_argument("--all", action="store_true",
                    help="pull everything, not just new (implies pull, not pull-new)")
    ap.add_argument("--flat", action="store_true", help="do not prefix filenames with id")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    drop = Airlock(a.subproject, a.config)
    keep = not a.flat
    if only_new and not a.all:
        paths = drop.pull_new(a.dest, keep_name=keep)
    else:
        paths = drop.pull(a.dest, keep_name=keep)
    print(f"Decrypted {len(paths)} file(s) into {a.dest}")
    for p in paths:
        print(f"  {p}")
    return 0


def _client_list(argv: list[str]) -> int:
    import argparse
    from .client import Airlock
    ap = argparse.ArgumentParser(prog="airlock list")
    ap.add_argument("subproject")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    files = Airlock(a.subproject, a.config).list()
    if not files:
        print("No cleared files for this subproject.")
        return 0
    for f in files:
        print(f"  {f['id']}  {f['size_bytes']:>10}  {f['name']}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd, rest = sys.argv[1], sys.argv[2:]

    if cmd == "serve":
        import uvicorn
        from .config import load_config
        cfg = load_config()
        uvicorn.run("airlock.ingress:app", host=cfg.host, port=cfg.port)
        return 0
    if cmd == "scan":
        from . import pipeline
        sys.argv = ["airlock.scan", *rest]
        pipeline.main(); return 0
    if cmd == "status":
        from . import status
        sys.argv = ["airlock.status", *rest]
        status.main(); return 0
    if cmd == "janitor":
        from . import janitor
        sys.argv = ["airlock.janitor", *rest]
        janitor.main(); return 0
    if cmd == "review":
        from . import review
        sys.argv = ["airlock.review", *rest]
        review.main(); return 0
    if cmd == "list":
        return _client_list(rest)
    if cmd == "pull":
        return _client_pull(rest, only_new=True)
    if cmd == "pull-new":
        return _client_pull(rest, only_new=True)
    print(f"Unknown command: {cmd}\n")
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
