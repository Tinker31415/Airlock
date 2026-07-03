"""`airlock status` — a quick operational snapshot."""
from __future__ import annotations

import time
from pathlib import Path

from .config import Config, load_config
from .manifest import Manifest


def _dir_size(path: Path) -> int:
    total = 0
    if path.exists():
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    return total


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def render(cfg: Config, manifest: Manifest) -> str:
    counts = manifest.counts_by_status()
    oldest = manifest.oldest_held_ts()
    lines = ["Airlock status", "=" * 40]
    order = ["received", "scanning", "held", "released", "deleted", "purged"]
    for st in order:
        if st in counts:
            lines.append(f"  {st:10}: {counts[st]}")
    for st, n in counts.items():
        if st not in order:
            lines.append(f"  {st:10}: {n}")

    if oldest:
        age = (time.time() - oldest) / 86400
        warn = "  <-- approaching purge!" if age > (cfg.held_retention_days - 3) else ""
        lines.append(f"\n  oldest held : {age:.1f} days "
                     f"(retention limit {cfg.held_retention_days}d){warn}")

    lines.append("\nStorage")
    lines.append(f"  vault      : {_human(_dir_size(cfg.vault_dir))}")
    lines.append(f"  quarantine : {_human(_dir_size(cfg.storage_dir / 'quarantine'))}")
    lines.append(f"  held       : {_human(_dir_size(cfg.held_dir))}")

    lines.append("\nSubprojects (released / new-since-cursor)")
    for sp in cfg.subprojects:
        rel = manifest.released_for(sp)
        new = manifest.released_since(sp, manifest.get_cursor(sp))
        lines.append(f"  {sp:30}: {len(rel):4} / {len(new)}")
    return "\n".join(lines)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="airlock status")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    cfg.ensure_dirs()
    print(render(cfg, Manifest(cfg.db_path)))


if __name__ == "__main__":
    main()
