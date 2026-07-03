"""Example: a subproject's scheduled job that ingests newly-cleared files.

Schedule this daily/weekly/monthly (Windows Task Scheduler or the Cowork
scheduler). Thanks to the per-subproject cursor, each run only picks up files
cleared since the last run.

    python examples/subproject_daily_pull.py "BLR - open data mining"
"""
import sys
from pathlib import Path

from airlock import Airlock

SUBPROJECT = sys.argv[1] if len(sys.argv) > 1 else "BLR - open data mining"
DEST = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./data")


def process(path: Path) -> None:
    # Replace with your real background task.
    print(f"  processing {path.name} ({path.stat().st_size} bytes)")


def main() -> None:
    drop = Airlock(SUBPROJECT)
    new_files = drop.pull_new(dest=DEST)
    print(f"[{SUBPROJECT}] {len(new_files)} new file(s) cleared and pulled.")
    for p in new_files:
        process(p)


if __name__ == "__main__":
    main()
