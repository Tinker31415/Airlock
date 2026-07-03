"""SQLite manifest — the single source of truth for every file's lifecycle.

Every file that enters the system gets one row, tracked through states:

    received -> scanning -> clean|held -> released|deleted

The manifest also records who uploaded it, which subproject it is addressed to,
its sha256, the scanner verdict, and an append-only audit log of every action.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    sha256        TEXT,
    size_bytes    INTEGER,
    uploader      TEXT,
    subproject    TEXT,
    status        TEXT NOT NULL,        -- received|scanning|clean|held|released|deleted
    verdict       TEXT,                 -- scanner verdict text
    reason        TEXT,                 -- why held / deleted
    vault_path    TEXT,                 -- relative path inside vault (encrypted)
    received_at   REAL NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id   TEXT,
    ts        REAL NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT
);
CREATE TABLE IF NOT EXISTS cursors (
    subproject TEXT PRIMARY KEY,
    last_ts    REAL NOT NULL,        -- high-water mark of consumed files
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_subproject ON files(subproject);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);
"""


class Manifest:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- writes --------------------------------------------------------
    def create(self, original_name: str, uploader: str, subproject: Optional[str],
               size_bytes: int) -> str:
        fid = uuid.uuid4().hex
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO files (id, original_name, uploader, subproject, size_bytes,"
                " status, received_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (fid, original_name, uploader, subproject, size_bytes,
                 "received", now, now),
            )
        self.audit(fid, "received", f"name={original_name} uploader={uploader} "
                                    f"subproject={subproject}")
        return fid

    def update(self, file_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE files SET {cols} WHERE id=?",
                      (*fields.values(), file_id))

    def audit(self, file_id: Optional[str], action: str, detail: str = "") -> None:
        with self._conn() as c:
            c.execute("INSERT INTO audit (file_id, ts, action, detail) VALUES (?,?,?,?)",
                      (file_id, time.time(), action, detail))

    # ---- reads ---------------------------------------------------------
    def get(self, file_id: str) -> Optional[sqlite3.Row]:
        with self._conn() as c:
            cur = c.execute("SELECT * FROM files WHERE id=?", (file_id,))
            return cur.fetchone()

    def by_status(self, status: str) -> list[sqlite3.Row]:
        with self._conn() as c:
            cur = c.execute("SELECT * FROM files WHERE status=? ORDER BY received_at",
                            (status,))
            return cur.fetchall()

    def released_for(self, subproject: str) -> list[sqlite3.Row]:
        with self._conn() as c:
            cur = c.execute(
                "SELECT * FROM files WHERE status='released' AND subproject=? "
                "ORDER BY received_at", (subproject,))
            return cur.fetchall()

    def released_since(self, subproject: str, since_ts: float) -> list[sqlite3.Row]:
        """Released files for a subproject newer than a cursor timestamp."""
        with self._conn() as c:
            cur = c.execute(
                "SELECT * FROM files WHERE status='released' AND subproject=? "
                "AND received_at > ? ORDER BY received_at", (subproject, since_ts))
            return cur.fetchall()

    def held_older_than(self, cutoff_ts: float) -> list[sqlite3.Row]:
        """Files still awaiting clearance that entered before cutoff_ts."""
        with self._conn() as c:
            cur = c.execute(
                "SELECT * FROM files WHERE status='held' AND received_at < ? "
                "ORDER BY received_at", (cutoff_ts,))
            return cur.fetchall()

    def counts_by_status(self) -> dict[str, int]:
        with self._conn() as c:
            cur = c.execute("SELECT status, COUNT(*) n FROM files GROUP BY status")
            return {r["status"]: r["n"] for r in cur.fetchall()}

    def oldest_held_ts(self) -> Optional[float]:
        with self._conn() as c:
            cur = c.execute("SELECT MIN(received_at) m FROM files WHERE status='held'")
            row = cur.fetchone()
            return row["m"] if row and row["m"] is not None else None

    def seen_sha256(self, sha256: str) -> list[sqlite3.Row]:
        with self._conn() as c:
            cur = c.execute("SELECT * FROM files WHERE sha256=?", (sha256,))
            return cur.fetchall()

    # ---- per-subproject consumption cursor -----------------------------
    def get_cursor(self, subproject: str) -> float:
        with self._conn() as c:
            cur = c.execute("SELECT last_ts FROM cursors WHERE subproject=?",
                            (subproject,))
            row = cur.fetchone()
            return float(row["last_ts"]) if row else 0.0

    def set_cursor(self, subproject: str, last_ts: float) -> None:
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO cursors (subproject, last_ts, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(subproject) DO UPDATE SET last_ts=excluded.last_ts, "
                "updated_at=excluded.updated_at",
                (subproject, last_ts, now))
