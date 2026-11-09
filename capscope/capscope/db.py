"""SQLite storage.

* ``catalog.sqlite``: opened captures, incidents, exports (small).
* ``captures/<id>/index.sqlite``: one disk-based index per capture (packets,
  analyzer tables, filter results). Deleting/re-indexing a capture is a file
  removal; later multi-capture work can ATTACH several of them.

Packet provenance kept per row: capture id (= the database), pcapng section,
interface id, original frame number (PRIMARY KEY) and the timestamp as an
integer number of nanoseconds since the epoch (lossless for us/ns captures).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import settings

CATALOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures(
  id INTEGER PRIMARY KEY, path TEXT NOT NULL, name TEXT, size INTEGER, mtime REAL, sha256 TEXT,
  format TEXT, status TEXT, created_at TEXT, finished_at TEXT, frames INTEGER DEFAULT 0,
  error TEXT, partial INTEGER DEFAULT 0, partial_reason TEXT, display_offset_ns INTEGER DEFAULT 0,
  tshark_version TEXT, info_json TEXT, limits_json TEXT, max_packets INTEGER, index_seconds REAL);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY, title TEXT, description TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS incident_items(
  id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL, kind TEXT, capture_id INTEGER, frame_no INTEGER,
  ref_table TEXT, ref_id INTEGER, ts_ns INTEGER, title TEXT, title_en TEXT, note TEXT, state TEXT, rule TEXT,
  frames_json TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS exports(
  id INTEGER PRIMARY KEY, file TEXT, kind TEXT, masked INTEGER, capture_id INTEGER, incident_id INTEGER,
  created_at TEXT, frames INTEGER, note TEXT, contains_secrets INTEGER DEFAULT 0);
"""

CAPTURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS packets(
  frame_no INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, section INTEGER, iface INTEGER,
  caplen INTEGER, len INTEGER, src TEXT, dst TEXT, sport INTEGER, dport INTEGER,
  osrc TEXT, odst TEXT, proto TEXT, info TEXT, offset INTEGER, tcp_stream INTEGER, udp_stream INTEGER);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, analyzer TEXT, rule TEXT, state TEXT, severity TEXT, ts_ns INTEGER,
  title TEXT, detail TEXT, frames TEXT, obj_type TEXT, obj_id INTEGER, title_en TEXT);
CREATE TABLE IF NOT EXISTS filters(
  id INTEGER PRIMARY KEY, expr TEXT, two_pass INTEGER, status TEXT, hits INTEGER DEFAULT 0,
  scanned_to INTEGER, partial_reason TEXT, error TEXT, created_at TEXT, elapsed_s REAL);
CREATE TABLE IF NOT EXISTS filter_hits(
  filter_id INTEGER NOT NULL, frame_no INTEGER NOT NULL, PRIMARY KEY(filter_id, frame_no)) WITHOUT ROWID;
"""

POST_INDEX = """
CREATE INDEX IF NOT EXISTS ix_packets_ts ON packets(ts_ns);
CREATE INDEX IF NOT EXISTS ix_packets_src ON packets(src);
CREATE INDEX IF NOT EXISTS ix_packets_dst ON packets(dst);
CREATE INDEX IF NOT EXISTS ix_findings_ts ON findings(ts_ns);
CREATE INDEX IF NOT EXISTS ix_packets_tcp ON packets(tcp_stream) WHERE tcp_stream IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_packets_udp ON packets(udp_stream) WHERE udp_stream IS NOT NULL;
"""


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def connect(path: Path | str, bulk: bool = False) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=30, check_same_thread=False, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF" if bulk else "PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA temp_store=FILE")
    con.execute("PRAGMA cache_size=-65536")  # 64 MiB page cache cap per connection
    return con


_cat_lock = threading.Lock()


@contextmanager
def catalog() -> Iterator[sqlite3.Connection]:
    settings.ensure_dirs()
    con = connect(settings.catalog_path)
    try:
        with _cat_lock:
            con.executescript(CATALOG_SCHEMA)
        yield con
    finally:
        con.close()


def capture_dir(cid: int) -> Path:
    return settings.captures_dir / str(int(cid))


def capture_db_path(cid: int) -> Path:
    return capture_dir(cid) / "index.sqlite"


@contextmanager
def capture_db(cid: int) -> Iterator[sqlite3.Connection]:
    p = capture_db_path(cid)
    if not p.is_file():
        raise FileNotFoundError("Ehhez a capture-höz még nincs index.")
    con = connect(p)
    try:
        yield con
    finally:
        con.close()


def rows(cur: sqlite3.Cursor) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def get_capture(cid: int) -> dict | None:
    with catalog() as c:
        r = c.execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["info"] = json.loads(d.pop("info_json") or "{}")
    d["limits"] = json.loads(d.pop("limits_json") or "{}")
    return d


def update_capture(cid: int, **kw: Any) -> None:
    if "info" in kw:
        kw["info_json"] = json.dumps(kw.pop("info"))
    if "limits" in kw:
        kw["limits_json"] = json.dumps(kw.pop("limits"))
    cols = ", ".join(f"{k}=?" for k in kw)
    with catalog() as c:
        c.execute(f"UPDATE captures SET {cols} WHERE id=?", (*kw.values(), cid))


class BatchWriter:
    """executemany in fixed-size batches; never keeps more than ``size`` rows."""

    def __init__(self, con: sqlite3.Connection, sql: str, size: int = 5000):
        self.con, self.sql, self.size, self.buf = con, sql, size, []
        self.count = 0

    def add(self, row: tuple) -> None:
        self.buf.append(row)
        if len(self.buf) >= self.size:
            self.flush()

    def flush(self) -> None:
        if self.buf:
            self.con.executemany(self.sql, self.buf)
            self.count += len(self.buf)
            self.buf.clear()
