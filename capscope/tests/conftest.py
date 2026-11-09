from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capscope import tshark  # noqa: E402
from capscope.config import settings  # noqa: E402

HAVE_TSHARK = True
try:
    tshark.tshark_path()
except tshark.TSharkNotFound:
    HAVE_TSHARK = False

needs_tshark = pytest.mark.skipif(not HAVE_TSHARK, reason="TShark not installed")


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    monkeypatch.setattr(settings, "data_dir", d)
    settings.ensure_dirs()
    # share the (slow) TShark field list between tests
    cache = Path(__file__).parent / ".fields-cache"
    cache.mkdir(exist_ok=True)
    for f in cache.glob("fields-*.txt"):
        shutil.copy(f, d / f.name)
    yield d
    for f in d.glob("fields-*.txt"):
        if not (cache / f.name).exists():
            shutil.copy(f, cache / f.name)


def index_file(path: str | Path, max_packets: int | None = None) -> int:
    from capscope import service
    r = service.register_capture(str(path), max_packets)
    job = service.start_index(r["id"])
    job.thread.join(timeout=300)
    assert job.state in ("done", "cancelled"), (job.state, job.error, job.result.get("traceback"))
    return r["id"]


def cdb(cid: int) -> sqlite3.Connection:
    from capscope.db import capture_db_path
    con = sqlite3.connect(capture_db_path(cid))
    con.row_factory = sqlite3.Row
    return con


def q(cid: int, sql: str, *args) -> list[dict]:
    con = cdb(cid)
    try:
        return [dict(r) for r in con.execute(sql, args)]
    finally:
        con.close()


def frames_comments(path: str | Path) -> list[tuple[int, str]]:
    rc, out, err = tshark.run(["-n", "-r", str(path), "-T", "fields", "-e", "frame.number", "-e", "frame.comment"])
    assert rc == 0, err
    res = []
    for line in out.splitlines():
        n, _, c = line.partition("\t")
        res.append((int(n), c))
    return res


_ = json
