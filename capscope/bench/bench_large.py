"""Reproducible large-file benchmark.

    python bench/bench_large.py --packets 2000000 --out bench/out

Generates a deterministic synthetic pcapng (seeded: mixed GTP-C / GTP-U / DNS / TCP),
indexes it with a fresh data directory and reports: file size, index time, peak
memory (this Python process and the TShark child, sampled every 100 ms), index DB
size, display-filter times (cold) and paged packet-list query times.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from capscope.config import settings  # noqa: E402


class PeakSampler(threading.Thread):
    def __init__(self, interval: float = 0.1):
        super().__init__(daemon=True)
        self.interval, self.stop_ev = interval, threading.Event()
        self.me = psutil.Process()
        self.peak_py = self.peak_children = self.peak_total = 0

    def run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                py = self.me.memory_info().rss
                ch = 0
                for c in self.me.children(recursive=True):
                    try:
                        ch += c.memory_info().rss
                    except psutil.Error:
                        pass
                self.peak_py = max(self.peak_py, py)
                self.peak_children = max(self.peak_children, ch)
                self.peak_total = max(self.peak_total, py + ch)
            except psutil.Error:
                pass
            time.sleep(self.interval)

    def stop(self) -> dict:
        self.stop_ev.set()
        self.join(2)
        mb = lambda v: round(v / 2**20, 1)
        return {"peak_rss_python_mib": mb(self.peak_py), "peak_rss_tshark_mib": mb(self.peak_children),
                "peak_rss_total_mib": mb(self.peak_total)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=int, default=2_000_000)
    ap.add_argument("--out", default=str(ROOT / "bench" / "out"))
    ap.add_argument("--reuse", action="store_true", help="reuse an existing generated file")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cap = out / f"bench_{a.packets}.pcapng"
    data = out / "data"
    shutil.rmtree(data, ignore_errors=True)
    settings.data_dir = data
    settings.ensure_dirs()

    from capscope import service, tshark
    from capscope.db import capture_db, capture_db_path, get_capture
    from capscope.jobs import jobs
    from capscope.synth import generate_large

    res: dict = {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                 "ram_gib": round(psutil.virtual_memory().total / 2**30, 1), "python": sys.version.split()[0],
                 "tshark": tshark.version(), "tshark_path": tshark.tshark_path(), "packets_requested": a.packets}
    if not (a.reuse and cap.exists()):
        t = time.time()
        g = generate_large(str(cap), a.packets)
        res["generate_s"] = round(time.time() - t, 1)
        res["packets"] = g["packets"]
    res["file_bytes"] = cap.stat().st_size
    res["file_mib"] = round(cap.stat().st_size / 2**20, 1)
    tshark.known_fields()  # field list is cached once per TShark version; not part of the index time

    sampler = PeakSampler()
    sampler.start()
    t = time.time()
    r = service.register_capture(str(cap))
    job = service.start_index(r["id"])
    job.thread.join()
    res["index_s"] = round(time.time() - t, 2)
    res.update(sampler.stop())
    c = get_capture(r["id"])
    res["index_status"] = c["status"]
    res["frames_indexed"] = c["frames"]
    res["index_rate_pps"] = round(c["frames"] / res["index_s"])
    res["index_db_mib"] = round(capture_db_path(r["id"]).stat().st_size / 2**20, 1)
    with capture_db(r["id"]) as con:
        res["counts"] = {k: con.execute(f"SELECT count(*) FROM {k}").fetchone()[0]
                         for k in ("transactions", "gtp_sessions", "gtpu_tunnels", "flows", "findings")}

    filters = ['dns.qry.name == "h4242.example.com"', "gtpv2.message_type == 32", "tcp.flags.syn == 1 && !gtp",
               "gtp.teid == 0x00300005"]
    res["filters"] = []
    for f in filters:
        sampler = PeakSampler()
        sampler.start()
        t = time.time()
        fr = service.start_filter(r["id"], f)
        jobs.get(fr["job"]["id"]).thread.join()
        el = round(time.time() - t, 2)
        mem = sampler.stop()
        with capture_db(r["id"]) as con:
            hits = con.execute("SELECT hits, status FROM filters WHERE id=?", (fr["filter"]["id"],)).fetchone()
        res["filters"].append({"expr": f, "seconds": el, "hits": hits[0], "status": hits[1],
                               "peak_rss_tshark_mib": mem["peak_rss_tshark_mib"]})

    # paged list queries (what the browser asks for): first page, deep page, filtered deep page
    from fastapi.testclient import TestClient
    from capscope.api import app, ensure_token
    cl = TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
    cl.get(f"/?token={ensure_token()}")
    pages = {}
    for name, params in (("first_page", {}), ("deep_page", {"around": c["frames"] // 2}),
                         ("filtered_deep_page", {"filter_id": 2, "around": c["frames"] // 2}),
                         ("time_window_page", {"t0": "1700000100000000000", "t1": "1700000101000000000"})):
        t = time.time()
        rr = cl.get(f"/api/captures/{r['id']}/packets", params={**params, "limit": 100})
        pages[name] = {"ms": round((time.time() - t) * 1000, 1), "rows": len(rr.json()["rows"])}
    res["page_queries"] = pages
    t = time.time()
    cl.get(f"/api/captures/{r['id']}/overview")
    res["overview_ms"] = round((time.time() - t) * 1000, 1)
    (out / "result.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
