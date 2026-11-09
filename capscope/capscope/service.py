"""Capture registry, display-filter jobs, packet detail and stream follow."""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from . import tshark
from .capfile import CaptureFormatError, export_pcapng, read_frame_bytes, sniff_format
from .config import settings
from .db import (BatchWriter, capture_db, capture_dir, catalog, get_capture, rows, update_capture, utcnow)
from .indexer import run_index
from .jobs import Job, jobs
from .tempfiles import temp_dir


class UserError(ValueError):
    """Error message meant for the UI (Hungarian)."""


# ---------------------------------------------------------------------------
# Capture registry
# ---------------------------------------------------------------------------

def normalize_path(raw: str) -> Path:
    s = (raw or "").strip().strip('"').strip("'").strip()
    if not s:
        raise UserError("Adj meg egy fájlútvonalat.")
    if "\x00" in s:
        raise UserError("Érvénytelen útvonal.")
    p = Path(os.path.expandvars(s)).expanduser()
    try:
        p = p.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise UserError(f"A fájl nem található: {s}")
    if not p.is_file():
        raise UserError("Az útvonal nem egy fájlra mutat.")
    low = p.name.lower()
    if not any(low.endswith(ext) for ext in settings.allowed_ext):
        raise UserError("Csak capture-fájl nyitható meg (.pcap, .pcapng, .cap, .ntar, .pcap.gz, .pcapng.gz).")
    try:
        fmt = sniff_format(str(p))
    except OSError as e:
        raise UserError(f"A fájl nem olvasható: {e}")
    if not fmt:
        raise UserError("A fájl nem pcap/pcapng formátumú (a fejléc nem ismerhető fel).")
    return p


def register_capture(raw_path: str, max_packets: int | None = None) -> dict:
    p = normalize_path(raw_path)
    st = p.stat()
    with catalog() as c:
        r = c.execute("SELECT id, status FROM captures WHERE path=? AND size=? AND mtime=?",
                      (str(p), st.st_size, st.st_mtime)).fetchone()
        if r and r["status"] in ("ready", "partial") and not max_packets:
            return {"id": r["id"], "existing": True}
        cur = c.execute("INSERT INTO captures(path, name, size, mtime, format, status, created_at, max_packets) "
                        "VALUES (?,?,?,?,?,?,?,?)", (str(p), p.name, st.st_size, st.st_mtime, sniff_format(str(p)),
                                                     "queued", utcnow(), max_packets))
        cid = cur.lastrowid
    return {"id": cid, "existing": False}


def start_index(cid: int) -> Job:
    if jobs.active_for(cid, "index"):
        raise UserError("Ennek a capture-nek az indexelése már fut.")
    cap = get_capture(cid)
    if cap is None:
        raise UserError("Ismeretlen capture.")
    for j in jobs.active_for(cid):
        j.cancel()
    return jobs.start("index", cid, f"Indexelés: {cap['name']}", lambda job: run_index(job, cid))


def delete_capture(cid: int) -> None:
    for j in jobs.active_for(cid):
        j.cancel()
        if j.thread:
            j.thread.join(timeout=10)
    shutil.rmtree(capture_dir(cid), ignore_errors=True)
    with catalog() as c:
        c.execute("DELETE FROM captures WHERE id=?", (cid,))


def recover_after_restart() -> None:
    """Imports that were running when the app stopped are marked, their partial index stays browsable."""
    with catalog() as c:
        c.execute("UPDATE captures SET status='interrupted', partial=1, partial_reason=? "
                  "WHERE status IN ('indexing','queued')",
                  ("Az import megszakadt (az alkalmazás leállt). Az index részleges; indítsd újra az indexelést.",))


def list_captures() -> list[dict]:
    with catalog() as c:
        out = rows(c.execute("SELECT id, name, path, size, status, frames, partial, partial_reason, created_at, "
                             "finished_at, format, sha256, index_seconds FROM captures ORDER BY id DESC"))
    for r in out:
        r["running_jobs"] = [j.to_dict() for j in jobs.active_for(r["id"])]
    return out


def require_capture(cid: int, need_index: bool = True) -> dict:
    cap = get_capture(cid)
    if cap is None:
        raise UserError("Ismeretlen capture.")
    if need_index and not (capture_dir(cid) / "index.sqlite").is_file():
        raise UserError("Ehhez a capture-höz még nincs index.")
    return cap


def file_changed(cap: dict) -> bool:
    try:
        st = os.stat(cap["path"])
    except OSError:
        return True
    return st.st_size != cap["size"] or abs(st.st_mtime - cap["mtime"]) > 1e-6


def require_unchanged(cap: dict) -> None:
    if file_changed(cap):
        raise UserError("A capture-fájl megváltozott vagy nem elérhető az indexelés óta. Indexeld újra, mielőtt "
                        "csomagtartalmat olvasol vagy exportálsz (az offsetek és csomagszámok érvénytelenek lehetnek).")


def indexed_frames(cap: dict) -> int:
    return int(cap.get("frames") or 0)


# ---------------------------------------------------------------------------
# Display filters
# ---------------------------------------------------------------------------

def start_filter(cid: int, expr: str, two_pass: bool = False) -> dict:
    cap = require_capture(cid)
    require_unchanged(cap)
    expr = (expr or "").strip()
    ok, msg, raw = tshark.validate_filter(expr)
    if not ok:
        return {"ok": False, "error": msg, "tshark": raw}
    with capture_db(cid) as con:
        r = con.execute("SELECT * FROM filters WHERE expr=? AND two_pass=? AND status='done'",
                        (expr, int(two_pass))).fetchone()
        if r:
            return {"ok": True, "filter": dict(r), "cached": True}
        cur = con.execute("INSERT INTO filters(expr, two_pass, status, created_at) VALUES (?,?,?,?)",
                          (expr, int(two_pass), "running", utcnow()))
        fid = cur.lastrowid
    job = jobs.start("filter", cid, f"Szűrés: {expr}", lambda j: _run_filter(j, cid, fid, expr, two_pass))
    return {"ok": True, "filter": {"id": fid, "expr": expr, "status": "running"}, "job": job.to_dict()}


def _run_filter(job: Job, cid: int, fid: int, expr: str, two_pass: bool) -> None:
    cap = get_capture(cid)
    n_idx = indexed_frames(cap)
    args = ["-n", "-r", cap["path"], "-Y", expr, "-T", "fields", "-e", "frame.number"]
    if two_pass:
        args.insert(0, "-2")
    if cap.get("partial") and n_idx:
        args += ["-c", str(n_idx)]
    t0 = time.time()
    proc = tshark.popen(args)
    job.attach(proc)
    err = tshark.StderrCollector(proc.stderr)
    from .db import connect, capture_db_path
    con = connect(capture_db_path(cid), bulk=True)
    w = BatchWriter(con, "INSERT OR IGNORE INTO filter_hits(filter_id, frame_no) VALUES (?,?)", 10000)
    hits, last, reason = 0, 0, None
    con.execute("BEGIN")
    try:
        for raw in proc.stdout:
            if job.cancelled():
                reason = "cancelled"
                break
            try:
                fr = int(raw.strip())
            except ValueError:
                continue
            w.add((fid, fr))
            hits += 1
            last = fr
            if hits % 10000 == 0:
                job.progress = min(0.99, last / max(1, n_idx))
                job.counters.update(hits=hits, scanned_to=last)
            if hits >= settings.filter_max_hits:
                reason = "limit"
                break
            if time.time() - t0 > settings.filter_timeout_s:
                reason = "timeout"
                break
        if reason:
            job._kill()
        proc.wait()
        w.flush()
        stderr = err.text()
        status = "done" if reason is None else "partial"
        notes = {"cancelled": "A szűrést a felhasználó megszakította",
                 "limit": f"Találati korlát ({settings.filter_max_hits}) elérve",
                 "timeout": f"Időtúllépés ({settings.filter_timeout_s} s)"}
        pr = None
        if reason:
            pr = f"{notes[reason]} a(z) {last}. csomagnál; a lista csak az eddigi találatokat tartalmazza."
        if proc.returncode not in (0, None) and reason is None:
            status, pr = "failed", f"A TShark hibával állt le: {stderr[:300]}"
        con.execute("UPDATE filters SET status=?, hits=?, scanned_to=?, partial_reason=?, error=?, elapsed_s=? "
                    "WHERE id=?", (status, hits, last, pr, stderr[:500] or None, round(time.time() - t0, 3), fid))
        con.execute("COMMIT")
    finally:
        con.close()
    job.result = {"filter_id": fid, "hits": hits, "status": status}
    job.progress = 1.0
    if reason == "cancelled":
        job.state = "cancelled"


# ---------------------------------------------------------------------------
# Packet detail (PDML tree + hex)
# ---------------------------------------------------------------------------

DEP_FIELDS = {"tcp.segment": "TCP-szegmens (reassembly)", "ip.fragment": "IPv4-fragmens",
              "ipv6.fragment": "IPv6-fragmens", "tcp.reassembled_in": "Ebben a csomagban áll össze",
              "ip.reassembled_in": "IPv4 reassembly itt", "ipv6.reassembled_in": "IPv6 reassembly itt",
              "dns.response_in": "DNS válasz (TShark)", "dns.response_to": "DNS kérés (TShark)",
              "gtpv2.response_in": "GTPv2 válasz (TShark)", "gtpv2.response_to": "GTPv2 kérés (TShark)",
              "gtp.response_in": "GTP válasz (TShark)", "gtp.response_to": "GTP kérés (TShark)",
              "frame.response_in": "Válasz", "tcp.analysis.retransmission": None}


def _pdml_tree(xml_text: str) -> tuple[list[dict], list[dict]]:
    root = ET.fromstring(xml_text)
    pkt = root.find("packet")
    if pkt is None:
        return [], []
    deps: list[dict] = []

    def conv(el) -> dict | None:
        name = el.get("name") or ""
        if el.tag == "proto" and name == "geninfo":
            return None
        if el.get("hide") == "yes":
            return None
        show = el.get("showname") or el.get("show") or name
        node = {"name": name, "text": show}
        if el.get("pos") is not None and el.get("size") not in (None, "0"):
            try:
                node["pos"], node["size"] = int(el.get("pos")), int(el.get("size"))
            except ValueError:
                pass
        if name in DEP_FIELDS and DEP_FIELDS[name] and el.get("show", "").isdigit():
            deps.append({"field": name, "role": DEP_FIELDS[name], "frame": int(el.get("show"))})
        kids = [c for c in (conv(ch) for ch in el) if c is not None]
        if kids:
            node["children"] = kids
        return node

    tree = [n for n in (conv(ch) for ch in pkt) if n is not None]
    return tree, deps


def packet_detail(cid: int, frame: int, mode: str = "context") -> dict:
    cap = require_capture(cid)
    require_unchanged(cap)
    with capture_db(cid) as con:
        row = con.execute("SELECT * FROM packets WHERE frame_no=?", (frame,)).fetchone()
    if row is None:
        raise UserError(f"A(z) {frame}. csomag nincs az indexben.")
    row = dict(row)
    info = cap["info"]
    t0 = time.time()
    note = ""
    random_access = info.get("random_access") and row.get("offset") is not None
    if mode == "isolated" and random_access:
        with temp_dir("detail") as d:
            one = str(Path(d) / "one.pcapng")
            export_pcapng(cap["path"], info, [{"frame_no": frame, "offset": row["offset"], "section": row["section"],
                                                "iface": row["iface"]}], one, source_label=cap["name"])
            rc, out, err = tshark.run(["-n", "-r", one, "-T", "pdml"], timeout=settings.detail_timeout_s)
        note = ("Izolált dekódolás: csak ez az egy csomag lett dekódolva, előzmények (TCP-reassembly, "
                "IP-defragmentálás, kérés-válasz állapot) nélkül.")
    else:
        try:
            rc, out, err = tshark.run(["-n", "-r", cap["path"], "-c", str(frame), "-Y", f"frame.number=={frame}",
                                       "-T", "pdml"], timeout=settings.detail_timeout_s)
        except subprocess.TimeoutExpired:
            raise UserError(f"A dekódolás időtúllépés miatt megszakadt ({settings.detail_timeout_s} s). Próbáld az "
                            "'Izolált' módot (előzmények nélkül).")
        note = (f"Kontextusos dekódolás: a TShark az 1–{frame}. csomagot dolgozta fel, így a reassembly és a "
                "protokollállapot az előzményekből épül fel (a későbbi csomagokra mutató hivatkozások hiányozhatnak).")
        mode = "context"
    tree, deps = _pdml_tree(out) if out.strip() else ([], [])
    hexdata = None
    if random_access:
        try:
            hexdata = read_frame_bytes(cap["path"], row["offset"], info["format"],
                                       _section_endian(info, row["section"])).hex()
        except (OSError, CaptureFormatError, KeyError):
            hexdata = None
    return {"packet": row, "tree": tree, "deps": deps, "hex": hexdata, "mode": mode, "note": note,
            "elapsed_s": round(time.time() - t0, 3), "tshark_error": err if rc else ""}


def _section_endian(info: dict, section: int | None) -> str:
    if info.get("format") == "pcap":
        return info.get("endian", "<")
    for s in info.get("sections", []):
        if s["section"] == section:
            return s["endian"]
    return "<"


# ---------------------------------------------------------------------------
# Follow stream
# ---------------------------------------------------------------------------

def follow_stream(cid: int, l4: str, stream: int) -> dict:
    if l4 not in ("tcp", "udp"):
        raise UserError("Csak TCP vagy UDP stream követhető.")
    cap = require_capture(cid)
    require_unchanged(cap)
    args = ["-n", "-r", cap["path"], "-q", "-z", f"follow,{l4},yaml,{int(stream)}"]
    if cap.get("partial") and indexed_frames(cap):
        args[4:4] = ["-c", str(indexed_frames(cap))]
    t0 = time.time()
    try:
        rc, out, err = tshark.run(args, timeout=settings.follow_timeout_s)
    except subprocess.TimeoutExpired:
        raise UserError(f"A stream követése időtúllépés miatt megszakadt ({settings.follow_timeout_s} s).")
    peers, chunks = {}, []
    cur = None
    total, truncated = 0, False
    lines = out.splitlines()
    i = 0
    section = None
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if s == "peers:":
            section = "peers"
        elif s == "packets:":
            section = "packets"
        elif section == "peers" and s.startswith("- peer:"):
            cur = {"peer": int(s.split(":", 1)[1])}
            peers[cur["peer"]] = cur
        elif section == "peers" and ":" in s and cur is not None:
            k, v = s.split(":", 1)
            cur[k.strip()] = v.strip()
        elif section == "packets" and s.startswith("- packet:"):
            cur = {"frame": int(s.split(":", 1)[1])}
            chunks.append(cur)
        elif section == "packets" and s.startswith("peer:"):
            cur["peer"] = int(s.split(":", 1)[1])
        elif section == "packets" and s.startswith("timestamp:"):
            cur["ts"] = s.split(":", 1)[1].strip()
        elif section == "packets" and s.startswith("data:"):
            b64 = []
            j = i + 1
            while j < len(lines) and lines[j].startswith("      "):
                b64.append(lines[j].strip())
                j += 1
            i = j - 1
            data = base64.b64decode("".join(b64)) if b64 else b""
            if total + len(data) > settings.follow_max_bytes:
                data = data[: max(0, settings.follow_max_bytes - total)]
                truncated = True
            total += len(data)
            cur["len"] = len(data)
            cur["hex"] = data.hex()
            cur["text"] = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)
            cur.pop("ts", None)
            if truncated:
                break
        i += 1
    return {"peers": list(peers.values()), "chunks": chunks, "bytes": total, "truncated": truncated,
            "limit": settings.follow_max_bytes, "elapsed_s": round(time.time() - t0, 3), "tshark_error": err if rc else ""}


def wipe_tmp(max_age_s: float = 6 * 3600) -> int:
    n = 0
    if not settings.tmp_dir.is_dir():
        return 0
    for p in settings.tmp_dir.iterdir():
        try:
            if time.time() - p.stat().st_mtime > max_age_s:
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink()
                n += 1
        except OSError:
            pass
    return n


_ = (json, re)
