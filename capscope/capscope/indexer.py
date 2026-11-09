"""Single-pass indexer: TShark ``-T fields`` stream + pcap/pcapng block walker.

Both iterate the file in frame order, so they are zipped frame-by-frame: TShark
supplies dissected fields, the walker supplies file offset, section, interface
and the raw timestamp. Rows are written in batches; only analyzer state (bounded
by time windows / flow limits) is kept in memory, never the packet list.
"""
from __future__ import annotations

import json
import shutil
import time

from . import tshark
from .analyzers import discover
from .analyzers.base import AGG, Context, Cut, Packet
from .capfile import CaptureFormatError, CaptureWalker
from .config import settings
from .db import (CAPTURE_SCHEMA, POST_INDEX, BatchWriter, capture_db_path, capture_dir, connect, get_capture,
                 update_capture, utcnow)
from .jobs import Job

BASE_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.interface_id",
               "frame.section_number", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]

PACKET_INSERT = ("INSERT INTO packets(frame_no, ts_ns, section, iface, caplen, len, src, dst, sport, dport, osrc, odst,"
                 " proto, info, offset, tcp_stream, udp_stream) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


def parse_epoch_ns(s: str) -> int:
    """'1700000000.123456789' -> integer ns, without going through float."""
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    sec, _, frac = s.partition(".")
    v = int(sec or 0) * 1_000_000_000 + int((frac + "000000000")[:9])
    return -v if neg else v


def build_field_list(analyzer_classes) -> tuple[list[str], list[str]]:
    known = tshark.known_fields()
    wanted = list(BASE_FIELDS) + [tshark.column_field("protocol")]
    for cls in analyzer_classes:
        for f in cls.fields:
            if f not in wanted:
                wanted.append(f)
    fields = [f for f in wanted if f in known or f.startswith("_ws.col")]
    missing = [f for f in wanted if f not in fields]
    fields.append(tshark.column_field("info"))  # last: may contain anything, split with maxsplit
    return fields, missing


def run_index(job: Job, cid: int) -> None:
    cap = get_capture(cid)
    if cap is None:
        raise ValueError("Ismeretlen capture.")
    path = cap["path"]
    t_start = time.time()
    d = capture_dir(cid)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)
    update_capture(cid, status="indexing", error=None, partial=0, partial_reason=None, frames=0,
                   tshark_version=tshark.version(), created_at=cap.get("created_at") or utcnow())
    con = connect(capture_db_path(cid), bulk=True)
    try:
        _index(job, cid, cap, path, con, t_start)
    finally:
        con.close()


def _index(job: Job, cid: int, cap: dict, path: str, con, t_start: float) -> None:
    classes = discover()
    con.executescript(CAPTURE_SCHEMA)
    for cls in classes:
        if cls.schema:
            con.executescript(cls.schema)
    ctx = Context(con, cap, settings)
    con.execute("BEGIN")
    analyzers = [cls(ctx) for cls in classes]
    fields, missing = build_field_list(classes)
    idx = {f: i for i, f in enumerate(fields)}
    nfields = len(fields)
    if missing:
        ctx.warnings.append("Ebben a TShark-verzióban nem létező mezők (kimaradnak): " + ", ".join(missing))

    args = ["-n", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", f"aggregator={AGG}",
            "-E", "header=n", "-E", "quote=n"]
    max_packets = cap.get("max_packets")
    if max_packets:
        args += ["-c", str(int(max_packets))]
    for f in fields:
        args += ["-e", f]

    walker = None
    walk_iter = None
    try:
        walker = CaptureWalker(path)
        walk_iter = walker.packets()
    except (CaptureFormatError, OSError) as e:
        ctx.warnings.append(f"A blokkbejáró nem használható ({e}); offset/hex/export korlátozott.")
    size = cap.get("size") or 1

    proc = tshark.popen(args)
    job.attach(proc)
    err = tshark.StderrCollector(proc.stderr)
    pw = BatchWriter(con, PACKET_INSERT, settings.index_batch)
    by_trigger = [(a, a.triggers) for a in analyzers]
    n = 0
    last_sec = None
    last_ts = None
    walker_ok = walk_iter is not None
    snap_trunc = 0
    first_ts = None
    i_section, i_iface = idx.get("frame.section_number"), idx.get("frame.interface_id")
    i_proto = idx[tshark.column_field("protocol")]
    i_info = nfields - 1
    cancelled = False
    for raw in proc.stdout:
        if job.cancelled():
            cancelled = True
            break
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        vals = line.split("\t", nfields - 1)
        if len(vals) < nfields:
            vals += [""] * (nfields - len(vals))
        try:
            frame = int(vals[0])
        except ValueError:
            continue
        ts = parse_epoch_ns(vals[1]) if vals[1] else 0
        length = int(vals[2] or 0)
        caplen = int(vals[3] or 0)
        if caplen < length:
            snap_trunc += 1
        layers = vals[6].split(":") if vals[6] else []
        pkt = Packet(vals, idx, frame, ts, length, caplen, layers)
        offset = None
        section = int(vals[i_section]) if i_section is not None and vals[i_section] else None
        iface = int(vals[i_iface]) if i_iface is not None and vals[i_iface] else None
        if walker_ok:
            try:
                ref = next(walk_iter)
                while ref.frame_no < frame:
                    ref = next(walk_iter)
                if ref.frame_no == frame:
                    offset, section, iface = ref.offset, ref.section, ref.iface
                    if walker.info.format == "pcap":
                        section = None
                    if frame % 2000 == 0:
                        job.progress = min(0.99, ref.offset / size)
                else:
                    walker_ok = False
            except (StopIteration, CaptureFormatError, OSError, IndexError) as e:
                walker_ok = False
                ctx.warnings.append(f"A blokkbejáró a(z) {frame}. csomagnál leállt ({type(e).__name__}).")
        if first_ts is None:
            first_ts = ts
        # packet-table columns (innermost IP like Wireshark; outer kept when tunnelled)
        ips = pkt.ip_layers()
        src = dst = osrc = odst = None
        sport = dport = tstream = ustream = None
        if ips:
            pos, l, k = ips[-1]
            src, dst = pkt.get(f"{l}.src", k), pkt.get(f"{l}.dst", k)
            if len(ips) > 1:
                _, l0, k0 = ips[0]
                osrc, odst = pkt.get(f"{l0}.src", k0), pkt.get(f"{l0}.dst", k0)
            for p4, l4, k4 in reversed(pkt.l4_layers()):
                if p4 > pos:
                    sport, dport = pkt.int(f"{l4}.srcport", k4), pkt.int(f"{l4}.dstport", k4)
                    st = pkt.int(f"{l4}.stream", k4)
                    if l4 == "tcp":
                        tstream = st
                    else:
                        ustream = st
                    break
        info = vals[i_info]
        if len(info) > 400:
            info = info[:400] + "…"
        pw.add((frame, ts, section, iface, caplen, length, src, dst, sport, dport, osrc, odst, vals[i_proto], info,
                offset, tstream, ustream))
        lset = None
        for a, trig in by_trigger:
            if trig is None:
                a.on_packet(pkt)
            else:
                if lset is None:
                    lset = set(layers)
                if not trig.isdisjoint(lset):
                    a.on_packet(pkt)
        sec = ts // 1_000_000_000
        if sec != last_sec:
            last_sec = sec
            for a in analyzers:
                a.periodic(ts)
        last_ts = ts
        n += 1
        if n % 20000 == 0:
            pw.flush()
            ctx.flush()
            con.execute("COMMIT")
            con.execute("BEGIN")
            job.counters.update(frames=n, rate=round(n / max(0.001, time.time() - t_start)))
            job.message = f"{n:,} csomag indexelve".replace(",", " ")
            update_capture(cid, frames=n)
    if cancelled:
        job._kill()
    proc.wait()
    stderr = err.text()
    rc = proc.returncode
    # drain the walker so file-level metadata (ISB drop counters, DSBs, sha256, truncation) is complete
    if walker_ok and not cancelled:
        try:
            for _ in walk_iter:
                pass
        except (CaptureFormatError, OSError):
            pass

    cut = Cut(last_ts_ns=last_ts, last_frame=n)
    if cancelled:
        cut.reason, cut.note = "cancelled", f"A felhasználó megszakította az importot a(z) {n}. csomag után."
    elif walker is not None and walker.info.truncated:
        cut.reason, cut.note = "truncated", "Csonka fájl: " + walker.info.truncation_note
    elif "cut short" in stderr or "damaged or corrupt" in stderr:
        cut.reason, cut.note = "truncated", "A TShark szerint a fájl csonka vagy sérült: " + stderr.splitlines()[0]
    elif max_packets and n >= int(max_packets):
        cut.reason, cut.note = "limit", f"Felhasználói korlát: csak az első {max_packets} csomag lett indexelve."
    elif rc not in (0, None) and n == 0:
        pw.flush()
        con.execute("COMMIT")
        raise RuntimeError(f"A TShark hibával állt le (kód {rc}): {stderr[:500]}")
    elif rc not in (0, None):
        cut.reason, cut.note = "error", f"A TShark hibakóddal állt le ({rc}): {stderr[:300]}"

    job.message = "Elemzők lezárása…"
    pw.flush()
    for a in analyzers:
        a.finish(cut)
    ctx.flush()
    con.execute("COMMIT")
    job.message = "Indexek építése…"
    con.executescript(POST_INDEX)

    info = {}
    if walker is not None:
        wi = walker.info
        info = {"format": wi.format, "compressed": wi.compressed, "sections": wi.sections,
                "interfaces": wi.interfaces, "dsb": wi.dsb, "truncated": wi.truncated,
                "truncation_note": wi.truncation_note, "sha256": wi.sha256 if not cancelled else None,
                "endian": wi.endian, "pcap_tsresol": wi.pcap_tsresol, "random_access": wi.random_access and walker_ok,
                "walker_packets": wi.packets}
    info.update({"first_ts_ns": first_ts, "last_ts_ns": last_ts, "snaplen_truncated": snap_trunc,
                 "tshark_stderr": stderr[:2000], "warnings": ctx.warnings,
                 "analyzers": [{"name": c.name, "title": c.title} for c in classes],
                 "fields_missing": missing})
    meta = {"fields": fields, "cut": cut.__dict__, "info": info}
    con.execute("INSERT OR REPLACE INTO meta VALUES ('index', ?)", (json.dumps(meta),))
    elapsed = time.time() - t_start
    status = "cancelled" if cancelled else ("partial" if cut.is_cut else "ready")
    update_capture(cid, status=status, frames=n, partial=int(cut.is_cut), partial_reason=cut.note or None,
                   info=info, finished_at=utcnow(), index_seconds=round(elapsed, 3),
                   sha256=info.get("sha256"), format=info.get("format"))
    job.counters.update(frames=n, seconds=round(elapsed, 2))
    job.progress = 1.0
    job.result = {"status": status, "frames": n, "cut": cut.__dict__}
    job.message = {"ready": "Kész", "partial": "Részleges index", "cancelled": "Megszakítva (részleges index)"}[status]
    if cancelled:
        job.state = "cancelled"
