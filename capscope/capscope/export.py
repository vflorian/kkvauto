"""Exports: raw capture (pcapng, lossless, provenance comments) and masked/unmasked tables."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from pathlib import Path

from . import tshark
from .capfile import export_pcapng
from .config import settings
from .db import capture_db, catalog, get_capture, rows, utcnow
from .jobs import Job, jobs
from .masking import Masker, known_identifiers
from .service import UserError, require_capture, require_unchanged

SECRETS_CONFIRM = "TITKOKKAL"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "capture"


def _register_export(file: Path, kind: str, masked: bool, cid: int | None, frames: int | None, note: str,
                     secrets: bool = False, incident_id: int | None = None) -> dict:
    with catalog() as c:
        cur = c.execute("INSERT INTO exports(file, kind, masked, capture_id, incident_id, created_at, frames, note, "
                        "contains_secrets) VALUES (?,?,?,?,?,?,?,?,?)",
                        (file.name, kind, int(masked), cid, incident_id, utcnow(), frames, note, int(secrets)))
        eid = cur.lastrowid
    return {"id": eid, "file": file.name, "kind": kind, "masked": masked, "frames": frames, "note": note,
            "contains_secrets": secrets}


def list_exports(cid: int | None = None, incident_id: int | None = None) -> list[dict]:
    q, a = "SELECT * FROM exports", []
    if cid is not None:
        q += " WHERE capture_id=?"
        a.append(cid)
    elif incident_id is not None:
        q += " WHERE incident_id=?"
        a.append(incident_id)
    with catalog() as c:
        out = rows(c.execute(q + " ORDER BY id DESC", a))
    for r in out:
        r["exists"] = (settings.exports_dir / r["file"]).is_file()
    return out


def export_path(eid: int) -> Path:
    with catalog() as c:
        r = c.execute("SELECT file FROM exports WHERE id=?", (eid,)).fetchone()
    if not r:
        raise UserError("Ismeretlen export.")
    p = (settings.exports_dir / r["file"]).resolve()
    if p.parent != settings.exports_dir.resolve() or not p.is_file():
        raise UserError("Az exportfájl nem található.")
    return p


# ---------------------------------------------------------------------------
# Frame selection
# ---------------------------------------------------------------------------

def select_frames(cid: int, sel: dict) -> list[dict]:
    q = "SELECT p.frame_no, p.offset, p.section, p.iface FROM packets p"
    where, args = [], []
    if sel.get("filter_id"):
        q += " JOIN filter_hits h ON h.frame_no=p.frame_no AND h.filter_id=?"
        args.append(int(sel["filter_id"]))
    if sel.get("t0") is not None:
        where.append("p.ts_ns >= ?")
        args.append(int(sel["t0"]))
    if sel.get("t1") is not None:
        where.append("p.ts_ns < ?")
        args.append(int(sel["t1"]))
    frames = sel.get("frames")
    if frames:
        frames = sorted({int(f) for f in frames})[: settings.export_max_frames]
        where.append(f"p.frame_no IN ({','.join('?' * len(frames))})" if len(frames) < 30000 else "1")
        if len(frames) < 30000:
            args += frames
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY p.frame_no LIMIT ?"
    args.append(settings.export_max_frames + 1)
    with capture_db(cid) as con:
        out = rows(con.execute(q, args))
    if frames and len(frames) >= 30000:
        fs = set(frames)
        out = [r for r in out if r["frame_no"] in fs]
    return out


def _dependencies(cap: dict, frames: list[int], job: Job) -> set[int]:
    """Frames the selected ones depend on for reassembly (tcp.segment / ip(v6).fragment)."""
    if not frames:
        return set()
    known = tshark.known_fields()
    dep_fields = [f for f in ("tcp.segment", "ip.fragment", "ipv6.fragment") if f in known]
    out: set[int] = set()
    for i in range(0, len(frames), 20000):
        chunk = frames[i:i + 20000]
        args = ["-n", "-r", cap["path"], "-c", str(max(chunk)), "-Y", "frame.number in {" + " ".join(map(str, chunk)) + "}",
                "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=,"]
        for f in dep_fields:
            args += ["-e", f]
        proc = tshark.popen(args)
        job.attach(proc)
        err = tshark.StderrCollector(proc.stderr)
        for raw in proc.stdout:
            for part in raw.decode("ascii", "replace").replace("\t", ",").split(","):
                part = part.strip()
                if part.isdigit():
                    out.add(int(part))
        proc.wait()
        err.text()
        if job.cancelled():
            raise InterruptedError
    return out - set(frames)


# ---------------------------------------------------------------------------
# Raw capture export
# ---------------------------------------------------------------------------

def start_pcap_export(cid: int, sel: dict, include_deps: bool = False, include_secrets: bool = False,
                      confirm: str = "", incident_id: int | None = None) -> Job:
    cap = require_capture(cid)
    require_unchanged(cap)
    has_dsb = bool(cap["info"].get("dsb"))
    if include_secrets:
        if not has_dsb:
            include_secrets = False
        elif confirm != SECRETS_CONFIRM:
            raise UserError(f"Beágyazott dekriptálási titkok exportjához írd be megerősítésként: {SECRETS_CONFIRM}")
    return jobs.start("export", cid, f"Capture-export: {cap['name']}",
                      lambda j: _pcap_export(j, cap, sel, include_deps, include_secrets, has_dsb, incident_id))


def _pcap_export(job: Job, cap: dict, sel: dict, include_deps: bool, include_secrets: bool, has_dsb: bool,
                 incident_id: int | None) -> None:
    cid = cap["id"]
    refs = select_frames(cid, sel)
    if len(refs) > settings.export_max_frames:
        raise UserError(f"Túl sok csomag ({len(refs)}); a korlát {settings.export_max_frames}.")
    if not refs:
        raise UserError("Nincs exportálható csomag a kijelölésben.")
    deps: set[int] = set()
    if include_deps:
        job.message = "Reassembly-előzmények keresése…"
        deps = _dependencies(cap, [r["frame_no"] for r in refs], job)
        if deps:
            refs = refs + select_frames(cid, {"frames": sorted(deps)})
            refs.sort(key=lambda r: r["frame_no"])
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    tag = "_RAW_WITH_SECRETS" if include_secrets else "_RAW"
    out = settings.exports_dir / f"{_safe(Path(cap['name']).stem)}_{stamp}_{len(refs)}fr{tag}.pcapng"
    part = out.with_suffix(".pcapng.part")
    info = cap["info"]
    note_parts = [f"{len(refs)} csomag (ebből {len(deps)} reassembly-előzmény)" if deps else f"{len(refs)} csomag"]
    try:
        if info.get("random_access") and all(r["offset"] is not None for r in refs):
            def prog(i, n):
                job.progress = i / max(1, n)
            res = export_pcapng(cap["path"], info, refs, str(part), source_label=cap["name"],
                                include_secrets=include_secrets, progress=prog, cancelled=job.cancelled)
            note_parts.append("eredeti csomagszám minden csomag kommentjében (capscope-ref … frame=N)")
            if res["secrets_blocks"]:
                note_parts.append(f"{res['secrets_blocks']} dekriptálási titok-blokk (DSB) MEGTARTVA")
        else:
            frames = [r["frame_no"] for r in refs]
            rc, _, err = tshark.run(["-n", "-r", cap["path"], "-Y", "frame.number in {" + " ".join(map(str, frames)) + "}",
                                     "-F", "pcapng", "-w", str(part)], timeout=3600)
            if rc != 0:
                raise RuntimeError(err[:300])
            sidecar = out.with_suffix(".refs.json")
            sidecar.write_text(json.dumps({"source": cap["name"], "sha256": info.get("sha256"),
                                           "original_frames_in_order": frames}), "utf-8")
            note_parts.append(f"TShark-export (tömörített/ismeretlen forrás); eredeti csomagszámok: {sidecar.name}")
        if has_dsb and not include_secrets:
            note_parts.append("beágyazott dekriptálási titkok (DSB) eltávolítva")
        os.replace(part, out)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    rec = _register_export(out, "pcapng", False, cid, len(refs), "; ".join(note_parts), include_secrets, incident_id)
    job.result = {"export": rec}
    job.progress = 1.0
    job.message = "Kész"


# ---------------------------------------------------------------------------
# Table exports (CSV / JSON, optional masking)
# ---------------------------------------------------------------------------

TABLES = {
    "transactions": "SELECT * FROM transactions ORDER BY coalesce(req_ts, rsp_ts)",
    "flows": "SELECT * FROM flows ORDER BY first_ts",
    "findings": "SELECT id, analyzer, rule, state, severity, ts_ns, title_en, title, detail, frames, obj_type, obj_id "
                "FROM findings ORDER BY ts_ns",
    "sessions": "SELECT * FROM gtp_sessions ORDER BY created_ts",
    "tunnels": "SELECT * FROM gtpu_tunnels ORDER BY first_ts",
}


def table_rows(cid: int, kind: str, sel: dict | None = None) -> list[dict]:
    with capture_db(cid) as con:
        if kind == "packets":
            sel = sel or {}
            q = ("SELECT p.frame_no, p.ts_ns, p.section, p.iface, p.len, p.caplen, p.src, p.dst, p.sport, p.dport, "
                 "p.osrc, p.odst, p.proto, p.info FROM packets p")
            args: list = []
            if sel.get("filter_id"):
                q += " JOIN filter_hits h ON h.frame_no=p.frame_no AND h.filter_id=?"
                args.append(int(sel["filter_id"]))
            w = []
            if sel.get("t0") is not None:
                w.append("p.ts_ns >= ?")
                args.append(int(sel["t0"]))
            if sel.get("t1") is not None:
                w.append("p.ts_ns < ?")
                args.append(int(sel["t1"]))
            if w:
                q += " WHERE " + " AND ".join(w)
            q += " ORDER BY p.frame_no LIMIT ?"
            args.append(settings.export_max_frames)
            return rows(con.execute(q, args))
        if kind not in TABLES:
            raise UserError("Ismeretlen tábla.")
        try:
            return rows(con.execute(TABLES[kind]))
        except Exception:
            return []


def ts_iso(ns: int | None) -> str | None:
    if ns is None:
        return None
    s, frac = divmod(int(ns), 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + f".{frac:09d}Z"


def export_table(cid: int, kind: str, fmt: str, mask: dict | None, sel: dict | None = None) -> dict:
    cap = require_capture(cid)
    data = table_rows(cid, kind, sel)
    masked = bool(mask and any(mask.values()))
    m = None
    if masked:
        with capture_db(cid) as con:
            known = known_identifiers(con)
        m = Masker(**{k: bool(v) for k, v in mask.items() if k in ("imsi", "msisdn", "imei", "ue_ip", "all_ip")},
                   known=known)
        data = [m.row(r) for r in data]
    for r in data:
        for k in list(r):
            if k.endswith("_ts") or k == "ts_ns":
                r[k + "_utc"] = ts_iso(r[k]) if isinstance(r[k], int) else None
        r.setdefault("capture_id", cid)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    label = "MASKED" if masked else "UNMASKED"
    out = settings.exports_dir / f"{_safe(Path(cap['name']).stem)}_{kind}_{stamp}_{label}.{fmt}"
    meta = {"source_capture": cap["name"], "capture_id": cid, "sha256": cap.get("sha256"), "generated_utc": utcnow(),
            "rows": len(data), "masking": m.scope() if m else "none (identifiers are NOT masked)",
            "index_status": cap["status"], "index_note": cap.get("partial_reason")}
    if fmt == "json":
        out.write_text(json.dumps({"meta": meta, "rows": data}, ensure_ascii=False, indent=1), "utf-8")
    elif fmt == "csv":
        buf = io.StringIO()
        cols: list[str] = []
        for r in data:
            for k in r:
                if k not in cols:
                    cols.append(k)
        w = csv.DictWriter(buf, fieldnames=cols or ["empty"], extrasaction="ignore")
        w.writeheader()
        for r in data:
            w.writerow(r)
        out.write_text(buf.getvalue(), "utf-8-sig")
        out.with_suffix(".meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
    else:
        raise UserError("Csak csv vagy json formátum.")
    note = f"{len(data)} sor; " + ("maszkolva: " + ", ".join(m.scope()["masked_classes"]) if m else "NEM maszkolt")
    return _register_export(out, f"{kind}.{fmt}", masked, cid, None, note)


_ = get_capture
