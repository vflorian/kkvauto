"""HTTP API + static UI. Served on 127.0.0.1 only.

Security: loopback bind, Host-header allow-list (DNS rebinding), random start-up
token exchanged for an HttpOnly SameSite=Strict cookie, custom header required
on state-changing requests, strict CSP (no external origins), file access only
through registered capture ids.
"""
from __future__ import annotations

import hmac
import json
import platform
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, export, incident, service, tshark
from .analyzers import discover
from .config import settings
from .db import capture_db, get_capture, rows
from .export import ts_iso
from .jobs import jobs
from .service import UserError

STATIC = Path(__file__).parent / "static"
COOKIE = "capscope_token"

app = FastAPI(title="CapScope", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


def ensure_token() -> str:
    if not settings.auth_token:
        settings.auth_token = secrets.token_urlsafe(24)
    return settings.auth_token


@app.middleware("http")
async def guard(request: Request, call_next):
    host = (request.headers.get("host") or "").lower()
    allowed = {f"127.0.0.1:{settings.port}", f"localhost:{settings.port}", "127.0.0.1", "localhost"}
    if host not in allowed:
        return JSONResponse({"error": "Tiltott Host fejléc."}, status_code=403)
    token = ensure_token()
    q = request.query_params.get("token")
    if q is not None and request.url.path == "/":
        if hmac.compare_digest(q, token):
            r = RedirectResponse("/", status_code=303)
            r.set_cookie(COOKIE, token, httponly=True, samesite="strict")
            return r
        return HTMLResponse("<h1>Érvénytelen token</h1>", status_code=401)
    if not hmac.compare_digest(request.cookies.get(COOKIE, ""), token):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "Nincs jogosultság. Nyisd meg az indításkor kiírt linket."}, status_code=401)
        return HTMLResponse("<!doctype html><meta charset=utf-8><title>CapScope</title><body style='font-family:sans-serif'>"
                            "<h1>CapScope</h1><p>Nyisd meg a PowerShell-ablakban kiírt, tokent tartalmazó linket "
                            "(http://127.0.0.1:…/?token=…).</p>", status_code=401)
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.headers.get("x-capscope") != "1":
        return JSONResponse({"error": "Hiányzó X-CapScope fejléc."}, status_code=403)
    try:
        resp = await call_next(request)
    except UserError as e:
        resp = JSONResponse({"error": str(e)}, status_code=400)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(UserError)
async def user_error(_: Request, e: UserError):
    return JSONResponse({"error": str(e)}, status_code=400)


@app.exception_handler(FileNotFoundError)
async def not_found(_: Request, e: FileNotFoundError):
    return JSONResponse({"error": str(e) or "Nem található."}, status_code=404)


@app.exception_handler(tshark.TSharkNotFound)
async def no_tshark(_: Request, e: Exception):
    return JSONResponse({"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---------------------------------------------------------------------------
# System / captures / jobs
# ---------------------------------------------------------------------------

@app.get("/api/system")
def system() -> dict:
    try:
        path, ver, err = tshark.tshark_path(), tshark.version(), None
    except tshark.TSharkNotFound as e:
        path, ver, err = None, None, str(e)
    return {"version": __version__, "tshark": {"path": path, "version": ver, "error": err},
            "python": sys.version.split()[0], "platform": platform.platform(), "data_dir": str(settings.data_dir),
            "bind": f"{settings.host}:{settings.port}",
            "analyzers": [{"name": c.name, "title": c.title} for c in discover()],
            "limits": {"filter_timeout_s": settings.filter_timeout_s, "filter_max_hits": settings.filter_max_hits,
                       "detail_timeout_s": settings.detail_timeout_s, "follow_timeout_s": settings.follow_timeout_s,
                       "follow_max_bytes": settings.follow_max_bytes, "export_max_frames": settings.export_max_frames,
                       "dns_timeout_s": settings.dns_timeout_s, "gtp_timeout_s": settings.gtp_timeout_s,
                       "gtpu_grace_s": settings.gtpu_grace_s}}


@app.post("/api/browse")
def browse() -> dict:
    try:
        p = subprocess.run([sys.executable, "-m", "capscope.filedialog"], capture_output=True, text=True, timeout=600,
                           creationflags=tshark.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"path": None, "error": f"A fájlválasztó nem indítható: {e}"}
    if p.returncode != 0:
        return {"path": None, "error": "A fájlválasztó nem érhető el ezen a gépen; írd be az útvonalat."}
    return {"path": p.stdout.strip() or None}


@app.get("/api/captures")
def captures() -> list[dict]:
    return service.list_captures()


@app.post("/api/captures")
def open_capture(body: dict = Body(...)) -> dict:
    mp = body.get("max_packets")
    mp = int(mp) if mp not in (None, "", 0, "0") else None
    r = service.register_capture(str(body.get("path", "")), mp)
    job = None
    if not r["existing"]:
        job = service.start_index(r["id"]).to_dict()
    return {"capture": get_capture(r["id"]), "job": job, "existing": r["existing"]}


@app.get("/api/captures/{cid}")
def capture(cid: int) -> dict:
    cap = service.require_capture(cid, need_index=False)
    cap["file_changed"] = service.file_changed(cap)
    cap["running_jobs"] = [j.to_dict() for j in jobs.active_for(cid)]
    return cap


@app.post("/api/captures/{cid}/reindex")
def reindex(cid: int, body: dict = Body(default={})) -> dict:
    cap = service.require_capture(cid, need_index=False)
    import os
    st = os.stat(cap["path"])
    from .db import update_capture
    mp = body.get("max_packets")
    update_capture(cid, size=st.st_size, mtime=st.st_mtime, max_packets=int(mp) if mp else None)
    return {"job": service.start_index(cid).to_dict()}


@app.delete("/api/captures/{cid}")
def delete(cid: int) -> dict:
    service.delete_capture(cid)
    return {"ok": True}


@app.get("/api/jobs")
def list_jobs() -> list[dict]:
    return [j.to_dict() for j in sorted(jobs.jobs.values(), key=lambda j: -j.id)[:50]]


@app.get("/api/jobs/{jid}")
def job(jid: int) -> dict:
    j = jobs.get(jid)
    if not j:
        raise UserError("Ismeretlen feladat.")
    return j.to_dict()


@app.post("/api/jobs/{jid}/cancel")
def cancel(jid: int) -> dict:
    j = jobs.get(jid)
    if not j:
        raise UserError("Ismeretlen feladat.")
    j.cancel()
    return j.to_dict()


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@app.get("/api/captures/{cid}/overview")
def overview(cid: int, buckets: int = 300) -> dict:
    cap = service.require_capture(cid)
    info = cap["info"]
    with capture_db(cid) as con:
        tl = rows(con.execute("SELECT bucket, pkts, bytes FROM timeline ORDER BY bucket"))
        phs = rows(con.execute("SELECT path, depth, pkts, bytes FROM proto_hier ORDER BY path"))
        talk_o = rows(con.execute("SELECT * FROM talkers WHERE scope='outer' ORDER BY bytes_tx+bytes_rx DESC LIMIT 15"))
        talk_i = rows(con.execute("SELECT * FROM talkers WHERE scope='inner' ORDER BY bytes_tx+bytes_rx DESC LIMIT 15"))
        fsum = rows(con.execute("SELECT severity, state, count(*) n FROM findings GROUP BY severity, state"))
        tsum = rows(con.execute("SELECT proto, status, state, count(*) n FROM transactions GROUP BY proto, status, state"))
        ssum = rows(con.execute("SELECT status, count(*) n FROM gtp_sessions GROUP BY status"))
        n_flows = con.execute("SELECT count(*) FROM flows").fetchone()[0]
        n_bytes = con.execute("SELECT coalesce(sum(bytes),0) FROM timeline").fetchone()[0]
        meta = con.execute("SELECT value FROM meta WHERE key='index'").fetchone()
    # aggregate the per-second timeline to at most `buckets` bars
    agg = []
    if tl:
        t0, t1 = tl[0]["bucket"], tl[-1]["bucket"] + 1
        width = max(1, -(-(t1 - t0) // max(1, buckets)))
        cur = None
        for r in tl:
            b = t0 + (r["bucket"] - t0) // width * width
            if cur is None or cur["t"] != b:
                cur = {"t": b, "w": width, "pkts": 0, "bytes": 0}
                agg.append(cur)
            cur["pkts"] += r["pkts"]
            cur["bytes"] += r["bytes"]
    ifaces = []
    for i in info.get("interfaces", []):
        ifaces.append({**i, "drop_text": "Nincs adat" if i.get("ifdrop") is None else str(i["ifdrop"])})
    first, last = info.get("first_ts_ns"), info.get("last_ts_ns")
    return {"capture": cap, "interfaces": ifaces, "first_utc": ts_iso(first), "last_utc": ts_iso(last),
            "duration_s": (last - first) / 1e9 if first is not None and last is not None else None,
            "bytes": n_bytes, "timeline": agg, "phs": phs, "talkers": {"outer": talk_o, "inner": talk_i},
            "findings": fsum, "transactions": tsum, "sessions": ssum, "flows": n_flows,
            "cut": json.loads(meta[0])["cut"] if meta else None, "file_changed": service.file_changed(cap)}


# ---------------------------------------------------------------------------
# Packets
# ---------------------------------------------------------------------------

@app.post("/api/captures/{cid}/filters")
def new_filter(cid: int, body: dict = Body(...)) -> dict:
    return service.start_filter(cid, str(body.get("expr", "")), bool(body.get("two_pass")))


@app.post("/api/filter/validate")
def validate(body: dict = Body(...)) -> dict:
    ok, msg, raw = tshark.validate_filter(str(body.get("expr", "")))
    return {"ok": ok, "error": msg, "tshark": raw}


@app.get("/api/captures/{cid}/filters/{fid}")
def get_filter(cid: int, fid: int) -> dict:
    with capture_db(cid) as con:
        r = con.execute("SELECT * FROM filters WHERE id=?", (fid,)).fetchone()
    if not r:
        raise UserError("Ismeretlen szűrő.")
    return dict(r)


@app.get("/api/captures/{cid}/packets")
def packets(cid: int, filter_id: int | None = None, t0: int | None = None, t1: int | None = None,
            tunnel_id: int | None = None, after: int | None = None, before: int | None = None,
            around: int | None = None, limit: int = Query(100, le=1000)) -> dict:
    cap = service.require_capture(cid)
    joins, where, args = [], [], []
    if filter_id:
        joins.append("JOIN filter_hits h ON h.frame_no=p.frame_no AND h.filter_id=?")
        args.append(filter_id)
    if tunnel_id:
        joins.append("JOIN gtpu_frames g ON g.frame_no=p.frame_no AND g.tunnel_id=?")
        args.append(tunnel_id)
    if t0 is not None:
        where.append("p.ts_ns >= ?")
        args.append(t0)
    if t1 is not None:
        where.append("p.ts_ns < ?")
        args.append(t1)
    base = "FROM packets p " + " ".join(joins) + (" WHERE " + " AND ".join(where) if where else "")
    with capture_db(cid) as con:
        def page(cond: str, cargs: list, order: str) -> list[dict]:
            w = (" AND " if where else " WHERE ") + cond if cond else ""
            return rows(con.execute(f"SELECT p.* {base}{w} ORDER BY p.frame_no {order} LIMIT ?", args + cargs + [limit]))
        if around is not None:
            prev = page("p.frame_no < ?", [around], "DESC")[: limit // 3]
            nxt = page("p.frame_no >= ?", [around], "ASC")
            data = list(reversed(prev)) + nxt
            data = data[:limit]
        elif before is not None:
            data = list(reversed(page("p.frame_no < ?", [before], "DESC")))
        else:
            data = page("p.frame_no > ?", [after or 0], "ASC")
        if not where and not joins:
            total = cap["frames"]
        elif filter_id and not where and not tunnel_id:
            total = con.execute("SELECT hits FROM filters WHERE id=?", (filter_id,)).fetchone()[0]
        else:
            total = con.execute(f"SELECT count(*) {base}", args).fetchone()[0]
        pos = None
        if data:
            w = (" AND " if where else " WHERE ") + "p.frame_no < ?"
            pos = con.execute(f"SELECT count(*) {base}{w}", args + [data[0]["frame_no"]]).fetchone()[0]
        has_prev = bool(data) and con.execute(f"SELECT 1 {base}{(' AND ' if where else ' WHERE ')}p.frame_no < ? LIMIT 1",
                                              args + [data[0]["frame_no"]]).fetchone() is not None
        has_next = bool(data) and con.execute(f"SELECT 1 {base}{(' AND ' if where else ' WHERE ')}p.frame_no > ? LIMIT 1",
                                              args + [data[-1]["frame_no"]]).fetchone() is not None
        flt = dict(con.execute("SELECT * FROM filters WHERE id=?", (filter_id,)).fetchone() or {}) if filter_id else None
    for r in data:
        r["ts_utc"] = ts_iso(r["ts_ns"])
    found = None
    if around is not None:
        found = any(r["frame_no"] == around for r in data)
    return {"rows": data, "total": total, "position": pos, "has_prev": has_prev, "has_next": has_next,
            "filter": flt, "around_found": found, "capture_status": cap["status"],
            "partial_reason": cap.get("partial_reason")}


@app.get("/api/captures/{cid}/packets/{frame}")
def detail(cid: int, frame: int, mode: str = "context") -> dict:
    d = service.packet_detail(cid, frame, mode)
    d["packet"]["ts_utc"] = ts_iso(d["packet"]["ts_ns"])
    return d


@app.get("/api/captures/{cid}/follow/{l4}/{stream}")
def follow(cid: int, l4: str, stream: int) -> dict:
    return service.follow_stream(cid, l4, stream)


# ---------------------------------------------------------------------------
# Transactions / flows / findings
# ---------------------------------------------------------------------------

def _q(con, sql: str, args: list, offset: int, limit: int) -> dict:
    total = con.execute(f"SELECT count(*) FROM ({sql})", args).fetchone()[0]
    data = rows(con.execute(f"{sql} LIMIT ? OFFSET ?", args + [limit, offset]))
    return {"rows": data, "total": total, "offset": offset}


@app.get("/api/captures/{cid}/transactions")
def transactions(cid: int, proto: str | None = None, status: str | None = None, q: str | None = None,
                 session_id: int | None = None, offset: int = 0, limit: int = Query(100, le=1000)) -> dict:
    service.require_capture(cid)
    w, a = [], []
    if proto:
        w.append("proto = ?")
        a.append(proto)
    if status:
        w.append("status = ?")
        a.append(status)
    if session_id:
        w.append("session_id = ?")
        a.append(session_id)
    if q:
        w.append("(summary LIKE ? OR client LIKE ? OR server LIKE ? OR txn_id LIKE ? OR imsi LIKE ? OR result LIKE ?)")
        a += [f"%{q}%"] * 6
    sql = "SELECT * FROM transactions" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY coalesce(req_ts, rsp_ts)"
    with capture_db(cid) as con:
        r = _q(con, sql, a, offset, limit)
    for x in r["rows"]:
        x["ts_utc"] = ts_iso(x["req_ts"] or x["rsp_ts"])
        x["retrans_frames"] = json.loads(x["retrans_frames"] or "[]")
        x["dup_rsp_frames"] = json.loads(x["dup_rsp_frames"] or "[]")
    return r


@app.get("/api/captures/{cid}/flows")
def flows(cid: int, l4: str | None = None, q: str | None = None, flag: str | None = None, sort: str = "first_ts",
          offset: int = 0, limit: int = Query(100, le=1000)) -> dict:
    service.require_capture(cid)
    w, a = [], []
    if l4 in ("tcp", "udp"):
        w.append("l4 = ?")
        a.append(l4)
    if q:
        w.append("(a_ip LIKE ? OR b_ip LIKE ? OR cast(a_port as text)=? OR cast(b_port as text)=? OR tls_sni LIKE ?)")
        a += [f"%{q}%", f"%{q}%", q, q, f"%{q}%"]
    flags = {"rst": "rst_count > 0", "retrans": "retrans > 0", "tls": "tls_ch_frame IS NOT NULL",
             "incomplete": "handshake IN ('syn_only','syn_synack','synack_only')", "icmp": "icmp_count > 0",
             "tunneled": "tunneled = 1", "alert": "tls_alert IS NOT NULL"}
    if flag in flags:
        w.append(flags[flag])
    order = {"first_ts": "first_ts", "bytes": "(bytes_ab+bytes_ba) DESC", "pkts": "(pkts_ab+pkts_ba) DESC"}.get(sort, "first_ts")
    sql = "SELECT * FROM flows" + (" WHERE " + " AND ".join(w) if w else "") + f" ORDER BY {order}"
    with capture_db(cid) as con:
        r = _q(con, sql, a, offset, limit)
    for x in r["rows"]:
        x["ts_utc"] = ts_iso(x["first_ts"])
        x["duration_ms"] = (x["last_ts"] - x["first_ts"]) / 1e6
        for k in ("rst_frames", "retrans_frames", "icmp_frames"):
            x[k] = json.loads(x[k] or "[]")
    return r


@app.get("/api/captures/{cid}/findings")
def findings(cid: int, analyzer: str | None = None, state: str | None = None, severity: str | None = None,
             obj_type: str | None = None, obj_id: int | None = None, offset: int = 0,
             limit: int = Query(200, le=2000)) -> dict:
    service.require_capture(cid)
    w, a = [], []
    for col, v in (("analyzer", analyzer), ("state", state), ("severity", severity), ("obj_type", obj_type),
                   ("obj_id", obj_id)):
        if v is not None and v != "":
            w.append(f"{col} = ?")
            a.append(v)
    sql = "SELECT * FROM findings" + (" WHERE " + " AND ".join(w) if w else "") + \
          " ORDER BY CASE severity WHEN 'error' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, ts_ns"
    with capture_db(cid) as con:
        r = _q(con, sql, a, offset, limit)
    for x in r["rows"]:
        x["frames"] = json.loads(x["frames"] or "[]")
        x["ts_utc"] = ts_iso(x["ts_ns"])
    return r


# ---------------------------------------------------------------------------
# SIM & session
# ---------------------------------------------------------------------------

def _teid(q: str) -> int | None:
    s = q.strip().lower()
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        try:
            return int(s, 16) if all(c in "0123456789abcdef" for c in s) and len(s) <= 8 else None
        except ValueError:
            return None


@app.get("/api/captures/{cid}/sessions")
def sessions(cid: int, q: str | None = None, field: str = "any", offset: int = 0,
             limit: int = Query(100, le=1000)) -> dict:
    service.require_capture(cid)
    w, a = [], []
    if q:
        q = q.strip()
        parts = []
        if field in ("any", "imsi"):
            parts.append("imsi LIKE ?")
            a.append(f"%{q}%")
        if field in ("any", "msisdn"):
            parts.append("msisdn LIKE ?")
            a.append(f"%{q}%")
        if field in ("any", "apn"):
            parts.append("apn LIKE ?")
            a.append(f"%{q}%")
        if field in ("any", "ip"):
            parts.append("ue_ipv4 = ? OR ue_ipv6 = ? OR id IN (SELECT session_id FROM gtp_fteids WHERE ip = ?)")
            a += [q, q, q]
        t = _teid(q)
        if field in ("any", "teid") and t is not None:
            parts.append("id IN (SELECT session_id FROM gtp_fteids WHERE teid = ?) OR "
                         "id IN (SELECT session_id FROM gtpu_tunnels WHERE teid = ?)")
            a += [t, t]
        w.append("(" + " OR ".join(parts or ["0"]) + ")")
    sql = ("SELECT s.*, (SELECT coalesce(sum(pkts),0) FROM gtpu_tunnels t WHERE t.session_id=s.id) AS u_pkts, "
           "(SELECT coalesce(sum(bytes),0) FROM gtpu_tunnels t WHERE t.session_id=s.id) AS u_bytes "
           "FROM gtp_sessions s" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY created_ts")
    with capture_db(cid) as con:
        r = _q(con, sql, a, offset, limit)
        unattributed = []
        t = _teid(q) if q else None
        if q and field in ("any", "teid", "ip"):
            unattributed = rows(con.execute(
                "SELECT * FROM gtpu_tunnels WHERE session_id IS NULL AND (teid = ? OR outer_src = ? OR outer_dst = ?)",
                (t if t is not None else -1, q, q)))
    for x in r["rows"]:
        x["created_utc"] = ts_iso(x["created_ts"])
        x["deleted_utc"] = ts_iso(x["deleted_ts"])
    r["unattributed_tunnels"] = unattributed
    return r


@app.get("/api/captures/{cid}/sessions/{sid}")
def session(cid: int, sid: int) -> dict:
    service.require_capture(cid)
    with capture_db(cid) as con:
        s = con.execute("SELECT * FROM gtp_sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            raise UserError("Ismeretlen session.")
        ev = rows(con.execute("SELECT * FROM gtp_events WHERE session_id=? ORDER BY frame", (sid,)))
        ft = rows(con.execute("SELECT * FROM gtp_fteids WHERE session_id=? ORDER BY id", (sid,)))
        tun = rows(con.execute("SELECT * FROM gtpu_tunnels WHERE session_id=? ORDER BY first_ts", (sid,)))
        amb = rows(con.execute("SELECT * FROM gtpu_tunnels WHERE session_id IS NULL AND candidates LIKE ?",
                               (f"%{sid}%",)))
        amb = [t for t in amb if sid in json.loads(t["candidates"] or "[]")]
        for t in tun + amb:
            t["inner"] = rows(con.execute("SELECT * FROM gtpu_inner WHERE tunnel_id=? ORDER BY bytes DESC LIMIT 20",
                                          (t["id"],)))
            t["candidates"] = json.loads(t["candidates"] or "[]")
            t["first_utc"], t["last_utc"] = ts_iso(t["first_ts"]), ts_iso(t["last_ts"])
        tx = rows(con.execute("SELECT * FROM transactions WHERE session_id=? ORDER BY req_ts", (sid,)))
    for e in ev:
        e["ts_utc"] = ts_iso(e["ts_ns"])
    for f in ft:
        f["valid_from_utc"], f["valid_to_utc"] = ts_iso(f["valid_from_ts"]), ts_iso(f["valid_to_ts"])
        f["teid_hex"] = f"0x{f['teid']:08x}"
    for t in tx:
        t["ts_utc"] = ts_iso(t["req_ts"] or t["rsp_ts"])
    d = dict(s)
    d["created_utc"], d["deleted_utc"] = ts_iso(d["created_ts"]), ts_iso(d["deleted_ts"])
    return {"session": d, "events": ev, "fteids": ft, "tunnels": tun, "ambiguous_tunnels": amb, "transactions": tx}


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

@app.post("/api/captures/{cid}/export/pcap")
def export_pcap(cid: int, body: dict = Body(...)) -> dict:
    sel = {k: body.get(k) for k in ("filter_id", "t0", "t1", "frames") if body.get(k) not in (None, "", [])}
    if not sel:
        raise UserError("Adj meg kijelölést (szűrő, időablak vagy csomaglista).")
    job = export.start_pcap_export(cid, sel, bool(body.get("include_deps")), bool(body.get("include_secrets")),
                                   str(body.get("confirm", "")), body.get("incident_id"))
    return {"job": job.to_dict()}


@app.post("/api/captures/{cid}/export/table")
def export_tbl(cid: int, body: dict = Body(...)) -> dict:
    sel = {k: body.get(k) for k in ("filter_id", "t0", "t1") if body.get(k) not in (None, "")}
    return export.export_table(cid, str(body.get("kind")), str(body.get("format", "csv")), body.get("mask") or {}, sel)


@app.get("/api/exports")
def exports(capture_id: int | None = None, incident_id: int | None = None) -> list[dict]:
    return export.list_exports(capture_id, incident_id)


@app.get("/api/exports/{eid}/download")
def download(eid: int) -> FileResponse:
    p = export.export_path(eid)
    media = "application/vnd.tcpdump.pcap" if p.suffix == ".pcapng" else None
    return FileResponse(p, filename=p.name, media_type=media)


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

@app.get("/api/incidents")
def incidents() -> list[dict]:
    return incident.list_incidents()


@app.post("/api/incidents")
def new_incident(body: dict = Body(...)) -> dict:
    return {"id": incident.create_incident(str(body.get("title", "Incident")), str(body.get("description", "")))}


@app.get("/api/incidents/{iid}")
def get_incident(iid: int) -> dict:
    return incident.get_incident(iid)


@app.put("/api/incidents/{iid}")
def put_incident(iid: int, body: dict = Body(...)) -> dict:
    incident.update_incident(iid, body.get("title"), body.get("description"))
    return {"ok": True}


@app.post("/api/incidents/{iid}/items")
def add_item(iid: int, body: dict = Body(...)) -> dict:
    return incident.add_item(iid, str(body.get("kind")), body.get("capture_id"), body.get("ref_id"),
                             body.get("frame"), str(body.get("note", "")), body.get("title"), body.get("ts_ns"))


@app.put("/api/incident-items/{item_id}")
def put_item(item_id: int, body: dict = Body(...)) -> dict:
    incident.update_item(item_id, body.get("note"), body.get("title"))
    return {"ok": True}


@app.delete("/api/incident-items/{item_id}")
def del_item(item_id: int) -> dict:
    incident.delete_item(item_id)
    return {"ok": True}


@app.post("/api/incidents/{iid}/report")
def report(iid: int, body: dict = Body(default={})) -> dict:
    return incident.build_report(iid, body.get("mask") or {})


@app.post("/api/incidents/{iid}/export/pcap")
def incident_pcap(iid: int, body: dict = Body(default={})) -> dict:
    per = incident.incident_frames(iid)
    if not per:
        raise UserError("Az incidensben nincs csomaghivatkozás.")
    out = []
    for cid, frames in per.items():
        out.append(export.start_pcap_export(cid, {"frames": frames}, bool(body.get("include_deps")),
                                            bool(body.get("include_secrets")), str(body.get("confirm", "")),
                                            iid).to_dict())
    return {"jobs": out}


_ = (Any, Response)
