"""Incident collection and the English, template-based summary (generated locally)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import __version__, tshark
from .config import settings
from .db import capture_db, catalog, get_capture, rows, utcnow
from .export import _register_export, _safe, ts_iso
from .masking import Masker, known_identifiers
from .service import UserError

STATE_EN = {"observed": "OBSERVED", "inferred": "INFERRED", "undetermined": "UNDETERMINED"}
NO_RSP_EN = "no response visible in the analysed capture"


def ensure_default() -> int:
    with catalog() as c:
        c.execute("CREATE TABLE IF NOT EXISTS _m(x)")
        cols = {r[1] for r in c.execute("PRAGMA table_info(incident_items)")}
        if "title_en" not in cols:
            c.execute("ALTER TABLE incident_items ADD COLUMN title_en TEXT")
        r = c.execute("SELECT id FROM incidents ORDER BY id LIMIT 1").fetchone()
        if r:
            return r[0]
        return c.execute("INSERT INTO incidents(title, description, created_at) VALUES (?,?,?)",
                         ("Incident", "", utcnow())).lastrowid


def list_incidents() -> list[dict]:
    ensure_default()
    with catalog() as c:
        return rows(c.execute("SELECT i.*, (SELECT count(*) FROM incident_items t WHERE t.incident_id=i.id) AS items "
                              "FROM incidents i ORDER BY id DESC"))


def create_incident(title: str, description: str = "") -> int:
    ensure_default()
    with catalog() as c:
        return c.execute("INSERT INTO incidents(title, description, created_at) VALUES (?,?,?)",
                         (title or "Incident", description, utcnow())).lastrowid


def update_incident(iid: int, title: str | None, description: str | None) -> None:
    with catalog() as c:
        if title is not None:
            c.execute("UPDATE incidents SET title=? WHERE id=?", (title, iid))
        if description is not None:
            c.execute("UPDATE incidents SET description=? WHERE id=?", (description, iid))


def get_incident(iid: int) -> dict:
    ensure_default()
    with catalog() as c:
        inc = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        if not inc:
            raise UserError("Ismeretlen incidens.")
        items = rows(c.execute("SELECT * FROM incident_items WHERE incident_id=? ORDER BY coalesce(ts_ns, 0), id", (iid,)))
    for it in items:
        it["frames"] = json.loads(it.pop("frames_json") or "[]")
        it["ts_utc"] = ts_iso(it["ts_ns"])
    return {**dict(inc), "items": items}


def _ms(ns: int | None) -> str:
    return f"{ns / 1e6:.1f} ms" if ns is not None else "n/a"


def _describe(cid: int, kind: str, ref_id: int | None, frame: int | None) -> dict:
    """Snapshot of the referenced object: Hungarian display title + English report text."""
    with capture_db(cid) as con:
        if kind == "packet":
            r = con.execute("SELECT * FROM packets WHERE frame_no=?", (frame,)).fetchone()
            if not r:
                raise UserError("A csomag nincs az indexben.")
            ep = f"{r['src'] or '?'}" + (f":{r['sport']}" if r["sport"] is not None else "") + " → " + \
                 f"{r['dst'] or '?'}" + (f":{r['dport']}" if r["dport"] is not None else "")
            outer = f" (tunnel {r['osrc']} → {r['odst']})" if r["osrc"] else ""
            en = f"Frame {frame}: {r['proto']} {ep.replace('→', '->')}{outer.replace('→', '->')} - {r['info']}"
            return {"title": f"#{frame} {r['proto']} {ep}{outer}: {r['info']}", "title_en": en, "ts_ns": r["ts_ns"],
                    "state": "observed", "rule": "PACKET", "frames": [frame]}
        if kind == "finding":
            r = con.execute("SELECT * FROM findings WHERE id=?", (ref_id,)).fetchone()
            if not r:
                raise UserError("Ismeretlen megállapítás.")
            return {"title": r["title"], "title_en": r["title_en"] or r["title"], "ts_ns": r["ts_ns"],
                    "state": r["state"], "rule": r["rule"], "frames": json.loads(r["frames"] or "[]")}
        if kind == "transaction":
            r = con.execute("SELECT * FROM transactions WHERE id=?", (ref_id,)).fetchone()
            if not r:
                raise UserError("Ismeretlen tranzakció.")
            frames = [f for f in [r["req_frame"], *json.loads(r["retrans_frames"] or "[]"), r["rsp_frame"]] if f]
            label = {"dns": "DNS query", "gtpv2c": "GTPv2-C", "gtpv1c": "GTPv1-C"}.get(r["proto"], r["proto"])
            subj = r["summary"] if r["proto"] == "dns" else r["kind"]
            ep = f"{r['client']}:{r['client_port']} -> {r['server']}" + (f":{r['server_port']}" if r["server_port"] else "")
            if r["status"] == "answered":
                outcome = f"answered {r['result'] or ''} after {_ms(r['rtt_ns'])} (request #{r['req_frame']}, response #{r['rsp_frame']})"
            elif r["status"] == "orphan_response":
                outcome = f"response #{r['rsp_frame']} seen, request not visible in the analysed capture"
            else:
                outcome = f"{NO_RSP_EN} (request #{r['req_frame']})"
                if r["state"] == "undetermined":
                    outcome += "; the capture/index ends inside the response window, so this cannot be decided"
            if r["retrans"]:
                outcome += f"; {r['retrans']} retransmission(s): {', '.join(map(str, json.loads(r['retrans_frames'])))}"
            imsi = f", IMSI {r['imsi']}" if r["imsi"] else ""
            en = f"{label} {subj} {ep} (id/seq {r['txn_id']}{imsi}): {outcome}"
            hu_out = {"answered": f"válasz: {r['result'] or ''} ({_ms(r['rtt_ns'])})",
                      "unanswered": "A válasz nem látszik a vizsgált capture-ben.",
                      "orphan_response": "a kérés nem látszik"}.get(r["status"], r["status"])
            return {"title": f"{label} {subj} {ep.replace('->', '→')}: {hu_out}", "title_en": en,
                    "ts_ns": r["req_ts"] or r["rsp_ts"], "state": r["state"], "rule": r["rule"], "frames": frames}
        if kind == "session":
            r = con.execute("SELECT * FROM gtp_sessions WHERE id=?", (ref_id,)).fetchone()
            if not r:
                raise UserError("Ismeretlen session.")
            ue = r["ue_ipv4"] or r["ue_ipv6"] or "n/a"
            cause = f", cause {r['cause']} {r['cause_text'] or ''}".rstrip() if r["cause"] is not None else ""
            frames = [f for f in (r["created_frame"], r["accepted_frame"], r["deleted_frame"]) if f]
            en = (f"GTPv{r['version']} session #{r['id']} ({r['leg'] or 'leg n/a'}) IMSI {r['imsi'] or 'n/a'}, "
                  f"MSISDN {r['msisdn'] or 'n/a'}, APN {r['apn'] or 'n/a'}, UE IP {ue}: status {r['status']}{cause}")
            return {"title": f"Session #{r['id']} IMSI {r['imsi'] or '–'} APN {r['apn'] or '–'}: {r['status']}{cause}",
                    "title_en": en, "ts_ns": r["created_ts"], "state": "observed" if r["status"] != "unknown_start"
                    else "undetermined", "rule": "GTPC-SESSION", "frames": frames}
        if kind == "flow":
            r = con.execute("SELECT * FROM flows WHERE id=?", (ref_id,)).fetchone()
            if not r:
                raise UserError("Ismeretlen flow.")
            ep = f"{r['a_ip']}:{r['a_port']} -> {r['b_ip']}:{r['b_port']}"
            parts = [f"{r['pkts_ab']}/{r['pkts_ba']} packets A->B/B->A"]
            if r["l4"] == "tcp":
                parts.append(f"handshake {r['handshake']}")
                if r["rst_count"]:
                    parts.append(f"{r['rst_count']} RST")
                if r["retrans"]:
                    parts.append(f"{r['retrans']} retransmissions")
            if r["tls_sni"] or r["tls_ch_frame"]:
                parts.append(f"TLS SNI {r['tls_sni'] or 'n/a'} {r['tls_version'] or ''}".strip())
            if r["tls_alert"]:
                parts.append(f"TLS alert {r['tls_alert']}")
            if r["icmp_count"]:
                parts.append(f"{r['icmp_count']} ICMP error(s)")
            frames = [f for f in (r["first_frame"], r["syn_frame"], r["synack_frame"], r["tls_ch_frame"],
                                  r["tls_alert_frame"], *json.loads(r["rst_frames"] or "[]")[:3], r["last_frame"]) if f]
            en = f"{r['l4'].upper()} flow {ep}" + (" (inside GTP-U)" if r["tunneled"] else "") + ": " + ", ".join(parts)
            return {"title": en.replace("->", "→"), "title_en": en, "ts_ns": r["first_ts"], "state": "observed",
                    "rule": "FLOW", "frames": sorted(set(frames))}
        if kind == "tunnel":
            r = con.execute("SELECT * FROM gtpu_tunnels WHERE id=?", (ref_id,)).fetchone()
            if not r:
                raise UserError("Ismeretlen tunnel.")
            att = f"attributed to session #{r['session_id']}" if r["session_id"] else "not attributed to a unique session"
            en = (f"GTP-U {r['outer_src']} -> {r['outer_dst']} TEID 0x{r['teid']:08x} ({r['direction'] or 'direction n/a'}): "
                  f"{r['pkts']} packets, {att} [{r['rule'].split(':')[0]}]")
            return {"title": en.replace("->", "→"), "title_en": en, "ts_ns": r["first_ts"], "state": r["state"],
                    "rule": r["rule"], "frames": [r["first_frame"], r["last_frame"]]}
    raise UserError("Ismeretlen elemtípus.")


def add_item(iid: int, kind: str, capture_id: int | None = None, ref_id: int | None = None, frame: int | None = None,
             note: str = "", title: str | None = None, ts_ns: int | None = None) -> dict:
    ensure_default()
    if kind == "note":
        d = {"title": title or "Megfigyelés", "title_en": title or "Analyst observation", "ts_ns": ts_ns,
             "state": "observed", "rule": "ANALYST", "frames": []}
    else:
        if capture_id is None:
            raise UserError("Hiányzó capture.")
        d = _describe(capture_id, kind, ref_id, frame)
    with catalog() as c:
        dup = c.execute("SELECT id FROM incident_items WHERE incident_id=? AND kind=? AND capture_id IS ? AND "
                        "ref_id IS ? AND frame_no IS ? AND kind!='note'", (iid, kind, capture_id, ref_id, frame)).fetchone()
        if dup:
            return {"id": dup[0], "duplicate": True}
        cur = c.execute("INSERT INTO incident_items(incident_id, kind, capture_id, frame_no, ref_table, ref_id, ts_ns, "
                        "title, title_en, note, state, rule, frames_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (iid, kind, capture_id, frame, kind, ref_id, d["ts_ns"], d["title"], d["title_en"], note,
                         d["state"], d["rule"], json.dumps(d["frames"]), utcnow()))
        return {"id": cur.lastrowid, "duplicate": False}


def update_item(item_id: int, note: str | None = None, title: str | None = None) -> None:
    with catalog() as c:
        if note is not None:
            c.execute("UPDATE incident_items SET note=? WHERE id=?", (note, item_id))
        if title is not None:
            c.execute("UPDATE incident_items SET title=?, title_en=? WHERE id=? AND kind='note'", (title, title, item_id))


def delete_item(item_id: int) -> None:
    with catalog() as c:
        c.execute("DELETE FROM incident_items WHERE id=?", (item_id,))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _limitations(caps: dict[int, dict]) -> list[str]:
    out = []
    for cid, cap in caps.items():
        info = cap.get("info") or {}
        n = f"Capture #{cid} ({cap['name']})"
        if cap["status"] != "ready":
            reason = {"partial": "the index is partial", "cancelled": "the import was cancelled by the user",
                      "interrupted": "the import was interrupted (application stopped)"}.get(cap["status"], cap["status"])
            out.append(f"{n}: {reason}; results cover frames 1-{cap['frames']} only. Original note: "
                       f"{cap.get('partial_reason') or 'n/a'}. Requests near the cut are marked UNDETERMINED.")
        if info.get("truncated"):
            out.append(f"{n}: the file is truncated (last record incomplete).")
        if info.get("snaplen_truncated"):
            out.append(f"{n}: {info['snaplen_truncated']} packet(s) were captured shorter than on the wire (snaplen); "
                       "upper-layer fields may be missing.")
        drops = [i for i in info.get("interfaces", [])]
        nodata = [str(i.get("name") or i["iface"]) for i in drops if i.get("ifdrop") is None]
        if nodata:
            out.append(f"{n}: no drop statistics in the file for interface(s) {', '.join(nodata)} – loss at the "
                       "capture point cannot be excluded.")
        for i in drops:
            if i.get("ifdrop"):
                out.append(f"{n}: interface {i.get('name') or i['iface']} reports {i['ifdrop']} dropped packet(s) (ISB).")
        if info.get("dsb"):
            out.append(f"{n}: the file embeds {len(info['dsb'])} decryption secrets block(s); no decryption was "
                       "performed for this analysis and secrets are excluded from exports unless explicitly confirmed.")
        if info.get("fields_missing"):
            out.append(f"{n}: fields unavailable in this TShark version: {', '.join(info['fields_missing'])}.")
        for w in info.get("warnings", []):
            out.append(f"{n}: {w}")
    out += [
        "Only traffic visible at the capture point(s) is analysed; absence of a packet means it is not visible in the "
        "analysed capture, not necessarily that it was never sent.",
        f"Request/response pairing windows: DNS {settings.dns_timeout_s:.0f} s, GTP-C {settings.gtp_timeout_s:.0f} s; "
        "retransmissions are counted inside these windows.",
        "GTP-U to session attribution is INFERRED from signalled user-plane F-TEIDs (receiving endpoint + TEID + "
        f"session time window, ±{settings.gtpu_grace_s:.0f} s at the edges); a TEID or an IP address alone is never used.",
        "All times are UTC as recorded by the capture host clock; no display offset or cross-capture alignment applied.",
        f"Decoding by TShark {tshark.version() or 'n/a'}; correlation rules by CapScope {__version__}.",
    ]
    return out


def build_report(iid: int, mask: dict | None = None) -> dict:
    inc = get_incident(iid)
    items = inc["items"]
    cids = sorted({it["capture_id"] for it in items if it["capture_id"]})
    caps = {cid: get_capture(cid) for cid in cids}
    caps = {k: v for k, v in caps.items() if v}
    known: dict[str, set[str]] = {"imsi": set(), "msisdn": set(), "imei": set(), "ue_ip": set()}
    for cid in caps:
        try:
            with capture_db(cid) as con:
                for k, v in known_identifiers(con).items():
                    known[k] |= v
        except FileNotFoundError:
            pass
    masked = bool(mask and any(mask.values()))
    m = Masker(**{k: bool(v) for k, v in (mask or {}).items() if k in ("imsi", "msisdn", "imei", "ue_ip", "all_ip")},
               known=known) if masked else None
    T = (lambda s: m.text(s)) if m else (lambda s: s)
    now = utcnow()
    L = []
    L.append(f"# Incident summary: {T(inc['title'])}")
    L.append("")
    L.append(f"- Generated (UTC): {now}, locally by CapScope {__version__} (template-based, no external service)")
    L.append(f"- Identifier masking: " + (f"ON – {', '.join(m.scope()['masked_classes'])}. Scope: {m.scope()['applies_to']}. "
                                           f"Not applied to: {m.scope()['not_applied_to']}." if m else
                                           "OFF – this report contains unmasked identifiers."))
    L.append(f"- Items: {len(items)}; captures referenced: {len(caps)}")
    L.append("")
    if inc.get("description"):
        L += ["## Analyst summary", "", T(inc["description"]), ""]
    key = [it for it in items if it["state"] in ("observed", "inferred", "undetermined") and it["kind"] != "packet"]
    if key:
        L += ["## Key observations", ""]
        for it in key:
            fr = ", ".join(f"#{f}" for f in it["frames"][:8])
            L.append(f"- [{STATE_EN.get(it['state'], it['state'])}] {T(it['title_en'] or it['title'])}"
                     + (f" (capture #{it['capture_id']}, frames {fr})" if it["capture_id"] else ""))
        L.append("")
    L += ["## Captures", "", "| # | File | SHA-256 | Frames indexed | First packet (UTC) | Last packet (UTC) | Index status |",
          "|---|---|---|---|---|---|---|"]
    for cid, c in caps.items():
        info = c.get("info") or {}
        L.append(f"| {cid} | {c['name']} | {(c.get('sha256') or 'n/a')[:16]}… | {c['frames']} | "
                 f"{ts_iso(info.get('first_ts_ns')) or 'n/a'} | {ts_iso(info.get('last_ts_ns')) or 'n/a'} | {c['status']} |")
    L += ["", "## Timeline (UTC)", "", "| Time (UTC) | Capture | Frames | Event | State | Rule |", "|---|---|---|---|---|---|"]
    for it in items:
        fr = ", ".join(f"#{f}" for f in it["frames"][:6]) + ("…" if len(it["frames"]) > 6 else "")
        ev = T(it["title_en"] or it["title"]).replace("|", "/")
        if it.get("note"):
            ev += f" — note: {T(it['note']).replace('|', '/')}"
        L.append(f"| {ts_iso(it['ts_ns']) or '–'} | {it['capture_id'] or '–'} | {fr or '–'} | {ev} | "
                 f"{STATE_EN.get(it['state'], it['state'] or '')} | {(it['rule'] or '').split(':')[0]} |")
    L += ["", "## Packet references", ""]
    for cid in caps:
        frs = sorted({f for it in items if it["capture_id"] == cid for f in it["frames"]})
        if frs:
            L.append(f"- Capture #{cid} ({caps[cid]['name']}): frames {', '.join(map(str, frs[:200]))}"
                     + (" …" if len(frs) > 200 else ""))
            L.append(f"  - Wireshark display filter: `frame.number in {{{' '.join(map(str, frs[:200]))}}}`")
    L += ["", "## State legend", "",
          "- OBSERVED: directly visible in the capture.",
          "- INFERRED: derived by a stated correlation rule (rule id in the timeline).",
          "- UNDETERMINED: the capture does not allow a decision (e.g. ambiguous candidates, capture ends inside the "
          "response window).", "",
          "## Analysis limitations", ""]
    L += [f"- {T(x)}" for x in _limitations(caps)]
    md = "\n".join(L) + "\n"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    label = "MASKED" if masked else "UNMASKED"
    base = settings.exports_dir / f"incident_{iid}_{_safe(inc['title'])}_{stamp}_{label}"
    md_path = base.with_suffix(".md")
    md_path.write_text(md, "utf-8")
    js = {"incident": {"id": iid, "title": T(inc["title"]), "description": T(inc.get("description") or "")},
          "generated_utc": now, "masking": m.scope() if m else None,
          "captures": [{"id": cid, "name": c["name"], "sha256": c.get("sha256"), "status": c["status"],
                        "frames": c["frames"]} for cid, c in caps.items()],
          "items": [{"time_utc": ts_iso(it["ts_ns"]), "capture_id": it["capture_id"], "frames": it["frames"],
                     "kind": it["kind"], "text": T(it["title_en"] or it["title"]), "note": T(it.get("note") or ""),
                     "state": it["state"], "rule": it["rule"]} for it in items],
          "limitations": [T(x) for x in _limitations(caps)]}
    js_path = base.with_suffix(".json")
    js_path.write_text(json.dumps(js, ensure_ascii=False, indent=1), "utf-8")
    note = "angol összefoglaló; " + ("MASZKOLT: " + ", ".join(m.scope()["masked_classes"]) if m else "NEM maszkolt")
    r1 = _register_export(md_path, "report.md", masked, None, None, note, incident_id=iid)
    r2 = _register_export(js_path, "report.json", masked, None, None, note, incident_id=iid)
    return {"markdown": md, "exports": [r1, r2]}


def incident_frames(iid: int) -> dict[int, list[int]]:
    inc = get_incident(iid)
    out: dict[int, set[int]] = {}
    for it in inc["items"]:
        if it["capture_id"]:
            out.setdefault(it["capture_id"], set()).update(it["frames"])
    return {k: sorted(v) for k, v in out.items()}


_ = Path
