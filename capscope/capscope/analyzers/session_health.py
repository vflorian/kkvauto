"""Session health: sessions without user-plane traffic, short-lived sessions, re-attach loops,
Create Session rate increases ("signalling storm") – per session, per IMSI and per APN.

Typical ticket this answers: "from 06:30 UTC there is an increase of data sessions without
traffic on APN X; sessions are created successfully and terminated shortly after".

Rules (stored with every result):

* ``SESSION-NO-UPLANE``: an accepted session has no GTP-U attributed to it (rule GTPU-FTEID).
  - observed      – its user-plane endpoints are visible in the capture (other GTP-U to/from
                    the same tunnel endpoint IPs exists), so the absence is real *in this capture*;
  - undetermined  – the user plane of this session is not visible at the capture point at all
                    (e.g. a control-plane-only trace): absence of traffic cannot be decided.
* ``SESSION-SHORT``: accepted and deleted within ``short_session_s``.
* ``SESSION-CHURN``: one IMSI creates ≥ ``churn_min_sessions`` short / empty sessions.
* ``SESSION-RATE-INCREASE``: Create Session (Create PDP Context) rate per APN jumps by
  ≥ ``rate_increase_factor`` at a change point (onset), compared with the time before it.
* ``PDN-TYPE-MISMATCH``: requested PDN type (e.g. IPv4v6) differs from what was allocated.
* Deletion side: the sender of Delete Session / Delete PDP Context / Delete Bearer Request is
  compared with the sender of the creating request – "access side" (MME/SGSN, i.e. UE- or
  MME-initiated) or "core side" (SGW/PGW/GGSN-initiated).
"""
from __future__ import annotations

import json
import statistics

from .base import INFERRED, OBSERVED, UNDETERMINED, Analyzer, Cut

SCHEMA = """
CREATE TABLE IF NOT EXISTS session_health(
  session_id INTEGER PRIMARY KEY, version INTEGER, imsi TEXT, apn TEXT, imei TEXT, tac TEXT, rat INTEGER,
  status TEXT, created_ts INTEGER, created_frame INTEGER, accepted INTEGER, deleted_ts INTEGER, deleted_frame INTEGER,
  duration_ns INTEGER, ul_pkts INTEGER, dl_pkts INTEGER, ul_bytes INTEGER, dl_bytes INTEGER,
  up_state TEXT, up_note TEXT, short_lived INTEGER, del_side TEXT, del_initiator TEXT, del_msg TEXT,
  del_req_frame INTEGER, pdn_req TEXT, pdn_alloc TEXT, pdn_mismatch INTEGER, prev_gap_ns INTEGER, imsi_seq INTEGER,
  dns_ok INTEGER, dns_fail INTEGER, dns_fail_qname TEXT, dns_fail_frame INTEGER, dns_fail_to_delete_ns INTEGER);
CREATE INDEX IF NOT EXISTS ix_sh_imsi ON session_health(imsi);
CREATE INDEX IF NOT EXISTS ix_sh_apn ON session_health(apn, created_ts);
CREATE TABLE IF NOT EXISTS imsi_health(
  imsi TEXT PRIMARY KEY, apn TEXT, tac TEXT, sessions INTEGER, accepted INTEGER, rejected INTEGER,
  no_traffic INTEGER, up_undetermined INTEGER, with_traffic INTEGER, short_lived INTEGER,
  median_duration_ns INTEGER, median_gap_ns INTEGER, del_access INTEGER, del_core INTEGER,
  first_ts INTEGER, last_ts INTEGER, first_frame INTEGER, score REAL);
CREATE TABLE IF NOT EXISTS apn_rate(
  apn TEXT, bucket INTEGER, width INTEGER, created INTEGER, accepted INTEGER, rejected INTEGER, no_traffic INTEGER,
  up_undetermined INTEGER, short_lived INTEGER, imsis INTEGER, PRIMARY KEY(apn, bucket)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS apn_onset(
  apn TEXT PRIMARY KEY, onset_bucket INTEGER, width INTEGER, before_per_min REAL, after_per_min REAL, ratio REAL,
  before_no_traffic_ratio REAL, after_no_traffic_ratio REAL, state TEXT, rule TEXT, note TEXT);
"""

PDN = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Non-IP", 5: "Ethernet"}


def _median(v: list[int]) -> int | None:
    v = [x for x in v if x is not None]
    return int(statistics.median(v)) if v else None


def detect_onset(series: list[tuple[int, int]], factor: float, min_after_per_bucket: float,
                 min_before: int = 3, min_after: int = 3) -> dict | None:
    """Single change point: the split that maximises mean(after)/mean(before).

    ``series``: [(bucket_start, count)] with every bucket present (zeros included)."""
    n = len(series)
    if n < min_before + min_after:
        return None
    counts = [c for _, c in series]
    prefix = [0]
    for c in counts:
        prefix.append(prefix[-1] + c)
    best = None
    for i in range(min_before, n - min_after + 1):
        before = prefix[i] / i
        after = (prefix[n] - prefix[i]) / (n - i)
        ratio = after / before if before > 0 else (float("inf") if after > 0 else 0.0)
        if after >= min_after_per_bucket and ratio >= factor and (best is None or ratio > best["ratio"]):
            best = {"index": i, "before": before, "after": after, "ratio": ratio}
    if best is None:
        return None
    # the split can land on a quiet bucket just before the jump: move to the first bucket that really jumps
    i = best["index"]
    while i < n - 1 and counts[i] <= best["before"] * factor and counts[i] < best["after"] / 2:
        i += 1
    best["index"], best["bucket"] = i, series[i][0]
    return best


class SessionHealthAnalyzer(Analyzer):
    name = "session_health"
    title = "Session-egészség (forgalom nélküli / rövid sessionök, churn, CSR-ráta)"
    order = 60          # after gtpc (40) and gtpu (50): works on their tables in finish()
    triggers = frozenset()  # never called per packet
    fields = ()
    schema = SCHEMA

    def finish(self, cut: Cut) -> None:
        con = self.ctx.con
        st = self.ctx.settings
        short_ns = int(st.short_session_s * 1e9)
        sessions = [dict(r) for r in con.execute("SELECT * FROM gtp_sessions ORDER BY created_ts, id")]
        if not sessions:
            return
        # user-plane counters per session and direction
        up = {}
        for r in con.execute("SELECT session_id, direction, sum(pkts), sum(bytes) FROM gtpu_tunnels "
                             "WHERE session_id IS NOT NULL GROUP BY session_id, direction"):
            up.setdefault(r[0], {})[r[1]] = (r[2], r[3])
        # which tunnel endpoint IPs carry any GTP-U in this capture
        seen_ips = {r[0] for r in con.execute("SELECT outer_dst FROM gtpu_tunnels UNION SELECT outer_src FROM gtpu_tunnels")}
        any_gtpu = bool(seen_ips)
        u_ips: dict[int, set] = {}
        for r in con.execute("SELECT session_id, ip FROM gtp_fteids WHERE plane='U'"):
            u_ips.setdefault(r[0], set()).add(r[1])
        creators = {r[0]: r[1] for r in con.execute(
            "SELECT session_id, src, min(frame) FROM gtp_events WHERE role='request' AND msg_type IN (32, 16) "
            "AND session_id IS NOT NULL GROUP BY session_id")}
        # DNS transactions by client IP (the UE address inside the tunnel / on SGi)
        dns: dict[str, list] = {}
        for t in con.execute("SELECT client, req_ts, rsp_ts, rsp_frame, result_ok, summary FROM transactions "
                             "WHERE proto='dns' AND req_ts IS NOT NULL ORDER BY req_ts"):
            dns.setdefault(t[0], []).append(t)
        end_ts = cut.last_ts_ns
        last_end: dict[str, int] = {}
        seq: dict[str, int] = {}
        rows = []
        for s in sessions:
            sid = s["id"]
            accepted = int(s["accepted_frame"] is not None)
            ul = up.get(sid, {}).get("uplink", (0, 0))
            dl = up.get(sid, {}).get("downlink", (0, 0))
            other = sum(v[0] for k, v in up.get(sid, {}).items() if k not in ("uplink", "downlink"))
            pk = (ul[0] or 0) + (dl[0] or 0) + (other or 0)
            dur = (s["deleted_ts"] - s["created_ts"]) if s["deleted_ts"] and accepted else None
            if not accepted:
                up_state, up_note = "n/a", "A session nem jött létre (elutasítva / válasz nélkül)."
            elif pk:
                up_state, up_note = "traffic", "GTP-U forgalom hozzárendelve (GTPU-FTEID)."
            elif not s["deleted_ts"] and cut.last_ts_ns is not None and \
                    cut.last_ts_ns - s["created_ts"] < st.min_observe_s * 1e9:
                up_state = "undetermined"
                up_note = (f"A session a capture végéig csak {(cut.last_ts_ns - s['created_ts']) / 1e9:.1f} s-ig "
                           f"látszik (< {st.min_observe_s:.0f} s) és nem bontott: túl rövid megfigyelés ahhoz, "
                           "hogy a forgalom hiánya eldönthető legyen.")
            elif u_ips.get(sid) and u_ips[sid] & seen_ips:
                up_state = "no_traffic"
                up_note = ("Nincs hozzárendelt GTP-U, pedig a session user-plane végpontjain (" +
                           ", ".join(sorted(u_ips[sid] & seen_ips)) + ") látszik GTP-U forgalom a capture-ben.")
            else:
                up_state = "undetermined"
                up_note = ("A session user plane-je nem látszik a capture-pontban" +
                           (" (a capture-ben egyáltalán nincs GTP-U)" if not any_gtpu else
                            " (a végpontjain nincs GTP-U a capture-ben)") +
                           ", ezért nem eldönthető, volt-e adatforgalom.")
            short = int(dur is not None and dur < short_ns)
            # TS 29.274: Delete Session Request always travels MME -> SGW -> PGW (UE/MME/SGW-initiated);
            # PGW-initiated release uses Delete Bearer Request. GTPv1 Delete PDP may come from either side.
            creator = creators.get(sid)
            del_side = None
            if s["del_msg"] == "Delete Session Request":
                del_side = "access"
            elif s["del_msg"] == "Delete Bearer Request":
                del_side = "core"
            elif s["del_initiator"] and creator:
                del_side = "access" if s["del_initiator"] == creator else "core"
            pdn_alloc = ("IPv4v6" if s["ue_ipv4"] and s["ue_ipv6"] else "IPv4" if s["ue_ipv4"] else
                         "IPv6" if s["ue_ipv6"] else None)
            pdn_req = PDN.get(s["pdn_type_req"]) if s["pdn_type_req"] else None
            mism = int(bool(accepted and pdn_req and pdn_alloc and pdn_req != pdn_alloc))
            imsi = s["imsi"]
            gap = None
            if imsi:
                seq[imsi] = seq.get(imsi, 0) + 1
                if imsi in last_end:
                    gap = s["created_ts"] - last_end[imsi]
                if s["deleted_ts"]:
                    last_end[imsi] = s["deleted_ts"]
            d_ok = d_fail = 0
            d_name = d_frame = d_gap = None
            ue = s["ue_ipv4"] or s["ue_ipv6"]
            if accepted and ue:
                hi = s["deleted_ts"] or end_ts or 0
                for _c, rq, rs, rf, okv, summ in dns.get(ue, ()):
                    if rq < s["created_ts"] or rq > hi:
                        continue
                    if okv == 1:
                        d_ok += 1
                    elif okv == 0:
                        d_fail += 1
                        if d_name is None:
                            d_name, d_frame = summ, rf
                            d_gap = (s["deleted_ts"] - rs) if s["deleted_ts"] and rs else None
            imei = s["imei"]
            rows.append((sid, s["version"], imsi, s["apn"], imei, imei[:8] if imei and len(imei) >= 8 else None,
                         s["rat"], s["status"], s["created_ts"], s["created_frame"], accepted, s["deleted_ts"],
                         s["deleted_frame"], dur, ul[0] or 0, dl[0] or 0, ul[1] or 0, dl[1] or 0, up_state, up_note,
                         short, del_side, s["del_initiator"], s["del_msg"], s["del_req_frame"], pdn_req, pdn_alloc,
                         mism, gap, seq.get(imsi), d_ok, d_fail, d_name, d_frame, d_gap))
        con.executemany(f"INSERT OR REPLACE INTO session_health VALUES ({','.join('?' * 35)})", rows)
        self._per_imsi()
        self._per_apn(cut)
        self._findings(any_gtpu)

    # ------------------------------------------------------------------
    def _per_imsi(self) -> None:
        con = self.ctx.con
        by: dict[str, list[dict]] = {}
        for r in con.execute("SELECT * FROM session_health WHERE imsi IS NOT NULL ORDER BY created_ts"):
            by.setdefault(r["imsi"], []).append(dict(r))
        out = []
        for imsi, ss in by.items():
            acc = [s for s in ss if s["accepted"]]
            nt = sum(1 for s in acc if s["up_state"] == "no_traffic")
            und = sum(1 for s in acc if s["up_state"] == "undetermined")
            wt = sum(1 for s in acc if s["up_state"] == "traffic")
            sh = sum(s["short_lived"] for s in acc)
            score = sh + nt + 0.5 * und + 0.25 * len(ss)
            tacs = [s["tac"] for s in ss if s["tac"]]
            out.append((imsi, ss[-1]["apn"], tacs[-1] if tacs else None, len(ss), len(acc),
                        sum(1 for s in ss if s["status"] == "rejected"), nt, und, wt, sh,
                        _median([s["duration_ns"] for s in acc]), _median([s["prev_gap_ns"] for s in ss]),
                        sum(1 for s in ss if s["del_side"] == "access"), sum(1 for s in ss if s["del_side"] == "core"),
                        ss[0]["created_ts"], ss[-1]["created_ts"], ss[0]["created_frame"], score))
        con.executemany(f"INSERT OR REPLACE INTO imsi_health VALUES ({','.join('?' * 18)})", out)

    def _per_apn(self, cut: Cut) -> None:
        con = self.ctx.con
        st = self.ctx.settings
        lo = con.execute("SELECT min(created_ts) FROM session_health").fetchone()[0]
        hi = max(cut.last_ts_ns or lo, con.execute("SELECT max(created_ts) FROM session_health").fetchone()[0])
        span = (hi - lo) / 1e9
        w = 1
        for cand in (int(st.rate_bucket_s), 10, 1):  # adaptive resolution: at least ~20 buckets if possible
            if span / cand >= 20:
                w = cand
                break
        con.execute("""INSERT OR REPLACE INTO apn_rate
            SELECT coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)'), (created_ts / 1000000000 / ?) * ?, ?, count(*), sum(accepted),
                   sum(status='rejected'), sum(up_state='no_traffic'), sum(up_state='undetermined'),
                   sum(short_lived), count(DISTINCT imsi)
            FROM session_health GROUP BY 1, 2""", (w, w, w))
        for (apn,) in con.execute("SELECT DISTINCT apn FROM apn_rate").fetchall():
            rows = con.execute("SELECT bucket, created, accepted, no_traffic, up_undetermined FROM apn_rate "
                               "WHERE apn=? ORDER BY bucket", (apn,)).fetchall()
            first, last = rows[0][0], rows[-1][0]
            # pad with empty buckets up to the end of the capture so a quiet tail counts as quiet
            end = (cut.last_ts_ns // 1_000_000_000 // w) * w if cut.last_ts_ns else last
            have = {r[0]: r for r in rows}
            series = [(b, have[b][1] if b in have else 0) for b in range(first, max(last, end) + 1, w)]
            per_min = 60.0 / w
            best = detect_onset(series, st.rate_increase_factor, st.rate_min_after_per_min / per_min)
            if not best:
                continue
            idx = best["index"]
            def nt_ratio(sel):
                acc = sum(have[b][2] for b, _ in sel if b in have)
                empty = sum(have[b][3] + have[b][4] for b, _ in sel if b in have)
                return round(empty / acc, 3) if acc else None
            ratio = best["ratio"] if best["ratio"] != float("inf") else 999.0
            note = (f"A Create Session/PDP ráta {best['before'] * per_min:.1f}/perc → {best['after'] * per_min:.1f}/perc "
                    f"({ratio:.1f}×). Kezdőpont: a változási pont, ahol az utána/előtte átlag aránya a legnagyobb; "
                    f"felbontás {w} s, a capture eleje előtti időszak nem ismert.")
            con.execute("INSERT OR REPLACE INTO apn_onset VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (apn, best["bucket"], w, best["before"] * per_min, best["after"] * per_min, ratio,
                         nt_ratio(series[:idx]), nt_ratio(series[idx:]), INFERRED,
                         f"SESSION-RATE-INCREASE: változási pont, arány ≥ {st.rate_increase_factor}", note))

    def _findings(self, any_gtpu: bool) -> None:
        con, st = self.ctx.con, self.ctx.settings
        f = self.ctx.finding
        for r in con.execute("SELECT * FROM apn_onset"):
            ts = r["onset_bucket"] * 1_000_000_000
            frames = [x[0] for x in con.execute(
                "SELECT created_frame FROM session_health WHERE coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)')=? AND created_ts>=? "
                "ORDER BY created_ts LIMIT 5", (r["apn"], ts))]
            f("session_health", "SESSION-RATE-INCREASE", INFERRED, "warn", ts,
              f"APN {r['apn']}: Create Session ráta-növekedés {r['ratio']:.1f}× ettől: "
              f"{_utc(r['onset_bucket'])} UTC", r["note"], frames, "apn", None,
              en=f"APN {r['apn']}: Create Session/PDP request rate increased {r['ratio']:.1f}x "
                 f"({r['before_per_min']:.1f}/min -> {r['after_per_min']:.1f}/min) starting at "
                 f"{_utc(r['onset_bucket'])} UTC ({r['width']} s resolution)")
        for r in con.execute("""SELECT coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)') apn, sum(accepted) acc,
                                  sum(up_state='no_traffic') nt, sum(up_state='undetermined') und,
                                  sum(short_lived) sh, sum(pdn_mismatch) mm FROM session_health GROUP BY 1"""):
            if r["nt"]:
                f("session_health", "SESSION-NO-UPLANE", OBSERVED, "warn", None,
                  f"APN {r['apn']}: {r['nt']}/{r['acc']} létrejött session user-plane forgalom nélkül",
                  "A session user-plane végpontjain más GTP-U forgalom látszik, ehhez a sessionhöz nem tartozik GTP-U.",
                  [], "apn", None,
                  en=f"APN {r['apn']}: {r['nt']} of {r['acc']} established sessions carried no user-plane traffic "
                     f"in the capture (their GTP-U endpoints are visible)")
            if r["und"]:
                f("session_health", "SESSION-NO-UPLANE", UNDETERMINED, "info", None,
                  f"APN {r['apn']}: {r['und']} session adatforgalma nem eldönthető (a user plane nem látszik, vagy a session túl rövid ideig látszik)",
                  "A capture-pontban ezeknek a sessionöknek a GTP-U végpontjai nem látszanak (pl. csak control-plane "
                  "trace). A 'forgalom nélküli' állításhoz user-plane (S1-U/S5-U/Gn-U) capture vagy CDR szükséges.",
                  [], "apn", None,
                  en=f"APN {r['apn']}: user-plane activity of {r['und']} sessions cannot be determined - the user "
                     f"plane is not visible at the capture point or the session is observed for less than "
                     f"{st.min_observe_s:.0f} s before the capture ends")
            if r["mm"]:
                f("session_health", "PDN-TYPE-MISMATCH", OBSERVED, "info", None,
                  f"APN {r['apn']}: {r['mm']} sessionnél a kért és a kiosztott PDN-típus eltér",
                  "Pl. IPv4v6 kérés, csak IPv4 kiosztás. Egyes eszközök ilyenkor bontanak és újrapróbálkoznak.",
                  [], "apn", None,
                  en=f"APN {r['apn']}: requested and allocated PDN type differ in {r['mm']} sessions")
        # DNS failure followed by the session being deleted (device gives up after a failed lookup)
        for r in con.execute("""SELECT coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)') apn, dns_fail_qname q, count(*) n,
                  sum(deleted_ts IS NOT NULL) deleted, sum(del_side='access') del_access
                  FROM session_health WHERE dns_fail > 0 GROUP BY 1, 2 ORDER BY n DESC""").fetchall():
            gaps = sorted(x[0] for x in con.execute(
                "SELECT dns_fail_to_delete_ns FROM session_health WHERE coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)')=? AND "
                "dns_fail_qname IS ? AND dns_fail_to_delete_ns IS NOT NULL", (r["apn"], r["q"])))
            ok = con.execute("SELECT count(*), sum(deleted_ts IS NOT NULL) FROM session_health WHERE "
                             "coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)')=? AND dns_ok > 0 AND dns_fail = 0", (r["apn"],)).fetchone()
            frames = [x[0] for x in con.execute("SELECT dns_fail_frame FROM session_health WHERE "
                                                "coalesce(apn,'(létrehozás nem látszik – APN ismeretlen)')=? AND dns_fail_qname IS ? LIMIT 5",
                                                (r["apn"], r["q"]))]
            med = f"{gaps[len(gaps) // 2] / 1e9:.1f} s ({gaps[0] / 1e9:.1f}–{gaps[-1] / 1e9:.1f} s)" if gaps else "–"
            okn = ok[0] or 0
            f("session_health", "DNS-FAIL-THEN-DELETE" if r["deleted"] else "DNS-FAIL-IN-SESSION",
              INFERRED if r["deleted"] else OBSERVED, "warn", None,
              f"APN {r['apn']}: {r['n']} sessionben sikertelen DNS ({r['q']}); ebből {r['deleted']} bontott a capture-ben",
              f"Hibás DNS-válasz → bontás medián {med}; bontást kezdeményezte a hozzáférési oldal {r['del_access']}×. "
              f"Összevetés: sikeres DNS-ű sessionök: {okn}, ebből bontott {ok[1] or 0}. Időbeli egymásutániság "
              f"(következtetés), nem bizonyított ok-okozat; a bontás csak a capture végéig látható.", frames, "apn", None,
              en=f"APN {r['apn']}: {r['n']} sessions got a failed DNS answer for {r['q']}; {r['deleted']} of them "
                 f"were deleted in the capture, median {med} after the failed answer"
                 + (f", deletion initiated by the access side {r['del_access']}x" if r["del_access"] else "")
                 + f" (comparison: {ok[1] or 0} of {okn} sessions with successful DNS were deleted)")
        churn = con.execute("""SELECT * FROM imsi_health WHERE (short_lived + no_traffic) >= ? OR sessions >= ?
                               ORDER BY score DESC""", (st.churn_min_sessions, st.churn_min_sessions * 2)).fetchall()
        for r in churn[:50]:
            frames = [x[0] for x in con.execute("SELECT created_frame FROM session_health WHERE imsi=? "
                                                "ORDER BY created_ts LIMIT 6", (r["imsi"],))]
            state = OBSERVED if r["no_traffic"] or r["short_lived"] else UNDETERMINED
            gap = f", medián újrakapcsolódás {r['median_gap_ns'] / 1e9:.1f} s" if r["median_gap_ns"] is not None else ""
            dur = f", medián élettartam {r['median_duration_ns'] / 1e9:.1f} s" if r["median_duration_ns"] is not None else ""
            side = (f"; bontást kezdeményezte: hozzáférési oldal {r['del_access']}×, core oldal {r['del_core']}×"
                    if r["del_access"] or r["del_core"] else "")
            f("session_health", "SESSION-CHURN", state, "warn", r["first_ts"],
              f"IMSI {r['imsi']}: {r['sessions']} session ({r['short_lived']} rövid, {r['no_traffic']} forgalom nélkül"
              + (f", {r['up_undetermined']} adatforgalma nem eldönthető" if r["up_undetermined"] else "") + ")",
              f"APN {r['apn']}{dur}{gap}{side}.", frames, "imsi", None,
              en=f"IMSI {r['imsi']} (APN {r['apn']}): {r['sessions']} sessions, {r['short_lived']} short-lived, "
                 + (f"{r['no_traffic']} without user-plane traffic" if not r["up_undetermined"] else
                    f"{r['no_traffic']} without user-plane traffic, {r['up_undetermined']} with user-plane activity "
                    f"not visible in the capture")
                 + (f", median lifetime {r['median_duration_ns'] / 1e9:.1f} s" if r["median_duration_ns"] is not None else "")
                 + (f", median re-attach gap {r['median_gap_ns'] / 1e9:.1f} s" if r["median_gap_ns"] is not None else "")
                 + (f"; deletion initiated by access side {r['del_access']}x, core side {r['del_core']}x"
                    if r["del_access"] or r["del_core"] else ""))
        if len(churn) > 50:
            f("session_health", "SESSION-CHURN", OBSERVED, "info", None, f"További {len(churn) - 50} érintett IMSI",
              "A teljes lista: Session-egészség nézet / CSV export.", [], None, None,
              en=f"{len(churn) - 50} further affected IMSIs (see the IMSI CSV export)")
        _ = json


def _utc(sec: int) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec))


ANALYZER = SessionHealthAnalyzer
