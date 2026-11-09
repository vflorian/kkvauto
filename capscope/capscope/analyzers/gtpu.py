"""GTP-U: attribute user-plane packets to GTP-C sessions.

Rule ``GTPU-FTEID``: a G-PDU (T-PDU) is attributed to a session only if
(outer destination ip, TEID) equals a user-plane F-TEID that the *receiving*
node signalled for that session, and the packet time lies in the F-TEID's
validity window (± ``gtpu_grace_s`` at the edges, flagged). The inner IP is a
cross-check against the allocated UE address (uplink: inner source, downlink:
inner destination). Same TEID on another endpoint, or only a matching inner IP,
is never enough. Several valid candidates -> ``undetermined`` with the list.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import INFERRED, OBSERVED, UNDETERMINED, Analyzer, Cut, Packet, dumps
from ..db import BatchWriter

SCHEMA = """
CREATE TABLE IF NOT EXISTS gtpu_tunnels(
  id INTEGER PRIMARY KEY, session_id INTEGER, fteid_id INTEGER, outer_src TEXT, outer_dst TEXT, teid INTEGER,
  direction TEXT, state TEXT, rule TEXT, candidates TEXT, note TEXT, pkts INTEGER, bytes INTEGER,
  first_frame INTEGER, last_frame INTEGER, first_ts INTEGER, last_ts INTEGER);
CREATE INDEX IF NOT EXISTS ix_tun_sess ON gtpu_tunnels(session_id);
CREATE INDEX IF NOT EXISTS ix_tun_teid ON gtpu_tunnels(teid);
CREATE TABLE IF NOT EXISTS gtpu_inner(
  tunnel_id INTEGER, inner_src TEXT, inner_dst TEXT, proto TEXT, pkts INTEGER, bytes INTEGER,
  first_frame INTEGER, PRIMARY KEY(tunnel_id, inner_src, inner_dst, proto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS gtpu_frames(frame_no INTEGER PRIMARY KEY, tunnel_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_gtpu_frames_tun ON gtpu_frames(tunnel_id, frame_no);
"""

MAX_INNER_PAIRS = 64


@dataclass
class Tunnel:
    id: int
    session_id: int | None
    fteid_id: int | None
    outer_src: str
    outer_dst: str
    teid: int
    direction: str | None
    state: str
    rule: str
    candidates: list
    note: str
    pkts: int = 0
    bytes: int = 0
    first_frame: int = 0
    last_frame: int = 0
    first_ts: int = 0
    last_ts: int = 0
    inner: dict = field(default_factory=dict)


class GtpuAnalyzer(Analyzer):
    name = "gtpu"
    title = "GTP-U"
    order = 50
    triggers = frozenset({"gtp"})
    fields = ("gtp.message", "gtp.teid")
    schema = SCHEMA

    def __init__(self, ctx):
        super().__init__(ctx)
        self.tunnels: dict[tuple, Tunnel] = {}
        self.next_id = 1
        self.frames = BatchWriter(ctx.con, "INSERT INTO gtpu_frames(frame_no, tunnel_id) VALUES (?,?)")
        self.grace = int(ctx.settings.gtpu_grace_s * 1e9)
        self.err_ind = 0

    def on_packet(self, pkt: Packet) -> None:
        osrc, odst, sport, dport, _ = pkt.endpoints_of("gtp")
        if 2152 not in (sport, dport):
            return
        mt = pkt.int("gtp.message")
        teid = pkt.int("gtp.teid")
        if mt == 26:
            self.ctx.finding("gtpu", "GTPU-ERROR-IND", OBSERVED, "error", pkt.ts_ns,
                             f"GTP-U Error Indication {osrc} → {odst}",
                             "A fogadó csomópont ismeretlen TEID-re kapott G-PDU-t (TS 29.281 7.3.1).", [pkt.frame],
                             en=f"GTP-U Error Indication {osrc} -> {odst} (peer received G-PDU for an unknown TEID)")
            return
        if mt != 255 or teid is None:
            return
        gpos = pkt.layers.index("gtp")
        inner_src = inner_dst = None
        iproto = None
        for i in range(gpos + 1, len(pkt.layers)):
            l = pkt.layers[i]
            if l in ("ip", "ipv6"):
                k = pkt.layers[:i].count(l)
                inner_src, inner_dst = pkt.get(f"{l}.src", k), pkt.get(f"{l}.dst", k)
                nxt = pkt.layers[i + 1] if i + 1 < len(pkt.layers) else ""
                iproto = nxt if nxt in ("tcp", "udp", "icmp", "icmpv6", "sctp", "esp") else (nxt or l)
                break
        uidx = self.ctx.shared.get("uplane")
        sessions = self.ctx.shared.get("sessions", {})
        cands = uidx.candidates(odst, teid, pkt.ts_ns, self.grace) if uidx else []
        fteid_id = session_id = direction = None
        cand_list: list = []
        note = ""
        if len(cands) == 1:
            f, exact = cands[0]
            fteid_id, session_id, direction = f.id, f.session_id, f.direction
            state, rule = INFERRED, "GTPU-FTEID: fogadó végpont (outer dst) + TEID + session-időablak"
            if not exact:
                note = "Az időablak szélén (±%.0f s) – az F-TEID jelzése/bontása közelében." % self.ctx.settings.gtpu_grace_s
            s = sessions.get(session_id)
            ue = (s.ue_ipv4 or s.ue_ipv6) if s else self._ue_ip(session_id)
            check = inner_src if direction == "uplink" else inner_dst if direction == "downlink" else None
            if ue and check and check != ue:
                state = UNDETERMINED
                note = (note + f" A belső IP ({check}) nem egyezik a session kiosztott címével ({ue}).").strip()
        elif len(cands) > 1:
            state, rule = UNDETERMINED, "GTPU-FTEID-AMBIGUOUS: több érvényes F-TEID jelölt"
            cand_list = sorted({f.session_id for f, _ in cands})
            note = "Több session is érvényes erre a (fogadó végpont, TEID) párra: " + \
                   ", ".join(f"#{c}" for c in cand_list)
        else:
            state, rule = UNDETERMINED, "GTPU-NOMATCH: nincs jelzett F-TEID ezen a fogadó végponton"
            other = sorted((uidx.ips_by_teid.get(teid, set()) - {odst}) if uidx else set())
            note = "Nincs GTP-C-ben jelzett F-TEID erre a (fogadó végpont, TEID) párra."
            if other:
                note += f" Azonos TEID más tunnelvégponto(ko)n ismert ({', '.join(other)}), ez önmagában nem elég " \
                        "a hozzárendeléshez."
        key = (osrc, odst, teid, fteid_id, session_id, state)
        t = self.tunnels.get(key)
        if t is None:
            t = Tunnel(self.next_id, session_id, fteid_id, osrc, odst, teid, direction, state, rule, cand_list, note,
                       first_frame=pkt.frame, first_ts=pkt.ts_ns)
            self.next_id += 1
            self.tunnels[key] = t
        t.pkts += 1
        t.bytes += pkt.length
        t.last_frame, t.last_ts = pkt.frame, pkt.ts_ns
        ik = (inner_src or "?", inner_dst or "?", iproto or "?")
        e = t.inner.get(ik)
        if e is None:
            if len(t.inner) >= MAX_INNER_PAIRS:
                ik = ("(egyéb)", "(egyéb)", "*")
                e = t.inner.get(ik)
            if e is None:
                e = t.inner[ik] = [0, 0, pkt.frame]
        e[0] += 1
        e[1] += pkt.length
        self.frames.add((pkt.frame, t.id))

    def _ue_ip(self, sid: int | None) -> str | None:
        if not sid:
            return None
        r = self.ctx.con.execute("SELECT coalesce(ue_ipv4, ue_ipv6) FROM gtp_sessions WHERE id=?", (sid,)).fetchone()
        return r[0] if r else None

    def periodic(self, now_ns: int) -> None:
        self._ticks = getattr(self, "_ticks", 0) + 1
        uidx = self.ctx.shared.get("uplane")
        if uidx and self._ticks % 60 == 0:  # once per ~minute of capture time: drop long-expired F-TEIDs
            uidx.prune(now_ns - 10 * self.grace)

    def finish(self, cut: Cut) -> None:
        self.frames.flush()
        con = self.ctx.con
        tw = BatchWriter(con, "INSERT INTO gtpu_tunnels(id, session_id, fteid_id, outer_src, outer_dst, teid, direction,"
                              " state, rule, candidates, note, pkts, bytes, first_frame, last_frame, first_ts, last_ts) "
                              "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        iw = BatchWriter(con, "INSERT INTO gtpu_inner(tunnel_id, inner_src, inner_dst, proto, pkts, bytes, first_frame) "
                              "VALUES (?,?,?,?,?,?,?)")
        unassigned = 0
        for t in self.tunnels.values():
            tw.add((t.id, t.session_id, t.fteid_id, t.outer_src, t.outer_dst, t.teid, t.direction, t.state, t.rule,
                    dumps(t.candidates), t.note, t.pkts, t.bytes, t.first_frame, t.last_frame, t.first_ts, t.last_ts))
            for (s, d, p), (n, b, ff) in t.inner.items():
                iw.add((t.id, s, d, p, n, b, ff))
            if t.session_id is None:
                unassigned += t.pkts
                self.ctx.finding("gtpu", t.rule.split(":")[0], UNDETERMINED, "warn", t.first_ts,
                                 f"GTP-U {t.outer_src} → {t.outer_dst} TEID 0x{t.teid:08x}: nincs egyértelmű session",
                                 f"{t.pkts} csomag. {t.note}", [t.first_frame, t.last_frame], "gtpu_tunnel", t.id,
                                 en=f"GTP-U {t.outer_src} -> {t.outer_dst} TEID 0x{t.teid:08x}: {t.pkts} packet(s) could "
                                    f"not be attributed to a unique session ({t.rule.split(':')[0]})")
        tw.flush()
        iw.flush()


ANALYZER = GtpuAnalyzer
