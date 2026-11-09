"""GTPv1-C / GTPv2-C: transactions and session life-cycle.

Correlation rules (all stored with the result):

* Transaction: (version, sequence number, requester ip, requester port,
  responder ip) and the response must come back from the responder to the
  requester with the paired message type inside ``gtp_timeout_s``.
* Session: a Create Session / Create PDP Context Request with header TEID 0
  opens a session. Later messages are attached via the *receiver's*
  control-plane F-TEID: (destination ip, header TEID) must match a C-plane
  F-TEID signalled by that receiver. A TEID on its own is never used.
* User-plane F-TEIDs (receiver ip, TEID, interface type, EBI) are recorded
  with a validity window (signalled -> replaced / released / deleted) and
  published to the GTP-U analyzer via ``ctx.shared['uplane']``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import (INFERRED, NO_RESPONSE_TEXT, OBSERVED, TXN_INSERT, TXN_SCHEMA, UNDETERMINED, Analyzer, Cut,
                   Packet, Pending, TxnMatcher, dumps, txn_state)
from ..db import BatchWriter

V2_MSG = {1: "Echo Request", 2: "Echo Response", 3: "Version Not Supported Indication",
          32: "Create Session Request", 33: "Create Session Response", 34: "Modify Bearer Request",
          35: "Modify Bearer Response", 36: "Delete Session Request", 37: "Delete Session Response",
          38: "Change Notification Request", 39: "Change Notification Response", 64: "Modify Bearer Command",
          65: "Modify Bearer Failure Indication", 66: "Delete Bearer Command", 67: "Delete Bearer Failure Indication",
          68: "Bearer Resource Command", 69: "Bearer Resource Failure Indication",
          70: "Downlink Data Notification Failure Indication", 95: "Create Bearer Request",
          96: "Create Bearer Response", 97: "Update Bearer Request", 98: "Update Bearer Response",
          99: "Delete Bearer Request", 100: "Delete Bearer Response", 101: "Delete PDN Connection Set Request",
          102: "Delete PDN Connection Set Response", 128: "Identification Request", 129: "Identification Response",
          130: "Context Request", 131: "Context Response", 132: "Context Acknowledge",
          133: "Forward Relocation Request", 134: "Forward Relocation Response",
          135: "Forward Relocation Complete Notification", 136: "Forward Relocation Complete Acknowledge",
          162: "Suspend Notification", 163: "Suspend Acknowledge", 164: "Resume Notification",
          165: "Resume Acknowledge", 166: "Create Indirect Data Forwarding Tunnel Request",
          167: "Create Indirect Data Forwarding Tunnel Response", 168: "Delete Indirect Data Forwarding Tunnel Request",
          169: "Delete Indirect Data Forwarding Tunnel Response", 170: "Release Access Bearers Request",
          171: "Release Access Bearers Response", 176: "Downlink Data Notification",
          177: "Downlink Data Notification Acknowledge", 179: "PGW Restart Notification",
          180: "PGW Restart Notification Acknowledge", 200: "Update PDN Connection Set Request",
          201: "Update PDN Connection Set Response", 211: "Modify Access Bearers Request",
          212: "Modify Access Bearers Response"}
V2_PAIR = {1: 2, 32: 33, 34: 35, 36: 37, 38: 39, 95: 96, 97: 98, 99: 100, 101: 102, 128: 129, 130: 131, 133: 134,
           135: 136, 162: 163, 164: 165, 166: 167, 168: 169, 170: 171, 176: 177, 179: 180, 200: 201, 211: 212}
V2_CAUSE = {16: "Request accepted", 17: "Request accepted partially", 18: "New PDN type due to network preference",
            19: "New PDN type due to single address bearer only", 64: "Context Not Found",
            65: "Invalid Message Format", 66: "Version not supported by next peer", 67: "Invalid length",
            68: "Service not supported", 69: "Mandatory IE incorrect", 70: "Mandatory IE missing",
            72: "System failure", 73: "No resources available", 74: "Semantic error in the TFT operation",
            75: "Syntactic error in the TFT operation", 76: "Semantic errors in packet filter(s)",
            77: "Syntactic errors in packet filter(s)", 78: "Missing or unknown APN", 80: "GRE key not found",
            81: "Relocation failure", 82: "Denied in RAT", 83: "Preferred PDN type not supported",
            84: "All dynamic addresses are occupied", 85: "UE context without TFT already activated",
            86: "Protocol type not supported", 87: "UE not responding", 88: "UE refuses", 89: "Service denied",
            90: "Unable to page UE", 91: "No memory available", 92: "User authentication failed",
            93: "APN access denied - no subscription", 94: "Request rejected (reason not specified)",
            96: "IMSI/IMEI not known", 100: "Remote peer not responding",
            101: "Collision with network initiated request", 103: "Conditional IE missing",
            107: "Invalid reply from remote peer", 110: "Temporarily rejected due to handover/TAU/RAU procedure in progress",
            113: "APN Congestion", 116: "Multiple PDN connections for a given APN not allowed",
            120: "GTP-C Entity Congestion", 122: "Timed out Request", 128: "S1-U Path Failure"}
V1_MSG = {1: "Echo Request", 2: "Echo Response", 3: "Version Not Supported", 16: "Create PDP Context Request",
          17: "Create PDP Context Response", 18: "Update PDP Context Request", 19: "Update PDP Context Response",
          20: "Delete PDP Context Request", 21: "Delete PDP Context Response",
          22: "Initiate PDP Context Activation Request", 23: "Initiate PDP Context Activation Response",
          26: "Error Indication", 27: "PDU Notification Request", 28: "PDU Notification Response",
          31: "Supported Extension Headers Notification", 254: "End Marker", 255: "G-PDU"}
V1_PAIR = {1: 2, 16: 17, 18: 19, 20: 21, 22: 23, 27: 28}
V1_CAUSE = {128: "Request accepted", 129: "New PDP type due to network preference",
            130: "New PDP type due to single address bearer only", 192: "Non-existent",
            193: "Invalid message format", 194: "IMSI/IMEI not known", 195: "MS is GPRS Detached",
            196: "MS is not GPRS Responding", 197: "MS Refuses", 198: "Version not supported",
            199: "No resources available", 200: "Service not supported", 201: "Mandatory IE incorrect",
            202: "Mandatory IE missing", 203: "Optional IE incorrect", 204: "System failure",
            205: "Roaming restriction", 206: "P-TMSI Signature mismatch", 207: "GPRS connection suspended",
            208: "Authentication failure", 209: "User authentication failed", 210: "Context not found",
            211: "All dynamic PDP addresses are occupied", 212: "No memory is available", 213: "Relocation failure",
            219: "Missing or unknown APN", 220: "Unknown PDP address or PDP type",
            222: "APN access denied - no subscription", 228: "Collision with network initiated request",
            229: "APN Congestion"}

# TS 29.274 table 8.22-1 (subset). direction = which way the GTP-U traffic *received* on it flows.
IFACE = {0: ("S1-U eNodeB GTP-U", "U", "downlink"), 1: ("S1-U SGW GTP-U", "U", "uplink"),
         2: ("S12 RNC GTP-U", "U", "downlink"), 3: ("S12 SGW GTP-U", "U", "uplink"),
         4: ("S5/S8 SGW GTP-U", "U", "downlink"), 5: ("S5/S8 PGW GTP-U", "U", "uplink"),
         6: ("S5/S8 SGW GTP-C", "C", None), 7: ("S5/S8 PGW GTP-C", "C", None), 10: ("S11 MME GTP-C", "C", None),
         11: ("S11/S4 SGW GTP-C", "C", None), 12: ("S10/N26 MME GTP-C", "C", None), 13: ("S3 MME GTP-C", "C", None),
         14: ("S3 SGSN GTP-C", "C", None), 15: ("S4 SGSN GTP-U", "U", "downlink"), 16: ("S4 SGW GTP-U", "U", "uplink"),
         17: ("S4 SGSN GTP-C", "C", None), 18: ("S16 SGSN GTP-C", "C", None),
         19: ("eNodeB/gNodeB GTP-U DL forwarding", "U", "forwarding"), 20: ("eNodeB GTP-U UL forwarding", "U", "forwarding"),
         21: ("RNC GTP-U forwarding", "U", "forwarding"), 22: ("SGSN GTP-U forwarding", "U", "forwarding"),
         23: ("SGW/UPF GTP-U DL forwarding", "U", "forwarding"), 28: ("SGW GTP-U UL forwarding", "U", "forwarding"),
         30: ("S2b ePDG GTP-C", "C", None), 31: ("S2b-U ePDG GTP-U", "U", "downlink"), 32: ("S2b PGW GTP-C", "C", None),
         33: ("S2b-U PGW GTP-U", "U", "uplink"), 34: ("S2a TWAN GTP-U", "U", "downlink"), 35: ("S2a TWAN GTP-C", "C", None),
         36: ("S2a PGW GTP-C", "C", None), 37: ("S2a PGW GTP-U", "U", "uplink"), 38: ("S11 MME GTP-U", "U", "downlink"),
         39: ("S11 SGW GTP-U", "U", "uplink"), 40: ("N26 AMF GTP-C", "C", None)}
LEG = {10: "S11", 11: "S11/S4", 6: "S5/S8", 7: "S5/S8", 12: "S10/N26", 13: "S3", 14: "S3", 17: "S4", 30: "S2b",
       32: "S2b", 35: "S2a", 36: "S2a", 40: "N26"}

SCHEMA = TXN_SCHEMA + """
CREATE TABLE IF NOT EXISTS gtp_sessions(
  id INTEGER PRIMARY KEY, version INTEGER, leg TEXT, imsi TEXT, msisdn TEXT, imei TEXT, apn TEXT, ue_ipv4 TEXT,
  ue_ipv6 TEXT, rat INTEGER, status TEXT, created_frame INTEGER, created_ts INTEGER, accepted_frame INTEGER,
  deleted_frame INTEGER, deleted_ts INTEGER, cause INTEGER, cause_text TEXT, cause_ok INTEGER, note TEXT,
  last_ts INTEGER);
CREATE TABLE IF NOT EXISTS gtp_events(
  id INTEGER PRIMARY KEY, session_id INTEGER, frame INTEGER, ts_ns INTEGER, version INTEGER, msg_type INTEGER,
  msg_name TEXT, src TEXT, dst TEXT, header_teid TEXT, seq TEXT, cause INTEGER, cause_text TEXT, role TEXT,
  state TEXT, rule TEXT);
CREATE INDEX IF NOT EXISTS ix_gtp_events_sess ON gtp_events(session_id);
CREATE TABLE IF NOT EXISTS gtp_fteids(
  id INTEGER PRIMARY KEY, session_id INTEGER, plane TEXT, iface_type INTEGER, iface_name TEXT, ip TEXT,
  teid INTEGER, ebi INTEGER, direction TEXT, valid_from_ts INTEGER, valid_to_ts INTEGER, source_frame INTEGER,
  end_frame INTEGER, end_reason TEXT);
CREATE INDEX IF NOT EXISTS ix_fteid_sess ON gtp_fteids(session_id);
CREATE INDEX IF NOT EXISTS ix_fteid_teid ON gtp_fteids(teid);
"""


@dataclass
class FTeid:
    id: int
    session_id: int
    plane: str
    iface_type: int | None
    ip: str
    teid: int
    ebi: int | None
    direction: str | None
    valid_from: int
    valid_to: int | None = None


class UPlaneIndex:
    """(receiver ip, TEID) -> F-TEIDs with validity windows. Shared with the GTP-U analyzer."""

    def __init__(self):
        self.by_key: dict[tuple[str, int], list[FTeid]] = {}
        self.ips_by_teid: dict[int, set[str]] = {}

    def add(self, f: FTeid) -> None:
        self.by_key.setdefault((f.ip, f.teid), []).append(f)
        self.ips_by_teid.setdefault(f.teid, set()).add(f.ip)

    def candidates(self, ip: str, teid: int, ts: int, grace_ns: int) -> list[tuple[FTeid, bool]]:
        out = []
        for f in self.by_key.get((ip, teid), ()):
            lo = f.valid_from
            hi = f.valid_to
            exact = lo <= ts and (hi is None or ts <= hi)
            near = (lo - grace_ns) <= ts and (hi is None or ts <= hi + grace_ns)
            if exact or near:
                out.append((f, exact))
        return out

    def prune(self, before_ns: int) -> None:
        for k in list(self.by_key):
            lst = [f for f in self.by_key[k] if f.valid_to is None or f.valid_to >= before_ns]
            if lst:
                self.by_key[k] = lst
            else:
                del self.by_key[k]


@dataclass
class Session:
    id: int
    version: int
    created_ts: int
    leg: str | None = None
    imsi: str | None = None
    msisdn: str | None = None
    imei: str | None = None
    apn: str | None = None
    ue_ipv4: str | None = None
    ue_ipv6: str | None = None
    rat: int | None = None
    status: str = "pending"
    ctrl: list[tuple[str, int]] = field(default_factory=list)
    uplane: list[FTeid] = field(default_factory=list)
    last_ts: int = 0


def _hex(v: int | None) -> str | None:
    return None if v is None else f"0x{v:08x}"


class GtpcAnalyzer(Analyzer):
    name = "gtpc"
    title = "GTP-C (GTPv1-C / GTPv2-C)"
    order = 40
    triggers = frozenset({"gtpv2", "gtp"})
    fields = ("gtpv2.message_type", "gtpv2.seq", "gtpv2.teid", "gtpv2.cause", "e212.imsi", "e164.msisdn",
              "gtpv2.mei", "gtpv2.apn", "gtpv2.rat_type", "gtpv2.f_teid_interface_type", "gtpv2.f_teid_gre_key",
              "gtpv2.f_teid_ipv4", "gtpv2.f_teid_ipv6", "gtpv2.f_teid_v4", "gtpv2.f_teid_v6", "gtpv2.ebi",
              "gtpv2.pdn_addr_and_prefix.ipv4", "gtpv2.pdn_addr_and_prefix.ipv6",
              "gtp.message", "gtp.seq_number", "gtp.teid", "gtp.cause", "gtp.apn", "gtp.teid_cp", "gtp.teid_data",
              "gtp.gsn_ipv4", "gtp.gsn_ipv6", "gtp.user_ipv4", "gtp.user_ipv6", "gtp.nsapi", "gtp.ext_imeisv")
    schema = SCHEMA

    def __init__(self, ctx):
        super().__init__(ctx)
        con = ctx.con
        self.con = con
        self.tx = BatchWriter(con, TXN_INSERT)
        self.ev = BatchWriter(con, "INSERT INTO gtp_events(session_id, frame, ts_ns, version, msg_type, msg_name, src, "
                                   "dst, header_teid, seq, cause, cause_text, role, state, rule) "
                                   "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        self.m = TxnMatcher(int(ctx.settings.gtp_timeout_s * 1e9), self._final, self._orphan)
        self.sessions: dict[int, Session] = {}
        self.ctrl_index: dict[tuple[str, int], int] = {}
        self.uidx = UPlaneIndex()
        ctx.shared["uplane"] = self.uidx
        ctx.shared["sessions"] = self.sessions

    # ------------------------------------------------------------------ helpers
    def _new_session(self, version: int, pkt: Packet, status: str, note: str | None = None) -> Session:
        cur = self.con.execute("INSERT INTO gtp_sessions(version, status, created_frame, created_ts, note) "
                               "VALUES (?,?,?,?,?)", (version, status, pkt.frame, pkt.ts_ns, note))
        s = Session(cur.lastrowid, version, pkt.ts_ns, status=status, last_ts=pkt.ts_ns)
        self.sessions[s.id] = s
        return s

    def _save(self, s: Session, **extra) -> None:
        cols = dict(leg=s.leg, imsi=s.imsi, msisdn=s.msisdn, imei=s.imei, apn=s.apn, ue_ipv4=s.ue_ipv4,
                    ue_ipv6=s.ue_ipv6, rat=s.rat, status=s.status, last_ts=s.last_ts, **extra)
        self.con.execute(f"UPDATE gtp_sessions SET {', '.join(k + '=?' for k in cols)} WHERE id=?",
                         (*cols.values(), s.id))

    def _add_ctrl(self, s: Session, ip: str | None, teid: int | None, iface_type: int | None, pkt: Packet) -> None:
        if not ip or not teid:
            return
        key = (ip, teid)
        old = self.ctrl_index.get(key)
        if old is not None and old != s.id:
            self.ctx.finding("gtpc", "GTPC-CTEID-REUSE", OBSERVED, "info", pkt.ts_ns,
                             f"C-plane TEID {_hex(teid)} @ {ip} újrafelhasználva",
                             f"Korábbi session #{old}, új session #{s.id}.", [pkt.frame], "gtp_session", s.id,
                             en=f"Control-plane TEID {_hex(teid)} at {ip} reused (session #{old} -> #{s.id})")
        self.ctrl_index[key] = s.id
        if key not in s.ctrl:
            s.ctrl.append(key)
            name = IFACE.get(iface_type, (None,))[0] if iface_type is not None else None
            self.con.execute("INSERT INTO gtp_fteids(session_id, plane, iface_type, iface_name, ip, teid, ebi, direction,"
                             " valid_from_ts, source_frame) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (s.id, "C", iface_type, name, ip, teid, None, None, pkt.ts_ns, pkt.frame))
        if iface_type in LEG and not s.leg:
            s.leg = LEG[iface_type]

    def _add_u(self, s: Session, ip: str, teid: int, iface_type: int | None, ebi: int | None, pkt: Packet,
               direction: str | None = None) -> None:
        if not ip or not teid:
            return
        name, _, d = IFACE.get(iface_type, (f"interface type {iface_type}", "U", None)) if iface_type is not None \
            else ("Gn/Gp GSN user plane", "U", direction)
        direction = direction or d
        for f in s.uplane:  # replaced by a newer F-TEID of the same interface type / bearer
            if f.valid_to is None and f.iface_type == iface_type and f.ebi == ebi and (f.ip, f.teid) != (ip, teid) \
                    and f.direction == direction:
                self._close_u(f, pkt, "replaced")
            elif f.valid_to is None and (f.ip, f.teid) == (ip, teid):
                return
        cur = self.con.execute("INSERT INTO gtp_fteids(session_id, plane, iface_type, iface_name, ip, teid, ebi, "
                               "direction, valid_from_ts, source_frame) VALUES (?,?,?,?,?,?,?,?,?,?)",
                               (s.id, "U", iface_type, name, ip, teid, ebi, direction, pkt.ts_ns, pkt.frame))
        f = FTeid(cur.lastrowid, s.id, "U", iface_type, ip, teid, ebi, direction, pkt.ts_ns)
        s.uplane.append(f)
        self.uidx.add(f)

    def _close_u(self, f: FTeid, pkt: Packet, reason: str) -> None:
        if f.valid_to is not None:
            return
        f.valid_to = pkt.ts_ns
        self.con.execute("UPDATE gtp_fteids SET valid_to_ts=?, end_frame=?, end_reason=? WHERE id=?",
                         (pkt.ts_ns, pkt.frame, reason, f.id))

    def _end_session(self, s: Session, pkt: Packet, status: str) -> None:
        for f in s.uplane:
            self._close_u(f, pkt, status)
        for key in s.ctrl:
            if self.ctrl_index.get(key) == s.id:
                del self.ctrl_index[key]
        self.con.execute("UPDATE gtp_fteids SET valid_to_ts=?, end_frame=?, end_reason=? "
                         "WHERE session_id=? AND plane='C' AND valid_to_ts IS NULL", (pkt.ts_ns, pkt.frame, status, s.id))
        s.status = status
        self._save(s, deleted_frame=pkt.frame, deleted_ts=pkt.ts_ns)
        self.sessions.pop(s.id, None)

    # ------------------------------------------------------------------ parsing
    def _fteids_v2(self, pkt: Packet) -> list[tuple[int | None, int, str | None]]:
        types = pkt.all("gtpv2.f_teid_interface_type")
        teids = pkt.all("gtpv2.f_teid_gre_key")
        v4f, v6f = pkt.all("gtpv2.f_teid_v4"), pkt.all("gtpv2.f_teid_v6")
        v4, v6 = iter(pkt.all("gtpv2.f_teid_ipv4")), iter(pkt.all("gtpv2.f_teid_ipv6"))
        out = []
        for i, t in enumerate(teids):
            ip4 = next(v4, None) if i < len(v4f) and v4f[i] in ("1", "True") else None
            ip6 = next(v6, None) if i < len(v6f) and v6f[i] in ("1", "True") else None
            try:
                it = int(types[i], 0) if i < len(types) else None
                te = int(t, 0)
            except ValueError:
                continue
            out.append((it, te, ip4 or ip6))
        return out

    def on_packet(self, pkt: Packet) -> None:
        if pkt.has_layer("gtpv2"):
            self._v2(pkt)
        elif pkt.has_layer("gtp"):
            src, dst, sport, dport, _ = pkt.endpoints_of("gtp")
            if 2123 in (sport, dport):
                self._v1(pkt, src, dst, sport, dport)

    def _v2(self, pkt: Packet) -> None:
        src, dst, sport, dport, _ = pkt.endpoints_of("gtpv2")
        mt = pkt.int("gtpv2.message_type")
        seq = pkt.int("gtpv2.seq")
        if mt is None or seq is None or src is None:
            return
        hteid = pkt.int("gtpv2.teid")
        cause = pkt.int("gtpv2.cause")
        name = V2_MSG.get(mt, f"GTPv2 message {mt}")
        data = {"mt": mt, "name": name, "hteid": hteid, "cause": cause, "src": src, "dst": dst, "v": 2}
        if mt in V2_PAIR:
            sess = None
            if mt == 32 and not hteid:
                key = (2, seq, src, sport, dst)
                pend = self.m.pending.get(key)
                if pend is not None and pend.rsp_frame is None:
                    sess = self.sessions.get(pend.data.get("sid"))
                else:
                    sess = self._new_session(2, pkt, "pending")
                    self._fill_v2_request(sess, pkt, src)
            elif hteid and mt != 1:
                sid = self.ctrl_index.get((dst, hteid))
                if sid is None:
                    sess = self._new_session(2, pkt, "unknown_start",
                                             "A session létrehozása nem látszik a capture-ben (a capture a session "
                                             "közben indult, vagy a C-plane F-TEID nem ismert).")
                    self._add_ctrl(sess, dst, hteid, None, pkt)
                else:
                    sess = self.sessions.get(sid)
            data["sid"] = sess.id if sess else None
            pend, retrans = self.m.request((2, seq, src, sport, dst), pkt, data)
            if sess and not retrans:
                self._apply_v2_request(sess, pkt, mt, src)
            self._event(sess, pkt, data, "request" if not retrans else "retransmission", seq)
            return
        if mt - 1 in V2_PAIR and V2_PAIR[mt - 1] == mt:
            key = (2, seq, dst, dport, src)
            peek = self.m.pending.get(key)
            if peek is not None and V2_PAIR.get(peek.data["mt"]) != mt:
                self._orphan(key, pkt, data)  # same sequence but a different procedure: not paired
                pend = None
            else:
                pend = self.m.response(key, pkt, data)
            sess = self.sessions.get(pend.data.get("sid")) if pend is not None else None
            if sess is not None and pend.rsp_frame == pkt.frame:
                self._apply_v2_response(sess, pkt, pend.data["mt"], cause, src, dst, hteid)
            elif sess is None and hteid:
                sid = self.ctrl_index.get((dst, hteid))
                sess = self.sessions.get(sid) if sid else None
            self._event(sess, pkt, data, "response", seq)
            return
        sid = self.ctrl_index.get((dst, hteid)) if hteid else None
        self._event(self.sessions.get(sid) if sid else None, pkt, data, "other", seq)

    def _fill_v2_request(self, s: Session, pkt: Packet, src: str) -> None:
        s.imsi = pkt.get("e212.imsi") or s.imsi
        s.msisdn = pkt.get("e164.msisdn") or s.msisdn
        s.imei = pkt.get("gtpv2.mei") or s.imei
        s.apn = pkt.get("gtpv2.apn") or s.apn
        s.rat = pkt.int("gtpv2.rat_type") or s.rat

    def _ebis(self, pkt: Packet) -> list[int]:
        out = []
        for e in pkt.all("gtpv2.ebi"):
            try:
                v = int(e, 0)
            except ValueError:
                continue
            if v not in out:
                out.append(v)
        return out

    def _register_v2_fteids(self, s: Session, pkt: Packet, sender_ip: str) -> None:
        fts = self._fteids_v2(pkt)
        cplane = [f for f in fts if IFACE.get(f[0], (None, "U"))[1] == "C"]
        sender = next((f for f in cplane if f[2] == sender_ip), cplane[0] if cplane else None)
        if sender:
            self._add_ctrl(s, sender[2], sender[1], sender[0], pkt)
        uplane = [f for f in fts if IFACE.get(f[0], (None, "U"))[1] == "U"]
        ebis = self._ebis(pkt)
        for i, (it, teid, ip) in enumerate(uplane):
            if len(ebis) == 1:
                ebi = ebis[0]
            elif len(ebis) == len(uplane):
                ebi = ebis[i]
            else:
                ebi = None
            self._add_u(s, ip, teid, it, ebi, pkt)

    def _apply_v2_request(self, s: Session, pkt: Packet, mt: int, src: str) -> None:
        s.last_ts = pkt.ts_ns
        self._fill_v2_request(s, pkt, src)
        if mt in (32, 34, 95, 97, 211, 133, 166):
            self._register_v2_fteids(s, pkt, src)
        if mt == 36:
            s.status = "deleting"
        self._save(s)

    def _apply_v2_response(self, s: Session, pkt: Packet, req_mt: int, cause: int | None, src: str, dst: str,
                           hteid: int | None) -> None:
        s.last_ts = pkt.ts_ns
        ok = cause is not None and 16 <= cause < 64
        if hteid:
            self._add_ctrl(s, dst, hteid, None, pkt)
        if req_mt == 32:
            if ok:
                s.status = "active"
                s.ue_ipv4 = pkt.get("gtpv2.pdn_addr_and_prefix.ipv4") or s.ue_ipv4
                s.ue_ipv6 = pkt.get("gtpv2.pdn_addr_and_prefix.ipv6") or s.ue_ipv6
                self._register_v2_fteids(s, pkt, src)
                self._save(s, accepted_frame=pkt.frame, cause=cause, cause_text=V2_CAUSE.get(cause), cause_ok=1)
            else:
                self._save(s, cause=cause, cause_text=V2_CAUSE.get(cause, f"cause {cause}"), cause_ok=0)
                self._end_session(s, pkt, "rejected")
            return
        if req_mt in (34, 95, 97, 211, 133, 166) and ok:
            self._register_v2_fteids(s, pkt, src)
        if req_mt == 36 and ok:
            self._end_session(s, pkt, "deleted")
            return
        if req_mt == 36 and not ok:
            s.status = "active"
        if req_mt == 99 and ok:
            ebis = set(self._ebis(pkt))
            for f in s.uplane:
                if f.ebi in ebis:
                    self._close_u(f, pkt, "bearer deleted")
        if req_mt == 170 and ok:  # Release Access Bearers: S1-U eNB tunnels released (ECM-IDLE)
            for f in s.uplane:
                if f.iface_type in (0, 2):
                    self._close_u(f, pkt, "access bearers released")
        self._save(s)

    def _v1(self, pkt: Packet, src: str, dst: str, sport: int, dport: int) -> None:
        mt = pkt.int("gtp.message")
        seq = pkt.int("gtp.seq_number")
        if mt is None or seq is None:
            return
        hteid = pkt.int("gtp.teid")
        cause = pkt.int("gtp.cause")
        name = V1_MSG.get(mt, f"GTPv1 message {mt}")
        data = {"mt": mt, "name": name, "hteid": hteid, "cause": cause, "src": src, "dst": dst, "v": 1}
        gsn = pkt.all("gtp.gsn_ipv4") or pkt.all("gtp.gsn_ipv6")
        if mt in V1_PAIR:
            sess = None
            key = (1, seq, src, sport, dst)
            if mt == 16 and not hteid:
                pend = self.m.pending.get(key)
                if pend is not None and pend.rsp_frame is None:
                    sess = self.sessions.get(pend.data.get("sid"))
                else:
                    sess = self._new_session(1, pkt, "pending")
                    sess.leg = "Gn/Gp"
            elif hteid and mt != 1:
                sid = self.ctrl_index.get((dst, hteid))
                if sid is None:
                    sess = self._new_session(1, pkt, "unknown_start",
                                             "A PDP context létrehozása nem látszik a capture-ben.")
                    sess.leg = "Gn/Gp"
                    self._add_ctrl(sess, dst, hteid, None, pkt)
                else:
                    sess = self.sessions.get(sid)
            data["sid"] = sess.id if sess else None
            pend, retrans = self.m.request(key, pkt, data)
            if sess and not retrans:
                sess.last_ts = pkt.ts_ns
                sess.imsi = pkt.get("e212.imsi") or sess.imsi
                sess.msisdn = pkt.get("e164.msisdn") or sess.msisdn
                sess.apn = pkt.get("gtp.apn") or sess.apn
                sess.imei = pkt.get("gtp.ext_imeisv") or sess.imei
                if mt in (16, 18):
                    self._register_v1(sess, pkt, gsn, "downlink")
                if mt == 20:
                    sess.status = "deleting"
                self._save(sess)
            self._event(sess, pkt, data, "request" if not retrans else "retransmission", seq)
            return
        if mt - 1 in V1_PAIR and V1_PAIR[mt - 1] == mt:
            key = (1, seq, dst, dport, src)
            peek = self.m.pending.get(key)
            if peek is not None and V1_PAIR.get(peek.data["mt"]) != mt:
                self._orphan(key, pkt, data)
                pend = None
            else:
                pend = self.m.response(key, pkt, data)
            sess = self.sessions.get(pend.data.get("sid")) if pend is not None else None
            if sess is not None and pend.rsp_frame == pkt.frame:
                ok = cause is not None and 128 <= cause < 192
                sess.last_ts = pkt.ts_ns
                if hteid:
                    self._add_ctrl(sess, dst, hteid, None, pkt)
                req_mt = pend.data["mt"]
                if req_mt == 16:
                    if ok:
                        sess.status = "active"
                        sess.ue_ipv4 = pkt.get("gtp.user_ipv4") or sess.ue_ipv4
                        sess.ue_ipv6 = pkt.get("gtp.user_ipv6") or sess.ue_ipv6
                        self._register_v1(sess, pkt, gsn, "uplink")
                        self._save(sess, accepted_frame=pkt.frame, cause=cause, cause_text=V1_CAUSE.get(cause), cause_ok=1)
                    else:
                        self._save(sess, cause=cause, cause_text=V1_CAUSE.get(cause, f"cause {cause}"), cause_ok=0)
                        self._end_session(sess, pkt, "rejected")
                elif req_mt == 18 and ok:
                    self._register_v1(sess, pkt, gsn, "uplink")
                    self._save(sess)
                elif req_mt == 20 and ok:
                    self._end_session(sess, pkt, "deleted")
                else:
                    self._save(sess)
            self._event(sess, pkt, data, "response", seq)
            return
        sid = self.ctrl_index.get((dst, hteid)) if hteid else None
        self._event(self.sessions.get(sid) if sid else None, pkt, data, "other", seq)

    def _register_v1(self, s: Session, pkt: Packet, gsn: list[str], direction: str) -> None:
        """GTPv1: GSN Address #1 = control plane, #2 = user plane (TS 29.060 7.3.1)."""
        c_ip = gsn[0] if gsn else None
        u_ip = gsn[1] if len(gsn) > 1 else c_ip
        self._add_ctrl(s, c_ip, pkt.int("gtp.teid_cp"), None, pkt)
        teid_d = pkt.int("gtp.teid_data")
        if u_ip and teid_d:
            nsapi = pkt.int("gtp.nsapi")
            self._add_u(s, u_ip, teid_d, None, nsapi, pkt, direction)

    # ------------------------------------------------------------------ output
    def _event(self, s: Session | None, pkt: Packet, data: dict, role: str, seq: int) -> None:
        cause = data.get("cause")
        ctab = V2_CAUSE if data["v"] == 2 else V1_CAUSE
        state, rule = OBSERVED, "GTPC-EVENT"
        if s is not None and role != "request" and data["mt"] not in (32, 16):
            state, rule = INFERRED, "GTPC-SESSION: fogadó C-plane F-TEID (dst ip + header TEID) vagy tranzakció"
        self.ev.add((s.id if s else None, pkt.frame, pkt.ts_ns, data["v"], data["mt"], data["name"], data["src"],
                     data["dst"], _hex(data.get("hteid")), f"0x{seq:06x}", cause,
                     ctab.get(cause) if cause is not None else None, role, state, rule))

    def periodic(self, now_ns: int) -> None:
        self.m.expire(now_ns)

    def _final(self, p: Pending, how: str) -> None:
        v, seq, client, cport, server = p.key
        status, state, note = txn_state(p, how)
        d = p.data
        cause = p.rsp_data.get("cause") if p.rsp_data else None
        ctab = V2_CAUSE if v == 2 else V1_CAUSE
        ok_range = (16, 64) if v == 2 else (128, 192)
        ok = None if cause is None else int(ok_range[0] <= cause < ok_range[1])
        result = None if cause is None else f"{cause} {ctab.get(cause, '')}".strip()
        if p.rsp_data and cause is None:
            result, ok = "(nincs Cause IE)", None
        s = self.sessions.get(d.get("sid")) if d.get("sid") else None
        imsi = s.imsi if s else self._imsi_of(d.get("sid"))
        rtt = (p.rsp_ts - p.req_ts) if p.rsp_ts else None
        proto = "gtpv2c" if v == 2 else "gtpv1c"
        rule = (f"GTPC-PAIR: verzió + sequence + kérő ip:port → válaszoló ip, párosított üzenettípus, ablak "
                f"{self.ctx.settings.gtp_timeout_s:.0f} s")
        self.tx.add((proto, d["name"], p.req_frame, p.rsp_frame, p.req_ts, p.rsp_ts, rtt, client, cport, server,
                     None, f"0x{seq:06x}", d["name"], result, ok, len(p.retrans), dumps(p.retrans), dumps(p.dup_rsp),
                     status, state, rule, note, d.get("sid"), imsi))
        frames = [p.req_frame, *p.retrans] + ([p.rsp_frame] if p.rsp_frame else [])
        label = "GTPv2-C" if v == 2 else "GTPv1-C"
        if status == "unanswered":
            self.ctx.finding("gtpc", "GTPC-NO-RESPONSE", state, "error", p.req_ts,
                             f"{label} {d['name']}: {NO_RESPONSE_TEXT}",
                             f"{client} → {server}, seq 0x{seq:06x}" + (f", IMSI {imsi}" if imsi else "") + f". {note}",
                             frames, "gtp_session", d.get("sid"),
                             en=f"{label} {d['name']} {client} -> {server} (seq 0x{seq:06x}"
                                + (f", IMSI {imsi}" if imsi else "") + "): no response visible in the analysed capture"
                                + (f" after {len(p.retrans)} retransmission(s)" if p.retrans else "")
                                + ("; capture/index ends inside the response window" if state != OBSERVED else ""))
            if s is not None and s.status == "pending":
                s.status = "no_response"
                self._save(s)
        elif ok == 0:
            self.ctx.finding("gtpc", "GTPC-REJECT", OBSERVED, "error", p.rsp_ts,
                             f"{label} {d['name']} elutasítva: cause {result}",
                             f"{server} → {client}" + (f", IMSI {imsi}" if imsi else "") + f", RTT {rtt / 1e6:.1f} ms.",
                             frames, "gtp_session", d.get("sid"),
                             en=f"{label} {d['name']} rejected by {server} with cause {result}"
                                + (f" (IMSI {imsi})" if imsi else "") + f", response after {rtt / 1e6:.1f} ms")
        if p.retrans:
            self.ctx.finding("gtpc", "GTPC-RETRANS", OBSERVED, "warn", p.req_ts,
                             f"{label} {d['name']}: {len(p.retrans)} ismételt kérés",
                             f"Első kérés #{p.req_frame}; ismétlések: {', '.join(map(str, p.retrans))}.", frames,
                             "gtp_session", d.get("sid"),
                             en=f"{label} {d['name']} retransmitted {len(p.retrans)}x ({client} -> {server})")

    def _imsi_of(self, sid: int | None) -> str | None:
        if not sid:
            return None
        r = self.con.execute("SELECT imsi FROM gtp_sessions WHERE id=?", (sid,)).fetchone()
        return r[0] if r else None

    def _orphan(self, key: tuple, pkt: Packet, data: dict) -> None:
        v, seq, client, cport, server = key
        self.tx.add(("gtpv2c" if v == 2 else "gtpv1c", data["name"], None, pkt.frame, None, pkt.ts_ns, None, client,
                     cport, server, None, f"0x{seq:06x}", data["name"], str(data.get("cause")), None, 0, "[]", "[]",
                     "orphan_response", OBSERVED, "GTPC-PAIR",
                     "A kéréshez tartozó csomag nem látszik a vizsgált capture-ben.", None, None))

    def finish(self, cut: Cut) -> None:
        self.m.flush(cut)
        for s in list(self.sessions.values()):
            if s.status == "pending":
                s.status = "undetermined"
            self._save(s)
        self.tx.flush()
        self.ev.flush()
        n_unknown = self.con.execute("SELECT count(*) FROM gtp_sessions WHERE status='unknown_start'").fetchone()[0]
        if n_unknown:
            self.ctx.finding("gtpc", "GTPC-MIDSESSION", UNDETERMINED, "info", None,
                             f"{n_unknown} session létrehozása nem látszik a capture-ben",
                             "Ezeknél az IMSI/APN/kiosztott IP hiányozhat; a hozzárendelés csak a fogadó C-plane "
                             "F-TEID-en alapul.",
                             en=f"{n_unknown} GTP session(s) were already established before the capture started")


ANALYZER = GtpcAnalyzer
