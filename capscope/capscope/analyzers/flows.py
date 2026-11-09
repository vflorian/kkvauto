"""Bidirectional TCP/UDP flows (keyed by TShark's tcp.stream / udp.stream).

Per flow: endpoints (A = initiator if a SYN is seen, else first sender),
packet/byte counters per direction, TCP handshake frames, resets,
retransmissions, visible TLS handshake (ClientHello/SNI, ServerHello,
version, alerts) and ICMP errors that quote the flow. Tunnelled flows
(inside GTP-U) are marked. Memory is bounded: idle flows are flushed to
SQLite with an UPSERT when the in-memory table grows too large.
"""
from __future__ import annotations

from .base import OBSERVED, UNDETERMINED, Analyzer, Cut, Packet, dumps

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows(
  id INTEGER PRIMARY KEY, l4 TEXT, stream INTEGER, a_ip TEXT, a_port INTEGER, b_ip TEXT, b_port INTEGER,
  first_frame INTEGER, last_frame INTEGER, first_ts INTEGER, last_ts INTEGER, pkts_ab INTEGER, pkts_ba INTEGER,
  bytes_ab INTEGER, bytes_ba INTEGER, syn_frame INTEGER, synack_frame INTEGER, ack_frame INTEGER,
  handshake TEXT, initiator_known INTEGER, rst_count INTEGER, rst_frames TEXT, fin_count INTEGER,
  retrans INTEGER, retrans_frames TEXT, tls_sni TEXT, tls_ch_frame INTEGER, tls_sh_frame INTEGER,
  tls_version TEXT, tls_alert TEXT, tls_alert_frame INTEGER, icmp_count INTEGER, icmp_frames TEXT,
  tunneled INTEGER);
CREATE INDEX IF NOT EXISTS ix_flows_a ON flows(a_ip);
CREATE INDEX IF NOT EXISTS ix_flows_b ON flows(b_ip);
"""

TLS_VERSIONS = {"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2",
                "0x0304": "TLS 1.3"}
TLS_ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
              42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
              45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
              49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
              71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
              109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
              116: "certificate_required", 120: "no_application_protocol"}
ICMP4 = {(3, 0): "Net unreachable", (3, 1): "Host unreachable", (3, 2): "Protocol unreachable",
         (3, 3): "Port unreachable", (3, 4): "Fragmentation needed", (3, 13): "Communication administratively prohibited",
         (11, 0): "TTL exceeded in transit", (11, 1): "Fragment reassembly time exceeded"}
ICMP6 = {(1, 0): "No route to destination", (1, 1): "Administratively prohibited", (1, 3): "Address unreachable",
         (1, 4): "Port unreachable", (2, 0): "Packet too big", (3, 0): "Hop limit exceeded"}

MAXF = 20  # frames kept per list


class Flow:
    __slots__ = ("id", "l4", "stream", "a_ip", "a_port", "b_ip", "b_port", "first_frame", "last_frame", "first_ts",
                 "last_ts", "pkts_ab", "pkts_ba", "bytes_ab", "bytes_ba", "syn_frame", "synack_frame", "ack_frame",
                 "initiator_known", "rst_frames", "rst_count", "fin_count", "retrans", "retrans_frames", "tls_sni",
                 "tls_ch_frame", "tls_sh_frame", "tls_version", "tls_alert", "tls_alert_frame", "icmp_frames",
                 "icmp_count", "tunneled")

    def __init__(self, fid, l4, stream, src, sport, dst, dport, pkt, initiator_known, tunneled):
        self.id, self.l4, self.stream = fid, l4, stream
        self.a_ip, self.a_port, self.b_ip, self.b_port = src, sport, dst, dport
        self.first_frame = self.last_frame = pkt.frame
        self.first_ts = self.last_ts = pkt.ts_ns
        self.pkts_ab = self.pkts_ba = self.bytes_ab = self.bytes_ba = 0
        self.syn_frame = self.synack_frame = self.ack_frame = None
        self.initiator_known = initiator_known
        self.rst_frames, self.retrans_frames, self.icmp_frames = [], [], []
        self.rst_count = self.fin_count = self.retrans = self.icmp_count = 0
        self.tls_sni = self.tls_ch_frame = self.tls_sh_frame = self.tls_version = None
        self.tls_alert = self.tls_alert_frame = None
        self.tunneled = tunneled


COLS = ("id", "l4", "stream", "a_ip", "a_port", "b_ip", "b_port", "first_frame", "last_frame", "first_ts", "last_ts",
        "pkts_ab", "pkts_ba", "bytes_ab", "bytes_ba", "syn_frame", "synack_frame", "ack_frame", "initiator_known",
        "rst_count", "rst_frames", "fin_count", "retrans", "retrans_frames", "tls_sni", "tls_ch_frame",
        "tls_sh_frame", "tls_version", "tls_alert", "tls_alert_frame", "icmp_count", "icmp_frames", "tunneled")
ADD = {"pkts_ab", "pkts_ba", "bytes_ab", "bytes_ba", "rst_count", "fin_count", "retrans", "icmp_count"}
KEEP_FIRST = {"l4", "stream", "a_ip", "a_port", "b_ip", "b_port", "first_frame", "first_ts", "initiator_known",
              "tunneled"}
UPSERT = (f"INSERT INTO flows({', '.join(COLS)}) VALUES ({', '.join('?' * len(COLS))}) ON CONFLICT(id) DO UPDATE SET "
          + ", ".join(
              f"{c}={c}+excluded.{c}" if c in ADD else
              f"{c}=excluded.{c}" if c in ("last_frame", "last_ts") else
              f"{c}=coalesce({c}, excluded.{c})"
              for c in COLS if c != "id" and c not in KEEP_FIRST))


class FlowAnalyzer(Analyzer):
    name = "flows"
    title = "TCP/UDP flow-k, TLS, ICMP"
    order = 20
    triggers = None
    fields = ("tcp.stream", "udp.stream", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
              "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tls.handshake.type",
              "tls.handshake.extensions_server_name", "tls.handshake.extensions.supported_version",
              "tls.handshake.version", "tls.alert_message.desc", "icmp.type", "icmp.code", "icmpv6.type",
              "icmpv6.code")
    schema = SCHEMA

    def __init__(self, ctx):
        super().__init__(ctx)
        self.flows: dict[int, Flow] = {}
        self.limit = ctx.settings.max_flows_in_memory
        self.flushed = 0

    def on_packet(self, pkt: Packet) -> None:
        l4s = pkt.l4_layers()
        tunneled = "gtp" in pkt.layers
        last_tcp = None
        for pos, l4, k in l4s:
            stream = pkt.int(f"{l4}.stream", k)
            if stream is None:
                continue
            src = dst = None
            for i in range(pos - 1, -1, -1):
                l = pkt.layers[i]
                if l in ("ip", "ipv6"):
                    kk = pkt.layers[:i].count(l)
                    src, dst = pkt.get(f"{l}.src", kk), pkt.get(f"{l}.dst", kk)
                    break
            sport, dport = pkt.int(f"{l4}.srcport", k), pkt.int(f"{l4}.dstport", k)
            fid = stream * 2 + (0 if l4 == "tcp" else 1)
            fl = self.flows.get(fid)
            flags = pkt.int("tcp.flags", k) if l4 == "tcp" else 0
            flags = flags or 0
            inner = tunneled and pos > pkt.layers.index("gtp") if tunneled else False
            if fl is None:
                syn_only = l4 == "tcp" and flags & 0x12 == 0x02
                if l4 == "tcp" and flags & 0x12 == 0x12:  # first seen is SYN/ACK: initiator is the receiver
                    fl = Flow(fid, l4, stream, dst, dport, src, sport, pkt, True, int(inner))
                else:
                    fl = Flow(fid, l4, stream, src, sport, dst, dport, pkt, syn_only or l4 == "udp", int(inner))
                self.flows[fid] = fl
                if len(self.flows) > self.limit:
                    self._flush_idle()
            ab = (src == fl.a_ip and sport == fl.a_port)
            if ab:
                fl.pkts_ab += 1
                fl.bytes_ab += pkt.length
            else:
                fl.pkts_ba += 1
                fl.bytes_ba += pkt.length
            fl.last_frame, fl.last_ts = pkt.frame, pkt.ts_ns
            if l4 == "tcp":
                last_tcp = fl
                if flags & 0x12 == 0x02 and fl.syn_frame is None:
                    fl.syn_frame = pkt.frame
                elif flags & 0x12 == 0x12 and fl.synack_frame is None:
                    fl.synack_frame = pkt.frame
                elif flags & 0x16 == 0x10 and fl.synack_frame is not None and fl.ack_frame is None and ab:
                    fl.ack_frame = pkt.frame
                if flags & 0x04:
                    fl.rst_count += 1
                    if len(fl.rst_frames) < MAXF:
                        fl.rst_frames.append(pkt.frame)
                if flags & 0x01:
                    fl.fin_count += 1
                if pkt.has("tcp.analysis.retransmission") or pkt.has("tcp.analysis.fast_retransmission"):
                    fl.retrans += 1
                    if len(fl.retrans_frames) < MAXF:
                        fl.retrans_frames.append(pkt.frame)
        if last_tcp is not None and "tls" in pkt.layers:
            self._tls(pkt, last_tcp)
        if "icmp" in pkt.layers or "icmpv6" in pkt.layers:
            self._icmp(pkt)

    def _tls(self, pkt: Packet, fl: Flow) -> None:
        types = pkt.all("tls.handshake.type")
        if "1" in types and fl.tls_ch_frame is None:
            fl.tls_ch_frame = pkt.frame
            fl.tls_sni = pkt.get("tls.handshake.extensions_server_name")
        if "2" in types and fl.tls_sh_frame is None:
            fl.tls_sh_frame = pkt.frame
            sv = pkt.all("tls.handshake.extensions.supported_version")
            v = sv[-1] if sv else pkt.get("tls.handshake.version", len(pkt.all("tls.handshake.version")) - 1)
            fl.tls_version = TLS_VERSIONS.get((v or "").lower(), v)
        desc = pkt.int("tls.alert_message.desc")
        if desc is not None and fl.tls_alert is None:
            fl.tls_alert = TLS_ALERTS.get(desc, f"alert {desc}")
            fl.tls_alert_frame = pkt.frame

    def _icmp(self, pkt: Packet) -> None:
        v6 = "icmpv6" in pkt.layers
        p = "icmpv6" if v6 else "icmp"
        t, c = pkt.int(f"{p}.type"), pkt.int(f"{p}.code")
        table = ICMP6 if v6 else ICMP4
        if (t, c) not in table and t not in ((1, 2, 3) if v6 else (3, 11, 12)):
            return
        name = table.get((t, c), f"type {t} code {c}")
        ipos = pkt.layers.index(p)
        src, dst, *_ = pkt.endpoints_before(ipos)
        flow_id = None
        quoted = ""
        for i in range(ipos + 1, len(pkt.layers)):
            l = pkt.layers[i]
            if l in ("udp", "tcp"):
                k = pkt.layers[:i].count(l)
                st = pkt.int(f"{l}.stream", k)
                sp, dp = pkt.int(f"{l}.srcport", k), pkt.int(f"{l}.dstport", k)
                quoted = f" Idézett {l.upper()} {sp} → {dp}."
                if st is not None:
                    flow_id = st * 2 + (0 if l == "tcp" else 1)
                    fl = self.flows.get(flow_id)
                    if fl is not None:
                        fl.icmp_count += 1
                        if len(fl.icmp_frames) < MAXF:
                            fl.icmp_frames.append(pkt.frame)
                break
        self.ctx.finding("flows", "ICMP-ERROR", OBSERVED, "warn", pkt.ts_ns, f"ICMP{'v6' if v6 else ''} {name}",
                         f"{src} → {dst}.{quoted}", [pkt.frame], "flow" if flow_id is not None else None, flow_id,
                         en=f"ICMP{'v6' if v6 else ''} {name} from {src} to {dst}{quoted.replace('Idézett', ' quoting')}")

    def _row(self, f: Flow) -> tuple:
        return (f.id, f.l4, f.stream, f.a_ip, f.a_port, f.b_ip, f.b_port, f.first_frame, f.last_frame, f.first_ts,
                f.last_ts, f.pkts_ab, f.pkts_ba, f.bytes_ab, f.bytes_ba, f.syn_frame, f.synack_frame, f.ack_frame,
                int(bool(f.initiator_known)), f.rst_count, dumps(f.rst_frames) if f.rst_frames else None, f.fin_count,
                f.retrans, dumps(f.retrans_frames) if f.retrans_frames else None, f.tls_sni, f.tls_ch_frame,
                f.tls_sh_frame, f.tls_version, f.tls_alert, f.tls_alert_frame, f.icmp_count,
                dumps(f.icmp_frames) if f.icmp_frames else None, f.tunneled)

    def _flush_idle(self) -> None:
        victims = sorted(self.flows.values(), key=lambda f: f.last_ts)[: len(self.flows) // 2]
        self.ctx.con.executemany(UPSERT, [self._row(f) for f in victims])
        for f in victims:
            del self.flows[f.id]
        self.flushed += len(victims)

    def finish(self, cut: Cut) -> None:
        con = self.ctx.con
        rows = [self._row(f) for f in self.flows.values()]
        for i in range(0, len(rows), 5000):
            con.executemany(UPSERT, rows[i:i + 5000])
        self.flows.clear()
        con.execute("""UPDATE flows SET handshake = CASE
            WHEN l4 != 'tcp' THEN NULL
            WHEN syn_frame IS NOT NULL AND synack_frame IS NOT NULL AND ack_frame IS NOT NULL THEN 'complete'
            WHEN syn_frame IS NOT NULL AND synack_frame IS NOT NULL THEN 'syn_synack'
            WHEN syn_frame IS NOT NULL THEN 'syn_only'
            WHEN synack_frame IS NOT NULL THEN 'synack_only'
            ELSE 'midstream' END""")
        cut_ts = cut.last_ts_ns
        for r in con.execute("SELECT * FROM flows WHERE handshake='syn_only' OR rst_count>0 OR retrans>0 "
                             "OR tls_alert IS NOT NULL").fetchall():
            ep = f"{r['a_ip']}:{r['a_port']} → {r['b_ip']}:{r['b_port']}"
            if r["handshake"] == "syn_only":
                near_end = cut_ts is not None and cut_ts - r["last_ts"] < 3_000_000_000
                st = UNDETERMINED if near_end else OBSERVED
                self.ctx.finding("flows", "TCP-HANDSHAKE-INCOMPLETE", st, "warn", r["first_ts"],
                                 f"TCP {ep}: a SYN-re nem látszik SYN/ACK",
                                 "A kapcsolatfelépítés nem fejeződött be a vizsgált capture-ben."
                                 + (" A capture/index vége közel van, ezért nem eldönthető." if near_end else ""),
                                 [r["syn_frame"]], "flow", r["id"],
                                 en=f"TCP {ep}: SYN without visible SYN/ACK (handshake not completed in the capture)")
            if r["rst_count"]:
                import json
                fr = json.loads(r["rst_frames"] or "[]")
                self.ctx.finding("flows", "TCP-RESET", OBSERVED, "warn", r["last_ts"], f"TCP reset: {ep}",
                                 f"{r['rst_count']} RST szegmens; első: #{fr[0] if fr else '?'}.", fr, "flow", r["id"],
                                 en=f"TCP reset on {ep} ({r['rst_count']} RST segment(s))")
            if r["retrans"]:
                import json
                fr = json.loads(r["retrans_frames"] or "[]")
                self.ctx.finding("flows", "TCP-RETRANS", OBSERVED, "info", r["first_ts"],
                                 f"TCP újraküldés: {ep} ({r['retrans']}×)", "TShark tcp.analysis szerint.", fr,
                                 "flow", r["id"], en=f"TCP retransmissions on {ep}: {r['retrans']} (TShark tcp.analysis)")
            if r["tls_alert"]:
                self.ctx.finding("flows", "TLS-ALERT", OBSERVED, "error", r["last_ts"],
                                 f"TLS alert {r['tls_alert']}: {ep}",
                                 f"SNI: {r['tls_sni'] or '–'}, ClientHello #{r['tls_ch_frame'] or '–'}, "
                                 f"ServerHello #{r['tls_sh_frame'] or '–'}.",
                                 [x for x in (r["tls_ch_frame"], r["tls_sh_frame"], r["tls_alert_frame"]) if x],
                                 "flow", r["id"], en=f"TLS alert {r['tls_alert']} on {ep} (SNI {r['tls_sni'] or 'n/a'})")


ANALYZER = FlowAnalyzer
