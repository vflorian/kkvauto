"""DNS request/response pairing.

Key: (L4, DNS transaction id, client ip, client port, server ip, server port);
the response must travel in the opposite direction within ``dns_timeout_s``
and carry the same question name. Retransmitted queries (same key while
unanswered) are kept as one transaction with the extra frames listed.
"""
from __future__ import annotations

from .base import (INFERRED, NO_RESPONSE_TEXT, OBSERVED, TXN_INSERT, TXN_SCHEMA, Analyzer, Cut, Packet, Pending,
                   TxnMatcher, dumps, txn_state)
from ..db import BatchWriter

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
          7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
          65: "HTTPS", 255: "ANY"}
MULTICAST_PORTS = {5353, 5355}


def truthy(v: str | None) -> bool:
    return v in ("1", "True", "true")


class DnsAnalyzer(Analyzer):
    name = "dns"
    title = "DNS"
    order = 30
    triggers = frozenset({"dns"})
    fields = ("dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a",
              "dns.aaaa", "dns.count.answers")
    schema = TXN_SCHEMA

    def __init__(self, ctx):
        super().__init__(ctx)
        self.w = BatchWriter(ctx.con, TXN_INSERT)
        self.m = TxnMatcher(int(ctx.settings.dns_timeout_s * 1e9), self._final, self._orphan)

    def on_packet(self, pkt: Packet) -> None:
        src, dst, sport, dport, l4 = pkt.endpoints_of("dns")
        txid = pkt.int("dns.id")
        if src is None or txid is None:
            return
        if sport in MULTICAST_PORTS or dport in MULTICAST_PORTS:
            return
        qname = (pkt.get("dns.qry.name") or "").lower()
        qtype = pkt.int("dns.qry.type")
        if truthy(pkt.get("dns.flags.response")):
            key = (l4, txid, dst, dport, src, sport)
            pend = self.m.pending.get(key)
            if pend is not None and pend.data.get("qname") and qname and pend.data["qname"] != qname:
                self.ctx.finding("dns", "DNS-QNAME-MISMATCH", OBSERVED, "warn", pkt.ts_ns,
                                 f"DNS válasz 0x{txid:04x}: a kérdés eltér a kéréstől",
                                 f"Kérés: {pend.data['qname']}, válasz: {qname}. Nem párosítva.",
                                 [pend.req_frame, pkt.frame],
                                 en=f"DNS response 0x{txid:04x} question differs from request ({pend.data['qname']} vs {qname}); not paired")
                return
            answers = pkt.all("dns.a") + pkt.all("dns.aaaa")
            self.m.response(key, pkt, {"rcode": pkt.int("dns.flags.rcode") or 0, "answers": answers[:8],
                                       "qname": qname})
        else:
            self.m.request((l4, txid, src, sport, dst, dport), pkt,
                           {"qname": qname, "qtype": qtype, "l4": l4})

    def periodic(self, now_ns: int) -> None:
        self.m.expire(now_ns)

    def _final(self, p: Pending, how: str) -> None:
        l4, txid, client, cport, server, sport = p.key
        status, state, note = txn_state(p, how)
        d = p.data
        qt = QTYPES.get(d.get("qtype"), str(d.get("qtype") or ""))
        summary = f"{d.get('qname') or '?'} {qt}".strip()
        result, ok = None, None
        if p.rsp_data is not None:
            rc = p.rsp_data["rcode"]
            result = RCODES.get(rc, f"RCODE {rc}")
            if p.rsp_data["answers"]:
                result += " → " + ", ".join(p.rsp_data["answers"])
            ok = 1 if rc == 0 else 0
        rtt = (p.rsp_ts - p.req_ts) if p.rsp_ts is not None else None
        rule = "DNS-PAIR: id + végpontok + irány + qname, ablak %.0f s" % self.ctx.settings.dns_timeout_s
        self.w.add(("dns", "query", p.req_frame, p.rsp_frame, p.req_ts, p.rsp_ts, rtt, client, cport, server, sport,
                    f"0x{txid:04x}", summary, result, ok, len(p.retrans), dumps(p.retrans), dumps(p.dup_rsp),
                    status, state, rule, note, None, None))
        frames = [p.req_frame, *p.retrans] + ([p.rsp_frame] if p.rsp_frame else [])
        if status == "unanswered":
            self.ctx.finding("dns", "DNS-NO-RESPONSE", state, "warn", p.req_ts,
                             f"DNS {summary}: {NO_RESPONSE_TEXT}",
                             f"{client}:{cport} → {server}:{sport}, id 0x{txid:04x}. {note}", frames, "txn_dns", None,
                             en=f"DNS query {summary} from {client}:{cport} to {server}:{sport} (id 0x{txid:04x}): "
                                f"no response visible in the analysed capture"
                                + (f" ({len(p.retrans)} retransmission(s))" if p.retrans else "")
                                + ("; capture/index ends inside the response window" if state != OBSERVED else ""))
        elif ok == 0:
            self.ctx.finding("dns", "DNS-RCODE", OBSERVED, "warn", p.rsp_ts, f"DNS {summary}: {result}",
                             f"{server} válasza {client} felé, RTT {rtt / 1e6:.1f} ms.", frames, "txn_dns", None,
                             en=f"DNS query {summary} answered {result} by {server} after {rtt / 1e6:.1f} ms")
        if p.retrans and p.rsp_frame:
            self.ctx.finding("dns", "DNS-RETRANS", OBSERVED, "info", p.req_ts,
                             f"DNS {summary}: ismételt kérés ({len(p.retrans)}×) a válasz előtt",
                             f"Első kérés #{p.req_frame}, ismétlések: {', '.join(map(str, p.retrans))}.", frames,
                             en=f"DNS query {summary} retransmitted {len(p.retrans)}x before the response")

    def _orphan(self, key: tuple, pkt: Packet, data: dict) -> None:
        l4, txid, client, cport, server, sport = key
        rc = data["rcode"]
        self.w.add(("dns", "query", None, pkt.frame, None, pkt.ts_ns, None, client, cport, server, sport,
                    f"0x{txid:04x}", data.get("qname"), RCODES.get(rc, str(rc)), 1 if rc == 0 else 0, 0, "[]", "[]",
                    "orphan_response", OBSERVED, "DNS-PAIR", "A kéréshez tartozó csomag nem látszik a vizsgált capture-ben.",
                    None, None))

    def finish(self, cut: Cut) -> None:
        self.m.flush(cut)
        self.w.flush()


ANALYZER = DnsAnalyzer
_ = INFERRED
