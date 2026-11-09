"""Synthetic capture generator (pure Python, no third-party deps).

Builds real Ethernet/IPv4/IPv6/UDP/TCP/DNS/GTPv1-C/GTPv2-C/GTP-U/ICMP/TLS
frames and writes them as classic pcap (us or ns) or pcapng (multiple
interfaces, per-interface tsresol, ISB drop counters, optional DSB).

Used by the test-suite, by the benchmark and for the README demo:

    python -m capscope.synth demo  demo.pcapng
    python -m capscope.synth large big.pcapng --packets 1000000
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Low-level packet builders
# ---------------------------------------------------------------------------

def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(n: int) -> bytes:
    return bytes([0x02, 0, 0, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def ether(payload: bytes, ethertype: int, src: int = 1, dst: int = 2) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0, ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, ttl, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    c = _csum(hdr)
    return hdr[:10] + struct.pack("!H", c) + hdr[12:] + payload


def ipv6(src: str, dst: str, nh: int, payload: bytes, hlim: int = 64) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, hlim,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + payload


def ip(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    if ":" in src:
        return ipv6(src, dst, proto, payload)
    return ipv4(src, dst, proto, payload, ident)


def eth_ip(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    return ether(ip(src, dst, proto, payload, ident), 0x86DD if ":" in src else 0x0800)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", win: int = 64240) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, win, 0, 0) + payload


def icmp_unreach(orig_ip_packet: bytes, code: int = 3) -> bytes:
    body = struct.pack("!BBHI", 3, code, 0, 0) + orig_ip_packet[:28]
    c = _csum(body)
    return body[:2] + struct.pack("!H", c) + body[4:]


# --- DNS -------------------------------------------------------------------

def _dns_name(name: str) -> bytes:
    out = b""
    for lab in name.strip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, qtype: int = 1, answers: Iterable[str] = (), rcode: int = 0) -> bytes:
    answers = list(answers)
    msg = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    msg += _dns_name(name) + struct.pack("!HH", qtype, 1)
    for a in answers:
        rdata = ipaddress.ip_address(a).packed
        t = 1 if len(rdata) == 4 else 28
        msg += struct.pack("!HHHIH", 0xC00C, t, 1, 300, len(rdata)) + rdata
    return msg


# --- TBCD helpers ------------------------------------------------------------

def tbcd(digits: str) -> bytes:
    if len(digits) % 2:
        digits += "f"
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo = int(digits[i], 16)
        hi = int(digits[i + 1], 16)
        out.append((hi << 4) | lo)
    return bytes(out)


def apn_enc(apn: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in apn.split("."))


# --- GTPv2-C -----------------------------------------------------------------

def v2_ie(t: int, value: bytes, instance: int = 0) -> bytes:
    return struct.pack("!BHB", t, len(value), instance & 0x0F) + value


def v2_fteid(iface_type: int, teid: int, ipv4_addr: str | None = None, ipv6_addr: str | None = None,
             instance: int = 0) -> bytes:
    flags = iface_type & 0x3F
    tail = b""
    if ipv4_addr:
        flags |= 0x80
        tail += ipaddress.IPv4Address(ipv4_addr).packed
    if ipv6_addr:
        flags |= 0x40
        tail += ipaddress.IPv6Address(ipv6_addr).packed
    return v2_ie(87, struct.pack("!BI", flags, teid) + tail, instance)


def v2_cause(cause: int) -> bytes:
    return v2_ie(2, bytes([cause, 0]))


def v2_imsi(imsi: str) -> bytes:
    return v2_ie(1, tbcd(imsi))


def v2_msisdn(msisdn: str) -> bytes:
    return v2_ie(76, tbcd(msisdn))


def v2_apn(apn: str) -> bytes:
    return v2_ie(71, apn_enc(apn))


def v2_paa_v4(addr: str) -> bytes:
    return v2_ie(79, b"\x01" + ipaddress.IPv4Address(addr).packed)


def v2_ebi(ebi: int) -> bytes:
    return v2_ie(73, bytes([ebi & 0x0F]))


def v2_rat(rat: int = 6) -> bytes:
    return v2_ie(82, bytes([rat]))


def v2_bearer_ctx(*ies: bytes, instance: int = 0) -> bytes:
    return v2_ie(93, b"".join(ies), instance)


def gtpv2(msg_type: int, seq: int, ies: bytes, teid: int | None = 0) -> bytes:
    if teid is None:
        body = struct.pack("!I", (seq & 0xFFFFFF) << 8) + ies
        return struct.pack("!BBH", 0x40, msg_type, len(body)) + body
    body = struct.pack("!II", teid, (seq & 0xFFFFFF) << 8) + ies
    return struct.pack("!BBH", 0x48, msg_type, len(body)) + body


# --- GTPv1-C / GTP-U -----------------------------------------------------------

def v1_tv(t: int, value: bytes) -> bytes:
    return bytes([t]) + value


def v1_tlv(t: int, value: bytes) -> bytes:
    return struct.pack("!BH", t, len(value)) + value


def gtpv1c(msg_type: int, seq: int, ies: bytes, teid: int = 0) -> bytes:
    body = struct.pack("!HBB", seq & 0xFFFF, 0, 0) + ies
    return struct.pack("!BBHI", 0x32, msg_type, len(body), teid) + body


def gtpu(teid: int, inner: bytes) -> bytes:
    return struct.pack("!BBHI", 0x30, 0xFF, len(inner), teid) + inner


# --- TLS -----------------------------------------------------------------------

def tls_client_hello(sni: str) -> bytes:
    sni_b = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(sni_b) + 5, len(sni_b) + 3, 0, len(sni_b)) + sni_b
    sv_ext = struct.pack("!HHB", 0x002B, 3, 2) + b"\x03\x04"
    exts = sni_ext + sv_ext
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!HH", 2, 0x1301) + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_server_hello() -> bytes:
    exts = struct.pack("!HH", 0x002B, 2) + b"\x03\x04"
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tls_alert(desc: int = 40) -> bytes:
    return b"\x15\x03\x03\x00\x02\x02" + bytes([desc])


# ---------------------------------------------------------------------------
# Capture writers
# ---------------------------------------------------------------------------

class PcapWriter:
    def __init__(self, path: str, linktype: int = 1, nanos: bool = False, snaplen: int = 262144):
        self.f = open(path, "wb")
        self.nanos = nanos
        self.snaplen = snaplen
        magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
        self.f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts_ns: int, data: bytes, iface: int = 0, comment: str | None = None) -> None:
        orig = len(data)
        data = data[: self.snaplen]
        sec, frac = divmod(ts_ns, 1_000_000_000)
        if not self.nanos:
            frac //= 1000
        self.f.write(struct.pack("<IIII", sec, frac, len(data), orig) + data)

    def close(self) -> None:
        self.f.close()


def _opt(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def _block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


class PcapngWriter:
    def __init__(self, path: str, comment: str | None = None):
        self.f = open(path, "wb")
        self.ifaces: list[dict] = []
        self.new_section(comment)

    def new_section(self, comment: str | None = None) -> None:
        opts = b""
        if comment:
            opts += _opt(1, comment.encode())
        opts += _opt(3, b"capscope-synth")
        opts += _opt(4, b"capscope synthetic generator")
        opts += _opt(0, b"")
        body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opts
        self.f.write(_block(0x0A0D0D0A, body))
        self.ifaces = []

    def add_interface(self, name: str, linktype: int = 1, tsresol: int = 6, snaplen: int = 262144,
                      description: str | None = None) -> int:
        opts = _opt(2, name.encode())
        if description:
            opts += _opt(3, description.encode())
        opts += _opt(9, bytes([tsresol])) + _opt(0, b"")
        self.f.write(_block(1, struct.pack("<HHI", linktype, 0, snaplen) + opts))
        self.ifaces.append({"tsresol": tsresol, "snaplen": snaplen})
        return len(self.ifaces) - 1

    def _units(self, iface: int, ts_ns: int) -> int:
        res = self.ifaces[iface]["tsresol"]
        return ts_ns // (10 ** (9 - res))

    def write(self, ts_ns: int, data: bytes, iface: int = 0, comment: str | None = None) -> None:
        orig = len(data)
        data = data[: self.ifaces[iface]["snaplen"]]
        u = self._units(iface, ts_ns)
        pad = (-len(data)) % 4
        opts = b""
        if comment:
            opts = _opt(1, comment.encode()) + _opt(0, b"")
        body = struct.pack("<IIIII", iface, u >> 32, u & 0xFFFFFFFF, len(data), orig) + data + b"\x00" * pad + opts
        self.f.write(_block(6, body))

    def write_isb(self, iface: int, ts_ns: int, ifdrop: int | None = None, ifrecv: int | None = None) -> None:
        u = self._units(iface, ts_ns)
        opts = b""
        if ifrecv is not None:
            opts += _opt(4, struct.pack("<Q", ifrecv))
        if ifdrop is not None:
            opts += _opt(5, struct.pack("<Q", ifdrop))
        opts += _opt(0, b"")
        self.f.write(_block(5, struct.pack("<III", iface, u >> 32, u & 0xFFFFFFFF) + opts))

    def write_dsb(self, secrets: bytes, stype: int = 0x544C534B) -> None:
        pad = (-len(secrets)) % 4
        self.f.write(_block(0x0A, struct.pack("<II", stype, len(secrets)) + secrets + b"\x00" * pad))

    def close(self) -> None:
        self.f.close()


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------

@dataclass
class Frame:
    ts_ns: int
    data: bytes
    iface: int = 0
    comment: str | None = None


@dataclass
class Scenario:
    t0_ns: int = 1_700_000_000_000_000_000
    frames: list[Frame] = field(default_factory=list)
    ident: int = 1

    def add(self, dt_ms: float, data: bytes, iface: int = 0) -> int:
        """Append a frame dt_ms after the previous one. Returns 1-based frame number."""
        last = self.frames[-1].ts_ns if self.frames else self.t0_ns
        self.frames.append(Frame(last + int(dt_ms * 1_000_000), data, iface))
        return len(self.frames)

    def udp(self, dt_ms: float, src: str, dst: str, sport: int, dport: int, payload: bytes, iface: int = 0) -> int:
        self.ident += 1
        return self.add(dt_ms, eth_ip(src, dst, 17, udp(sport, dport, payload), self.ident), iface)

    def tcp(self, dt_ms: float, src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
            payload: bytes = b"", iface: int = 0) -> int:
        self.ident += 1
        return self.add(dt_ms, eth_ip(src, dst, 6, tcp(sport, dport, seq, ack, flags, payload), self.ident), iface)

    def gtpu(self, dt_ms: float, osrc: str, odst: str, teid: int, inner: bytes, iface: int = 0) -> int:
        self.ident += 1
        return self.add(dt_ms, eth_ip(osrc, odst, 17, udp(2152, 2152, gtpu(teid, inner)), self.ident), iface)

    def write(self, path: str, fmt: str = "pcapng", ifaces: list[dict] | None = None, nanos: bool = False,
              section_comment: str | None = None) -> str:
        if fmt == "pcap":
            w = PcapWriter(path, nanos=nanos)
            for fr in self.frames:
                w.write(fr.ts_ns, fr.data)
            w.close()
            return path
        w = PcapngWriter(path, section_comment)
        for spec in (ifaces or [{"name": "eth0"}]):
            w.add_interface(**spec)
        for fr in self.frames:
            w.write(fr.ts_ns, fr.data, fr.iface, fr.comment)
        w.close()
        return path


def inner_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return ip(src, dst, 17, udp(sport, dport, payload))


def inner_tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return ip(src, dst, 6, tcp(sport, dport, seq, ack, flags, payload))


# GTPv2 interface types (TS 29.274 8.22)
IF_S1U_ENB, IF_S1U_SGW, IF_S5U_SGW, IF_S5U_PGW, IF_S11_MME, IF_S11_SGW = 0, 1, 4, 5, 10, 11
IF_S5C_SGW, IF_S5C_PGW = 6, 7


def lte_attach(sc: Scenario, *, imsi: str, msisdn: str, apn: str, ue_ip: str, seq: int,
               mme: str = "10.0.0.1", sgw_c: str = "10.0.0.2", sgw_u: str = "10.0.1.2", enb: str = "10.0.2.1",
               mme_teid: int = 0x1001, sgw_teid: int = 0x2001, sgw_u_teid: int = 0xA0001,
               enb_teid: int = 0xB0001, ebi: int = 5, cause: int = 16, with_mbr: bool = True,
               iface: int = 0) -> dict:
    """S11 Create Session (+ Modify Bearer). Returns frame numbers."""
    out: dict = {}
    csr = (v2_imsi(imsi) + v2_msisdn(msisdn) + v2_rat(6) + v2_fteid(IF_S11_MME, mme_teid, mme) + v2_apn(apn)
           + v2_bearer_ctx(v2_ebi(ebi)))
    out["csr"] = sc.udp(5, mme, sgw_c, 2123, 2123, gtpv2(32, seq, csr, 0), iface)
    if cause is None:
        return out
    rsp = v2_cause(cause)
    if cause < 64:
        rsp += (v2_fteid(IF_S11_SGW, sgw_teid, sgw_c, instance=0) + v2_paa_v4(ue_ip)
                + v2_bearer_ctx(v2_ebi(ebi), v2_cause(16), v2_fteid(IF_S1U_SGW, sgw_u_teid, sgw_u, instance=0)))
    out["csr_rsp"] = sc.udp(12, sgw_c, mme, 2123, 2123, gtpv2(33, seq, rsp, mme_teid), iface)
    if cause < 64 and with_mbr:
        mbr = v2_bearer_ctx(v2_ebi(ebi), v2_fteid(IF_S1U_ENB, enb_teid, enb))
        out["mbr"] = sc.udp(30, mme, sgw_c, 2123, 2123, gtpv2(34, seq + 1, mbr, sgw_teid), iface)
        out["mbr_rsp"] = sc.udp(4, sgw_c, mme, 2123, 2123,
                                gtpv2(35, seq + 1, v2_cause(16) + v2_bearer_ctx(v2_ebi(ebi), v2_cause(16)), mme_teid), iface)
    return out


def lte_detach(sc: Scenario, *, seq: int, mme: str = "10.0.0.1", sgw_c: str = "10.0.0.2",
               mme_teid: int = 0x1001, sgw_teid: int = 0x2001, ebi: int = 5, iface: int = 0) -> dict:
    out = {"dsr": sc.udp(10, mme, sgw_c, 2123, 2123, gtpv2(36, seq, v2_ebi(ebi), sgw_teid), iface)}
    out["dsr_rsp"] = sc.udp(3, sgw_c, mme, 2123, 2123, gtpv2(37, seq, v2_cause(16), mme_teid), iface)
    return out


def build_demo() -> Scenario:
    """Demo capture: LTE attach, user traffic in GTP-U, DNS, TLS, failures."""
    sc = Scenario()
    imsi, ue = "216301234567890", "100.64.0.10"
    a = lte_attach(sc, imsi=imsi, msisdn="36301234567", apn="internet.example.hu", ue_ip=ue, seq=0x10)
    # DNS inside the tunnel (uplink to SGW S1-U, downlink to eNB)
    sc.gtpu(20, "10.0.2.1", "10.0.1.2", 0xA0001, inner_udp(ue, "8.8.8.8", 40001, 53, dns_query(0x1111, "example.com")))
    sc.gtpu(35, "10.0.1.2", "10.0.2.1", 0xB0001,
            inner_udp("8.8.8.8", ue, 53, 40001, dns_response(0x1111, "example.com", answers=["93.184.216.34"])))
    # TCP + TLS inside the tunnel
    S, C = 1000, 5000
    up = lambda dt, fl, pl=b"", s=0, a_=0: sc.gtpu(dt, "10.0.2.1", "10.0.1.2", 0xA0001,
                                                    inner_tcp(ue, "93.184.216.34", 50000, 443, C + s, S + a_, fl, pl))
    dn = lambda dt, fl, pl=b"", s=0, a_=0: sc.gtpu(dt, "10.0.1.2", "10.0.2.1", 0xB0001,
                                                    inner_tcp("93.184.216.34", ue, 443, 50000, S + s, C + a_, fl, pl))
    up(5, TCP_SYN)
    dn(40, TCP_SYN | TCP_ACK, s=0, a_=1)
    up(40, TCP_ACK, s=1, a_=1)
    ch = tls_client_hello("www.example.com")
    up(1, TCP_PSH | TCP_ACK, ch, s=1, a_=1)
    up(300, TCP_PSH | TCP_ACK, ch, s=1, a_=1)  # retransmission
    sh = tls_server_hello()
    dn(45, TCP_PSH | TCP_ACK, sh, s=1, a_=1 + len(ch))
    dn(2, TCP_PSH | TCP_ACK, tls_alert(40), s=1 + len(sh), a_=1 + len(ch))
    dn(1, TCP_RST | TCP_ACK, s=1 + len(sh) + 7, a_=1 + len(ch))
    # DNS on the SGi side: unanswered + retransmitted query, NXDOMAIN
    sc.udp(100, "100.64.0.10", "9.9.9.9", 40002, 53, dns_query(0x2222, "nem-valaszol.example"))
    sc.udp(1000, "100.64.0.10", "9.9.9.9", 40002, 53, dns_query(0x2222, "nem-valaszol.example"))
    sc.udp(50, "100.64.0.10", "9.9.9.9", 40003, 53, dns_query(0x3333, "nincs.example"))
    sc.udp(20, "9.9.9.9", "100.64.0.10", 53, 40003, dns_response(0x3333, "nincs.example", rcode=3))
    # ICMP port unreachable for a UDP probe
    probe = ip("100.64.0.10", "198.51.100.7", 17, udp(40004, 5000, b"probe"))
    sc.add(30, ether(probe, 0x0800))
    sc.add(5, eth_ip("198.51.100.7", "100.64.0.10", 1, icmp_unreach(probe)))
    # Second subscriber: Create Session rejected (cause 78 Missing or unknown APN)
    lte_attach(sc, imsi="216309876543210", msisdn="36309876543", apn="rossz.apn", ue_ip="0.0.0.0", seq=0x20,
               mme_teid=0x1002, cause=78)
    # Third: Create Session Request retransmitted, never answered in capture
    for i in range(3):
        lte_attach(sc, imsi="216305555555555", msisdn="36305555555", apn="internet.example.hu", ue_ip="0.0.0.0",
                   seq=0x30, mme_teid=0x1003, cause=None)
        sc.frames[-1].ts_ns += 3000_000_000 if i else 0
    # Roaming: GTPv1 Create PDP Context (visited SGSN -> home GGSN over Gp)
    sgsn, ggsn = "192.0.2.10", "203.0.113.20"
    req = (v1_tv(2, tbcd("262019999999999")) + v1_tv(14, b"\x01") + v1_tv(15, b"\x01") + v1_tv(16, struct.pack("!I", 0x5001))
           + v1_tv(17, struct.pack("!I", 0x5002)) + v1_tv(20, b"\x05") + v1_tlv(128, b"\xf1\x21")
           + v1_tlv(131, apn_enc("roaming.example")) + v1_tlv(133, ipaddress.IPv4Address(sgsn).packed)
           + v1_tlv(133, ipaddress.IPv4Address(sgsn).packed) + v1_tlv(134, b"\x91" + tbcd("4915112345678")))
    sc.udp(200, sgsn, ggsn, 2123, 2123, gtpv1c(16, 0x0101, req, 0))
    rsp = (v1_tv(1, b"\x80") + v1_tv(14, b"\x01") + v1_tv(16, struct.pack("!I", 0x6001)) + v1_tv(17, struct.pack("!I", 0x6002))
           + v1_tlv(128, b"\xf1\x21" + ipaddress.IPv4Address("10.200.0.5").packed)
           + v1_tlv(133, ipaddress.IPv4Address(ggsn).packed) + v1_tlv(133, ipaddress.IPv4Address(ggsn).packed))
    sc.udp(180, ggsn, sgsn, 2123, 2123, gtpv1c(17, 0x0101, rsp, 0x5002))
    sc.gtpu(50, sgsn, ggsn, 0x6001, inner_udp("10.200.0.5", "1.1.1.1", 41000, 53, dns_query(0x4444, "roaming.example.org")))
    sc.gtpu(60, ggsn, sgsn, 0x5001, inner_udp("1.1.1.1", "10.200.0.5", 53, 41000,
                                              dns_response(0x4444, "roaming.example.org", answers=["192.0.2.99"])))
    # Detach of the first subscriber
    lte_detach(sc, seq=0x40)
    _ = a
    return sc


def generate_large(path: str, packets: int, seed: int = 1) -> dict:
    """Streaming writer for the benchmark: mixed DNS / TCP / GTP-C / GTP-U traffic."""
    import random
    rnd = random.Random(seed)
    w = PcapngWriter(path, "capscope benchmark")
    w.add_interface("s1u", tsresol=9)
    w.add_interface("sgi", tsresol=6)
    ts = 1_700_000_000_000_000_000
    n = 0
    seq = 1
    sessions = []
    while n < packets:
        ts += rnd.randint(5_000, 200_000)
        r = rnd.random()
        if r < 0.002 or not sessions:
            k = len(sessions)
            ue = f"100.{64 + (k >> 16) % 64}.{(k >> 8) & 255}.{k & 255}"
            imsi = f"21630{k:010d}"
            mme_teid, sgw_teid, u_teid, e_teid = 0x10000 + k, 0x20000 + k, 0x300000 + k, 0x400000 + k
            csr = (v2_imsi(imsi) + v2_rat(6) + v2_fteid(IF_S11_MME, mme_teid, "10.0.0.1") + v2_apn("internet.example.hu")
                   + v2_bearer_ctx(v2_ebi(5)))
            rsp = (v2_cause(16) + v2_fteid(IF_S11_SGW, sgw_teid, "10.0.0.2") + v2_paa_v4(ue)
                   + v2_bearer_ctx(v2_ebi(5), v2_cause(16), v2_fteid(IF_S1U_SGW, u_teid, "10.0.1.2")))
            mbr = v2_bearer_ctx(v2_ebi(5), v2_fteid(IF_S1U_ENB, e_teid, "10.0.2.1"))
            for data in (eth_ip("10.0.0.1", "10.0.0.2", 17, udp(2123, 2123, gtpv2(32, seq, csr, 0))),
                         eth_ip("10.0.0.2", "10.0.0.1", 17, udp(2123, 2123, gtpv2(33, seq, rsp, mme_teid))),
                         eth_ip("10.0.0.1", "10.0.0.2", 17, udp(2123, 2123, gtpv2(34, seq + 1, mbr, sgw_teid))),
                         eth_ip("10.0.0.2", "10.0.0.1", 17, udp(2123, 2123, gtpv2(35, seq + 1, v2_cause(16), mme_teid)))):
                ts += 1_000_000
                w.write(ts, data, 0)
                n += 1
            seq += 2
            sessions.append((ue, u_teid, e_teid))
        elif r < 0.55:
            ue, u_teid, e_teid = rnd.choice(sessions)
            port = 40000 + rnd.randint(0, 50)
            pl = os.urandom(rnd.randint(40, 1200))
            if rnd.random() < 0.6:
                inner = inner_tcp(ue, "93.184.216.34", port, 443, rnd.randint(0, 1 << 30), 1, TCP_ACK | TCP_PSH, pl)
                w.write(ts, eth_ip("10.0.2.1", "10.0.1.2", 17, udp(2152, 2152, gtpu(u_teid, inner))), 0)
            else:
                inner = inner_tcp("93.184.216.34", ue, 443, port, rnd.randint(0, 1 << 30), 1, TCP_ACK | TCP_PSH, pl)
                w.write(ts, eth_ip("10.0.1.2", "10.0.2.1", 17, udp(2152, 2152, gtpu(e_teid, inner))), 0)
            n += 1
        elif r < 0.85:
            txid = rnd.randint(0, 65535)
            host = f"h{rnd.randint(0, 5000)}.example.com"
            src = f"100.64.{rnd.randint(0, 3)}.{rnd.randint(1, 250)}"
            sport = rnd.randint(1024, 65000)
            w.write(ts, eth_ip(src, "8.8.8.8", 17, udp(sport, 53, dns_query(txid, host))), 1)
            n += 1
            if rnd.random() < 0.97 and n < packets:
                ts += rnd.randint(1_000_000, 40_000_000)
                w.write(ts, eth_ip("8.8.8.8", src, 17, udp(53, sport, dns_response(txid, host, answers=["192.0.2.1"]))), 1)
                n += 1
        else:
            src = f"100.64.{rnd.randint(0, 3)}.{rnd.randint(1, 250)}"
            sport = rnd.randint(1024, 65000)
            w.write(ts, eth_ip(src, "198.51.100.80", 6, tcp(sport, 80, rnd.randint(0, 1 << 30), 0, TCP_SYN)), 1)
            n += 1
    w.write_isb(0, ts, ifdrop=0)
    w.close()
    return {"path": path, "packets": n, "bytes": os.path.getsize(path)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="CapScope synthetic capture generator")
    ap.add_argument("kind", choices=["demo", "large"])
    ap.add_argument("out")
    ap.add_argument("--packets", type=int, default=1_000_000)
    ap.add_argument("--format", choices=["pcap", "pcapng"], default=None)
    a = ap.parse_args(argv)
    if a.kind == "demo":
        fmt = a.format or ("pcap" if a.out.endswith(".pcap") else "pcapng")
        sc = build_demo()
        if fmt == "pcapng":
            sc.write(a.out, "pcapng", ifaces=[{"name": "s11-s1u", "description": "S11 + S1-U mirror"}],
                     section_comment="CapScope demo capture")
        else:
            sc.write(a.out, "pcap")
        print(f"{a.out}: {len(sc.frames)} frames")
    else:
        print(generate_large(a.out, a.packets))


if __name__ == "__main__":
    main()
