"""DNS request/response pairing."""
from __future__ import annotations

from capscope.analyzers.base import NO_RESPONSE_TEXT
from capscope.synth import Scenario, dns_query, dns_response

from conftest import index_file, needs_tshark, q

C, S = "100.64.0.10", "9.9.9.9"


@needs_tshark
def test_dns_pairing_cases(tmp_path):
    sc = Scenario()
    f_req = sc.udp(0, C, S, 40001, 53, dns_query(0x1111, "ok.example"))
    f_rsp = sc.udp(42, S, C, 53, 40001, dns_response(0x1111, "ok.example", answers=["192.0.2.1"]))
    # same id, different client port: must be a separate transaction (and unanswered)
    f_other = sc.udp(1, C, S, 40002, 53, dns_query(0x1111, "ok.example"))
    # retransmitted query, then answered
    f_r1 = sc.udp(1, C, S, 40003, 53, dns_query(0x2222, "retry.example"))
    f_r2 = sc.udp(1000, C, S, 40003, 53, dns_query(0x2222, "retry.example"))
    f_r3 = sc.udp(30, S, C, 53, 40003, dns_response(0x2222, "retry.example", rcode=3))
    # response without visible request
    f_orph = sc.udp(5, S, C, 53, 40009, dns_response(0x9999, "orphan.example", answers=["192.0.2.9"]))
    # unanswered, then the capture continues long enough (> 5 s window)
    f_un = sc.udp(5, C, S, 40004, 53, dns_query(0x3333, "silent.example"))
    sc.udp(8000, "10.0.0.1", "10.0.0.2", 1, 2, b"keepalive")
    # unanswered close to the end of the capture -> undetermined
    f_late = sc.udp(1, C, S, 40005, 53, dns_query(0x4444, "late.example"))
    sc.udp(100, "10.0.0.1", "10.0.0.2", 1, 2, b"end")
    cid = index_file(sc.write(str(tmp_path / "dns.pcapng")))
    t = {(r["txn_id"], r["client_port"]): r for r in q(cid, "SELECT * FROM transactions WHERE proto='dns'")}

    ok = t[("0x1111", 40001)]
    assert (ok["req_frame"], ok["rsp_frame"], ok["status"], ok["state"]) == (f_req, f_rsp, "answered", "observed")
    assert ok["rtt_ns"] == 42_000_000 and ok["result"].startswith("NOERROR")

    other = t[("0x1111", 40002)]
    assert other["req_frame"] == f_other and other["rsp_frame"] is None and other["status"] == "unanswered"

    rt = t[("0x2222", 40003)]
    assert (rt["req_frame"], rt["rsp_frame"], rt["retrans"]) == (f_r1, f_r3, 1)
    assert rt["retrans_frames"] == f"[{f_r2}]" and rt["result"] == "NXDOMAIN" and rt["result_ok"] == 0

    orph = t[("0x9999", 40009)]
    assert orph["status"] == "orphan_response" and orph["req_frame"] is None and orph["rsp_frame"] == f_orph

    un = t[("0x3333", 40004)]
    assert un["status"] == "unanswered" and un["state"] == "observed" and un["note"].startswith(NO_RESPONSE_TEXT)
    late = t[("0x4444", 40005)]
    assert late["status"] == "unanswered" and late["state"] == "undetermined" and NO_RESPONSE_TEXT in late["note"]

    f = q(cid, "SELECT * FROM findings WHERE rule='DNS-NO-RESPONSE' ORDER BY ts_ns")
    assert any(str(f_un) in x["frames"] and NO_RESPONSE_TEXT in x["title"] for x in f)
    assert any(x["rule"] == "DNS-RCODE" for x in q(cid, "SELECT rule FROM findings"))
