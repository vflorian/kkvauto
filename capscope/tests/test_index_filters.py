"""Indexing real pcap/pcapng files through TShark; display filters (valid / invalid)."""
from __future__ import annotations

from capscope import service
from capscope.db import get_capture
from capscope.synth import PcapngWriter, Scenario, build_demo, dns_query, eth_ip, udp

from conftest import index_file, needs_tshark, q

T0 = 1_700_000_000_123_456_789


@needs_tshark
def test_index_pcap_and_pcapng_same_content(tmp_path):
    sc = build_demo()
    a = sc.write(str(tmp_path / "demo.pcap"), "pcap", nanos=True)
    b = sc.write(str(tmp_path / "demo.pcapng"), "pcapng", ifaces=[{"name": "mirror", "tsresol": 9}])
    ca, cb = index_file(a), index_file(b)
    for cid, fmt in ((ca, "pcap"), (cb, "pcapng")):
        cap = get_capture(cid)
        assert cap["status"] == "ready" and cap["frames"] == len(sc.frames)
        assert cap["info"]["format"] == fmt
        rows = q(cid, "SELECT frame_no, ts_ns, section, iface, offset FROM packets ORDER BY frame_no")
        assert [r["ts_ns"] for r in rows] == [f.ts_ns for f in sc.frames]  # lossless ns timestamps
        assert all(r["offset"] is not None for r in rows)
    assert q(ca, "SELECT section FROM packets LIMIT 1")[0]["section"] is None
    assert q(cb, "SELECT section FROM packets LIMIT 1")[0]["section"] == 1
    # identical analysis results regardless of container format
    sql = "SELECT proto, req_frame, rsp_frame, status FROM transactions ORDER BY req_frame"
    assert q(ca, sql) == q(cb, sql)


@needs_tshark
def test_multi_interface_pcapng_and_drop_stats(tmp_path):
    p = tmp_path / "multi.pcapng"
    w = PcapngWriter(str(p), "two interfaces")
    w.add_interface("s1u", tsresol=9)
    w.add_interface("sgi", tsresol=6)
    w.write(T0, eth_ip("100.64.0.1", "8.8.8.8", 17, udp(4000, 53, dns_query(1, "a.example"))), 1)
    w.write(T0 + 5, eth_ip("10.0.2.1", "10.0.1.2", 17, udp(2152, 2152, b"\x30\xff\x00\x00\x00\x00\x00\x01")), 0)
    w.write_isb(0, T0 + 10, ifdrop=3)
    w.close()
    cid = index_file(p)
    rows = q(cid, "SELECT frame_no, ts_ns, iface, section FROM packets ORDER BY frame_no")
    assert [(r["iface"], r["section"]) for r in rows] == [(1, 1), (0, 1)]
    assert rows[0]["ts_ns"] == T0 // 1000 * 1000 and rows[1]["ts_ns"] == T0 + 5
    ifs = get_capture(cid)["info"]["interfaces"]
    assert ifs[0]["name"] == "s1u" and ifs[0]["ifdrop"] == 3
    assert ifs[1]["name"] == "sgi" and ifs[1]["ifdrop"] is None   # shown as "Nincs adat"


@needs_tshark
def test_truncated_capture_is_partial(tmp_path):
    sc = build_demo()
    p = tmp_path / "trunc.pcapng"
    sc.write(str(p), "pcapng")
    data = p.read_bytes()
    p.write_bytes(data[:-30])
    cid = index_file(p)
    cap = get_capture(cid)
    assert cap["status"] == "partial" and cap["partial"] == 1
    assert "Csonka" in cap["partial_reason"] or "csonka" in cap["partial_reason"]
    assert cap["frames"] == len(sc.frames) - 1


@needs_tshark
def test_snaplen_truncated_packets_counted(tmp_path):
    sc = build_demo()
    p = tmp_path / "snap.pcapng"
    sc.write(str(p), "pcapng", ifaces=[{"name": "eth0", "snaplen": 64}])
    cid = index_file(p)
    info = get_capture(cid)["info"]
    assert info["snaplen_truncated"] > 0
    assert get_capture(cid)["status"] == "ready"


@needs_tshark
def test_user_limit_marks_partial_and_undetermined(tmp_path):
    sc = Scenario()
    sc.udp(0, "10.1.1.1", "8.8.8.8", 5000, 53, dns_query(7, "late.example"))
    sc.udp(1, "10.1.1.1", "8.8.8.8", 5001, 53, dns_query(8, "other.example"))
    sc.udp(1, "8.8.8.8", "10.1.1.1", 53, 5000, b"")  # never reached because of the limit
    p = sc.write(str(tmp_path / "lim.pcapng"))
    cid = index_file(p, max_packets=2)
    cap = get_capture(cid)
    assert cap["status"] == "partial" and "korlát" in cap["partial_reason"]
    t = q(cid, "SELECT status, state, note FROM transactions WHERE txn_id='0x0007'")[0]
    assert t["status"] == "unanswered" and t["state"] == "undetermined"
    assert "A válasz nem látszik a vizsgált capture-ben." in t["note"]


@needs_tshark
def test_valid_filter(tmp_path):
    p = build_demo().write(str(tmp_path / "d.pcapng"))
    cid = index_file(p)
    r = service.start_filter(cid, "dns.flags.response == 1 && !gtp")
    assert r["ok"]
    from capscope.jobs import jobs
    j = jobs.get(r["job"]["id"])
    j.thread.join(60)
    hits = [x["frame_no"] for x in q(cid, "SELECT frame_no FROM filter_hits WHERE filter_id=? ORDER BY frame_no",
                                      r["filter"]["id"])]
    assert hits == [18]
    f = q(cid, "SELECT status, hits FROM filters WHERE id=?", r["filter"]["id"])[0]
    assert f == {"status": "done", "hits": 1}
    again = service.start_filter(cid, "dns.flags.response == 1 && !gtp")
    assert again.get("cached")


@needs_tshark
def test_invalid_filter_is_explained(tmp_path):
    p = build_demo().write(str(tmp_path / "d.pcapng"))
    cid = index_file(p)
    for expr in ("dns.qry.nme == 1", "ip.addr == ", "gtpv2.cause >> 3", "ip.src == notanip"):
        r = service.start_filter(cid, expr)
        assert not r["ok"], expr
        assert r["error"].startswith("Érvénytelen display filter.")
        assert r["tshark"], expr  # TShark's own message (with caret) is kept for the expert
    assert q(cid, "SELECT count(*) n FROM filters")[0]["n"] == 0
