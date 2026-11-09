"""GTP-C session correlation and GTP-U attribution."""
from __future__ import annotations

import json

from capscope.synth import Scenario, dns_query, inner_udp, lte_attach, lte_detach

from conftest import index_file, needs_tshark, q

IMSI_A, IMSI_B = "216300000000001", "216300000000002"


def build() -> tuple[Scenario, dict]:
    sc = Scenario()
    fr: dict = {}
    # Two sessions behind two different SGWs that use the SAME numeric TEIDs (C-plane 0x2001, S1-U 0xA0001, eNB 0xB0001)
    fr["A"] = lte_attach(sc, imsi=IMSI_A, msisdn="3630000001", apn="internet", ue_ip="100.64.0.1", seq=0x10,
                         sgw_c="10.0.0.2", sgw_u="10.0.1.2", enb="10.0.2.1", mme_teid=0x1001)
    fr["B"] = lte_attach(sc, imsi=IMSI_B, msisdn="3630000002", apn="internet", ue_ip="100.64.0.2", seq=0x20,
                         sgw_c="10.0.0.3", sgw_u="10.0.1.3", enb="10.0.2.2", mme_teid=0x1002)
    up = lambda dst, ue, teid=0xA0001, src="10.0.2.1": sc.gtpu(5, src, dst, teid, inner_udp(ue, "8.8.8.8", 4000, 53, dns_query(1, "x.example")))
    fr["ul_a"] = up("10.0.1.2", "100.64.0.1")
    fr["ul_b"] = up("10.0.1.3", "100.64.0.2", src="10.0.2.2")
    fr["dl_a"] = sc.gtpu(5, "10.0.1.2", "10.0.2.1", 0xB0001, inner_udp("8.8.8.8", "100.64.0.1", 53, 4000, b"\x00" * 12))
    fr["dl_b"] = sc.gtpu(5, "10.0.1.3", "10.0.2.2", 0xB0001, inner_udp("8.8.8.8", "100.64.0.2", 53, 4000, b"\x00" * 12))
    fr["unknown_ep"] = up("10.0.1.9", "100.64.0.1")             # same TEID, endpoint never signalled
    fr["ip_mismatch"] = up("10.0.1.2", "100.64.0.99")             # right F-TEID, wrong inner UE IP
    fr["cplane_teid"] = sc.gtpu(5, "10.0.0.1", "10.0.0.2", 0x2001, inner_udp("100.64.0.1", "1.1.1.1", 1, 2, b"x"))
    # Two sessions signal the same S1-U F-TEID at the same endpoint -> ambiguous
    fr["C"] = lte_attach(sc, imsi="216300000000003", msisdn="3630000003", apn="iot", ue_ip="100.64.0.3", seq=0x30,
                         sgw_c="10.0.0.4", sgw_u="10.0.1.4", sgw_u_teid=0xC0001, mme_teid=0x1003, sgw_teid=0x3001,
                         with_mbr=False)
    fr["D"] = lte_attach(sc, imsi="216300000000004", msisdn="3630000004", apn="iot", ue_ip="100.64.0.3", seq=0x40,
                         sgw_c="10.0.0.4", sgw_u="10.0.1.4", sgw_u_teid=0xC0001, mme_teid=0x1004, sgw_teid=0x3002,
                         with_mbr=False)
    fr["amb"] = up("10.0.1.4", "100.64.0.3", teid=0xC0001)
    # Delete session A; user-plane after the validity window must not be attributed
    fr["del_a"] = lte_detach(sc, seq=0x50, sgw_c="10.0.0.2", mme_teid=0x1001, sgw_teid=0x2001)
    fr["after_del"] = sc.gtpu(5000, "10.0.2.1", "10.0.1.2", 0xA0001, inner_udp("100.64.0.1", "8.8.8.8", 4000, 53, b"late"))
    return sc, fr


@needs_tshark
def test_same_teid_on_different_endpoints_not_merged(tmp_path):
    sc, fr = build()
    cid = index_file(sc.write(str(tmp_path / "gtp.pcapng")))
    sess = {r["imsi"]: r for r in q(cid, "SELECT * FROM gtp_sessions")}
    a, b = sess[IMSI_A], sess[IMSI_B]
    assert a["id"] != b["id"]
    assert a["ue_ipv4"] == "100.64.0.1" and b["ue_ipv4"] == "100.64.0.2"
    assert a["status"] == "deleted" and b["status"] == "active"

    # Modify Bearer of B (header TEID 0x2001 to 10.0.0.3) belongs to B, not to A (0x2001 @ 10.0.0.2)
    ev = {r["frame"]: r for r in q(cid, "SELECT * FROM gtp_events")}
    assert ev[fr["B"]["mbr"]]["session_id"] == b["id"]
    assert ev[fr["A"]["mbr"]]["session_id"] == a["id"]
    assert ev[fr["del_a"]["dsr"]]["session_id"] == a["id"]

    tun = {r["frame_no"]: r for r in q(cid, "SELECT f.frame_no, t.* FROM gtpu_frames f JOIN gtpu_tunnels t ON t.id=f.tunnel_id")}
    assert tun[fr["ul_a"]]["session_id"] == a["id"] and tun[fr["ul_a"]]["direction"] == "uplink"
    assert tun[fr["ul_b"]]["session_id"] == b["id"] and tun[fr["ul_b"]]["direction"] == "uplink"
    assert tun[fr["dl_a"]]["session_id"] == a["id"] and tun[fr["dl_a"]]["direction"] == "downlink"
    assert tun[fr["dl_b"]]["session_id"] == b["id"]
    for k in ("ul_a", "ul_b", "dl_a", "dl_b"):
        assert tun[fr[k]]["state"] == "inferred" and tun[fr[k]]["rule"].startswith("GTPU-FTEID")

    # TEID alone (other endpoint) is not enough
    u = tun[fr["unknown_ep"]]
    assert u["session_id"] is None and u["state"] == "undetermined" and u["rule"].startswith("GTPU-NOMATCH")
    assert "10.0.1.2" in u["note"] and "10.0.1.3" in u["note"]
    # right F-TEID but inner IP disagrees with the allocated address -> undetermined
    m = tun[fr["ip_mismatch"]]
    assert m["state"] == "undetermined" and "nem egyezik" in m["note"]
    # C-plane TEIDs are never used for user-plane attribution
    assert tun[fr["cplane_teid"]]["session_id"] is None
    # after Delete Session (+ grace) no attribution
    assert tun[fr["after_del"]]["session_id"] is None


@needs_tshark
def test_ambiguous_candidates_are_listed(tmp_path):
    sc, fr = build()
    cid = index_file(sc.write(str(tmp_path / "gtp.pcapng")))
    ids = {r["imsi"]: r["id"] for r in q(cid, "SELECT id, imsi FROM gtp_sessions")}
    t = q(cid, "SELECT t.* FROM gtpu_frames f JOIN gtpu_tunnels t ON t.id=f.tunnel_id WHERE f.frame_no=?", fr["amb"])[0]
    assert t["session_id"] is None and t["state"] == "undetermined"
    assert sorted(json.loads(t["candidates"])) == sorted([ids["216300000000003"], ids["216300000000004"]])


@needs_tshark
def test_control_and_user_plane_fteids_are_separate(tmp_path):
    sc, fr = build()
    cid = index_file(sc.write(str(tmp_path / "gtp.pcapng")))
    a = q(cid, "SELECT id FROM gtp_sessions WHERE imsi=?", IMSI_A)[0]["id"]
    ft = q(cid, "SELECT plane, iface_type, ip, teid, direction, valid_to_ts FROM gtp_fteids WHERE session_id=? ORDER BY id", a)
    planes = {(f["plane"], f["ip"], f["teid"]) for f in ft}
    assert ("C", "10.0.0.1", 0x1001) in planes and ("C", "10.0.0.2", 0x2001) in planes
    assert ("U", "10.0.1.2", 0xA0001) in planes and ("U", "10.0.2.1", 0xB0001) in planes
    assert all(f["valid_to_ts"] is not None for f in ft)  # closed by Delete Session


@needs_tshark
def test_gtp_transactions_retrans_and_reject(tmp_path):
    from capscope.synth import build_demo
    cid = index_file(build_demo().write(str(tmp_path / "demo.pcapng")))
    tx = q(cid, "SELECT * FROM transactions WHERE proto='gtpv2c' ORDER BY req_frame")
    rej = [t for t in tx if t["result_ok"] == 0][0]
    assert rej["result"].startswith("78") and rej["rsp_frame"] == rej["req_frame"] + 1
    unans = [t for t in tx if t["status"] == "unanswered"][0]
    assert unans["retrans"] == 2 and json.loads(unans["retrans_frames"]) == [unans["req_frame"] + 1, unans["req_frame"] + 2]
    v1 = q(cid, "SELECT * FROM gtp_sessions WHERE version=1")[0]
    assert v1["leg"] == "Gn/Gp" and v1["ue_ipv4"] == "10.200.0.5" and v1["imsi"] == "262019999999999"
    assert q(cid, "SELECT count(*) n FROM gtpu_tunnels WHERE session_id=?", v1["id"])[0]["n"] == 2
