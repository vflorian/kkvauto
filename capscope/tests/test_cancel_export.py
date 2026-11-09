"""Cancellation/re-use, lossless export with original references, secrets handling, masking."""
from __future__ import annotations

import json
import time

import pytest

from capscope import export, incident, service
from capscope.capfile import CaptureWalker
from capscope.config import settings
from capscope.db import get_capture
from capscope.jobs import jobs
from capscope.synth import (TCP_ACK, TCP_PSH, PcapngWriter, Scenario, build_demo, dns_query, eth_ip, generate_large,
                            tcp, udp)
from capscope.tempfiles import live_dirs

from conftest import frames_comments, index_file, needs_tshark, q


def _wait(job, timeout=300):
    job.thread.join(timeout)
    assert not job.thread.is_alive()
    return job


@needs_tshark
def test_cancelled_import_leaves_app_usable(tmp_path):
    big = tmp_path / "big.pcapng"
    generate_large(str(big), 300_000)
    r = service.register_capture(str(big))
    job = service.start_index(r["id"])
    t0 = time.time()
    while job.counters.get("frames", 0) < 20_000 and job.thread.is_alive() and time.time() - t0 < 120:
        time.sleep(0.05)
    job.cancel()
    _wait(job)
    assert job.state == "cancelled"
    assert all(p.poll() is not None for p in job._procs)  # tshark terminated
    cap = get_capture(r["id"])
    assert cap["status"] == "cancelled" and cap["partial"] == 1 and 0 < cap["frames"] < 300_000
    assert "megszakította" in cap["partial_reason"]
    n = cap["frames"]
    assert q(r["id"], "SELECT count(*) n FROM packets")[0]["n"] == n
    # the partial index is usable: filters are limited to the indexed range, detail works
    f = service.start_filter(r["id"], "dns")
    _wait(jobs.get(f["job"]["id"]), 120)
    hits = q(r["id"], "SELECT max(frame_no) m, count(*) c FROM filter_hits")[0]
    assert hits["c"] > 0 and hits["m"] <= n
    d = service.packet_detail(r["id"], 5, "isolated")
    assert d["tree"] and d["hex"]
    assert live_dirs() == [] and list(settings.tmp_dir.iterdir()) == []
    # a second import of another file and a re-index of the same file both work
    other = index_file(build_demo().write(str(tmp_path / "demo.pcapng")))
    assert get_capture(other)["status"] == "ready"
    job2 = service.start_index(r["id"])
    _wait(job2, 600)
    assert job2.state == "done" and get_capture(r["id"])["status"] == "ready"
    assert get_capture(r["id"])["frames"] == 300_000


@needs_tshark
def test_restart_during_import_is_recovered(tmp_path):
    cid = index_file(build_demo().write(str(tmp_path / "d.pcapng")))
    from capscope.db import update_capture
    update_capture(cid, status="indexing")
    service.recover_after_restart()
    cap = get_capture(cid)
    assert cap["status"] == "interrupted" and cap["partial"] == 1


@needs_tshark
def test_filtered_export_keeps_original_references(tmp_path):
    src = build_demo().write(str(tmp_path / "demo.pcapng"), ifaces=[{"name": "s11-s1u", "tsresol": 9}])
    cid = index_file(src)
    f = service.start_filter(cid, "dns && !gtp")
    _wait(jobs.get(f["job"]["id"]), 60)
    job = export.start_pcap_export(cid, {"filter_id": f["filter"]["id"]})
    _wait(job)
    assert job.state == "done", job.error
    out = settings.exports_dir / job.result["export"]["file"]
    com = frames_comments(out)
    orig = [x["frame_no"] for x in q(cid, "SELECT frame_no FROM filter_hits WHERE filter_id=? ORDER BY frame_no",
                                      f["filter"]["id"])]
    assert len(com) == len(orig) == 4
    for (new_no, c), o in zip(com, orig):
        assert f"frame={o} " in c + " " and "file=demo.pcapng" in c and "section=1 iface=0" in c
    # bytes and timestamps unchanged
    wk_src, wk_out = CaptureWalker(src), CaptureWalker(str(out))
    src_refs = {r.frame_no: r for r in wk_src.packets()}
    out_refs = list(wk_out.packets())
    for o, r in zip(orig, out_refs):
        assert (r.ts_units, r.tsresol, r.caplen) == (src_refs[o].ts_units, src_refs[o].tsresol, src_refs[o].caplen)
    assert wk_out.info.interfaces[0]["name"] == "s11-s1u"


@needs_tshark
def test_classic_pcap_export_and_selected_frames(tmp_path):
    src = build_demo().write(str(tmp_path / "demo.pcap"), "pcap")
    cid = index_file(src)
    job = export.start_pcap_export(cid, {"frames": [2, 22, 31]})
    _wait(job)
    com = frames_comments(settings.exports_dir / job.result["export"]["file"])
    assert [c.split("frame=")[1].split()[0] for _, c in com] == ["2", "22", "31"]


@needs_tshark
def test_secrets_only_with_confirmation(tmp_path):
    p = tmp_path / "keys.pcapng"
    w = PcapngWriter(str(p))
    w.add_interface("eth0")
    w.write_dsb(b"CLIENT_RANDOM 0011 2233\n")
    w.write(1_700_000_000_000_000_000, eth_ip("10.0.0.1", "8.8.8.8", 17, udp(1, 53, dns_query(1, "a.example"))))
    w.close()
    cid = index_file(p)
    assert get_capture(cid)["info"]["dsb"]
    job = export.start_pcap_export(cid, {"frames": [1]})
    _wait(job)
    rec = job.result["export"]
    assert not rec["contains_secrets"] and "eltávolítva" in rec["note"]
    wk = CaptureWalker(str(settings.exports_dir / rec["file"]))
    list(wk.packets())
    assert wk.info.dsb == []
    with pytest.raises(service.UserError):
        export.start_pcap_export(cid, {"frames": [1]}, include_secrets=True, confirm="igen")
    job = export.start_pcap_export(cid, {"frames": [1]}, include_secrets=True, confirm=export.SECRETS_CONFIRM)
    _wait(job)
    rec = job.result["export"]
    assert rec["contains_secrets"] and "_RAW_WITH_SECRETS" in rec["file"]
    wk = CaptureWalker(str(settings.exports_dir / rec["file"]))
    list(wk.packets())
    assert len(wk.info.dsb) == 1


@needs_tshark
def test_export_with_reassembly_dependencies(tmp_path):
    msg = dns_query(0x5555, "reassembled.example")
    wire = len(msg).to_bytes(2, "big") + msg
    a, b = wire[:10], wire[10:]
    sc = Scenario()
    C, S = "10.9.0.1", "10.9.0.2"
    sc.tcp(0, C, S, 40000, 53, 100, 0, 0x02)
    sc.tcp(1, S, C, 53, 40000, 500, 101, 0x12)
    sc.tcp(1, C, S, 40000, 53, 101, 501, TCP_ACK)
    f1 = sc.tcp(1, C, S, 40000, 53, 101, 501, TCP_ACK | TCP_PSH, a)
    f2 = sc.tcp(1, C, S, 40000, 53, 101 + len(a), 501, TCP_ACK | TCP_PSH, b)
    cid = index_file(sc.write(str(tmp_path / "tcpdns.pcapng")))
    d = service.packet_detail(cid, f2, "context")
    assert any(x["frame"] == f1 for x in d["deps"])
    job = export.start_pcap_export(cid, {"frames": [f2]}, include_deps=True)
    _wait(job)
    com = frames_comments(settings.exports_dir / job.result["export"]["file"])
    assert sorted(int(c.split("frame=")[1].split()[0]) for _, c in com) == [f1, f2]
    _ = tcp


@needs_tshark
def test_incident_report_masked_and_unmasked(tmp_path):
    cid = index_file(build_demo().write(str(tmp_path / "demo.pcapng")))
    iid = incident.ensure_default()
    rej = q(cid, "SELECT id FROM findings WHERE rule='GTPC-REJECT'")[0]["id"]
    nores = q(cid, "SELECT id FROM transactions WHERE proto='dns' AND status='unanswered'")[0]["id"]
    sess = q(cid, "SELECT id FROM gtp_sessions WHERE imsi='216301234567890'")[0]["id"]
    incident.add_item(iid, "finding", cid, rej)
    incident.add_item(iid, "transaction", cid, nores)
    incident.add_item(iid, "session", cid, sess)
    incident.add_item(iid, "packet", cid, frame=22)
    assert incident.add_item(iid, "packet", cid, frame=22)["duplicate"]
    masked = incident.build_report(iid, {"imsi": 1, "msisdn": 1, "imei": 1})
    raw = incident.build_report(iid, {})
    md = masked["markdown"]
    assert "216309876543210" not in md and "216301234567890" not in md and "21630xxxxxxxxxx [IMSI#" in md
    assert "Identifier masking: ON" in md and "Not applied to: raw capture exports" in md
    assert "## Timeline (UTC)" in md and "2023-11-14T22:13:21.762000000Z" in md
    assert "frame.number in {" in md and "no response visible in the analysed capture" in md
    assert "## Analysis limitations" in md and "no drop statistics" in md
    assert "216309876543210" in raw["markdown"] and "masking: OFF" in raw["markdown"]
    assert {e["masked"] for e in masked["exports"]} == {True} and {e["masked"] for e in raw["exports"]} == {False}
    js = json.loads((settings.exports_dir / masked["exports"][1]["file"]).read_text("utf-8"))
    assert js["masking"]["masked_classes"][:3] == ["IMSI", "MSISDN", "IMEI/IMEISV"]
    assert all("216301234567890" not in json.dumps(i) for i in js["items"])


@needs_tshark
def test_table_export_masking(tmp_path):
    cid = index_file(build_demo().write(str(tmp_path / "demo.pcapng")))
    m = export.export_table(cid, "sessions", "csv", {"imsi": 1, "msisdn": 1})
    txt = (settings.exports_dir / m["file"]).read_text("utf-8-sig")
    assert "216301234567890" not in txt and "36301234567" not in txt and "MASKED" in m["file"]
    u = export.export_table(cid, "sessions", "json", {})
    js = json.loads((settings.exports_dir / u["file"]).read_text("utf-8"))
    assert js["meta"]["masking"].startswith("none") and any(r["imsi"] == "216301234567890" for r in js["rows"])
    assert "UNMASKED" in u["file"]
