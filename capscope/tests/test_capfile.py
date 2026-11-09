"""pcap / pcapng walker: formats, interfaces, sections, lossless timestamps, truncation (no TShark needed)."""
from __future__ import annotations

from capscope.capfile import CaptureWalker, units_to_ns
from capscope.synth import PcapngWriter, PcapWriter, eth_ip, udp

T0 = 1_700_000_000_123_456_789


def _pkt(i: int) -> bytes:
    return eth_ip("10.0.0.1", "10.0.0.2", 17, udp(1000 + i, 2000, b"x" * 10))


def test_pcap_us_and_ns(tmp_path):
    for nanos in (False, True):
        p = tmp_path / f"t{int(nanos)}.pcap"
        w = PcapWriter(str(p), nanos=nanos)
        for i in range(3):
            w.write(T0 + i, _pkt(i))
        w.close()
        wk = CaptureWalker(str(p))
        refs = list(wk.packets())
        assert [r.frame_no for r in refs] == [1, 2, 3]
        assert wk.info.format == "pcap" and wk.info.sha256
        ns = units_to_ns(refs[0].ts_units, refs[0].tsresol)
        assert ns == (T0 if nanos else T0 // 1000 * 1000)
        assert refs[0].section is None and refs[0].iface == 0


def test_pcapng_multi_interface_sections_isb(tmp_path):
    p = tmp_path / "m.pcapng"
    w = PcapngWriter(str(p), "section one")
    w.add_interface("eth0", tsresol=6)
    w.add_interface("s1u", tsresol=9, description="mirror")
    w.write(T0, _pkt(0), 0)
    w.write(T0 + 1, _pkt(1), 1)
    w.write_isb(1, T0 + 2, ifdrop=7, ifrecv=100)
    w.new_section("section two")
    w.add_interface("other", tsresol=9)
    w.write(T0 + 3, _pkt(2), 0)
    w.close()
    wk = CaptureWalker(str(p))
    refs = list(wk.packets())
    assert [(r.frame_no, r.section, r.iface) for r in refs] == [(1, 1, 0), (2, 1, 1), (3, 2, 0)]
    assert units_to_ns(refs[1].ts_units, refs[1].tsresol) == T0 + 1          # ns interface: lossless
    assert units_to_ns(refs[0].ts_units, refs[0].tsresol) == T0 // 1000 * 1000  # us interface
    ifs = wk.info.interfaces
    assert [i["name"] for i in ifs] == ["eth0", "s1u", "other"]
    assert ifs[0]["ifdrop"] is None and ifs[1]["ifdrop"] == 7
    assert len(wk.info.sections) == 2 and wk.info.sections[1]["comment"] == "section two"


def test_truncated_pcapng_detected(tmp_path):
    p = tmp_path / "t.pcapng"
    w = PcapngWriter(str(p))
    w.add_interface("eth0")
    for i in range(5):
        w.write(T0 + i * 1000, _pkt(i))
    w.close()
    data = p.read_bytes()
    p.write_bytes(data[:-20])
    wk = CaptureWalker(str(p))
    refs = list(wk.packets())
    assert len(refs) == 4
    assert wk.info.truncated and "csonka" in wk.info.truncation_note


def test_dsb_detected(tmp_path):
    p = tmp_path / "d.pcapng"
    w = PcapngWriter(str(p))
    w.add_interface("eth0")
    w.write_dsb(b"CLIENT_RANDOM 00 11\n")
    w.write(T0, _pkt(0))
    w.close()
    wk = CaptureWalker(str(p))
    list(wk.packets())
    assert wk.info.dsb and wk.info.dsb[0]["kind"] == "TLS key log"
