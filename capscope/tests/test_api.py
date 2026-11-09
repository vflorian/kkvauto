"""HTTP API: security guards and the end-to-end vertical slice
(open local file -> index -> filter -> DNS transaction -> jump to request/response -> filtered export)."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from capscope.api import app, ensure_token
from capscope.config import settings
from capscope.synth import build_demo

from conftest import frames_comments, needs_tshark

BASE = f"http://127.0.0.1:{settings.port}"
H = {"X-CapScope": "1"}


@pytest.fixture
def client():
    c = TestClient(app, base_url=BASE)
    r = c.get(f"/?token={ensure_token()}", follow_redirects=False)
    assert r.status_code == 303 and "capscope_token" in r.headers["set-cookie"]
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    return c


def wait_job(c, jid, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] not in ("queued", "running"):
            return j
        time.sleep(0.1)
    raise AssertionError("job timeout")


def test_security_guards(tmp_path):
    c = TestClient(app, base_url=BASE)
    assert c.get("/api/captures").status_code == 401                                   # no token cookie
    assert c.get("/?token=wrong").status_code == 401
    evil = TestClient(app, base_url="http://evil.example:8765")
    assert evil.get(f"/?token={ensure_token()}").status_code == 403                    # DNS rebinding guard
    c.get(f"/?token={ensure_token()}", follow_redirects=False)
    c.cookies.set("capscope_token", ensure_token())
    assert c.post("/api/captures", json={"path": "x"}).status_code == 403              # missing X-CapScope
    txt = tmp_path / "secret.txt"
    txt.write_text("not a capture")
    r = c.post("/api/captures", json={"path": str(txt)}, headers=H)
    assert r.status_code == 400 and "capture" in r.json()["error"]
    fake = tmp_path / "fake.pcap"
    fake.write_text("not a capture either")
    assert c.post("/api/captures", json={"path": str(fake)}, headers=H).status_code == 400
    assert c.post("/api/captures", json={"path": str(tmp_path / "missing.pcap")}, headers=H).status_code == 400
    assert c.get("/api/exports/999/download").status_code == 400
    csp = c.get("/").headers["content-security-policy"]
    assert "default-src 'self'" in csp and "http" not in csp


@needs_tshark
def test_vertical_slice(client, tmp_path):
    c = client
    src = build_demo().write(str(tmp_path / "slice.pcapng"))
    r = c.post("/api/captures", json={"path": f'"{src}"'}, headers=H).json()   # quoted Windows-style path accepted
    cid = r["capture"]["id"]
    assert wait_job(c, r["job"]["id"])["state"] == "done"
    ov = c.get(f"/api/captures/{cid}/overview").json()
    assert ov["capture"]["frames"] == 31 and ov["interfaces"][0]["drop_text"] == "Nincs adat" and ov["timeline"]
    # bad then good filter
    bad = c.post(f"/api/captures/{cid}/filters", json={"expr": "dns.qry.nme == 1"}, headers=H).json()
    assert bad["ok"] is False and "Érvénytelen" in bad["error"]
    good = c.post(f"/api/captures/{cid}/filters", json={"expr": "dns"}, headers=H).json()
    wait_job(c, good["job"]["id"])
    pk = c.get(f"/api/captures/{cid}/packets", params={"filter_id": good["filter"]["id"]}).json()
    assert pk["total"] == 8 and all(p["proto"] in ("DNS", "GTP <DNS>") for p in pk["rows"])
    # DNS transaction and jump to request and response
    tx = c.get(f"/api/captures/{cid}/transactions", params={"proto": "dns", "q": "example.com"}).json()["rows"][0]
    for f in (tx["req_frame"], tx["rsp_frame"]):
        page = c.get(f"/api/captures/{cid}/packets", params={"around": f}).json()
        assert page["around_found"] is True
        d = c.get(f"/api/captures/{cid}/packets/{f}").json()
        assert d["packet"]["frame_no"] == f and d["hex"] and any("Domain Name System" in n["text"] for n in d["tree"])
    unans = c.get(f"/api/captures/{cid}/transactions", params={"status": "unanswered", "proto": "dns"}).json()["rows"]
    assert unans and unans[0]["note"].startswith("A válasz nem látszik a vizsgált capture-ben.")
    # filtered export keeps original frame numbers
    ex = c.post(f"/api/captures/{cid}/export/pcap", json={"filter_id": good["filter"]["id"]}, headers=H).json()
    j = wait_job(c, ex["job"]["id"])
    eid = j["result"]["export"]["id"]
    dl = c.get(f"/api/exports/{eid}/download")
    assert dl.status_code == 200 and dl.content[:4] == b"\x0a\x0d\x0d\x0a"
    out = tmp_path / "dl.pcapng"
    out.write_bytes(dl.content)
    nums = [int(cm.split("frame=")[1].split()[0]) for _, cm in frames_comments(out)]
    assert nums == [p["frame_no"] for p in pk["rows"]]
    # follow the TCP stream
    fl = c.get(f"/api/captures/{cid}/follow/tcp/0").json()
    assert [ch["frame"] for ch in fl["chunks"]][:2] == [10, 12]  # #11 is a retransmission: not repeated and fl["peers"][0]["host"] == "100.64.0.10"
    # SIM search by TEID and IP
    s = c.get(f"/api/captures/{cid}/sessions", params={"q": "0x000a0001", "field": "teid"}).json()
    assert s["total"] == 1 and s["rows"][0]["imsi"] == "216301234567890"
    s = c.get(f"/api/captures/{cid}/sessions", params={"q": "10.200.0.5", "field": "ip"}).json()
    assert s["rows"][0]["version"] == 1
