"""Session health: sessions without traffic, short-lived sessions, re-attach loops, Create Session rate onset."""
from __future__ import annotations

from capscope import export
from capscope.analyzers.session_health import detect_onset
from capscope.config import settings
from capscope.synth import generate_churn

from conftest import index_file, needs_tshark, q

ONSET = 1_763_186_400 + 30 * 60  # 2025-11-15 06:30:00 UTC


def test_detect_onset_step_and_flat():
    flat = [(i * 60, 2) for i in range(30)]
    assert detect_onset(flat, 3.0, 1.0) is None
    step = [(i * 60, 1 if i < 20 else 40) for i in range(30)]
    o = detect_onset(step, 3.0, 1.0)
    assert o["bucket"] == 20 * 60 and o["ratio"] == 40.0


@needs_tshark
def test_churn_with_user_plane_visible(tmp_path):
    p = tmp_path / "churn.pcapng"
    generate_churn(str(p), minutes=40, onset_min=25, bad_devices=10)
    cid = index_file(p)
    o = q(cid, "SELECT * FROM apn_onset")[0]
    assert abs(o["onset_bucket"] - (ONSET - 5 * 60)) <= 60 and o["ratio"] >= 3
    bad = q(cid, "SELECT * FROM session_health WHERE imsi LIKE '90128800%'")
    good = q(cid, "SELECT * FROM session_health WHERE imsi LIKE '90128890%' AND accepted")
    assert bad and all(s["up_state"] == "no_traffic" and s["short_lived"] == 1 for s in bad)
    assert all(s["del_side"] == "access" and s["del_msg"] == "Delete Session Request" for s in bad)
    assert all(s["pdn_req"] == "IPv4v6" and s["pdn_alloc"] == "IPv4" and s["pdn_mismatch"] for s in bad)
    assert all(s["tac"] == "35999901" for s in bad)
    assert any(s["up_state"] == "traffic" for s in good) and not any(s["up_state"] == "no_traffic" for s in good)
    top = q(cid, "SELECT * FROM imsi_health ORDER BY score DESC LIMIT 10")
    assert all(r["imsi"].startswith("90128800") for r in top)
    assert all(20e9 <= r["median_gap_ns"] <= 50e9 and r["median_duration_ns"] < 5e9 for r in top)
    f = {(r["rule"], r["state"]) for r in q(cid, "SELECT rule, state FROM findings WHERE analyzer='session_health'")}
    assert {("SESSION-RATE-INCREASE", "inferred"), ("SESSION-NO-UPLANE", "observed"), ("SESSION-CHURN", "observed"),
            ("PDN-TYPE-MISMATCH", "observed")} <= f
    # masked IMSI list for the customer reply
    e = export.export_table(cid, "imsi_health", "csv", {"imsi": 1})
    txt = (settings.exports_dir / e["file"]).read_text("utf-8-sig")
    assert "90128xxxxxxxxxx [IMSI#1]" in txt and "901288000000001" not in txt  # MCC+MNC kept


@needs_tshark
def test_control_plane_only_trace_is_undetermined(tmp_path):
    p = tmp_path / "cp.pcapng"
    generate_churn(str(p), control_plane_only=True, minutes=40, onset_min=25, bad_devices=10)
    cid = index_file(p)
    states = {r["up_state"] for r in q(cid, "SELECT up_state FROM session_health WHERE accepted")}
    assert states == {"undetermined"}  # no GTP-U at all: absence of traffic cannot be claimed
    f = q(cid, "SELECT state, title_en FROM findings WHERE rule='SESSION-NO-UPLANE'")
    assert f and all(x["state"] == "undetermined" for x in f)
    assert q(cid, "SELECT count(*) n FROM apn_onset")[0]["n"] == 1  # rate increase is still visible


@needs_tshark
def test_session_health_api(tmp_path):
    from fastapi.testclient import TestClient
    from capscope.api import app, ensure_token
    p = tmp_path / "churn.pcapng"
    generate_churn(str(p), minutes=30, onset_min=20, bad_devices=5)
    cid = index_file(p)
    c = TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
    c.get(f"/?token={ensure_token()}")
    d = c.get(f"/api/captures/{cid}/session-health").json()
    assert d["available"] and d["apn"] == "iot.example.nl" and d["user_plane_visible"]
    assert d["onset"]["utc"].startswith("2025-11-15T06:20") and d["imsis"][0]["imsi"].startswith("90128800")
    assert any(h["bucket"] == "< 5 s" for h in d["duration_hist"]) and d["tacs"][0]["tac"]
