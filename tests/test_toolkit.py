import pandas as pd
import pytest

from demo import DEMO_PRESETS
from safesms import ROOT, normalize, url_features, url_report

RT = pd.read_csv(ROOT / "data" / "redteam.csv")


def test_o3_at_least_8_url_features():
    assert len(url_features("http://bit.ly/abc")) >= 8


def test_o3_risky_link_scores_high():
    assert url_report("verify at http://41.89.12.7/login")[0]["risk"] >= 0.7


def test_official_link_is_low_risk():
    assert url_report("help: https://www.safaricom.co.ke/help")[0]["risk"] <= 0.2


def test_genuine_receipt_is_safe(model):
    msg = "BC34DE56FG Confirmed. Ksh250.00 sent to ALICE MUTUA 0700 000 205 on 6/11/26 at 3:15 PM. New M-PESA balance is Ksh780.00. Transaction cost, Ksh5.00."
    assert model.analyze(msg)["verdict"] == "SAFE"


def test_o4_three_reasons_for_every_flagged_message(model):
    flagged = [r for r in (model.analyze(t) for t in RT.text) if r["verdict"] != "SAFE"]
    assert flagged and all(len(r["reasons"]) == 3 for r in flagged)


def test_o5_p95_latency_under_200ms(model):
    from app import app
    c, ms = app.test_client(), []
    import time
    for t in list(RT.text) * 5:
        t0 = time.perf_counter()
        assert c.post("/predict", json={"message": t}).status_code == 200
        ms.append((time.perf_counter() - t0) * 1000)
    assert sorted(ms)[int(len(ms) * 0.95)] < 200


def test_o6_redteam_detection_rate(model):
    sc = RT[RT.label == "scam"]
    hit = sum(model.analyze(t)["verdict"] != "SAFE" for t in sc.text)
    assert hit / len(sc) >= 0.90, f"detected {hit}/{len(sc)}"


# --- Enhanced System & Optimization Tests ---


def test_batch_analysis_matches_single(model):
    sample_texts = list(RT.text)[:10]
    single_res = [model.analyze(t) for t in sample_texts]
    batch_res = model.analyze_batch(sample_texts)

    assert len(single_res) == len(batch_res)
    for s, b in zip(single_res, batch_res):
        assert s["verdict"] == b["verdict"]
        assert abs(s["score"] - b["score"]) < 1e-3
        assert s["reasons"] == b["reasons"]


def test_explain_debug_structure(model):
    dbg = model.explain_debug("KRA tax refund approved: claim at http://kra-verify.top/claim")
    assert "verdict" in dbg
    assert "score" in dbg
    assert "raw_margin" in dbg
    assert "reasons" in dbg
    assert "dense_active" in dbg
    assert "top_contributions" in dbg
    assert dbg["verdict"] == "SCAM"
    assert len(dbg["reasons"]) == 3


def test_edge_case_inputs(model):
    # Empty string
    r_empty = model.analyze("")
    assert r_empty["verdict"] == "SAFE"

    # Whitespace only
    r_space = model.analyze("   \n\t  ")
    assert r_space["verdict"] == "SAFE"

    # None / non-string type handling
    r_none = model.analyze(None)
    assert r_none["verdict"] == "SAFE"


def test_app_endpoints():
    from app import app
    client = app.test_client()

    # GET /
    res = client.get("/")
    assert res.status_code == 200
    assert b"SafeSMS-KE" in res.data

    # POST /predict valid
    res_p = client.post("/predict", json={"message": "Hello test message"})
    assert res_p.status_code == 200
    assert "verdict" in res_p.get_json()

    # POST /predict invalid / empty
    res_err = client.post("/predict", json={"message": ""})
    assert res_err.status_code == 400

    # POST /predict malformed json or bad structure
    res_bad = client.post("/predict", data="invalid json", content_type="application/json")
    assert res_bad.status_code == 400

    # POST /debug
    res_d = client.post("/debug", json={"message": "Urgent KRA notice http://bad.xyz"})
    assert res_d.status_code == 200
    assert "raw_margin" in res_d.get_json()


def test_demo_presets_validity(model):
    assert len(DEMO_PRESETS) >= 8
    for p in DEMO_PRESETS:
        assert "id" in p
        assert "text" in p
        assert "expected" in p
        res = model.analyze(p["text"])
        assert res["verdict"] in ("SAFE", "SUSPICIOUS", "SCAM")
