import pandas as pd

from safesms import ROOT, url_features, url_report

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
