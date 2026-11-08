"""Run the held-out red-team set (30 simulated scams + 15 genuine controls).  Usage: python redteam.py"""
import pandas as pd

from safesms import ROOT, load, update_metrics


def main():
    model = load()
    df = pd.read_csv(ROOT / "data" / "redteam.csv")
    res = model.analyze_batch(df.text.tolist())
    df["verdict"] = [r["verdict"] for r in res]
    df["score"] = [r["score"] for r in res]
    df["n_reasons"] = [len(r["reasons"]) for r in res]

    sc, sf = df[df.label == "scam"], df[df.label == "safe"]
    hit, strict, fa = int((sc.verdict != "SAFE").sum()), int((sc.verdict == "SCAM").sum()), int((sf.verdict != "SAFE").sum())
    print(f"Scams flagged (SCAM or SUSPICIOUS): {hit}/{len(sc)} = {hit / len(sc):.1%}")
    print(f"Scams rated SCAM (strict):          {strict}/{len(sc)} = {strict / len(sc):.1%}")
    print(f"Genuine controls wrongly flagged:   fa={fa}/{len(sf)} = {fa / len(sf):.1%}")

    for _, r in df[((df.label == "scam") & (df.verdict == "SAFE")) | ((df.label == "safe") & (df.verdict != "SAFE"))].iterrows():
        print(f"  WRONG [{r.label} -> {r.verdict} {r.score}] {r.text[:95]}")

    fl = df[df.verdict != "SAFE"]
    three = int((fl.n_reasons == 3).sum())
    print(f"Flagged red-team messages showing 3 reasons: {three}/{len(fl)}")

    update_metrics(
        o6=dict(scams=len(sc), flagged=hit, flagged_pct=round(100 * hit / len(sc), 1), strict_scam=strict,
                strict_pct=round(100 * strict / len(sc), 1), controls=len(sf), controls_wrongly_flagged=fa),
        o4_redteam=dict(flagged=len(fl), with_3_reasons=three, pct=round(100 * three / max(1, len(fl)), 1))
    )


if __name__ == "__main__":
    main()
