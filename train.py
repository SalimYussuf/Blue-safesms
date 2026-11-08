"""Train SafeSMS-KE and report objectives O1-O4.   Usage: python train.py"""
import csv
import urllib.request

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from safesms import METRICS_PATH, MODEL_PATH, ROOT, SafeSMS, W, update_metrics

SMS_FILE = ROOT / "data" / "sms_spam.tsv"
SMS_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"


def load_data():
    if not SMS_FILE.exists():
        urllib.request.urlretrieve(SMS_URL, SMS_FILE)
    sms = pd.read_csv(SMS_FILE, sep="\t", header=None, names=["label", "text"], quoting=csv.QUOTE_NONE, dtype=str).dropna()
    raw = len(sms)
    sms = sms.drop_duplicates("text")
    sms = sms.assign(y=(sms.label == "spam").astype(int), source="sms")
    loc = pd.read_csv(ROOT / "data" / "local_samples.csv").drop_duplicates("text")
    loc = loc.assign(y=(loc.label == "scam").astype(int), source="local")
    cols = ["text", "y", "source"]
    return pd.concat([sms[cols], loc[cols]], ignore_index=True), raw, len(sms), len(loc)


def main():
    df, raw, n_sms, n_loc = load_data()
    tr, te = train_test_split(df, test_size=0.2, stratify=df.source + df.y.astype(str), random_state=42)
    model = SafeSMS().fit(tr.text.tolist(), tr.y.values, np.where(tr.source == "local", 5.0, 1.0))  # local samples weighted x5
    y = te.y.values
    pred = (model.proba(te.text.tolist()) >= 0.5).astype(int)
    loc = (te.source == "local").values
    rec, prec, f1 = recall_score(y, pred), precision_score(y, pred), f1_score(y, pred)
    lrec, lprec = recall_score(y[loc], pred[loc]), precision_score(y[loc], pred[loc], zero_division=0)
    flagged = [r for r in (model.analyze(t) for t in te.text) if r["verdict"] != "SAFE"]
    three = sum(len(r["reasons"]) == 3 for r in flagged)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.unlink(missing_ok=True)
    update_metrics(
        o1=dict(sms_raw=raw, sms_deduplicated=n_sms, local=n_loc, total=len(df), train=len(tr), test=len(te)),
        o2=dict(recall=round(rec, 4), precision=round(prec, 4), f1=round(f1, 4), threshold=0.5, n_test=len(te),
                scam_in_test=int(y.sum()), local_n=int(loc.sum()), local_recall=round(lrec, 4), local_precision=round(lprec, 4)),
        o3=dict(url_features=len(W)),
        o4_test=dict(flagged=len(flagged), with_3_reasons=three, pct=round(100 * three / max(1, len(flagged)), 1)))
    print(f"O1 data: {raw} SMS rows -> {n_sms} after de-duplication + {n_loc} local = {len(df)} (train {len(tr)}, test {len(te)})")
    print(classification_report(y, pred, target_names=["safe", "scam"], digits=3))
    print("Confusion matrix [[TN FP] [FN TP]]:", confusion_matrix(y, pred).tolist())
    print(f"O2 scam recall {rec:.1%}, precision {prec:.1%}, F1 {f1:.1%}")
    print(f"   local-only test subset (n={int(loc.sum())}): recall {lrec:.1%}, precision {lprec:.1%}")
    print(f"O3 URL risk features: {len(W)}")
    print(f"O4 flagged test messages showing 3 reasons: {three}/{len(flagged)}")


if __name__ == "__main__":
    main()
