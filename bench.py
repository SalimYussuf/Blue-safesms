"""Latency over 1,000 requests through the Flask app (O5).  Usage: python bench.py"""
import statistics
import time

import pandas as pd

from app import app
from safesms import ROOT, update_metrics

texts = pd.read_csv(ROOT / "data" / "redteam.csv").text.tolist()
client = app.test_client()
ms = []
for i in range(1000):
    t0 = time.perf_counter()
    r = client.post("/predict", json={"message": texts[i % len(texts)]})
    ms.append((time.perf_counter() - t0) * 1000)
    assert r.status_code == 200
ms.sort()
res = dict(requests=1000, median_ms=round(statistics.median(ms), 1), p95_ms=round(ms[949], 1), max_ms=round(ms[-1], 1))
print("O5 latency:", res)
update_metrics(o5=res)
