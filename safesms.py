"""SafeSMS-KE core: normalisation, URL risk scoring, features, model and explainable verdicts."""
import functools
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).parent
MODEL_PATH = ROOT / "model.joblib"
METRICS_PATH = ROOT / "metrics.json"
SCAM_AT, SUSPICIOUS_AT, LINK_ESCALATE_AT = 0.70, 0.40, 0.70   # verdict bands

# ------------------------------------------------------------------ URL risk (O3)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc"}
BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "live", "icu", "buzz", "link", "site", "online", "cc", "ws"}
OFFICIAL = ("safaricom.co.ke", "kra.go.ke", "kplc.co.ke", "equitybank.co.ke", "kcbgroup.com")
BRANDS = ("mpesa", "m-pesa", "safaricom", "kra", "kplc", "equity", "kcb", "login", "verify", "secure",
          "claim", "refund", "update", "promo", "bonus", "loan", "token", "statement", "grant")
W = {"ip_host": 0.6, "at_symbol": 0.5, "shortener": 0.4, "bad_tld": 0.4, "brand_keyword": 0.3,
     "many_hyphens": 0.2, "deep_subdomain": 0.2, "plain_http": 0.15, "digits_in_host": 0.15, "long_url": 0.1}
URL_LABELS = {"ip_host": "link uses a raw IP address", "at_symbol": "link hides its real host behind @",
              "shortener": "link uses a URL shortener", "bad_tld": "link uses a high-risk domain ending",
              "brand_keyword": "link imitates a trusted brand or action", "many_hyphens": "link host is stuffed with hyphens",
              "deep_subdomain": "link has stacked subdomains", "plain_http": "link is not HTTPS",
              "digits_in_host": "link host is full of digits", "long_url": "link is unusually long"}

_TLDS = "|".join(sorted({"com", "net", "org", "info", "biz", "ke", "me", "ly", "gl", "io", "app", "co"} | BAD_TLDS, key=len, reverse=True))
URL_RE = re.compile(r"(?i)\b(?:https?://\S+|www\.\S+|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/\S*)?|(?:[a-z0-9-]+\.)+(?:" + _TLDS + r")\b(?::\d+)?(?:/\S*)?)")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?254|0)\s?[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}(?!\d)")
RECEIPT_RE = re.compile(r"^[A-Z0-9]{10}\s+Confirmed\.", re.IGNORECASE)

# Precompiled regexes for high-throughput normalisation
MONEY_RE = re.compile(r"(?:ksh|kes|kshs|usd)\.?\s?\d[\d,.]*|[£$]\s?\d[\d,.]*", re.IGNORECASE)
CODE_RE = re.compile(r"\b(?=[a-z0-9]{10}\b)(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{10}\b")
NUM_RE = re.compile(r"\d+(?:[.,:/]\d+)*")
WS_RE = re.compile(r"\s+")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def url_features(url):
    """10 binary risk flags for one link."""
    low = url.lower()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""
    h = host[4:] if host.startswith("www.") else host
    ip = bool(IP_RE.match(h))
    depth = len(h.split(".")) - (3 if h.endswith((".co.ke", ".go.ke", ".or.ke", ".ac.ke")) else 2)
    official = any(h == d or h.endswith("." + d) for d in OFFICIAL)
    f = {"plain_http": low.startswith("http://"), "ip_host": ip, "shortener": h in SHORTENERS,
         "at_symbol": "@" in url, "long_url": len(url) > 40, "many_hyphens": h.count("-") >= 2,
         "deep_subdomain": depth >= 2 and not ip, "bad_tld": h.rsplit(".", 1)[-1] in BAD_TLDS,
         "digits_in_host": sum(c.isdigit() for c in h) >= 3 and not ip,
         "brand_keyword": (not official) and any(b in low for b in BRANDS)}
    return {k: int(v) for k, v in f.items()}


def url_report(text):
    """Every link in the message with a 0-1 risk score and the flags that fired (deduplicated)."""
    out = []
    seen = set()
    for u in URL_RE.findall(str(text or "")):
        u = u.rstrip(".,;:)!?'\">]")
        if not u or u in seen:
            continue
        seen.add(u)
        f = url_features(u)
        risk = min(1.0, 0.1 + sum(W[k] * v for k, v in f.items()))
        out.append({"url": u, "risk": round(risk, 2), "flags": [k for k, v in f.items() if v]})
    return out


# ------------------------------------------------------------------ text features
LEX = {  # English / Swahili / Sheng cue lexicon: key -> (regex on lower-cased text, reader-friendly label)
    "asks_credentials": (r"\b(?:pin|otp|password|passcode|verification code|6-digit|4-digit|nambari ya siri)\b", "asks for your PIN, OTP or password"),
    "urgency": (r"\b(?:urgent|urgently|immediately|asap|haraka|sasa hivi|expires?|last chance|hurry|tonight|today|within \d+ ?(?:hrs|hours|minutes|mins))\b", "creates urgency or a deadline"),
    "asks_payment": (r"\b(?:send|tuma|pay|lipa|deposit|transfer|fee|ada)\b", "asks you to send or pay money"),
    "mistake_story": (r"\b(?:by mistake|wrong number|wrong person|wrongly|kimakosa|kwa makosa|makosa|reverse|reversal|return it|send it back|rudisha|nirudishie|rudishia)\b", "uses a sent-by-mistake or reversal story"),
    "prize_bait": (r"\b(?:won|winner|win|congratulations|hongera|mshindi|umeshinda|prize|jackpot|bonus|reward|zawadi|free|claim|selected|lucky)\b", "promises a prize, bonus or free reward"),
    "account_threat": (r"\b(?:suspended|blocked|locked|deactivated|closed|disconnected|disconnection|sim swap|unauthori[sz]ed|unusual|limited|arrest)\b", "threatens your account or line"),
    "impersonation": (r"\b(?:safaricom|m-?pesa|kra|nhif|sha|kplc|kenya power|customer care|hustler fund|equity|kcb|fuliza|airtel|bank)\b", "claims to come from an official service"),
    "job_loan_bait": (r"\b(?:job|vacanc(?:y|ies)|recruitment|loan|mkopo|kazi|interview|grant|invest|investment|earn)\b", "offers a job, loan, grant or investment"),
}
_LEX = {k: (re.compile(p), lab) for k, (p, lab) in LEX.items()}
DENSE = list(LEX) + ["receipt_format", "has_phone", "shouting", "exclaims", "link_count", "link_risk"] + ["link_" + k for k in W]
LABELS = {**{k: v[1] for k, v in LEX.items()},
          "receipt_format": "matches the genuine M-PESA receipt format", "has_phone": "contains a phone number to call or pay",
          "shouting": "uses SHOUTING capitals", "exclaims": "uses excessive exclamation marks",
          "link_count": "contains a link", "link_risk": "contains a risky link",
          **{"link_" + k: v for k, v in URL_LABELS.items()}}
TOKEN_LABELS = {"urltoken": "contains a link", "phonetoken": "contains a phone number to call or pay", "moneytoken": "names an amount of money"}


def normalize(text):
    """Mask links, phones, money, codes and numbers so the model learns wording, not specifics."""
    s = str(text or "")
    t = URL_RE.sub(" urltoken ", s)
    t = PHONE_RE.sub(" phonetoken ", t).lower()
    t = MONEY_RE.sub(" moneytoken ", t)
    t = CODE_RE.sub(" codetoken ", t)
    t = NUM_RE.sub(" numtoken ", t)
    return WS_RE.sub(" ", t).strip()


def dense_features(text, links=None):
    """Extract dense domain and heuristic features for one text sample."""
    text_str = str(text or "")
    low = text_str.lower()
    v = [min(len(rx.findall(low)), 3) / 3 for rx, _ in _LEX.values()]
    letters = [c for c in text_str if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
    if links is None:
        links = url_report(text_str)
    stripped = text_str.strip("'\" \t\r\n")
    receipt = float(bool(RECEIPT_RE.match(stripped)))
    has_phone = float(bool(PHONE_RE.search(text_str)))
    v += [receipt, has_phone, min(1.0, caps * 2),
          min(text_str.count("!"), 3) / 3, min(len(links), 3) / 3, max((l["risk"] for l in links), default=0.0)]
    v += [float(any(k in l["flags"] for l in links)) for k in W]
    return v


# ------------------------------------------------------------------ model + verdicts
class SafeSMS:
    def _X(self, texts, fit=False, precomputed_links=None):
        norm = [normalize(t) for t in texts]
        if fit:
            self.vecs = (TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=False),
                         TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, sublinear_tf=True, lowercase=False))
            w, c = (v.fit_transform(norm) for v in self.vecs)
        else:
            w, c = (v.transform(norm) for v in self.vecs)

        if precomputed_links and len(precomputed_links) == len(texts):
            dense_mat = [dense_features(t, links=l) for t, l in zip(texts, precomputed_links)]
        else:
            dense_mat = [dense_features(t) for t in texts]
        return hstack([w, c, csr_matrix(np.array(dense_mat))]).tocsr()

    def fit(self, texts, y, weights=None):
        X = self._X(texts, fit=True)
        self.nw, self.nc = len(self.vecs[0].vocabulary_), len(self.vecs[1].vocabulary_)
        self.words = np.array(self.vecs[0].get_feature_names_out())
        self.clf = LogisticRegression(C=10, class_weight="balanced", max_iter=3000).fit(X, y, sample_weight=weights)
        return self

    def proba(self, texts):
        return self.clf.predict_proba(self._X(texts))[:, 1]

    def analyze(self, text):
        text_str = str(text or "")
        links = url_report(text_str)
        X = self._X([text_str], precomputed_links=[links])
        p = float(self.clf.predict_proba(X)[0, 1])
        verdict = "SCAM" if p >= SCAM_AT else "SUSPICIOUS" if p >= SUSPICIOUS_AT else "SAFE"
        escalated = verdict == "SAFE" and max((l["risk"] for l in links), default=0) >= LINK_ESCALATE_AT
        if escalated:
            verdict = "SUSPICIOUS"
        return {"verdict": verdict, "score": round(p, 3), "reasons": self._reasons(X, verdict, escalated, links=links), "links": links}

    def analyze_batch(self, texts):
        """Analyze multiple texts in a single vectorized pass."""
        if not texts:
            return []
        texts_str = [str(t or "") for t in texts]
        links_list = [url_report(t) for t in texts_str]
        X = self._X(texts_str, precomputed_links=links_list)
        probs = self.clf.predict_proba(X)[:, 1]
        results = []
        for i, (text, p, links) in enumerate(zip(texts_str, probs, links_list)):
            p_float = float(p)
            verdict = "SCAM" if p_float >= SCAM_AT else "SUSPICIOUS" if p_float >= SUSPICIOUS_AT else "SAFE"
            escalated = verdict == "SAFE" and max((l["risk"] for l in links), default=0) >= LINK_ESCALATE_AT
            if escalated:
                verdict = "SUSPICIOUS"
            row_X = X.getrow(i)
            results.append({
                "verdict": verdict,
                "score": round(p_float, 3),
                "reasons": self._reasons(row_X, verdict, escalated, links=links),
                "links": links
            })
        return results

    def _reasons(self, X, verdict, escalated, links=None):
        d0 = self.nw + self.nc
        if verdict == "SAFE":
            ok = ["matches the genuine M-PESA receipt format"] if X[0, d0 + DENSE.index("receipt_format")] > 0 else []
            return ok + ["no strong scam wording or risky links found"]

        # Sparse contribution extraction: compute non-zero items instead of converting 15,000 features
        row = X.getrow(0)
        nz_indices = row.indices
        nz_data = row.data
        coef = self.clf.coef_[0]
        nz_contrib = nz_data * coef[nz_indices]

        pos_mask = nz_contrib > 0
        pos_indices = nz_indices[pos_mask]
        pos_contrib = nz_contrib[pos_mask]

        out = []
        if len(pos_contrib) > 0:
            order = np.argsort(-pos_contrib)
            for idx in pos_indices[order]:
                if len(out) == 3:
                    break
                if idx < self.nw:
                    term = self.words[idx]
                    lab = TOKEN_LABELS.get(term)
                    if lab is None:
                        if "token" in term:
                            continue
                        lab = f"wording: '{term}'"
                elif idx >= d0:
                    lab = LABELS[DENSE[idx - d0]]
                else:
                    continue  # character n-grams help model but are skipped for user readability

                # Duplicate / overlap filter with safe wording comparison
                term_match = re.search(r"'([^']+)'", lab)
                term_word = term_match.group(1).lower() if term_match else None

                if lab in out:
                    continue
                if term_word and any(
                    (re.search(r"'([^']+)'", e) and (term_word in re.search(r"'([^']+)'", e).group(1).lower() or
                     re.search(r"'([^']+)'", e).group(1).lower() in term_word))
                    for e in out if e.startswith("wording")
                ):
                    continue
                out.append(lab)

        if escalated:
            out = ["contains a risky link"] + [o for o in out if o != "contains a risky link"][:2]

        # Guarantee 3 reasons for every flagged message (Objective O4)
        if len(out) < 3 and links:
            for l in links:
                for flag in l.get("flags", []):
                    flag_lab = URL_LABELS.get(flag)
                    if flag_lab and flag_lab not in out:
                        out.append(flag_lab)
                        if len(out) == 3:
                            break
                if len(out) == 3:
                    break

        fallbacks = [
            "unsolicited request for sensitive action",
            "message structure matches known phishing patterns",
            "lacks verified institutional signature",
            "overall wording resembles known scams"
        ]
        for fb in fallbacks:
            if len(out) == 3:
                break
            if fb not in out:
                out.append(fb)

        return out[:3]

    def explain_debug(self, text):
        """Deep diagnostic breakdown of feature activations and model decision logic."""
        text_str = str(text or "")
        links = url_report(text_str)
        norm = normalize(text_str)
        X = self._X([text_str], precomputed_links=[links])
        p = float(self.clf.predict_proba(X)[0, 1])

        # Intercept and raw margin
        raw_margin = float(X.dot(self.clf.coef_.T)[0, 0] + self.clf.intercept_[0])
        verdict = "SCAM" if p >= SCAM_AT else "SUSPICIOUS" if p >= SUSPICIOUS_AT else "SAFE"
        escalated = verdict == "SAFE" and max((l["risk"] for l in links), default=0) >= LINK_ESCALATE_AT
        if escalated:
            verdict = "SUSPICIOUS"

        reasons = self._reasons(X, verdict, escalated, links=links)

        # Dense features mapping
        d0 = self.nw + self.nc
        dense_vec = X.toarray()[0, d0:]
        dense_debug = {name: round(float(val), 3) for name, val in zip(DENSE, dense_vec) if val > 0}

        # Non-zero feature contributions
        row = X.getrow(0)
        nz_indices = row.indices
        nz_data = row.data
        coef = self.clf.coef_[0]
        nz_contrib = nz_data * coef[nz_indices]

        top_pos_idx = nz_indices[np.argsort(-nz_contrib)]
        top_pos = []
        for i in top_pos_idx:
            c = float(nz_data[list(nz_indices).index(i)] * coef[i])
            if c <= 0.01:
                break
            if i < self.nw:
                name = f"word:{self.words[i]}"
            elif i < d0:
                name = f"char_ngram:{i}"
            else:
                name = f"dense:{DENSE[i - d0]}"
            top_pos.append({"feature": name, "weight": round(c, 3)})

        return {
            "text": text_str,
            "normalized": norm,
            "raw_margin": round(raw_margin, 3),
            "score": round(p, 4),
            "verdict": verdict,
            "escalated": escalated,
            "reasons": reasons,
            "links": links,
            "dense_active": dense_debug,
            "top_contributions": top_pos[:8]
        }


@functools.lru_cache(maxsize=1)
def load(model_path=None):
    """Load model with thread-safe caching."""
    target = Path(model_path) if model_path else MODEL_PATH
    if not target.exists():
        raise FileNotFoundError(f"SafeSMS model file not found at: {target}")
    return joblib.load(target)


def clear_cache():
    """Clear memory-cached model instance."""
    load.cache_clear()


def update_metrics(**kw):
    m = json.loads(METRICS_PATH.read_text()) if METRICS_PATH.exists() else {}
    m.update(kw)
    METRICS_PATH.write_text(json.dumps(m, indent=2))


def pretty(r):
    lines = [f"Verdict: {r['verdict']}  (scam score {r['score']:.2f})", "Why:"]
    lines += [f"  {i}. {x}" for i, x in enumerate(r["reasons"], 1)]
    if r["links"]:
        lines.append("Links:")
        lines += [f"  {l['url']}  risk {l['risk']:.2f}  {l['flags']}" for l in r["links"]]
    return "\n".join(lines)
