# SafeSMS-KE: Explainable Phishing & Mobile-Money Scam Detector

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-12%20passed-brightgreen.svg)]()
[![Latency P95](https://img.shields.io/badge/latency%20p95-7.7ms-orange.svg)]()

SafeSMS-KE is a privacy-first, ultra-low-latency machine learning detector designed to identify phishing, smishing, and mobile-money scams targeting Kenyan mobile phone users. It combines statistical natural language processing, English/Swahili/Sheng linguistic heuristics, 10-point URL security analysis, and transparent linear feature attribution.

All processing runs 100% locally. Zero message contents or telemetry are logged or sent to the cloud.

---

## Table of Contents
- [Key Features](#key-features)
- [System Architecture & Decision Flow](#system-architecture--decision-flow)
- [Benchmark Objectives & Performance (O1–O6)](#benchmark-objectives--performance-o1o6)
- [Installation](#installation)
- [How to Run](#how-to-run)
  - [1. Interactive Easy Demo (`demo.py`)](#1-interactive-easy-demo-demopy)
  - [2. Deep Diagnostic Debugger (`debug.py`)](#2-deep-diagnostic-debugger-debugpy)
  - [3. Interactive Web Demo & API Server (`app.py`)](#3-interactive-web-demo--api-server-apppy)
  - [4. Quick CLI Predictor (`predict.py`)](#4-quick-cli-predictor-predictpy)
  - [5. Model Training (`train.py`)](#5-model-training-trainpy)
  - [6. Red-Team Simulation (`redteam.py`)](#6-red-team-simulation-redteampy)
  - [7. Latency Benchmark (`bench.py`)](#7-latency-benchmark-benchpy)
  - [8. Test Suite (`pytest`)](#8-test-suite-pytest)
- [REST API Reference](#rest-api-reference)
- [Datasets](#datasets)
- [Limitations & Ethical Use](#limitations--ethical-use)

---

## Key Features

- **Kenyan Linguistic Context**: Accurately recognizes cues across Kenyan English, Swahili (*tuma, lipa, kimakosa, nirudishie, zawadi, mkopo*), and Sheng.
- **Dual-Engine Detection**:
  - **TF-IDF NLP Vectorizers**: Sublinear word n-grams (1–2 words) and character n-grams (2–5 chars) on entity-masked text.
  - **Dense Domain & URL Signals**: English/Swahili cue lexicon, genuine receipt structure parsing, capital letter shouting ratios, and 10 URL heuristic risk flags.
- **Transparent Explainability (Objective O4)**: Every flagged message returns the **top 3 actionable reasons** explaining why it was flagged, derived directly from positive linear model contributions.
- **Safety Escalation Policy**: If an SMS message has low textual suspicion but includes a high-risk link ($\text{risk} \ge 0.70$), the verdict is automatically escalated from `SAFE` to `SUSPICIOUS`.
- **Ultra-Fast Performance**: Under 5ms median inference latency; runs completely offline on minimal hardware.

---

## System Architecture & Decision Flow

```
Incoming SMS Text
       │
       ├──► Normalization & Masking
       │     (URL -> urltoken, Phone -> phonetoken, Money -> moneytoken, Code -> codetoken)
       │
       ├──► TF-IDF Vectorizers (Word 1-2 n-grams + Char 2-5 n-grams)
       │
       ├──► 10-Point URL Heuristic Analyzer
       │     (IP host, URL shorteners, bad TLDs, brand spoofing, http vs https, hyphens, subdomains)
       │
       ├──► Dense Domain Features (Kenyan Lexicon, Capitalization, Exclamations, Receipt Match)
       │
       ▼
Logistic Regression Classifier (Balanced class weights + 5x local weight)
       │
       ▼
   Scam Probability Score (0.0 to 1.0)
       │
       ├── Score >= 0.70                     ──► VERDICT: SCAM
       ├── Score 0.40 - 0.70                 ──► VERDICT: SUSPICIOUS
       └── Score < 0.40 AND Link Risk >= 0.70 ──► ESCALATED TO SUSPICIOUS
       └── Score < 0.40 AND Link Risk < 0.70  ──► VERDICT: SAFE
       │
       ▼
Linear Explainability Engine (Extracts Top 3 Positive Log-Odds Contributors)
```

---

## Benchmark Objectives & Performance (O1–O6)

The project validates against six core security and performance benchmarks recorded in `metrics.json`:

| Objective | Target / Requirement | Observed Result | Status |
| :--- | :--- | :--- | :--- |
| **O1: Dataset Pipeline** | Deduplication & synthetic Kenyan augmentation | 5,574 raw $\to$ 5,171 deduplicated SMS + 120 local = **5,291 total** | Verified |
| **O2: Detection Accuracy** | High recall & precision on scam class | **96.5% Recall, 96.5% Precision, 96.5% F1** (Local test: 91.7%) | Verified |
| **O3: URL Risk Engine** | $\ge 8$ link security heuristic flags | **10 binary heuristics** (IP, shorteners, bad TLDs, impersonation, etc.) | Verified |
| **O4: Explainability** | Top 3 reasons for every flagged message | **100% of flagged messages** show exactly 3 clear reasons | Verified |
| **O5: Latency** | P95 latency under 200 ms | **4.5 ms Median, 7.7 ms P95** over 1,000 live HTTP requests | Verified |
| **O6: Red-Team Validation** | $\ge 90\%$ detection on held-out simulated attacks | **100.0% Flagged (30/30), 0.0% False Alarms (0/15)** | Verified |

---

## Installation

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### Setup
```bash
# 1. Clone repository
git clone https://github.com/your-username/Blue-safesms.git
cd Blue-safesms

# 2. Create virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

---

## How to Run

### 1. Interactive Easy Demo (`demo.py`)
Run the interactive console demo with built-in scenario presets, live message tester, and system health checks:

```bash
# Launch interactive terminal demo
python demo.py
```

**Non-Interactive CLI Options:**
```bash
# Run all 8 preset scenarios and display a formatted benchmark summary table:
python demo.py --all-presets

# Run a specific scenario preset (1 to 8):
python demo.py --preset 3

# Test an ad-hoc custom message directly:
python demo.py "Ndugu yangu nimekutumia pesa kimakosa, nirudishie kwa 0712345678"
```

**Built-in Demo Presets:**
1. **Official M-PESA Receipt** (`SAFE`): Valid M-PESA transfer receipt format.
2. **Everyday Sheng/Swahili Chat** (`SAFE`): Informal communication between acquaintances.
3. **M-PESA "Reversal" Scam** (`SCAM`): Fake sent-by-mistake story begging for refund.
4. **KRA Tax Refund Phishing** (`SCAM`): Urgent fake refund approval with malicious `.xyz` link.
5. **SIM Swap / Account Threat** (`SCAM`): False disconnection alert demanding phone call or payment.
6. **Fake Job Recruitment Bait** (`SCAM`): High-paying vacancy asking for upfront interview booking fee.
7. **Suspicious Link Shortener** (`SCAM`/`SUSPICIOUS`): Obfuscated shortener link concealing destination.
8. **Lottery / Promotion Win** (`SCAM`): Unsolicited prize winner notification.

---

### 2. Deep Diagnostic Debugger (`debug.py`)
Inspect the model's inner mechanics for any text:
```bash
python debug.py "KRA tax refund of Ksh 5,000 approved. Claim at http://kra-portal.top/login"
```

**What the Debugger Outputs:**
- **Input Character Statistics**: Case ratio, word count, exclamation frequency.
- **Normalization & Token Masking**: Raw text transformed to tokenized representations.
- **Model Decision Flow**: Sigmoid probability, raw log-odds margin, and threshold rules.
- **Top 3 Reasons**: User-facing explainability bullets.
- **10-Point URL Heuristic Breakdown**: Detailed security flag audit for every detected link with individual heuristic weights.
- **Active Dense Features**: All triggered lexicon patterns and structural metrics.
- **Linear Feature Contributions**: Top positive weights driving the classification towards scam.

**Diagnostic Flags:**
```bash
# Output full diagnostic JSON:
python debug.py --json "Urgent: send Ksh 2000 to 0712345678"

# Read input from a text file:
python debug.py --file path/to/sample.txt
```

---

### 3. Interactive Web Demo & API Server (`app.py`)
Launch the web interface and REST API service:

```bash
python app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

**Web UI Features:**
- One-click Preset Example buttons for instant testing.
- Visual verdict cards with dynamic color coding (Green for Safe, Amber for Suspicious, Red for Scam).
- Real-time confidence meter.
- Detected links analysis table displaying risk scores and triggered security flags.
- Collapsible **Debug & Diagnostic Inspector** providing real-time feature breakdowns.
- Custom host/port flags: `python app.py --port 8080 --host 0.0.0.0`

---

### 4. Quick CLI Predictor (`predict.py`)
Quick command-line classification:

```bash
# Pass message as argument
python predict.py "KRA tax refund approved. Click http://kra-verify.top/claim"

# Output structured JSON
python predict.py --json "BC34DE56FG Confirmed. Ksh250.00 sent to Alice..."

# Interactive prompt (if called without arguments)
python predict.py
```

---

### 5. Model Training (`train.py`)
Retrain the model on the combined SMS Spam Collection + Kenyan synthetic dataset:

```bash
python train.py
```
This updates `model.joblib` and recalculates objectives O1–O4 in `metrics.json`.

---

### 6. Red-Team Simulation (`redteam.py`)
Evaluate against 45 held-out messages (30 simulated sophisticated Kenyan scams + 15 genuine controls):

```bash
python redteam.py
```
Outputs strict and overall scam detection percentages and verifies zero false alarms on controls.

---

### 7. Latency Benchmark (`bench.py`)
Executes 1,000 requests against the Flask prediction service to measure real-world performance:

```bash
python bench.py
```
Records median, P95, and maximum response latency in milliseconds to `metrics.json`.

---

### 8. Test Suite (`pytest`)
Run the 12 automated unit and integration tests:

```bash
python -m pytest -v
```

---

## REST API Reference

### 1. `POST /predict`
Analyzes a message and returns the verdict and top explanations.

**Request:**
```http
POST /predict HTTP/1.1
Content-Type: application/json

{
  "message": "SAFARICOM ALERT: Line suspended. Call 0722000123 immediately."
}
```

**Response (200 OK):**
```json
{
  "verdict": "SCAM",
  "score": 0.999,
  "reasons": [
    "threatens your account or line",
    "contains a phone number to call or pay",
    "claims to come from an official service"
  ],
  "links": []
}
```

---

### 2. `POST /debug`
Returns full diagnostic feature activations, raw margin, normalized text, and link heuristics.

**Request:**
```http
POST /debug HTTP/1.1
Content-Type: application/json

{
  "message": "Claim refund at http://kra-claim.xyz/verify"
}
```

**Response (200 OK):**
```json
{
  "text": "Claim refund at http://kra-claim.xyz/verify",
  "normalized": "claim refund at urltoken",
  "verdict": "SCAM",
  "score": 1.0,
  "raw_margin": 10.316,
  "escalated": false,
  "reasons": [
    "contains a risky link",
    "link is not HTTPS",
    "link uses a high-risk domain ending"
  ],
  "links": [
    {
      "url": "http://kra-claim.xyz/verify",
      "risk": 0.95,
      "flags": ["plain_http", "bad_tld", "brand_keyword"]
    }
  ],
  "dense_active": {
    "prize_bait": 0.33,
    "impersonation": 0.67,
    "link_count": 0.33,
    "link_risk": 0.95,
    "link_bad_tld": 1.0,
    "link_brand_keyword": 1.0,
    "link_plain_http": 1.0
  },
  "top_contributions": [
    { "feature": "dense:link_risk", "weight": 3.614 },
    { "feature": "dense:link_plain_http", "weight": 2.076 },
    { "feature": "dense:link_bad_tld", "weight": 1.931 }
  ]
}
```

---

### 3. `GET /metrics`
Returns current system metrics and benchmark records.

---

## Datasets

1. **`data/sms_spam.tsv`**: 5,574 messages from the SMS Spam Collection (Almeida et al., 2011). Automatically deduplicated during training to 5,171 messages.
2. **`data/local_samples.csv`**: 120 synthetic messages representing Kenyan mobile banking and communication styles (60 scams, 60 genuine), weighted 5x in training.
3. **`data/redteam.csv`**: 45 held-out messages (30 simulated scams, 15 genuine controls) never included in training, designed to stress-test the model against evasion tactics.

---

## Limitations & Ethical Use

- **Synthetic Training Data**: The local and red-team samples are synthetically modeled on real-world incident patterns. Always validate against production telemetry before deploying in automated blocking workflows.
- **Evolving Threats**: Scammers frequently adapt domains, obfuscation techniques, and phrasing. Maintain regular model re-training and keep brand/TLD heuristics up to date.
- **Privacy Assurance**: This software operates completely offline. No SMS content is transmitted or retained.
