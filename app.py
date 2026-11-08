"""SafeSMS-KE Web Application & REST API.

Provides an interactive demo UI, diagnostic inspector, and JSON endpoints.
Usage:
    python app.py
    python app.py --port 5000 --host 127.0.0.1
"""
import argparse
import json
import os
from flask import Flask, jsonify, request

from safesms import METRICS_PATH, ROOT, load

app = Flask(__name__)
model = load()

PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeSMS-KE | Kenyan Phishing & Scam Detector</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --safe: #10b981;
      --safe-bg: rgba(16, 185, 129, 0.12);
      --suspicious: #f59e0b;
      --suspicious-bg: rgba(245, 158, 11, 0.12);
      --scam: #ef4444;
      --scam-bg: rgba(239, 68, 68, 0.12);
      --primary: #3b82f6;
      --primary-hover: #2563eb;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 1.5rem 1rem;
    }
    .container { max-width: 820px; margin: 0 auto; }
    header { margin-bottom: 2rem; text-align: center; }
    h1 { font-size: 2rem; font-weight: 700; color: #fff; margin-bottom: 0.4rem; letter-spacing: -0.5px; }
    .badge-sub { display: inline-block; background: #1e3a8a; color: #93c5fd; font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.6rem; border-radius: 9999px; margin-bottom: 0.5rem; text-transform: uppercase; }
    p.subtitle { color: var(--text-muted); font-size: 0.95rem; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .presets-label { font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 0.6rem; font-weight: 600; }
    .preset-pills { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1.25rem; }
    .preset-pill {
      background: #334155;
      color: #e2e8f0;
      border: 1px solid transparent;
      padding: 0.4rem 0.8rem;
      border-radius: 20px;
      font-size: 0.82rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .preset-pill:hover { background: #475569; color: #fff; }
    textarea {
      width: 100%;
      height: 7.5rem;
      background: #0f172a;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 0.8rem;
      color: #fff;
      font-size: 0.95rem;
      font-family: inherit;
      resize: vertical;
      outline: none;
      transition: border-color 0.2s;
    }
    textarea:focus { border-color: var(--primary); }
    .actions { display: flex; gap: 0.75rem; margin-top: 1rem; align-items: center; }
    button.btn-primary {
      background: var(--primary);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 0.65rem 1.4rem;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button.btn-primary:hover { background: var(--primary-hover); }
    button.btn-secondary {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 0.65rem 1rem;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    button.btn-secondary:hover { color: #fff; border-color: #64748b; }
    .result-box { display: none; margin-top: 1.5rem; border-radius: 10px; padding: 1.25rem; border: 1px solid transparent; }
    .result-box.SCAM { background: var(--scam-bg); border-color: rgba(239, 68, 68, 0.35); }
    .result-box.SUSPICIOUS { background: var(--suspicious-bg); border-color: rgba(245, 158, 11, 0.35); }
    .result-box.SAFE { background: var(--safe-bg); border-color: rgba(16, 185, 129, 0.35); }
    .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem; }
    .verdict-tag { font-size: 1.3rem; font-weight: 800; letter-spacing: 0.5px; }
    .SCAM .verdict-tag { color: var(--scam); }
    .SUSPICIOUS .verdict-tag { color: var(--suspicious); }
    .SAFE .verdict-tag { color: var(--safe); }
    .score-badge { font-size: 0.9rem; font-weight: 600; color: var(--text-muted); }
    .meter { height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin-bottom: 1rem; }
    .meter-bar { height: 100%; border-radius: 4px; transition: width 0.3s ease; }
    .SCAM .meter-bar { background: var(--scam); }
    .SUSPICIOUS .meter-bar { background: var(--suspicious); }
    .SAFE .meter-bar { background: var(--safe); }
    .reasons-title { font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 0.4rem; }
    ul.reasons-list { list-style: none; margin-bottom: 1rem; }
    ul.reasons-list li { padding: 0.25rem 0; font-size: 0.95rem; }
    ul.reasons-list li::before { content: "• "; font-weight: bold; }
    .SCAM ul.reasons-list li::before { color: var(--scam); }
    .SUSPICIOUS ul.reasons-list li::before { color: var(--suspicious); }
    .SAFE ul.reasons-list li::before { color: var(--safe); }
    .links-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.85rem; }
    .links-table th, .links-table td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.08); }
    .links-table th { color: var(--text-muted); font-weight: 600; }
    .debug-toggle { margin-top: 1rem; font-size: 0.85rem; color: #60a5fa; cursor: pointer; display: inline-block; user-select: none; }
    .debug-panel { display: none; margin-top: 0.8rem; background: #090d16; border: 1px solid #1e293b; border-radius: 6px; padding: 0.8rem; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; color: #cbd5e1; max-height: 250px; overflow-y: auto; }
    footer { text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-sub">SafeSMS-KE Security Engine</div>
      <h1>Phishing & Mobile-Money Scam Detector</h1>
      <p class="subtitle">Real-time local analysis with Kenyan English, Swahili, and Sheng cue detection. Zero data stored.</p>
    </header>

    <div class="card">
      <div class="presets-label">Quick Test Scenarios (Click to test):</div>
      <div class="preset-pills">
        <button class="preset-pill" onclick="loadPreset(0)">Genuine M-PESA</button>
        <button class="preset-pill" onclick="loadPreset(1)">Swahili Reversal Scam</button>
        <button class="preset-pill" onclick="loadPreset(2)">KRA Phishing Link</button>
        <button class="preset-pill" onclick="loadPreset(3)">SIM Swap Threat</button>
        <button class="preset-pill" onclick="loadPreset(4)">Fake Job Vacancy</button>
        <button class="preset-pill" onclick="loadPreset(5)">Casual Chat</button>
      </div>

      <textarea id="msg" placeholder="Paste an SMS message here to analyze..."></textarea>

      <div class="actions">
        <button class="btn-primary" onclick="checkMessage()">Check Message</button>
        <button class="btn-secondary" onclick="clearInput()">Clear</button>
      </div>

      <div id="resultBox" class="result-box">
        <div class="result-header">
          <div id="verdictTag" class="verdict-tag"></div>
          <div id="scoreBadge" class="score-badge"></div>
        </div>
        <div class="meter"><div id="meterBar" class="meter-bar"></div></div>
        
        <div class="reasons-title">Explainability Reasons:</div>
        <ul id="reasonsList" class="reasons-list"></ul>

        <div id="linksContainer" style="display:none;">
          <div class="reasons-title">Extracted Link Heuristics:</div>
          <table class="links-table">
            <thead><tr><th>URL</th><th>Risk Score</th><th>Triggered Flags</th></tr></thead>
            <tbody id="linksBody"></tbody>
          </table>
        </div>

        <div class="debug-toggle" onclick="toggleDebug()">[+] Toggle Debug & Diagnostic Inspector</div>
        <pre id="debugPanel" class="debug-panel"></pre>
      </div>
    </div>

    <footer>
      SafeSMS-KE Model Engine &bull; Riara University CAT 3 Information Security &bull; Powered by Scikit-Learn
    </footer>
  </div>

  <script>
    const PRESETS = [
      "BC34DE56FG Confirmed. Ksh250.00 sent to ALICE MUTUA 0700 000 205 on 6/11/26 at 3:15 PM. New M-PESA balance is Ksh780.00. Transaction cost, Ksh5.00.",
      "Ndugu yangu nimekutumia Ksh 3,500 kimakosa kwa nambari yako. Tafadhali nirudishie kwa 0712345678, ni za mgonjwa hospitali haraka.",
      "KRA NOTICE: Your tax refund of KES 14,250 has been approved. Claim your refund immediately at http://kra-portal-claim.xyz/refund before expiration tonight.",
      "SAFARICOM ALERT: Your line has been flagged for unverified SIM swap and will be blocked within 2 hours. Call customer care now on 0722000123 or pay unblock fee.",
      "URGENT JOB VACANCY: Kenya Airways recruitment ongoing. Salary Ksh 85,000. Send registration fee of Ksh 1,200 to 0719876543 to confirm your interview slot today.",
      "Niko njiani kuelekea tao, tukutane archive saa kumi. Nitakununulia lunch leo usijali."
    ];

    function loadPreset(idx) {
      document.getElementById('msg').value = PRESETS[idx];
      checkMessage();
    }

    function clearInput() {
      document.getElementById('msg').value = '';
      document.getElementById('resultBox').style.display = 'none';
    }

    function toggleDebug() {
      const p = document.getElementById('debugPanel');
      p.style.display = (p.style.display === 'block') ? 'none' : 'block';
    }

    async function checkMessage() {
      const text = document.getElementById('msg').value.trim();
      const box = document.getElementById('resultBox');
      if (!text) {
        alert("Please enter or select a message to check.");
        return;
      }

      try {
        const [predRes, debugRes] = await Promise.all([
          fetch('/predict', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: text})
          }),
          fetch('/debug', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: text})
          })
        ]);

        const data = await predRes.json();
        const debugData = await debugRes.json();

        if (data.error) {
          alert("Error: " + data.error);
          return;
        }

        box.className = 'result-box ' + data.verdict;
        box.style.display = 'block';

        document.getElementById('verdictTag').textContent = data.verdict;
        document.getElementById('scoreBadge').textContent = 'Scam Score: ' + (data.score * 100).toFixed(1) + '%';
        document.getElementById('meterBar').style.width = Math.min(100, Math.max(5, data.score * 100)) + '%';

        const reasonsList = document.getElementById('reasonsList');
        reasonsList.innerHTML = '';
        data.reasons.forEach(r => {
          const li = document.createElement('li');
          li.textContent = r;
          reasonsList.appendChild(li);
        });

        const linksContainer = document.getElementById('linksContainer');
        const linksBody = document.getElementById('linksBody');
        linksBody.innerHTML = '';
        if (data.links && data.links.length > 0) {
          linksContainer.style.display = 'block';
          data.links.forEach(l => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td><code>' + l.url + '</code></td><td>' + (l.risk * 100).toFixed(0) + '%</td><td>' + (l.flags.join(', ') || 'none') + '</td>';
            linksBody.appendChild(tr);
          });
        } else {
          linksContainer.style.display = 'none';
        }

        document.getElementById('debugPanel').textContent = JSON.stringify(debugData, null, 2);
      } catch (err) {
        alert("Request failed: " + err);
      }
    }
  </script>
</body>
</html>
"""


@app.get("/")
def index():
    return PAGE_HTML


@app.post("/predict")
def predict():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        msg = data.get("message", "")
    else:
        msg = request.form.get("message", "")

    if not isinstance(msg, str) or not msg.strip():
        return jsonify(error="message required"), 400

    return jsonify(model.analyze(msg))


@app.post("/debug")
def debug_endpoint():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        msg = data.get("message", "")
    else:
        msg = request.form.get("message", "")

    if not isinstance(msg, str) or not msg.strip():
        return jsonify(error="message required"), 400

    return jsonify(model.explain_debug(msg))


@app.get("/metrics")
def get_metrics():
    if METRICS_PATH.exists():
        try:
            return jsonify(json.loads(METRICS_PATH.read_text()))
        except Exception as e:
            return jsonify(error=str(e)), 500
    return jsonify(error="metrics not generated yet"), 404


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SafeSMS-KE Web Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)), help="Port to listen on")
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "127.0.0.1"), help="Host interface")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
