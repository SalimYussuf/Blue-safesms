"""Bare Flask page + REST endpoint.  Usage: python app.py  then open http://127.0.0.1:5000"""
from flask import Flask, jsonify, request

from safesms import load

app = Flask(__name__)
model = load()
PAGE = """<!doctype html><meta charset=utf-8><title>SafeSMS-KE</title>
<style>body{font-family:system-ui;max-width:640px;margin:2rem auto;padding:0 1rem}textarea{width:100%;height:8rem}
.SCAM{color:#d64545}.SUSPICIOUS{color:#b07a00}.SAFE{color:#1f9d55}pre{white-space:pre-wrap;font-size:1rem}</style>
<h2>SafeSMS-KE</h2><p>Paste a message to check it. Processing is local; nothing is stored.</p>
<textarea id=m></textarea><br><button onclick=check()>Check message</button><pre id=out></pre>
<script>async function check(){const r=await fetch('/predict',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:m.value})});
const d=await r.json();if(d.error){out.textContent=d.error;return}out.className=d.verdict;
out.textContent=d.verdict+' (scam score '+d.score+')\\n'+d.reasons.map((x,i)=>(i+1)+'. '+x).join('\\n')+'\\n'+d.links.map(l=>l.url+'  risk '+l.risk).join('\\n')}</script>"""


@app.get("/")
def index():
    return PAGE


@app.post("/predict")
def predict():
    msg = (request.get_json(silent=True) or {}).get("message", "")
    if not msg.strip():
        return jsonify(error="message required"), 400
    return jsonify(model.analyze(msg))


if __name__ == "__main__":
    app.run(debug=False)
