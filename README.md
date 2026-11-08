# SafeSMS-KE (alpha test build)

ML detector for phishing and mobile-money scam messages (English, Swahili and Sheng cues).
Runs locally; nothing is stored. Built for Riara CAT 3 Information Security.

## Run
    pip install -r requirements.txt
    python train.py      # trains, prints O1-O4, writes model.joblib and metrics.json (seconds)
    python redteam.py    # O6: held-out simulated scams
    python bench.py      # O5: latency over 1,000 requests through the Flask app
    python -m pytest -q  # checks O3-O6
    python predict.py "message text"   # CLI verdict + top 3 reasons + link risk
    python app.py        # web page at http://127.0.0.1:5000  (POST /predict {"message": "..."})

## Data
- data/sms_spam.tsv: SMS Spam Collection (Almeida et al., 2011), GitHub mirror. train.py downloads it if missing.
- data/local_samples.csv: 120 synthetic Kenyan-style messages (60 scam, 60 genuine), weighted x5 in training.
- data/redteam.csv: 30 simulated scams + 15 genuine controls, never used in training.

## How it decides
TF-IDF word and character n-grams + an English/Swahili cue lexicon + 10 URL risk flags -> Logistic Regression.
Score >= 0.70 SCAM, 0.40-0.70 SUSPICIOUS, below 0.40 SAFE. A very risky link (risk >= 0.70) lifts SAFE to SUSPICIOUS.
Reasons are the top positive contributions of the linear model.

## Limits
Local and red-team messages are synthetic, so results are indicative, not production accuracy.
Validate with real reported scams before any real use.
