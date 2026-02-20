from flask import Flask, render_template, request
import re
import requests
from urllib.parse import urlparse
import os
import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# -----------------------------
# LOAD DATASET WITHOUT PANDAS
# -----------------------------
texts = []
labels = []

with open("dataset.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        texts.append(row["text"])
        labels.append(int(row["label"]))

# -----------------------------
# ML MODEL (SENTENCE LEVEL)
# -----------------------------
vectorizer = TfidfVectorizer(ngram_range=(1,2), max_features=5000)
X = vectorizer.fit_transform(texts)

model = LogisticRegression(max_iter=2000, class_weight="balanced")
model.fit(X, labels)

# -----------------------------
# OPTIONAL: SAVE MODEL FOR FUTURE USE
# -----------------------------
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

# -----------------------------
# DETECTION FUNCTION
# -----------------------------
def analyze_message(message):
    score = 0
    reasons = []

    # ML prediction
    X_new = vectorizer.transform([message])
    probability = model.predict_proba(X_new)[0][1]

    if probability > 0.80:
        score += 3
        reasons.append(f"AI High Risk: {round(probability*100,2)}% phishing")
    elif probability > 0.60:
        score += 2
        reasons.append(f"AI Moderate Risk: {round(probability*100,2)}%")
    elif probability > 0.40:
        score += 1
        reasons.append(f"AI Slight Suspicion: {round(probability*100,2)}%")

    # URL checks
    urls = re.findall(r'https?://\S+|www\.\S+', message)
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if parsed.scheme == "http":
            score += 1
            reasons.append("Insecure HTTP link")

        if len(domain.split(".")) > 3:
            score += 1
            reasons.append("Too many subdomains")

        if domain.replace(".", "").isdigit():
            score += 1
            reasons.append("IP address used instead of domain")

        try:
            response = requests.get(url, timeout=3)
            if response.status_code != 200:
                score += 1
                reasons.append("Website returned abnormal status")
        except:
            score += 1
            reasons.append("Website not reachable")

    return score, reasons, probability

# -----------------------------
# FLASK ROUTES
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []
    probability = None

    if request.method == "POST":
        message = request.form["message"]
        score, reasons, probability = analyze_message(message)

        if score >= 6:
            result = "🚨 HIGH RISK - Phishing Detected"
        elif score >= 3:
            result = "⚠ Medium Risk - Be Careful"
        else:
            result = "✅ Looks Safe"

    return render_template(
        "index.html",
        result=result,
        reasons=reasons,
        confidence=round(probability*100,2) if probability else None
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))