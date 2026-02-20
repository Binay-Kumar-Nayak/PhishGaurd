from flask import Flask, render_template, request
import re
import requests
from urllib.parse import urlparse
from collections import Counter

# ML Imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# -----------------------------
# Expanded Training Data
# -----------------------------
texts = [

# 🔴 PHISHING (1)
"Verify your bank account immediately",
"Click this link to win prize",
"Urgent update your account now",
"Your account has been suspended verify now",
"Unauthorized login attempt detected confirm immediately",
"Reset your password to avoid account lock",
"Security alert update banking information",
"Confirm your identity to restore access",
"Your payment was declined update details now",
"Final warning respond immediately",
"Your account will be permanently closed",
"Failure to act will result in suspension",
"Legal notice verify your account now",
"Immediate action required confirm details",
"Congratulations you won a free iPhone",
"Claim your free gift card now",
"You are selected as a lucky winner",
"Get free diamonds click here",
"Exclusive reward waiting claim now",
"Sign in to resolve account issue",
"Login immediately to prevent deactivation",
"Verify your email password now",
"Update login credentials immediately",
"Your package delivery is pending confirm address",
"Shipment on hold update shipping details",
"Track parcel by confirming payment",
"Tax refund available submit bank details",
"Government payment waiting verify identity",
"IRS notice unpaid taxes respond now",
"Double your bitcoin investment today",
"Limited crypto investment opportunity",
"Payment failed update billing information",
"Confirm credit card to continue service",
"Invoice overdue click to pay now",
"Email access restricted verify immediately",
"Technical issue detected confirm account",
"Suspicious activity verify your profile",
"Confirm login attempt from new device",
"Click here to unlock reward",
"Important notification verify now",

# 🟢 SAFE (0)
"Meeting tomorrow at 10am",
"Your salary has been credited",
"Project discussion at 5pm",
"Lets schedule a call for Monday",
"Please review the attached report",
"The presentation slides are ready",
"Team lunch scheduled for Friday",
"Budget approval meeting next week",
"Client feedback has been received",
"Quarterly performance review scheduled",
"Submit your timesheet by Friday",
"The server maintenance is complete",
"Reminder about tomorrow workshop",
"HR policy document updated",
"Training session starts at 2pm",
"Conference room has been booked",
"New employee onboarding session",
"Monthly report has been shared",
"Please check the shared folder",
"The invoice has been processed",
"Marketing campaign results attached",
"Your leave request is approved",
"Office will remain closed on Monday",
"System update completed successfully",
"Team outing planned this weekend",
"Project deadline extended to next week",
"Please confirm your attendance",
"Your reimbursement has been processed",
"Internal audit scheduled next month",
"Weekly sync meeting link shared",
"Please confirm receipt of this document",
"Account summary has been generated",
"Let me know if you need any details",
"We noticed a discrepancy in the report",
"Kindly review the attached file",
"Please confirm receipt of the updated project document",
"The account summary for this quarter has been generated successfully",
"Kindly review the meeting notes and share your feedback",
"The finance team processed the payment yesterday",
"Let me know if you need any additional details regarding the report"
]

labels = [

# 40 phishing
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,

# 30 safe
0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
]

# -----------------------------
# ML Model Setup
# -----------------------------
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

model = LogisticRegression()
model.fit(X, labels)

# -----------------------------
# Detection Function
# -----------------------------
def analyze_message(message):
    score = 0
    reasons = []

    message_lower = message.lower()

    # 1️⃣ Keyword Check
    suspicious_words = ["urgent", "verify", "login", "update", "bank", "password"]
    for word in suspicious_words:
        if word in message_lower:
            score += 1
            reasons.append(f"Suspicious keyword detected: {word}")

    # 2️⃣ Frequency Analysis
    word_count = Counter(message_lower.split())
    if word_count.get("urgent", 0) >= 2:
        score += 1
        reasons.append("Repeated urgent words detected")

    # 3️⃣ URL Extraction
    urls = re.findall(r'https?://\S+|www\.\S+', message)
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if parsed.scheme == "http":
            score += 1
            reasons.append("URL uses insecure HTTP")

        if len(domain.split(".")) > 3:
            score += 1
            reasons.append("Too many subdomains detected")

        if domain.replace(".", "").isdigit():
            score += 1
            reasons.append("IP address used instead of domain")

        try:
            response = requests.get(url, timeout=3)
            if response.status_code != 200:
                score += 1
                reasons.append("Website returned suspicious status code")
        except:
            score += 1
            reasons.append("Website not reachable")

    # 4️⃣ ML Prediction — Adjusted Weight
    X_new = vectorizer.transform([message])
    prediction = model.predict(X_new)[0]

    # Only boost score if there are other suspicious indicators
    if prediction == 1 and score > 0:
        score += 1
        reasons.append("AI model classified as phishing")

    return score, reasons

# -----------------------------
# Flask Routes
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []

    if request.method == "POST":
        message = request.form["message"]
        score, reasons = analyze_message(message)

        # Adjusted thresholds
        if score >= 5:
            result = "⚠ HIGH RISK - Phishing Detected"
        elif score >= 3:
            result = "⚠ Medium Risk - Be Careful"
        else:
            result = "✅ Looks Safe"

    return render_template("index.html", result=result, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)
