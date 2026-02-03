import re

SUSPICIOUS_KEYWORDS = ["urgent", "verify", "account", "password", "login", "suspended", "immediately"]
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}(/|\b)")

def _safe_get(row, *candidates):
    for c in candidates:
        if c in row and isinstance(row[c], str):
            return row[c]
    return ""

def scan_row(subject: str, body: str) -> tuple[int, list]:
    reasons = []
    score = 0

    text = f"{subject}\n{body}".lower()

    # Keyword detection
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in text]
    if hits:
        score += 2
        reasons.append(f"Suspicious keywords: {', '.join(sorted(set(hits)))} (+2)")

        # Position weighting (subject)
        subj_hits = [k for k in SUSPICIOUS_KEYWORDS if k in subject.lower()]
        if subj_hits:
            score += 2
            reasons.append("Keyword in subject (+2)")

        # Early body (first 200 chars)
        early = body[:200].lower()
        early_hits = [k for k in SUSPICIOUS_KEYWORDS if k in early]
        if early_hits:
            score += 1
            reasons.append("Keyword early in body (+1)")

    # URL checks
    if "http://" in text or "https://" in text:
        score += 1
        reasons.append("Contains URL (+1)")

    if IP_URL_PATTERN.search(text):
        score += 3
        reasons.append("IP-based URL detected (+3)")

    return score, reasons


def scan_dataframe_for_phishing(df):
    # Standardize expected columns if missing
    df = df.copy()

    # Ensure columns exist (if not, create empty)
    for col in ["from", "subject", "body"]:
        if col not in df.columns:
            df[col] = ""

    risk_scores = []
    predicted = []
    reasons_all = []

    for _, row in df.iterrows():
        subject = str(row.get("subject", ""))
        body = str(row.get("body", ""))

        score, reasons = scan_row(subject, body)
        label = "phishing" if score >= 4 else "ham"  # demo threshold

        risk_scores.append(score)
        predicted.append(label)
        reasons_all.append("; ".join(reasons) if reasons else "No suspicious signals")

    df["risk_score"] = risk_scores
    df["predicted"] = predicted
    df["reasons"] = reasons_all

    summary = {
        "total": len(df),
        "phishing": sum(1 for x in predicted if x == "phishing"),
        "ham": sum(1 for x in predicted if x == "ham"),
        "threshold": 4,
    }

    return df, summary
