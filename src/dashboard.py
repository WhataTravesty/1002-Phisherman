import random
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report


def generate_mock_results(n: int = 200) -> pd.DataFrame:
    
    #Generate synthetic evaluation results for dashboard development.
    
    data = []

    for _ in range(n):
        actual = random.choices(["ham", "phishing"], weights=[0.65, 0.35])[0]

        # Rule triggers (phishing more likely to trigger)
        keyword = random.random() < (0.7 if actual == "phishing" else 0.15)
        url = random.random() < (0.8 if actual == "phishing" else 0.2)
        edit_distance = random.random() < (0.4 if actual == "phishing" else 0.05)
        whitelist = random.random() < (0.1 if actual == "phishing" else 0.9)

        # Placeholder scoring (ok for dashboard demo; replace later)
        risk_score = (
            keyword * 2 +
            url * 3 +
            edit_distance * 2 +
            (not whitelist) * 2
        )

        predicted = "phishing" if risk_score >= 5 else "ham"

        data.append({
            "actual": actual,
            "predicted": predicted,
            "risk_score": int(risk_score),
            "keyword": int(keyword),
            "url": int(url),
            "edit_distance": int(edit_distance),
            "whitelist": int(whitelist),
        })

    return pd.DataFrame(data)


def build_dashboard_data(n: int = 200) -> dict:
    """Compute all statistics required by the dashboard template."""
    df = generate_mock_results(n=n)

    total = len(df)
    ham = int((df["actual"] == "ham").sum())
    phishing = int((df["actual"] == "phishing").sum())
    accuracy = float((df["actual"] == df["predicted"]).mean())

    cm = confusion_matrix(df["actual"], df["predicted"], labels=["ham", "phishing"])
    report = classification_report(df["actual"], df["predicted"], output_dict=True)

    rule_stats = {
        "Keyword Detection": float(df["keyword"].mean() * 100),
        "Suspicious URL": float(df["url"].mean() * 100),
        "Edit Distance": float(df["edit_distance"].mean() * 100),
        "Whitelist Failure": float((1 - df["whitelist"].mean()) * 100),
    }

    return {
        "total": total,
        "ham": ham,
        "phishing": phishing,
        "accuracy": round(accuracy * 100, 2),
        "cm": cm.tolist(),
        "rule_stats": rule_stats,
        "report": report,
        # Optional fields the Bootstrap demo dashboard can display
        "dataset_name": "Mock/Dev",
        "last_updated": "Just now",
        "threshold": "N/A",
    }