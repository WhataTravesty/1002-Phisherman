import random
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report


def generate_mock_results(n=200):
    """
    Generates synthetic evaluation results for dashboard development.
    """
    data = []

    for _ in range(n):
        actual = random.choices(
            ["ham", "phishing"], weights=[0.65, 0.35]
        )[0]

        keyword = random.random() < (0.7 if actual == "phishing" else 0.15)
        url = random.random() < (0.8 if actual == "phishing" else 0.2)
        edit_distance = random.random() < (0.4 if actual == "phishing" else 0.05)
        whitelist = random.random() < (0.1 if actual == "phishing" else 0.9)

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
            "risk_score": risk_score,
            "keyword": int(keyword),
            "url": int(url),
            "edit_distance": int(edit_distance),
            "whitelist": int(whitelist)
        })

    return pd.DataFrame(data)


def build_dashboard_data():
    """
    Computes all statistics required by the dashboard template.
    """
    df = generate_mock_results()

    total = len(df)
    ham = (df["actual"] == "ham").sum()
    phishing = (df["actual"] == "phishing").sum()
    accuracy = (df["actual"] == df["predicted"]).mean()

    cm = confusion_matrix(
        df["actual"], df["predicted"], labels=["ham", "phishing"]
    )

    report = classification_report(
        df["actual"], df["predicted"], output_dict=True
    )

    rule_stats = {
        "Keyword Detection": df["keyword"].mean() * 100,
        "Suspicious URL": df["url"].mean() * 100,
        "Edit Distance": df["edit_distance"].mean() * 100,
        "Whitelist Failure": (1 - df["whitelist"].mean()) * 100
    }

    return {
        "total": total,
        "ham": ham,
        "phishing": phishing,
        "accuracy": round(accuracy * 100, 2),
        "cm": cm.tolist(),
        "rule_stats": rule_stats,
        "report": report
    }
