import json
import pandas as pd


def _safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


def _safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def build_dashboard_data(df: pd.DataFrame) -> dict:
    out = df.copy()

    # Normalize expected columns if missing
    for col in ["predicted", "risk_score_pct", "reasons", "reasons_list", "label", "subject_clean", "sender_email", "sender_domain"]:
        if col not in out.columns:
            out[col] = ""

    total = len(out)
    phishing = int((out["predicted"] == "phishing").sum())
    ham = int((out["predicted"] != "phishing").sum())

    threshold = _safe_int(out["threshold"].iloc[0], default=0) if "threshold" in out.columns and len(out) else 0

    # Accuracy vs label (your label convention: 0=phishing, 1=safe)
    accuracy = None
    if "label" in out.columns:
        labels = out["label"]
        # only compute if label has at least some numeric-like values
        try:
            lab = pd.to_numeric(labels, errors="coerce")
            valid = lab.notna()
            if valid.any():
                y_true_phish = lab[valid].astype(int).eq(0)
                y_pred_phish = out.loc[valid, "predicted"].eq("phishing")
                accuracy = round(float((y_true_phish == y_pred_phish).mean() * 100), 2)
        except Exception:
            accuracy = None

    # Rule trigger counts / rates (based on your columns from scoring)
    rule_map = [
        ("Keyword Detection", "hit_keyword"),
        ("Whitelist Failure", "hit_whitelist"),
        ("Edit Distance", "hit_distance"),
        ("Suspicious URL", "hit_suspicious_url"),
    ]

    rule_counts = {}
    rule_rates = {}
    for label, col in rule_map:
        if col in out.columns and total > 0:
            c = int(pd.to_numeric(out[col], errors="coerce").fillna(0).astype(int).sum())
            rule_counts[label] = c
            rule_rates[label] = round((c / total) * 100, 2)
        else:
            rule_counts[label] = 0
            rule_rates[label] = 0.0

    # Top risky emails
    # Ensure numeric sort
    out["_risk"] = pd.to_numeric(out["risk_score_pct"], errors="coerce").fillna(0.0)

    top = out.sort_values("_risk", ascending=False).head(15)

    sample_rows = []
    for _, r in top.iterrows():
        subject = str(r.get("subject_clean", "") or "")
        sender_email = str(r.get("sender_email", "") or "")
        sender_domain = str(r.get("sender_domain", "") or "")
        from_display = sender_email if sender_email else sender_domain

        # Parse reasons_list JSON
        raw = r.get("reasons_list", "[]")
        why_items = []
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    why_items = parsed
            except Exception:
                why_items = []

        sample_rows.append({
            "subject": subject,
            "from": from_display,
            "risk_score_pct": round(_safe_float(r.get("risk_score_pct", 0.0)), 2),
            "pred": str(r.get("predicted", "") or ""),
            "why": str(r.get("reasons", "") or ""),
            "why_items": why_items,
        })

    return {
        "empty": total == 0,
        "total": total,
        "ham": ham,
        "phishing": phishing,
        "threshold": threshold,
        "accuracy": accuracy,
        "rule_counts": rule_counts,
        "rule_rates": rule_rates,
        "sample_rows": sample_rows,
    }