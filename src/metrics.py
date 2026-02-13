# src/metrics.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

import pandas as pd


@dataclass(frozen=True)
class MetricsResult:
    threshold: float
    total: int
    tp: int
    fp: int
    fn: int
    tn: int
    accuracy: float
    precision: float
    recall: float
    f1: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "total": self.total,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


def _safe_div(n: float, d: float) -> float:
    return float(n / d) if d else 0.0


def compute_metrics(
    df: pd.DataFrame,
    *,
    score_col: str = "risk_score_pct",
    label_col: str = "label",
    threshold: float = 50,
    phishing_label: int = 0,     # your dataset: 0 = phishing, 1 = safe
    safe_label: int = 1,
    predicted_col: Optional[str] = None,
    phishing_pred_value: str = "phishing",
) -> MetricsResult:
    """
    Compute confusion matrix + metrics.

    Two modes:
    1) Score mode: uses score_col and threshold to create prediction.
       - predicted phishing if score > threshold
    2) Predicted mode: if predicted_col is provided, uses that column directly.

    Assumptions (your case):
      label == 0 => phishing
      label == 1 => safe
    """

    if label_col not in df.columns:
        raise KeyError(f"Missing label column '{label_col}'")

    y = df[label_col]

    if predicted_col is not None:
        if predicted_col not in df.columns:
            raise KeyError(f"Missing predicted column '{predicted_col}'")
        pred_is_phish = df[predicted_col].astype(str).str.lower().eq(phishing_pred_value.lower())
        thr_used = float("nan")
    else:
        if score_col not in df.columns:
            raise KeyError(f"Missing score column '{score_col}'")
        scores = pd.to_numeric(df[score_col], errors="coerce").fillna(0)
        pred_is_phish = scores > float(threshold)
        thr_used = float(threshold)

    actual_is_phish = (y == phishing_label)
    actual_is_safe = (y == safe_label)

    tp = int((pred_is_phish & actual_is_phish).sum())
    fp = int((pred_is_phish & actual_is_safe).sum())
    fn = int((~pred_is_phish & actual_is_phish).sum())
    tn = int((~pred_is_phish & actual_is_safe).sum())
    total = int(len(df))

    accuracy = _safe_div(tp + tn, total)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return MetricsResult(
        threshold=thr_used,
        total=total,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def scan_thresholds(
    df: pd.DataFrame,
    thresholds: Iterable[float],
    *,
    score_col: str = "risk_score_pct",
    label_col: str = "label",
    phishing_label: int = 0,
    safe_label: int = 1,
) -> pd.DataFrame:
    """
    Evaluate many thresholds and return a DataFrame sorted by accuracy (desc),
    with recall/precision/F1 included.

    Useful for deciding whether THRESHOLD=20 is best for your dataset.
    """
    rows = []
    for t in thresholds:
        r = compute_metrics(
            df,
            score_col=score_col,
            label_col=label_col,
            threshold=float(t),
            phishing_label=phishing_label,
            safe_label=safe_label,
            predicted_col=None,
        )
        rows.append(r.as_dict())

    out = pd.DataFrame(rows)
    # sort by accuracy then f1 as tie-breaker
    out = out.sort_values(["accuracy", "f1"], ascending=[False, False]).reset_index(drop=True)
    return out


def pretty_print(result: MetricsResult) -> None:
    """
    Simple human-readable print.
    """
    print(f"Threshold: {result.threshold}")
    print(f"Total: {result.total}")
    print(f"TP: {result.tp}  FP: {result.fp}  FN: {result.fn}  TN: {result.tn}")
    print(
        f"Acc: {result.accuracy:.3f}  "
        f"Recall: {result.recall:.3f}  "
        f"Precision: {result.precision:.3f}  "
        f"F1: {result.f1:.3f}"
    )


# test metrics
# import pandas as pd
# from src.metrics import compute_metrics, pretty_print, scan_thresholds

# df = pd.read_csv("outputs/latest_scored.csv")

# r = compute_metrics(df, threshold=20)  # uses risk_score_pct by default
# pretty_print(r)

# grid = scan_thresholds(df, thresholds=[0,1,20, 30, 35, 40, 45, 50])
# print(grid.head(10))