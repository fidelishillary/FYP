"""Detection metrics (FR-10) and target comparison (PRD Section 10)."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)


def detection_metrics(y_true, y_pred, y_score=None) -> dict:
    y_true, y_pred = np.asarray(y_true).astype(int), np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y_true)),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred) if len(set(y_true)) > 1 else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
        "roc_auc": None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if y_score is not None and len(set(y_true)) > 1:
        out["roc_auc"] = roc_auc_score(y_true, y_score)
    return {k: (float(v) if isinstance(v, np.floating) else v) for k, v in out.items()}


def compare_to_targets(model_name: str, m: dict, targets: dict) -> dict:
    """Return {metric: {"value", "target", "met"}} for the PRD 10.1 / 10.2 targets."""
    rows = {}
    for metric, target in targets.get("models", {}).get(model_name, {}).items():
        v = m.get(metric)
        rows[metric] = {"value": v, "target": f">= {target}",
                        "met": v is not None and v >= target}
    for metric, key in (("fpr", "fpr_max"), ("fnr", "fnr_max")):
        if key in targets:
            v = m.get(metric)
            rows[metric] = {"value": v, "target": f"< {targets[key]}",
                            "met": v is not None and v < targets[key]}
    return rows
