"""Static-first hybrid evaluation and efficiency analysis (FR-12, NFR-05, PRD 10.3-10.4).

The decision gate escalates uncertain samples to dynamic analysis. Offline we
rarely have a sandbox verdict for every escalated sample, so the verdict used
for escalated samples is an explicit, reported policy:

* ``oracle``   - escalated samples receive their true label. An *upper bound*
                 that assumes a perfect sandbox; report it as such.
* ``static``   - escalated samples keep the static model's 0.5-threshold
                 label. A *lower bound* (the sandbox adds nothing).
* ``verdicts`` - use measured CAPE verdicts from a CSV (sha256,verdict[,seconds]);
                 escalated samples without a verdict fall back to ``static``.

Workload reduction versus a fully dynamic pipeline = 1 - escalation rate
(every sample would otherwise be sandboxed).
"""

from __future__ import annotations

import csv

import numpy as np

from pemd.evaluation.metrics import detection_metrics
from pemd.gate.prioritisation import BENIGN, ESCALATE, MALWARE, DecisionGate


def load_dynamic_verdicts(path: str | None) -> dict[str, tuple[int, float]]:
    if not path:
        return {}
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            secs = float(row["seconds"]) if row.get("seconds") else np.nan
            out[row["sha256"].lower()] = (int(row["verdict"]), secs)
    return out


def evaluate_hybrid(
    y: np.ndarray, proba: np.ndarray, gate: DecisionGate, sha256: np.ndarray,
    policy: str = "oracle", verdicts: dict | None = None,
    static_seconds: np.ndarray | None = None, dynamic_seconds_estimate: float = 180.0,
) -> dict:
    y, proba = np.asarray(y).astype(int), np.asarray(proba)
    routes = gate.route(proba)
    esc = routes == ESCALATE
    static_label = (proba >= 0.5).astype(int)

    final = np.where(routes == MALWARE, 1, 0)
    dyn_secs = np.full(len(y), np.nan)
    n_measured = 0
    if policy == "oracle":
        final[esc] = y[esc]
    elif policy == "static":
        final[esc] = static_label[esc]
    elif policy == "verdicts":
        verdicts = verdicts or {}
        for i in np.flatnonzero(esc):
            v = verdicts.get(str(sha256[i]).lower())
            if v is None:
                final[i] = static_label[i]
            else:
                final[i], dyn_secs[i] = v
                n_measured += 1
    else:
        raise ValueError(f"unknown escalation policy {policy!r}")

    resolved = ~esc
    static_only = detection_metrics(y, static_label, proba)
    hybrid = detection_metrics(y, final, proba)
    resolved_m = detection_metrics(y[resolved], final[resolved]) if resolved.any() else None

    static_secs = np.asarray(static_seconds) if static_seconds is not None else None
    mean_static = (float(np.nanmean(static_secs))
                   if static_secs is not None and np.isfinite(static_secs).any() else None)
    measured_dyn = dyn_secs[np.isfinite(dyn_secs)]
    mean_dyn = float(measured_dyn.mean()) if len(measured_dyn) else float(dynamic_seconds_estimate)

    n = len(y)
    esc_rate = float(esc.mean()) if n else 0.0
    timing = {
        "mean_static_seconds": mean_static,
        "mean_dynamic_seconds": mean_dyn,
        "dynamic_seconds_source": "measured" if len(measured_dyn) else "configured estimate",
    }
    if mean_static is not None:
        hybrid_total = n * mean_static + esc.sum() * mean_dyn
        fully_dynamic_total = n * mean_dyn
        timing["mean_hybrid_seconds_per_sample"] = hybrid_total / n if n else None
        timing["time_reduction_vs_fully_dynamic"] = (
            1 - hybrid_total / fully_dynamic_total if fully_dynamic_total else None
        )
    return {
        "policy": policy,
        "gate": gate.to_dict(),
        "routing": {
            "n": n,
            "benign_cleared": int((routes == BENIGN).sum()),
            "malware_reported": int((routes == MALWARE).sum()),
            "escalated": int(esc.sum()),
            "static_resolution_rate": 1 - esc_rate,
            "escalation_rate": esc_rate,
            "workload_reduction_vs_fully_dynamic": 1 - esc_rate,
            "escalated_with_measured_verdict": n_measured,
        },
        "static_only": static_only,
        "statically_resolved_subset": resolved_m,
        "hybrid": hybrid,
        "timing": timing,
    }
