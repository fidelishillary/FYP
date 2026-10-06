"""Prioritisation engine / decision gate (FR-08, report Section 3.4).

    p(malware) <  t_benign            -> BENIGN    (cleared statically)
    p(malware) >= t_malware           -> MALWARE   (reported statically)
    t_benign <= p(malware) < t_malware -> ESCALATE  (dynamic analysis fallback)

Thresholds are configurable and can be tuned on the validation split so that
the statically resolved samples meet the FPR / FNR targets while escalating as
few samples as possible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np

BENIGN, MALWARE, ESCALATE = "benign", "malware", "escalate"


@dataclass
class DecisionGate:
    t_benign: float = 0.2
    t_malware: float = 0.8

    def __post_init__(self):
        if not 0.0 <= self.t_benign <= self.t_malware <= 1.0:
            raise ValueError("need 0 <= t_benign <= t_malware <= 1")

    @classmethod
    def from_config(cls, cfg: dict) -> DecisionGate:
        g = cfg["gate"]
        return cls(float(g["t_benign"]), float(g["t_malware"]))

    def route(self, proba: np.ndarray) -> np.ndarray:
        proba = np.asarray(proba)
        out = np.full(proba.shape, ESCALATE, dtype=object)
        out[proba < self.t_benign] = BENIGN
        out[proba >= self.t_malware] = MALWARE
        return out

    def to_dict(self) -> dict:
        return asdict(self)


def _rates(y: np.ndarray, pred: np.ndarray) -> tuple[float, float]:
    neg, pos = (y == 0), (y == 1)
    fpr = float((pred[neg] == 1).mean()) if neg.any() else 0.0
    fnr = float((pred[pos] == 0).mean()) if pos.any() else 0.0
    return fpr, fnr


def tune_thresholds(
    y_val: np.ndarray, p_val: np.ndarray, max_fpr: float = 0.05, max_fnr: float = 0.03,
    step: float = 0.01,
) -> tuple[DecisionGate, dict]:
    """Grid-search thresholds on the validation split.

    Among threshold pairs whose *statically resolved* samples satisfy
    FPR <= max_fpr and FNR <= max_fnr, pick the one that resolves the most
    samples statically (i.e. escalates the fewest). Ties are broken by the
    lower combined error. If no pair satisfies the constraints the narrowest
    escalation band with the lowest combined error is returned and flagged.
    """
    y_val, p_val = np.asarray(y_val), np.asarray(p_val)
    grid = np.round(np.arange(0.0, 1.0 + step / 2, step), 6)
    best, best_key, fallback, fallback_key = None, None, None, None
    for tb in grid[grid <= 0.5]:
        for tm in grid[grid >= 0.5]:
            if tm < tb:
                continue
            resolved = (p_val < tb) | (p_val >= tm)
            coverage = float(resolved.mean())
            if resolved.any():
                pred = (p_val[resolved] >= tm).astype(int)
                fpr, fnr = _rates(y_val[resolved], pred)
            else:
                fpr = fnr = 0.0
            info = {"t_benign": float(tb), "t_malware": float(tm), "coverage": coverage,
                    "fpr_resolved": fpr, "fnr_resolved": fnr}
            if fpr <= max_fpr and fnr <= max_fnr:
                key = (coverage, -(fpr + fnr))
                if best_key is None or key > best_key:
                    best, best_key = info, key
            key2 = (-(fpr + fnr), coverage)
            if fallback_key is None or key2 > fallback_key:
                fallback, fallback_key = info, key2
    chosen = best if best is not None else fallback
    chosen["constraints_met"] = best is not None
    chosen["max_fpr"], chosen["max_fnr"] = max_fpr, max_fnr
    return DecisionGate(chosen["t_benign"], chosen["t_malware"]), chosen
