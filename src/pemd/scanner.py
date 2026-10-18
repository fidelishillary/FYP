"""Reusable scanner (FR-07, FR-08, FR-15).

Loads a trained run once (model, feature selector, tuned gate, hash-bucket
vocabulary) and scans files or in-memory bytes. Used by both ``pemd scan`` and
the dashboard. Files are only parsed, never executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

from pemd.features.extractor import FeatureExtractor, InvalidPEError
from pemd.gate.prioritisation import ESCALATE, DecisionGate
from pemd.models.classifiers import malware_proba, per_sample_contributions
from pemd.selection.selector import FeatureSelector

VERDICTS = {"benign": "benign", "malware": "malware", ESCALATE: "uncertain"}


class LayoutMismatchError(RuntimeError):
    """The run was trained on a different feature layout (e.g. EMBER)."""


class Scanner:
    def __init__(self, run_dir: str | Path, cfg: dict, model: str | None = None):
        self.run_dir = Path(run_dir)
        self.cfg = cfg
        gate_info = json.loads((self.run_dir / "gate.json").read_text(encoding="utf-8"))
        self.model_name = model or gate_info["model"]
        self.model = joblib.load(self.run_dir / f"{self.model_name}.joblib")
        self.selector = FeatureSelector.load(self.run_dir / "selector.joblib")
        self.gate = DecisionGate(gate_info["t_benign"], gate_info["t_malware"])
        vocab_path = self.run_dir / "vocab.json"
        self.vocab = (json.loads(vocab_path.read_text(encoding="utf-8"))
                      if vocab_path.exists() else {})
        self.extractor = FeatureExtractor(cfg)
        if self.selector.input_names_ != self.extractor.names:
            raise LayoutMismatchError(
                "this run was trained on a different feature layout (e.g. EMBER); train on a "
                "dataset built with `pemd extract` (or `pemd demo`) to scan raw files")

    @staticmethod
    def can_scan(run_dir: str | Path, cfg: dict) -> bool:
        """True if the run's feature layout matches the in-house extractor."""
        try:
            sel = FeatureSelector.load(Path(run_dir) / "selector.joblib")
        except (OSError, EOFError):
            return False
        return sel.input_names_ == FeatureExtractor(cfg).names

    def scan_bytes(self, data: bytes, name: str = "<upload>", top: int = 10) -> dict:
        """Scan in-memory bytes. Invalid PE files return a dict with ``error``."""
        try:
            res = self.extractor.extract_bytes(data)  # static only - never executed
        except InvalidPEError as exc:
            return {"file": name, "error": f"rejected: {exc}"}
        return self._result(name, res, top)

    def scan_file(self, path: str | Path, top: int = 10) -> dict:
        try:
            res = self.extractor.extract_file(path)
        except (InvalidPEError, OSError) as exc:
            return {"file": str(path), "error": f"rejected: {exc}"}
        return self._result(str(path), res, top)

    def _result(self, name: str, res, top: int) -> dict:
        x = self.selector.transform(res.vector.reshape(1, -1))
        p = float(malware_proba(self.model, x)[0])
        route = str(self.gate.route(np.array([p]))[0])
        contrib = per_sample_contributions(self.model, x[0])
        feats = []
        if contrib is not None:
            names = self.selector.selected_names
            for i in np.argsort(-np.abs(contrib))[:top]:
                if contrib[i] != 0:
                    feats.append({"feature": names[i], "tokens": self.vocab.get(names[i], []),
                                  "value": float(x[0, i]), "contribution": float(contrib[i])})
        return {
            "file": name, "sha256": res.sha256, "model": self.model_name,
            "p_malware": round(p, 4), "route": route, "verdict": VERDICTS.get(route, route),
            "t_benign": self.gate.t_benign, "t_malware": self.gate.t_malware,
            "static_seconds": round(res.seconds, 4),
            "influential_features": feats,
            "explanation_method": ("TreeSHAP (xgboost pred_contribs)"
                                   if self.model_name == "xgboost"
                                   else "global importance of features present (approximation)"),
        }

    def escalate(self, path: str | Path, result: dict) -> dict:
        """Send an escalated file to the isolated CAPE sandbox (FR-14) and update the result."""
        from pemd.dynamic.cape import CapeClient

        d = CapeClient(self.cfg).analyse(path)
        result = dict(result)
        result["dynamic"] = {"task_id": d.task_id, "malscore": d.malscore,
                             "signatures": d.signatures, "seconds": round(d.seconds, 1)}
        result["verdict"] = "malware" if d.verdict else "benign"
        return result
