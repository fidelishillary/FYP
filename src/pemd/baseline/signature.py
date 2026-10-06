"""Signature-based baselines (FR-09, RQ4).

Two baselines are provided so RQ4 can be answered whatever data is available:

* :class:`HashSignatureBaseline` - an exact-match signature database built from
  the SHA-256 hashes of *training* malware. It models classic hash signatures
  and works on any dataset with hashes (including EMBER). It can only detect
  re-submissions of already catalogued files, which is exactly the
  generalisation weakness the hybrid approach is meant to address.
* :class:`YaraBaseline` - YARA rules run over the raw test files. Needs the
  binaries (``Dataset.path``) and therefore runs inside the isolated VM only.

A sample is labelled malware if any signature matches, benign otherwise.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)


class HashSignatureBaseline:
    def fit(self, sha256: np.ndarray, y: np.ndarray) -> HashSignatureBaseline:
        self.db_ = {h for h, label in zip(sha256, y) if label == 1 and h}
        return self

    def predict(self, sha256: np.ndarray) -> np.ndarray:
        return np.array([int(h in self.db_) for h in sha256])


class YaraBaseline:
    def __init__(self, rules_dir: str | Path):
        try:
            import yara
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("yara-python is not installed: pip install yara-python") from exc
        rules_dir = Path(rules_dir)
        files = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")])
        if not files:
            raise FileNotFoundError(f"no .yar/.yara rules in {rules_dir}")
        self.rule_files = files
        self.rules = yara.compile(filepaths={f"r{i}": str(p) for i, p in enumerate(files)})

    def scan(self, path: str | Path) -> list[str]:
        return [m.rule for m in self.rules.match(str(path), timeout=60)]

    def predict(self, paths: np.ndarray) -> tuple[np.ndarray, np.ndarray, list[list[str]]]:
        """Returns (prediction, seconds per sample, matched rule names). Missing files -> -1."""
        preds, secs, hits = [], [], []
        for p in paths:
            if not p or not Path(p).exists():
                preds.append(-1)
                secs.append(np.nan)
                hits.append([])
                continue
            t0 = time.perf_counter()
            matched = self.scan(p)
            secs.append(time.perf_counter() - t0)
            preds.append(int(bool(matched)))
            hits.append(matched)
        return np.array(preds), np.array(secs), hits
