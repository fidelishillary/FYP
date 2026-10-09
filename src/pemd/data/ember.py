"""Import pre-extracted EMBER features (NFR-02: prefer feature datasets over binaries).

Expects the vectorised EMBER files produced by the official ``ember`` package
(``ember.create_vectorized_features`` / ``create_metadata``)::

    <ember_dir>/X_train.dat  y_train.dat  X_test.dat  y_test.dat  metadata.csv

Unlabelled rows (label -1) are dropped. EMBER's 2,381-dimensional vector uses a
different layout from :mod:`pemd.features.extractor`, so models trained on EMBER
cannot score raw files with the in-house extractor; that combination is
documented in docs/evaluation_protocol.md.
"""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

from pemd.data.dataset import Dataset

EMBER_DIM = {1: 2351, 2: 2381}


def _memmap(path: Path, dtype, ncols: int | None = None) -> np.ndarray:
    arr = np.memmap(path, dtype=dtype, mode="r")
    if ncols:
        arr = arr.reshape(-1, ncols)
    return arr


def load_ember(ember_dir: str | Path, feature_version: int = 2,
               per_class: int | None = None, seed: int = 42) -> Dataset:
    """Load labelled EMBER rows. With ``per_class``, sample that many rows per class
    *before* reading the feature matrix, so only the kept rows are loaded into RAM
    (the full EMBER 2018 matrix is ~9 GB)."""
    ember_dir = Path(ember_dir)
    dim = EMBER_DIM[feature_version]
    Xs, ys = [], []
    for part in ("train", "test"):
        Xp, yp = ember_dir / f"X_{part}.dat", ember_dir / f"y_{part}.dat"
        if Xp.exists() and yp.exists():
            Xs.append(_memmap(Xp, np.float32, dim))
            ys.append(np.asarray(_memmap(yp, np.float32)))
    if not Xs:
        raise FileNotFoundError(f"no X_*.dat / y_*.dat in {ember_dir}")
    y = np.concatenate(ys)
    offsets = np.cumsum([0] + [len(a) for a in ys])

    n = len(y)
    sha = np.array([""] * n, dtype=object)
    first_seen = np.array([""] * n, dtype=object)
    meta = ember_dir / "metadata.csv"
    if meta.exists():
        # metadata.csv rows follow the same train-then-test order as the .dat files
        with open(meta, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        if len(rows) == n:
            sha = np.array([r.get("sha256", "") for r in rows], dtype=object)
            first_seen = np.array([r.get("appeared", "") for r in rows], dtype=object)

    keep = np.flatnonzero(y != -1)  # -1 = unlabelled
    if per_class:
        rng = np.random.default_rng(seed)
        keep = np.sort(np.concatenate([
            rng.choice(c, size=min(per_class, len(c)), replace=False)
            for c in (keep[y[keep] == 0], keep[y[keep] == 1])
        ]))
    X = np.empty((len(keep), dim), dtype=np.float32)
    for part, (lo, hi) in enumerate(zip(offsets[:-1], offsets[1:])):
        sel = (keep >= lo) & (keep < hi)
        X[sel] = Xs[part][keep[sel] - lo]

    names = [f"ember:{i}" for i in range(dim)]
    return Dataset(
        X=X, y=y[keep].astype(int), feature_names=names, sha256=sha[keep],
        first_seen=first_seen[keep],
    )
