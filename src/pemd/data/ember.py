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

# Layout of EMBER's feature vector (ember/features.py, PEFeatureExtractor), in order.
_GENERAL = ["size", "vsize", "has_debug", "exports", "imports", "has_relocations",
            "has_resources", "has_signature", "has_tls", "symbols"]
_STRINGS = (["numstrings", "avlength", "printables"] + [f"printabledist_{i}" for i in range(96)]
            + ["printables_entropy", "paths", "urls", "registry", "MZ"])
_HEADER = (["coff_timestamp"] + [f"machine_h{i}" for i in range(10)]
           + [f"coff_characteristics_h{i}" for i in range(10)]
           + [f"subsystem_h{i}" for i in range(10)]
           + [f"dll_characteristics_h{i}" for i in range(10)]
           + [f"magic_h{i}" for i in range(10)]
           + [f"{a}_{b}_version" for b in ("image", "linker", "os", "subsystem")
              for a in ("major", "minor")]
           + ["sizeof_code", "sizeof_headers", "sizeof_heap_commit"])
_SECTION = (["n_sections", "n_zero_size", "n_empty_name", "n_rx", "n_w"]
            + [f"{k}_h{i}" for k in ("size", "entropy", "vsize", "entry_name",
                                     "entry_characteristics") for i in range(50)])
_IMPORTS = [f"lib_h{i}" for i in range(256)] + [f"func_h{i}" for i in range(1024)]
_DATADIR = [f"dir{i}_{k}" for i in range(15) for k in ("size", "vaddr")]


def ember_feature_names(feature_version: int = 2) -> list[str]:
    """Readable names ``ember_<group>:<field>`` so feature importance can be reported per
    EMBER feature group (RQ1) instead of as anonymous column numbers."""
    groups = [
        ("byte_hist", [str(i) for i in range(256)]),
        ("byte_entropy", [str(i) for i in range(256)]),
        ("strings", _STRINGS), ("general", _GENERAL), ("header", _HEADER),
        ("section", _SECTION), ("imports", _IMPORTS),
        ("exports", [f"h{i}" for i in range(128)]),
    ]
    if feature_version == 2:
        groups.append(("datadir", _DATADIR))
    names = [f"ember_{g}:{f}" for g, fields in groups for f in fields]
    assert len(names) == EMBER_DIM[feature_version], len(names)
    return names


def readable_ember_name(name: str, feature_version: int = 2) -> str:
    """Map a legacy column name ``ember:<i>`` (runs made before named features) to its
    readable name; any other name is returned unchanged."""
    if name.startswith("ember:") and name[6:].isdigit():
        names = ember_feature_names(feature_version)
        i = int(name[6:])
        if i < len(names):
            return names[i]
    return name


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

    names = ember_feature_names(feature_version)
    return Dataset(
        X=X, y=y[keep].astype(int), feature_names=names, sha256=sha[keep],
        first_seen=first_seen[keep],
    )
