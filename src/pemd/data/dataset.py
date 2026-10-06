"""Labelled feature datasets: building, cleaning, saving and splitting.

A dataset is a single ``.npz`` file holding

* ``X``             float32 matrix (n_samples, n_features)
* ``y``             int8 labels, 1 = malware, 0 = benign
* ``feature_names`` feature names (columns of X)
* ``sha256``        sample hashes (used for de-duplication and the hash baseline)
* ``first_seen``    ISO date string or "" (enables the time-based split, FR-13)
* ``path``          path of the raw file or "" (needed by the YARA baseline, FR-09)
* ``extract_s``     static extraction time in seconds, NaN if unknown (FR-12)
* ``vocab``         JSON: hash bucket -> most frequent tokens (explains hashed features)
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from pemd.features.extractor import FeatureExtractor, InvalidPEError

log = logging.getLogger(__name__)


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray
    feature_names: list[str]
    sha256: np.ndarray
    first_seen: np.ndarray = field(default=None)
    path: np.ndarray = field(default=None)
    extract_s: np.ndarray = field(default=None)
    vocab: dict[str, list[str]] = field(default_factory=dict)  # hash bucket -> top tokens

    def __post_init__(self):
        n = len(self.y)
        if self.first_seen is None:
            self.first_seen = np.array([""] * n, dtype=object)
        if self.path is None:
            self.path = np.array([""] * n, dtype=object)
        if self.extract_s is None:
            self.extract_s = np.full(n, np.nan)

    def __len__(self) -> int:
        return len(self.y)

    def subset(self, idx: np.ndarray) -> Dataset:
        return Dataset(
            X=self.X[idx], y=self.y[idx], feature_names=self.feature_names,
            sha256=self.sha256[idx], first_seen=self.first_seen[idx], path=self.path[idx],
            extract_s=self.extract_s[idx], vocab=self.vocab,
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            path, X=self.X.astype(np.float32), y=self.y.astype(np.int8),
            feature_names=np.array(self.feature_names), sha256=self.sha256.astype(str),
            first_seen=self.first_seen.astype(str), path=self.path.astype(str),
            extract_s=self.extract_s.astype(np.float64), vocab=np.array(json.dumps(self.vocab)),
        )

    @classmethod
    def load(cls, path: str | Path) -> Dataset:
        z = np.load(path, allow_pickle=False)
        return cls(
            X=z["X"], y=z["y"].astype(int), feature_names=[str(n) for n in z["feature_names"]],
            sha256=z["sha256"].astype(object), first_seen=z["first_seen"].astype(object),
            path=z["path"].astype(object), extract_s=z["extract_s"],
            vocab=json.loads(str(z["vocab"])) if "vocab" in z.files else {},
        )

    def describe(self, feature: str) -> str:
        """Feature name plus the tokens hashed into it, if known."""
        toks = self.vocab.get(feature)
        return f"{feature} ({', '.join(toks)})" if toks else feature

    def summary(self) -> dict:
        dated = int(sum(bool(d) for d in self.first_seen))
        return {
            "n_samples": len(self), "n_features": self.X.shape[1],
            "n_malware": int((self.y == 1).sum()), "n_benign": int((self.y == 0).sum()),
            "n_dated": dated,
        }


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            yield p


def _load_dates(csv_path: str | Path | None) -> dict[str, str]:
    """Optional sha256,first_seen CSV (e.g. from MalwareBazaar metadata)."""
    if not csv_path:
        return {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        return {row["sha256"].lower(): row.get("first_seen", "") for row in csv.DictReader(fh)}


def build_from_directories(
    cfg: dict, malware_dir: str | Path, benign_dir: str | Path,
    dates_csv: str | Path | None = None, rejected_log: str | Path | None = None,
) -> Dataset:
    """Extract features from raw PE files (static only, FR-02).

    Duplicates (same SHA-256, including the same file under both labels) and
    files that are not valid PE are dropped and logged (FR-01, NFR-07).
    """
    extractor = FeatureExtractor(cfg)
    extractor.collect_vocabulary()
    dates = _load_dates(dates_csv)
    rows, seen, rejected = [], {}, []
    for label, root in ((1, Path(malware_dir)), (0, Path(benign_dir))):
        if not root.exists():
            log.warning("directory %s does not exist, skipping", root)
            continue
        for fp in _iter_files(root):
            try:
                res = extractor.extract_file(fp)
            except (InvalidPEError, OSError) as exc:
                rejected.append((str(fp), label, f"invalid: {exc}"))
                continue
            if res.sha256 in seen:
                prev = seen[res.sha256]
                reason = "duplicate" if prev == label else "duplicate with conflicting label"
                rejected.append((str(fp), label, reason))
                continue
            seen[res.sha256] = label
            rows.append((res.vector, label, res.sha256, dates.get(res.sha256, ""), str(fp),
                         res.seconds))
    if rejected_log:
        with open(rejected_log, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["path", "label", "reason"])
            w.writerows(rejected)
    log.info("extracted %d samples, rejected %d", len(rows), len(rejected))
    vocab = extractor.vocabulary()
    if not rows:
        raise RuntimeError("no valid PE samples found")
    X, y, sha, fs, paths, secs = zip(*rows)
    return Dataset(
        X=np.vstack(X), y=np.array(y), feature_names=extractor.names,
        sha256=np.array(sha, dtype=object), first_seen=np.array(fs, dtype=object),
        path=np.array(paths, dtype=object), extract_s=np.array(secs, dtype=float),
        vocab=vocab,
    )


def balance(ds: Dataset, per_class: int, seed: int) -> Dataset:
    """Randomly sub-sample each class to ``per_class`` samples (report: 6,000 + 6,000)."""
    rng = np.random.default_rng(seed)
    idx = []
    for label in (0, 1):
        cls = np.flatnonzero(ds.y == label)
        take = min(per_class, len(cls))
        if take < per_class:
            log.warning("class %d has only %d samples (wanted %d)", label, take, per_class)
        idx.append(rng.choice(cls, size=take, replace=False))
    return ds.subset(np.sort(np.concatenate(idx)))


@dataclass
class Splits:
    train: np.ndarray
    val: np.ndarray
    test: np.ndarray
    method: str


def split(ds: Dataset, cfg: dict) -> Splits:
    """Stratified 70/15/15 split, or a time-ordered split when dates exist (FR-13)."""
    from sklearn.model_selection import train_test_split

    fr = cfg["data"]["split"]
    seed = cfg["seed"]
    mode = cfg["data"].get("time_based", "auto")
    dated = np.array([bool(d) for d in ds.first_seen])
    use_time = mode is True or (mode == "auto" and len(ds) > 0 and dated.all())

    idx = np.arange(len(ds))
    if use_time:
        if not dated.all():
            raise ValueError("time_based split requested but some samples have no first_seen date")
        # Oldest samples train, newest test; stratification is preserved within each
        # time slice only approximately, which is reported in the split summary.
        order = idx[np.argsort(ds.first_seen.astype(str), kind="stable")]
        n_tr = int(round(fr["train"] * len(ds)))
        n_va = int(round(fr["val"] * len(ds)))
        return Splits(order[:n_tr], order[n_tr : n_tr + n_va], order[n_tr + n_va :], "time")

    test_frac = fr["test"]
    val_frac = fr["val"] / (fr["train"] + fr["val"])
    trval, test = train_test_split(idx, test_size=test_frac, stratify=ds.y, random_state=seed)
    train, val = train_test_split(
        trval, test_size=val_frac, stratify=ds.y[trval], random_state=seed
    )
    return Splits(np.sort(train), np.sort(val), np.sort(test), "stratified")


def split_summary(ds: Dataset, s: Splits) -> dict:
    out = {"method": s.method}
    for name in ("train", "val", "test"):
        idx = getattr(s, name)
        ratio = float(ds.y[idx].mean()) if len(idx) else 0.0
        out[name] = {"n": int(len(idx)), "malware_ratio": ratio}
    return out
