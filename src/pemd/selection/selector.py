"""Feature ranking and reduction (FR-04) combined with the RE review (FR-05).

Procedure (fitted on the training split only, to avoid leakage):

1. drop features the RE review marked ``discard`` and zero-variance features;
2. score the rest with chi-square (on min-max scaled values, since chi2 needs
   non-negative inputs) and mutual information;
3. rank by the mean of the two rank positions;
4. keep every ``prioritise`` feature, then fill up to ``k`` from the ranking.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.feature_selection import chi2, mutual_info_classif
from sklearn.preprocessing import MinMaxScaler


def load_re_review(path: str | Path | None) -> dict[str, list[str]]:
    if not path or not Path(path).exists():
        return {"prioritise": [], "discard": []}
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return {k: [e["pattern"] for e in (doc.get(k) or [])] for k in ("prioritise", "discard")}


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch(name, p) for p in patterns)


@dataclass
class FeatureSelector:
    k: int = 300
    methods: tuple[str, ...] = ("chi2", "mutual_info")
    seed: int = 42
    prioritise: tuple[str, ...] = ()
    discard: tuple[str, ...] = ()

    selected_: np.ndarray | None = None
    report_: pd.DataFrame | None = None
    input_names_: list[str] | None = None

    @classmethod
    def from_config(cls, cfg: dict) -> FeatureSelector:
        scfg = cfg["selection"]
        review = load_re_review(scfg.get("re_review"))
        return cls(
            k=int(scfg["k"]), methods=tuple(scfg["methods"]), seed=cfg["seed"],
            prioritise=tuple(review["prioritise"]), discard=tuple(review["discard"]),
        )

    def fit(self, X: np.ndarray, y: np.ndarray, names: list[str]) -> FeatureSelector:
        names = list(names)
        n = len(names)
        decision = np.array(["retain"] * n, dtype=object)
        for i, nm in enumerate(names):
            if _matches(nm, list(self.discard)):
                decision[i] = "discard"
            elif _matches(nm, list(self.prioritise)):
                decision[i] = "prioritise"

        variance = X.var(axis=0)
        candidate = (decision != "discard") & (variance > 0)
        cols = np.flatnonzero(candidate)

        df = pd.DataFrame({"feature": names, "re_decision": decision, "variance": variance})
        df["chi2"] = np.nan
        df["mutual_info"] = np.nan
        ranks = []
        if len(cols):
            Xc = X[:, cols]
            if "chi2" in self.methods:
                scores, _ = chi2(MinMaxScaler().fit_transform(Xc), y)
                scores = np.nan_to_num(scores)
                df.loc[cols, "chi2"] = scores
                ranks.append(pd.Series(scores).rank(ascending=False).to_numpy())
            if "mutual_info" in self.methods:
                mi = mutual_info_classif(Xc, y, random_state=self.seed)
                df.loc[cols, "mutual_info"] = mi
                ranks.append(pd.Series(mi).rank(ascending=False).to_numpy())
        df["mean_rank"] = np.nan
        if ranks:
            df.loc[cols, "mean_rank"] = np.mean(ranks, axis=0)

        forced = np.flatnonzero((decision == "prioritise") & (variance > 0))
        ranked = df.loc[cols].sort_values("mean_rank").index.to_numpy()
        chosen = list(forced)
        for i in ranked:
            if len(chosen) >= max(self.k, len(forced)):
                break
            if i not in chosen:
                chosen.append(i)
        self.selected_ = np.array(sorted(chosen), dtype=int)
        df["selected"] = False
        df.loc[self.selected_, "selected"] = True
        self.report_ = df.sort_values(["selected", "mean_rank"], ascending=[False, True])
        self.input_names_ = names
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        return X[:, self.selected_]

    @property
    def selected_names(self) -> list[str]:
        return [self.input_names_[i] for i in self.selected_]

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> FeatureSelector:
        return joblib.load(path)
