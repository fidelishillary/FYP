"""Classifiers (FR-06, FR-07, report Table 3.2).

Primary: Random Forest and XGBoost. Secondary comparison: SVM.
Every model exposes ``predict_proba`` so the prioritisation engine can use
p(malware) as the confidence score. Class imbalance is handled with class
weights (NFR-07).
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier

MODEL_NAMES = ("random_forest", "xgboost", "svm")


def build_model(name: str, cfg: dict, y_train: np.ndarray | None = None):
    mcfg = cfg["models"]
    seed = cfg["seed"]
    balanced = mcfg.get("class_weight") == "balanced"
    if name == "random_forest":
        p = mcfg["random_forest"]
        return RandomForestClassifier(
            n_estimators=p["n_estimators"], max_depth=p["max_depth"],
            min_samples_leaf=p["min_samples_leaf"], n_jobs=-1, random_state=seed,
            class_weight="balanced" if balanced else None,
        )
    if name == "xgboost":
        p = mcfg["xgboost"]
        spw = 1.0
        if balanced and y_train is not None and (y_train == 1).sum() > 0:
            spw = float((y_train == 0).sum() / (y_train == 1).sum())
        return XGBClassifier(
            n_estimators=p["n_estimators"], max_depth=p["max_depth"],
            learning_rate=p["learning_rate"], subsample=p["subsample"],
            colsample_bytree=p["colsample_bytree"], scale_pos_weight=spw,
            eval_metric="logloss", tree_method="hist", n_jobs=-1, random_state=seed,
        )
    if name == "svm":
        p = mcfg["svm"]
        # Log-compress large raw counts/sizes before scaling; RBF kernels are
        # sensitive to heavy-tailed inputs.
        from sklearn.preprocessing import FunctionTransformer

        return Pipeline([
            ("log", FunctionTransformer(_signed_log1p)),
            ("scale", StandardScaler()),
            ("svm", SVC(C=p["C"], kernel=p["kernel"], gamma=p["gamma"], probability=True,
                        class_weight="balanced" if balanced else None, random_state=seed)),
        ])
    raise ValueError(f"unknown model {name!r}; choose from {MODEL_NAMES}")


def _signed_log1p(X):
    return np.sign(X) * np.log1p(np.abs(X))


def malware_proba(model, X: np.ndarray) -> np.ndarray:
    """Confidence score = p(malware) (FR-07)."""
    return model.predict_proba(X)[:, 1]


def feature_importance(model) -> np.ndarray | None:
    """Global importances for tree models (FR-11, NFR-06); None for SVM."""
    est = model.steps[-1][1] if isinstance(model, Pipeline) else model
    return getattr(est, "feature_importances_", None)


def per_sample_contributions(model, x: np.ndarray) -> np.ndarray | None:
    """Per-feature contribution to one prediction (used by the scan interface).

    XGBoost: exact TreeSHAP contributions via ``pred_contribs``.
    Random Forest: global importance of the features that are non-zero in this
    sample (an approximation, labelled as such in the interface). SVM: None.
    """
    if isinstance(model, XGBClassifier):
        import xgboost as xgb

        contrib = model.get_booster().predict(xgb.DMatrix(x.reshape(1, -1)), pred_contribs=True)
        return contrib[0, :-1]  # last column is the bias term
    imp = feature_importance(model)
    if imp is None:
        return None
    return imp * (x != 0)
