"""End-to-end experiment: select -> train -> tune gate -> evaluate -> baselines -> report.

Each run writes to experiments/<timestamp>_<name>/:

    config.yaml, environment.json   reproducibility record (NFR-04)
    splits.json                     split method and class ratios
    selection.csv, selector.joblib  feature ranking and RE decisions (FR-04, FR-05)
    <model>.joblib                  trained models (FR-06)
    gate.json                       tuned thresholds (FR-08)
    predictions.csv                 per-sample test scores and routes
    feature_importance.csv          (FR-11)
    results.json, report.md         all metrics (FR-10, FR-12, FR-13)
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from pemd.baseline.signature import HashSignatureBaseline, YaraBaseline
from pemd.config import new_run_dir, set_seed, write_json
from pemd.data.dataset import Dataset, split, split_summary
from pemd.evaluation.hybrid import evaluate_hybrid, load_dynamic_verdicts
from pemd.evaluation.metrics import compare_to_targets, detection_metrics
from pemd.evaluation.report import write_report
from pemd.gate.prioritisation import DecisionGate, tune_thresholds
from pemd.models.classifiers import MODEL_NAMES, build_model, feature_importance, malware_proba
from pemd.selection.selector import FeatureSelector

log = logging.getLogger(__name__)


def group_of(feature: str) -> str:
    return feature.split(":", 1)[0]


def cross_validate(cfg: dict, X: np.ndarray, y: np.ndarray, models: list[str]) -> dict:
    """Stratified k-fold CV on the training split (FR-13)."""
    from sklearn.model_selection import StratifiedKFold

    skf = StratifiedKFold(n_splits=cfg["evaluation"]["cv_folds"], shuffle=True,
                          random_state=cfg["seed"])
    out = {}
    for name in models:
        scores = {k: [] for k in ("accuracy", "f1", "roc_auc", "mcc", "fpr", "fnr")}
        for tr, te in skf.split(X, y):
            m = build_model(name, cfg, y[tr]).fit(X[tr], y[tr])
            p = malware_proba(m, X[te])
            res = detection_metrics(y[te], (p >= 0.5).astype(int), p)
            for k in scores:
                scores[k].append(res[k] if res[k] is not None else np.nan)
        out[name] = {k: (float(np.nanmean(v)), float(np.nanstd(v))) for k, v in scores.items()}
    return out


def run_experiment(cfg: dict, dataset_path: str | Path, name: str = "run",
                   models: list[str] | None = None, do_cv: bool = False) -> Path:
    set_seed(cfg["seed"])
    models = models or list(MODEL_NAMES)
    run = new_run_dir(cfg, name)
    ds = Dataset.load(dataset_path)
    sp = split(ds, cfg)
    write_json(run / "splits.json", split_summary(ds, sp))
    write_json(run / "vocab.json", ds.vocab)
    log.info("dataset %s, split %s", ds.summary(), sp.method)

    # FR-04 / FR-05 - fitted on training data only
    selector = FeatureSelector.from_config(cfg).fit(ds.X[sp.train], ds.y[sp.train],
                                                    ds.feature_names)
    selector.report_.to_csv(run / "selection.csv", index=False)
    selector.save(run / "selector.joblib")
    Xtr, Xva, Xte = (selector.transform(ds.X[i]) for i in (sp.train, sp.val, sp.test))
    ytr, yva, yte = ds.y[sp.train], ds.y[sp.val], ds.y[sp.test]
    names = selector.selected_names

    results: dict = {"dataset": {**ds.summary(), "split": split_summary(ds, sp)},
                     "selection": {"n_selected": len(names)}, "models": {}}
    probas_val, probas_test = {}, {}
    for mname in models:
        log.info("training %s", mname)
        model = build_model(mname, cfg, ytr).fit(Xtr, ytr)
        joblib.dump(model, run / f"{mname}.joblib")
        pv, pt = malware_proba(model, Xva), malware_proba(model, Xte)
        probas_val[mname], probas_test[mname] = pv, pt
        test_m = detection_metrics(yte, (pt >= 0.5).astype(int), pt)
        results["models"][mname] = {
            "val": detection_metrics(yva, (pv >= 0.5).astype(int), pv),
            "test": test_m,
            "targets": compare_to_targets(mname, test_m, cfg["targets"]),
        }

    # best model by validation ROC-AUC drives the gate and the interface
    best = max(models, key=lambda m: results["models"][m]["val"]["roc_auc"] or 0)
    results["best_model"] = best
    model = joblib.load(run / f"{best}.joblib")

    imp = feature_importance(model)
    if imp is None:  # SVM: fall back to the best tree model for RQ1
        trees = [m for m in models if m != "svm"]
        if trees:
            tree = max(trees, key=lambda m: results["models"][m]["val"]["roc_auc"] or 0)
            imp, imp_model = feature_importance(joblib.load(run / f"{tree}.joblib")), tree
    else:
        imp_model = best
    if imp is not None:
        fi = pd.DataFrame({"feature": names, "importance": imp}).sort_values(
            "importance", ascending=False)
        fi["group"] = fi["feature"].map(group_of)
        fi["tokens"] = fi["feature"].map(lambda f: "; ".join(ds.vocab.get(f, [])))
        fi.to_csv(run / "feature_importance.csv", index=False)
        top = cfg["evaluation"]["top_features"]
        groups = fi.groupby("group")["importance"].sum().sort_values(ascending=False)
        results["top_features"] = {
            "model": imp_model,
            "features": list(zip(fi["feature"].head(top).map(ds.describe),
                                 fi["importance"].head(top))),
            "groups": list(groups.items()),
        }

    # FR-08 - tune gate on validation
    tcfg = cfg["gate"].get("tune")
    if tcfg:
        gate, info = tune_thresholds(yva, probas_val[best], tcfg["max_fpr"], tcfg["max_fnr"],
                                     tcfg["grid_step"])
        if not info["constraints_met"]:
            log.warning("no thresholds met the FPR/FNR constraints on validation; "
                        "using the lowest-error band")
    else:
        gate, info = DecisionGate.from_config(cfg), {"tuned": False}
    write_json(run / "gate.json", {"model": best, **gate.to_dict(), "tuning": info})

    # FR-12 / RQ4 - hybrid evaluation
    ecfg = cfg["evaluation"]
    hyb = evaluate_hybrid(
        yte, probas_test[best], gate, ds.sha256[sp.test], policy=ecfg["escalation_policy"],
        verdicts=load_dynamic_verdicts(ecfg.get("dynamic_verdicts")),
        static_seconds=ds.extract_s[sp.test],
        dynamic_seconds_estimate=ecfg["dynamic_seconds_estimate"],
    )
    hyb["model"] = best
    results["hybrid"] = hyb

    # FR-09 - signature baselines on the same test data
    results["baselines"] = {}
    hb = HashSignatureBaseline().fit(ds.sha256[sp.train], ytr)
    if any(ds.sha256):
        results["baselines"]["hash"] = {
            "metrics": detection_metrics(yte, hb.predict(ds.sha256[sp.test])),
            "note": "exact SHA-256 matches against training malware",
        }
    test_paths = ds.path[sp.test]
    rules_dir = cfg["baseline"].get("yara_rules")
    if rules_dir and any(test_paths):
        try:
            yb = YaraBaseline(rules_dir)
            pred, secs, _ = yb.predict(test_paths)
            ok = pred >= 0
            results["baselines"]["yara"] = {
                "metrics": detection_metrics(yte[ok], pred[ok]) if ok.any() else None,
                "n_scanned": int(ok.sum()),
                "mean_seconds": float(np.nanmean(secs)) if ok.any() else None,
            }
        except (RuntimeError, FileNotFoundError) as exc:
            log.warning("YARA baseline skipped: %s", exc)
            results["baselines"]["yara"] = {"skipped": str(exc)}

    pd.DataFrame({
        "sha256": ds.sha256[sp.test], "label": yte, "p_malware": probas_test[best],
        "route": gate.route(probas_test[best]),
    }).to_csv(run / "predictions.csv", index=False)

    if do_cv:
        results["cross_validation"] = cross_validate(cfg, Xtr, ytr, models)

    write_json(run / "results.json", results)
    write_report(run / "report.md", results)
    log.info("results written to %s", run)
    return run
