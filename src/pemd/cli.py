"""Command-line interface.

    pemd features                                  list the feature vector layout
    pemd extract --malware-dir D --benign-dir D    build a dataset from raw PE files (in the VM)
    pemd import-ember --ember-dir D                build a dataset from EMBER features
    pemd run --dataset F [--cv]                    full experiment + report
    pemd scan FILE --run-dir R [--dynamic]         proof-of-concept scanner (FR-15)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np


def _cfg(args):
    from pemd.config import load_config

    cfg = load_config(args.config)
    if getattr(args, "seed", None) is not None:
        cfg["seed"] = args.seed
    return cfg


def cmd_features(args) -> int:
    from pemd.features.extractor import FeatureExtractor

    names = FeatureExtractor(_cfg(args)).names
    groups: dict[str, int] = {}
    for n in names:
        groups[n.split(":")[0]] = groups.get(n.split(":")[0], 0) + 1
    if args.all:
        print("\n".join(names))
    else:
        for g, c in groups.items():
            print(f"{g:12s} {c:5d}")
        print(f"{'total':12s} {len(names):5d}")
    return 0


def cmd_extract(args) -> int:
    from pemd.data.dataset import balance, build_from_directories

    cfg = _cfg(args)
    out = Path(args.out or cfg["paths"]["dataset"])
    ds = build_from_directories(
        cfg, args.malware_dir or cfg["paths"]["raw_malware"],
        args.benign_dir or cfg["paths"]["raw_benign"], dates_csv=args.dates,
        rejected_log=out.with_suffix(".rejected.csv"),
    )
    per_class = args.balance or cfg["data"].get("balance_to")
    if per_class:
        ds = balance(ds, int(per_class), cfg["seed"])
    ds.save(out)
    print(json.dumps(ds.summary(), indent=2))
    return 0


def cmd_import_ember(args) -> int:
    from pemd.data.dataset import balance
    from pemd.data.ember import load_ember

    cfg = _cfg(args)
    ds = load_ember(args.ember_dir, args.feature_version)
    per_class = args.balance or cfg["data"].get("balance_to")
    if per_class:
        ds = balance(ds, int(per_class), cfg["seed"])
    out = Path(args.out or "data/processed/ember.npz")
    ds.save(out)
    print(json.dumps(ds.summary(), indent=2))
    return 0


def cmd_run(args) -> int:
    from pemd.pipeline import run_experiment

    cfg = _cfg(args)
    models = args.models.split(",") if args.models else None
    run = run_experiment(cfg, args.dataset or cfg["paths"]["dataset"], args.name, models, args.cv)
    print((run / "report.md").read_text(encoding="utf-8"))
    print(f"\nrun directory: {run}")
    return 0


def cmd_scan(args) -> int:
    import joblib

    from pemd.features.extractor import FeatureExtractor, InvalidPEError
    from pemd.gate.prioritisation import ESCALATE, DecisionGate
    from pemd.models.classifiers import malware_proba, per_sample_contributions
    from pemd.selection.selector import FeatureSelector

    run = Path(args.run_dir)
    cfg = _cfg(args)
    gate_info = json.loads((run / "gate.json").read_text(encoding="utf-8"))
    model_name = args.model or gate_info["model"]
    model = joblib.load(run / f"{model_name}.joblib")
    selector = FeatureSelector.load(run / "selector.joblib")
    gate = DecisionGate(gate_info["t_benign"], gate_info["t_malware"])
    vocab_path = run / "vocab.json"
    vocab = json.loads(vocab_path.read_text(encoding="utf-8")) if vocab_path.exists() else {}

    extractor = FeatureExtractor(cfg)
    if selector.input_names_ != extractor.names:
        print("error: this run was trained on a different feature layout (e.g. EMBER); "
              "train on a dataset built with `pemd extract` to scan raw files", file=sys.stderr)
        return 2
    try:
        res = extractor.extract_file(args.file)  # static only - the file is never executed
    except (InvalidPEError, OSError) as exc:
        print(json.dumps({"file": str(args.file), "error": f"rejected: {exc}"}, indent=2))
        return 1

    x = selector.transform(res.vector.reshape(1, -1))
    p = float(malware_proba(model, x)[0])
    route = str(gate.route(np.array([p]))[0])
    contrib = per_sample_contributions(model, x[0])
    top = []
    if contrib is not None:
        order = np.argsort(-np.abs(contrib))[: args.top]
        names = selector.selected_names
        top = [{"feature": names[i], "tokens": vocab.get(names[i], []),
                "value": float(x[0, i]), "contribution": float(contrib[i])}
               for i in order if contrib[i] != 0]
    out = {
        "file": str(args.file), "sha256": res.sha256, "model": model_name,
        "p_malware": round(p, 4), "route": route,
        "verdict": {"benign": "benign", "malware": "malware"}.get(route, "uncertain"),
        "static_seconds": round(res.seconds, 4),
        "influential_features": top,
        "explanation_method": ("TreeSHAP (xgboost pred_contribs)" if model_name == "xgboost"
                               else "global importance of features present (approximation)"),
    }
    if route == ESCALATE and args.dynamic:
        from pemd.dynamic.cape import CapeClient

        d = CapeClient(cfg).analyse(args.file)
        out["dynamic"] = {"task_id": d.task_id, "malscore": d.malscore,
                          "signatures": d.signatures, "seconds": round(d.seconds, 1)}
        out["verdict"] = "malware" if d.verdict else "benign"
    print(json.dumps(out, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pemd", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=None, help="YAML overriding configs/default.yaml")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("features", help="list feature groups / names")
    s.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_features)

    s = sub.add_parser("extract", help="build dataset from raw PE directories")
    s.add_argument("--malware-dir")
    s.add_argument("--benign-dir")
    s.add_argument("--dates", help="CSV with sha256,first_seen columns")
    s.add_argument("--balance", type=int, help="samples per class")
    s.add_argument("--out")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("import-ember", help="build dataset from vectorised EMBER features")
    s.add_argument("--ember-dir", required=True)
    s.add_argument("--feature-version", type=int, default=2, choices=[1, 2])
    s.add_argument("--balance", type=int)
    s.add_argument("--out")
    s.set_defaults(func=cmd_import_ember)

    s = sub.add_parser("run", help="select, train, tune gate, evaluate, report")
    s.add_argument("--dataset")
    s.add_argument("--name", default="run")
    s.add_argument("--models", help="comma list from: random_forest,xgboost,svm")
    s.add_argument("--cv", action="store_true", help="also run k-fold cross-validation")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("scan", help="scan one PE file with a trained run")
    s.add_argument("file")
    s.add_argument("--run-dir", required=True)
    s.add_argument("--model", help="override the run's best model")
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--dynamic", action="store_true",
                   help="send escalated files to the CAPE sandbox (dynamic.enabled must be true)")
    s.set_defaults(func=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
