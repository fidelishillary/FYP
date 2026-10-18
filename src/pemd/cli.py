"""Command-line interface.

    pemd features                                  list the feature vector layout
    pemd extract --malware-dir D --benign-dir D    build a dataset from raw PE files (in the VM)
    pemd import-ember --ember-dir D                build a dataset from EMBER features
    pemd run --dataset F [--cv]                    full experiment + report
    pemd scan FILE --run-dir R [--dynamic] [--log] proof-of-concept scanner (FR-15)
    pemd demo                                      harmless synthetic end-to-end demo
    pemd dashboard                                 web dashboard (monitoring, scan, results)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


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
    from pemd.data.ember import load_ember

    cfg = _cfg(args)
    per_class = args.balance or cfg["data"].get("balance_to")
    ds = load_ember(args.ember_dir, args.feature_version,
                    per_class=int(per_class) if per_class else None, seed=cfg["seed"])
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
    from pemd.gate.prioritisation import ESCALATE
    from pemd.scanner import LayoutMismatchError, Scanner

    cfg = _cfg(args)
    try:
        scanner = Scanner(args.run_dir, cfg, model=args.model)
    except LayoutMismatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = scanner.scan_file(args.file, top=args.top)  # static only - never executed
    if "error" not in out and out["route"] == ESCALATE and args.dynamic:
        out = scanner.escalate(args.file, out)
    if args.log:
        from pemd.history import ScanHistory

        ScanHistory().add(out, run=Path(args.run_dir).name, source="cli")
    print(json.dumps(out, indent=2))
    return 1 if "error" in out else 0


def cmd_demo(args) -> int:
    """Synthetic end-to-end demo: harmless generated PEs -> dataset -> run -> logged scans."""
    from pemd.data.dataset import build_from_directories
    from pemd.history import ScanHistory
    from pemd.pipeline import run_experiment
    from pemd.scanner import Scanner
    from pemd.synthetic import generate_corpus

    cfg = _cfg(args)
    cfg["demo"] = True  # recorded in the run's config.yaml; the dashboard shows a banner
    root = Path(args.out)
    print(f"[1/4] generating {2 * args.n} harmless synthetic PE files in {root} ...")
    paths = generate_corpus(root, n_per_class=args.n, seed=cfg["seed"])
    print("[2/4] extracting static features ...")
    ds_path = Path("data/processed/demo.npz")
    ds = build_from_directories(cfg, paths["malware"], paths["benign"], dates_csv=paths["dates"],
                                rejected_log=ds_path.with_suffix(".rejected.csv"))
    ds.save(ds_path)
    print("[3/4] selecting features, training RF / XGBoost / SVM, tuning the gate ...")
    run = run_experiment(cfg, ds_path, name="demo", do_cv=not args.no_cv)
    print("[4/4] scanning the hold-out samples into the dashboard history ...")
    scanner, history = Scanner(run, cfg), ScanHistory()
    for f in sorted(paths["samples"].iterdir()):
        history.add(scanner.scan_file(f), run=run.name, source="demo")
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    best = results["best_model"]
    test = results["models"][best]["test"]
    print(f"\nDone. Run folder: {run}")
    print(f"Best model {best}: accuracy {test['accuracy']:.3f}, F1 {test['f1']:.3f}, "
          f"ROC-AUC {test['roc_auc']:.3f}  (synthetic data - not research results)")
    print("Next: pemd dashboard")
    return 0


def cmd_dashboard(args) -> int:
    import os
    import subprocess

    from pemd.config import DEFAULT_CONFIG

    app = Path(__file__).resolve().parent / "dashboard" / "app.py"
    env = dict(os.environ)
    if args.config:
        env["PEMD_CONFIG"] = str(Path(args.config).resolve())
    project_root = DEFAULT_CONFIG.parents[1]
    cmd = [sys.executable, "-m", "streamlit", "run", str(app),
           "--server.address", "127.0.0.1",  # local only, never exposed to the network
           "--server.port", str(args.port),
           "--server.maxUploadSize", "64",
           "--browser.gatherUsageStats", "false",
           "--server.headless", "true" if args.no_browser else "false"]
    print(f"Dashboard: http://127.0.0.1:{args.port}   (Ctrl+C to stop)")
    try:
        return subprocess.call(cmd, cwd=project_root, env=env)
    except KeyboardInterrupt:
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
    s.add_argument("--log", action="store_true",
                   help="record the result in the dashboard scan history")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("demo", help="harmless synthetic end-to-end demo (fills the dashboard)")
    s.add_argument("--n", type=int, default=300, help="synthetic files per class")
    s.add_argument("--out", default="data/demo", help="where to write the synthetic files")
    s.add_argument("--no-cv", action="store_true", help="skip cross-validation (faster)")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("dashboard", help="start the web dashboard on http://127.0.0.1:8501")
    s.add_argument("--port", type=int, default=8501)
    s.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    s.set_defaults(func=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
