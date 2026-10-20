"""FR-17 robustness check: leave-one-family-out on the raw-file dataset.

    python scripts/family_holdout.py --dataset data/processed/raw.npz \
        --families-csv data/raw/malwarebazaar_metadata.csv

For every malware family with at least --min-samples files in the dataset, the family is
removed from training and validation and used (with an equal number of benign files) as the
test set. The table reports how much of each UNSEEN family is still detected, which is the
generalisation question that exact signatures cannot answer. Uses only extracted features,
so it can run outside the VM. Writes experiments/family_holdout_<timestamp>.csv and .md.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

from pemd.config import load_config
from pemd.data.dataset import Dataset, load_families
from pemd.pipeline import run_experiment


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="data/processed/raw.npz")
    ap.add_argument("--families-csv", default="data/raw/malwarebazaar_metadata.csv")
    ap.add_argument("--config", default=None, help="YAML overriding configs/default.yaml")
    ap.add_argument("--min-samples", type=int, default=20)
    ap.add_argument("--models", default="xgboost,random_forest")
    args = ap.parse_args(argv)

    base = load_config(args.config)
    ds = Dataset.load(args.dataset)
    fam = load_families(args.families_csv)
    counts = Counter(fam.get(str(h).lower(), "") for h, y in zip(ds.sha256, ds.y) if y == 1)
    families = sorted(f for f, n in counts.items() if f and n >= args.min_samples)
    print(f"{len(families)} families with >= {args.min_samples} samples: {families}")

    rows = []
    for f in families:
        cfg = copy.deepcopy(base)
        cfg["data"]["holdout_families"] = [f]
        cfg["data"]["families_csv"] = args.families_csv
        run = run_experiment(cfg, args.dataset, name=f"holdout_{f}",
                             models=args.models.split(","))
        r = json.loads((run / "results.json").read_text(encoding="utf-8"))
        best = r["best_model"]
        t = r["models"][best]["test"]
        h = r["hybrid"]
        rows.append({
            "held_out_family": f, "n_family": counts[f], "model": best,
            "detection_rate": t["recall"], "fpr": t["fpr"], "accuracy": t["accuracy"],
            "roc_auc": t["roc_auc"], "escalated": h["routing"]["escalation_rate"],
            "hybrid_detection_oracle": h["hybrid"]["recall"], "run": run.name,
        })
        print(f"{f:20s} unseen-family detection {t['recall']:.3f}  FPR {t['fpr']:.3f}")

    df = pd.DataFrame(rows)
    out = Path(base["paths"]["experiments"])
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    df.to_csv(out / f"family_holdout_{stamp}.csv", index=False)
    lines = ["# Leave-one-family-out (FR-17)", "",
             "| Held-out family | Samples | Model | Detection of unseen family | FPR | "
             "Escalated | Hybrid detection (oracle) |", "|---|---|---|---|---|---|---|"]
    lines += [f"| {r.held_out_family} | {r.n_family} | {r.model} | {r.detection_rate:.3f} | "
              f"{r.fpr:.3f} | {r.escalated:.3f} | {r.hybrid_detection_oracle:.3f} |"
              for r in df.itertuples()]
    lines += ["", f"Mean detection of unseen families: **{df.detection_rate.mean():.3f}** "
              f"(min {df.detection_rate.min():.3f})"]
    (out / f"family_holdout_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
