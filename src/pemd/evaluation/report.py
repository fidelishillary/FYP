"""Markdown report in the shape of report Tables 4.1 / 4.2 (PRD 10.5)."""

from __future__ import annotations

from pathlib import Path

METRIC_COLS = ["accuracy", "precision", "recall", "f1", "roc_auc", "mcc", "fpr", "fnr"]


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def _metric_table(rows: dict[str, dict]) -> list[str]:
    lines = ["| Approach | " + " | ".join(c.upper() for c in METRIC_COLS) + " |",
             "|---" * (len(METRIC_COLS) + 1) + "|"]
    for name, m in rows.items():
        lines.append(f"| {name} | " + " | ".join(_fmt(m.get(c)) for c in METRIC_COLS) + " |")
    return lines


def write_report(path: str | Path, results: dict) -> None:
    out = ["# Evaluation report", ""]
    if "dataset" in results:
        d = results["dataset"]
        out += ["## Data", "", f"{d['n_samples']} samples ({d['n_malware']} malware, "
                f"{d['n_benign']} benign), {d['n_features']} features, "
                f"{d['n_dated']} with first-seen dates.", ""]
        sp = d.get("split")
        if sp:
            out += [f"Split method: **{sp['method']}**", "", "| Split | Samples | Malware ratio |",
                    "|---|---|---|"]
            out += [f"| {k} | {sp[k]['n']} | {sp[k]['malware_ratio']:.3f} |"
                    for k in ("train", "val", "test")]
            out += ["", f"Features kept after selection: {results['selection']['n_selected']}", ""]

    out += ["## Classifier performance on the held-out test set (FR-10)", ""]
    out += _metric_table({k: v["test"] for k, v in results["models"].items()})
    out += ["", "### Against PRD targets (10.1, 10.2)", "",
            "| Model | Metric | Measured | Target | Met |", "|---|---|---|---|---|"]
    for name, v in results["models"].items():
        for metric, row in v.get("targets", {}).items():
            out.append(f"| {name} | {metric} | {_fmt(row['value'])} | {row['target']} | "
                       f"{_fmt(row['met'])} |")

    if results.get("hybrid"):
        h = results["hybrid"]
        out += ["", f"## Static-first hybrid vs baselines (RQ4) - model `{h['model']}`, "
                f"escalation policy `{h['policy']}`", ""]
        rows = {"Static-only ML": h["static_only"], "Static-first hybrid": h["hybrid"]}
        for name, b in results.get("baselines", {}).items():
            if b.get("metrics"):
                rows[f"Signature baseline ({name})"] = b["metrics"]
        out += _metric_table(rows)
        r = h["routing"]
        out += ["", "## Routing and efficiency (FR-12, NFR-05, PRD 10.4)", "",
                "| Quantity | Value |", "|---|---|"]
        out += [f"| {k} | {_fmt(v)} |" for k, v in {**r, **h["timing"]}.items()]
        out += [f"| gate thresholds | t_benign={h['gate']['t_benign']}, "
                f"t_malware={h['gate']['t_malware']} |"]
        if h["policy"] == "oracle":
            out += ["", "> `oracle` assumes the sandbox labels every escalated sample correctly: "
                    "an upper bound, not a measured result."]

    if results.get("cross_validation"):
        out += ["", "## Cross-validation (FR-13)", "", "| Model | Metric | Mean | Std |",
                "|---|---|---|---|"]
        for name, cv in results["cross_validation"].items():
            for metric, (mean, std) in cv.items():
                out.append(f"| {name} | {metric} | {mean:.4f} | {std:.4f} |")

    if results.get("top_features"):
        model = results["top_features"]["model"]
        out += ["", f"## Most important features - `{model}` (FR-11, RQ1)", "",
                "| Rank | Feature | Importance |", "|---|---|---|"]
        for i, (f, v) in enumerate(results["top_features"]["features"], 1):
            out.append(f"| {i} | `{f}` | {v:.5f} |")
        if results["top_features"].get("groups"):
            out += ["", "| Feature group | Total importance |", "|---|---|"]
            for g, v in results["top_features"]["groups"]:
                out.append(f"| `{g}` | {v:.4f} |")
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
