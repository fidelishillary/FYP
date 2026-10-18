"""Gate lab: what-if analysis of the decision-gate thresholds (FR-08, NFR-05)."""

from __future__ import annotations

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from pemd.dashboard.common import (
    MODEL_LABELS,
    demo_banner,
    fmt_pct,
    get_config,
    no_runs_message,
    score_histogram,
    selected_run,
)
from pemd.evaluation.metrics import detection_metrics
from pemd.gate.prioritisation import ESCALATE, MALWARE, DecisionGate, tune_thresholds


def render() -> None:
    st.title("🎚️ Gate lab")
    st.caption("Move the thresholds and see the trade-off between how many files are settled "
               "statically and how many errors the static path makes. The official thresholds "
               "are tuned on the **validation** split; the test split is for reporting only.")
    run = selected_run()
    if run is None:
        no_runs_message()
        return
    demo_banner(run)
    splits = {"Validation": run.csv("predictions_val.csv"), "Test": run.csv("predictions.csv")}
    splits = {k: v for k, v in splits.items() if v is not None}
    if not splits:
        st.info("This run has no saved predictions.")
        return
    c1, c2 = st.columns(2)
    split = c1.radio("Data", list(splits), horizontal=True)
    df = splits[split]
    models = [c[2:] for c in df.columns if c.startswith("p_") and c != "p_malware"]
    model = c2.radio("Model", models or [run.best_model], horizontal=True,
                     index=models.index(run.best_model) if run.best_model in models else 0,
                     format_func=lambda m: MODEL_LABELS.get(m, m))
    col = f"p_{model}" if f"p_{model}" in df.columns else "p_malware"
    y, p = df["label"].to_numpy().astype(int), df[col].to_numpy()

    tuned = (run.gate.get("t_benign", 0.2), run.gate.get("t_malware", 0.8))
    tb, tm = st.slider("Thresholds: t_benign … t_malware", 0.0, 1.0, value=tuned, step=0.01)
    if tb > 0.5 or tm < 0.5:
        st.warning("Keep t_benign ≤ 0.5 ≤ t_malware so cleared/reported files agree with the "
                   "model's own decision.")
    cfg = get_config()
    t = cfg["targets"]
    gate = DecisionGate(tb, tm)
    routes = gate.route(p)
    esc = routes == ESCALATE
    resolved = ~esc
    pred_static = (routes == MALWARE).astype(int)
    res_m = detection_metrics(y[resolved], pred_static[resolved]) if resolved.any() else None
    oracle = np.where(esc, y, pred_static)
    hyb = detection_metrics(y, oracle, p)

    k = st.columns(5)
    k[0].metric("Resolved statically", fmt_pct(resolved.mean()),
                delta=f"{(resolved.mean() - t['workload_reduction']) * 100:+.1f} pts vs "
                      f"{t['workload_reduction']:.0%} target")
    k[1].metric("Escalated files", int(esc.sum()), help=f"of {len(y)}")
    fpr = res_m["fpr"] if res_m else None
    fnr = res_m["fnr"] if res_m else None
    k[2].metric("FPR (resolved)", fmt_pct(fpr),
                delta=None if fpr is None else ("meets" if fpr <= t["fpr_max"] else "misses")
                + f" < {t['fpr_max']:.0%}", delta_color="off")
    k[3].metric("FNR (resolved)", fmt_pct(fnr),
                delta=None if fnr is None else ("meets" if fnr <= t["fnr_max"] else "misses")
                + f" < {t['fnr_max']:.0%}", delta_color="off")
    k[4].metric("Hybrid accuracy (oracle)", fmt_pct(hyb["accuracy"], 2),
                help="Upper bound: escalated files take their true label")

    plot = df.assign(**{"class": df["label"].map({0: "benign", 1: "malware"})})
    st.altair_chart(score_histogram(plot, col, tb, tm, height=280), use_container_width=True)

    st.subheader("Trade-off curve")
    st.caption("Symmetric bands around 0.5: wider band → more escalations, fewer static errors.")
    rows = []
    for w in np.arange(0, 0.5, 0.01):
        g = DecisionGate(round(0.5 - w, 2), round(0.5 + w, 2))
        r = g.route(p)
        rs = r != ESCALATE
        if rs.any():
            m = detection_metrics(y[rs], (r[rs] == MALWARE).astype(int))
            rows.append({"band half-width": w, "resolved statically": rs.mean(),
                         "FPR (resolved)": m["fpr"], "FNR (resolved)": m["fnr"]})
    curve = pd.DataFrame(rows).melt("band half-width", var_name="quantity")
    rule = alt.Chart(pd.DataFrame({"y": [t["fpr_max"], t["fnr_max"]]})).mark_rule(
        strokeDash=[3, 3], color="#888").encode(y="y:Q")
    st.altair_chart((alt.Chart(curve).mark_line().encode(
        x="band half-width:Q", y=alt.Y("value:Q", title=None), color="quantity:N",
        tooltip=["quantity", alt.Tooltip("value:Q", format=".3f"), "band half-width"],
    ) + rule).properties(height=260), use_container_width=True)

    st.subheader("Re-tune")
    st.caption("Runs the same grid search as `pemd run` on the validation split "
               "(maximise static resolution subject to the error limits).")
    a, b, c = st.columns(3)
    max_fpr = a.number_input("max FPR", 0.0, 0.5, float(cfg["gate"]["tune"]["max_fpr"]), 0.01)
    max_fnr = b.number_input("max FNR", 0.0, 0.5, float(cfg["gate"]["tune"]["max_fnr"]), 0.01)
    if c.button("Tune on validation", disabled="Validation" not in splits):
        v = splits["Validation"]
        vcol = f"p_{model}" if f"p_{model}" in v.columns else "p_malware"
        g, info = tune_thresholds(v["label"].to_numpy(), v[vcol].to_numpy(), max_fpr, max_fnr)
        msg = (f"t_benign = **{g.t_benign:.2f}**, t_malware = **{g.t_malware:.2f}**, "
               f"coverage {info['coverage']:.1%}, FPR {info['fpr_resolved']:.2%}, "
               f"FNR {info['fnr_resolved']:.2%}")
        (st.success if info["constraints_met"] else st.warning)(
            msg + ("" if info["constraints_met"] else " - constraints NOT met"))
