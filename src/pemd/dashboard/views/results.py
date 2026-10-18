"""Experiment results of one run: metrics, PRD targets, hybrid/efficiency, features, CV."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st
from sklearn.metrics import roc_curve

from pemd.dashboard.common import (
    METRICS,
    MODEL_LABELS,
    demo_banner,
    fmt_num,
    fmt_pct,
    get_config,
    no_runs_message,
    score_histogram,
    selected_run,
)


def render() -> None:
    st.title("📈 Experiment results")
    run = selected_run()
    if run is None:
        no_runs_message()
        return
    r = run.results
    st.caption(f"Run `{run.name}` · best model by validation ROC-AUC: "
               f"**{MODEL_LABELS.get(run.best_model, run.best_model)}**")
    demo_banner(run)

    d = r.get("dataset", {})
    sp = d.get("split", {})
    k = st.columns(5)
    k[0].metric("Samples", d.get("n_samples", "-"))
    k[1].metric("Malware / benign", f"{d.get('n_malware', '-')} / {d.get('n_benign', '-')}")
    k[2].metric("Features → selected",
                f"{d.get('n_features', '-')} → {r.get('selection', {}).get('n_selected', '-')}")
    k[3].metric("Split", sp.get("method", "-"))
    k[4].metric("Test samples", sp.get("test", {}).get("n", "-"))

    tabs = st.tabs(["Model performance", "Hybrid & efficiency", "Features (RQ1)",
                    "Cross-validation", "Report & files"])
    with tabs[0]:
        _performance(run)
    with tabs[1]:
        _hybrid(run)
    with tabs[2]:
        _features(run)
    with tabs[3]:
        _cv(run)
    with tabs[4]:
        _files(run)


def _performance(run) -> None:
    models = run.results.get("models", {})
    st.subheader("Held-out test set (FR-10, RQ3)")
    rows = []
    for name, m in models.items():
        t = m["test"]
        rows.append({"model": MODEL_LABELS.get(name, name), **{c: t.get(c) for c in METRICS}})
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True,
                 column_config={c: st.column_config.NumberColumn(format="%.4f") for c in METRICS})

    st.subheader("Against PRD targets (Section 10.1, 10.2)")
    trow = []
    for name, m in models.items():
        for metric, row in m.get("targets", {}).items():
            trow.append({"model": MODEL_LABELS.get(name, name), "metric": metric,
                         "measured": row["value"], "target": row["target"],
                         "met": "✅ met" if row["met"] else "❌ not met"})
    if trow:
        tdf = pd.DataFrame(trow)
        met = (tdf["met"] == "✅ met").sum()
        st.caption(f"{met} of {len(tdf)} targets met. Every 'not met' needs a gap analysis "
                   "in the dissertation (PRD 10).")
        st.dataframe(tdf, hide_index=True, use_container_width=True,
                     column_config={"measured": st.column_config.NumberColumn(format="%.4f")})

    preds = run.csv("predictions.csv")
    st.subheader("ROC curves (test)")
    cols = [c for c in (preds.columns if preds is not None else []) if c.startswith("p_")
            and c != "p_malware"]
    if preds is not None and cols and preds["label"].nunique() == 2:
        curves = []
        for c in cols:
            fpr, tpr, _ = roc_curve(preds["label"], preds[c])
            name = c[2:]
            auc = models.get(name, {}).get("test", {}).get("roc_auc")
            curves.append(pd.DataFrame({"FPR": fpr, "TPR": tpr,
                                        "model": f"{MODEL_LABELS.get(name, name)} "
                                                 f"(AUC {fmt_num(auc, 3)})"}))
        diag = alt.Chart(pd.DataFrame({"x": [0, 1], "y": [0, 1]})).mark_line(
            strokeDash=[4, 4], color="#999").encode(x="x:Q", y="y:Q")
        st.altair_chart(diag + alt.Chart(pd.concat(curves)).mark_line().encode(
            x=alt.X("FPR:Q", title="false positive rate"),
            y=alt.Y("TPR:Q", title="true positive rate"),
            color=alt.Color("model:N", legend=alt.Legend(orient="bottom", columns=1)),
        ).properties(height=360), use_container_width=True)
    else:
        st.caption("Per-model scores are not in this run's predictions.csv "
                   "(runs made before the dashboard only store the best model).")

    st.subheader("Confusion matrices (test)")
    for col, (name, m) in zip(st.columns(len(models) or 1), models.items()):
        cm = m["test"]["confusion_matrix"]
        col.markdown(f"**{MODEL_LABELS.get(name, name)}**")
        col.table(pd.DataFrame(
            {"pred. benign": [cm["tn"], cm["fn"]], "pred. malware": [cm["fp"], cm["tp"]]},
            index=["actual benign", "actual malware"]))


def _hybrid(run) -> None:
    h = run.results.get("hybrid")
    if not h:
        st.info("No hybrid evaluation in this run.")
        return
    ro, tm = h["routing"], h["timing"]
    targets = get_config()["targets"]
    st.subheader(f"Static-first routing - escalation policy `{h['policy']}` (FR-12, NFR-05)")
    k = st.columns(5)
    k[0].metric("Benign cleared", ro["benign_cleared"])
    k[1].metric("Malware reported", ro["malware_reported"])
    k[2].metric("Escalated", ro["escalated"], help="Sent to dynamic analysis")
    wr = ro["workload_reduction_vs_fully_dynamic"]
    k[3].metric("Workload reduction", fmt_pct(wr),
                delta=f"{(wr - targets['workload_reduction']) * 100:+.1f} pts vs "
                      f"{targets['workload_reduction']:.0%} target")
    tr = tm.get("time_reduction_vs_fully_dynamic")
    k[4].metric("Time reduction", fmt_pct(tr),
                help=f"Dynamic time source: {tm.get('dynamic_seconds_source')}")
    if h["policy"] == "oracle":
        st.warning("`oracle` assumes the sandbox labels every escalated file correctly: this is "
                   "an **upper bound**. Report it together with a `static` (lower-bound) run.")

    st.subheader("Static-first hybrid vs baselines (RQ4)")
    rows = {"Static-only ML": h["static_only"], "Static-first hybrid": h["hybrid"]}
    if h.get("statically_resolved_subset"):
        rows["Statically resolved subset"] = h["statically_resolved_subset"]
    for name, b in run.results.get("baselines", {}).items():
        if b.get("metrics"):
            rows[f"Signature baseline ({name})"] = b["metrics"]
    df = pd.DataFrame([{"approach": k, **{c: v.get(c) for c in METRICS}} for k, v in rows.items()])
    st.dataframe(df, hide_index=True, use_container_width=True,
                 column_config={c: st.column_config.NumberColumn(format="%.4f") for c in METRICS})
    st.caption(f"Targets: FPR < {targets['fpr_max']:.0%}, FNR < {targets['fnr_max']:.0%}. "
               "YARA appears only for raw-file runs.")
    long = df.melt(id_vars="approach", value_vars=["accuracy", "f1", "fpr", "fnr"],
                   var_name="metric")
    st.altair_chart(alt.Chart(long).mark_bar().encode(
        x=alt.X("approach:N", title=None, axis=alt.Axis(labelAngle=-20)),
        y=alt.Y("value:Q"), color="approach:N", column=alt.Column("metric:N", title=None),
        tooltip=["approach", "metric", alt.Tooltip("value:Q", format=".4f")],
    ).properties(width=150, height=220))

    preds = run.csv("predictions.csv")
    if preds is not None:
        st.subheader("Where the test files fall in the gate")
        preds["class"] = preds["label"].map({0: "benign", 1: "malware"})
        st.altair_chart(score_histogram(preds, "p_malware", h["gate"]["t_benign"],
                                        h["gate"]["t_malware"]), use_container_width=True)
        met = run.gate.get("tuning", {}).get("constraints_met")
        st.caption("Colour = true label. Files in the middle band are escalated. Tuning "
                   f"constraints met on validation: **{met}**")

    st.subheader("Timing")
    st.dataframe(pd.DataFrame([{"quantity": k, "value": v} for k, v in tm.items()]),
                 hide_index=True)


def _features(run) -> None:
    fi = run.csv("feature_importance.csv")
    if fi is None:
        st.info("No feature importance in this run.")
        return
    model = run.results.get("top_features", {}).get("model", run.best_model)
    n = st.slider("Top features", 10, 50, 20)
    top = fi.head(n).copy()
    top["label"] = top.apply(lambda f: f["feature"] + (
        f"  ({str(f['tokens'])[:40]})" if isinstance(f.get("tokens"), str) and f["tokens"] else ""),
        axis=1)
    c1, c2 = st.columns([3, 2])
    with c1:
        st.subheader(f"Most important features - {MODEL_LABELS.get(model, model)} (FR-11)")
        st.altair_chart(alt.Chart(top).mark_bar().encode(
            x="importance:Q", y=alt.Y("label:N", sort="-x", title=None), color="group:N",
            tooltip=["feature", "group", "tokens", alt.Tooltip("importance:Q", format=".5f")],
        ).properties(height=22 * n + 40), use_container_width=True)
    with c2:
        st.subheader("By feature group")
        groups = fi.groupby("group")["importance"].sum().sort_values(ascending=False).reset_index()
        st.altair_chart(alt.Chart(groups).mark_bar().encode(
            x="importance:Q", y=alt.Y("group:N", sort="-x", title=None), color="group:N",
        ).properties(height=320), use_container_width=True)
        st.caption("hdr = header, sec = sections/entropy, imp = imports, api_cat = RE-guided API "
                   "capabilities, op = opcode n-grams, str = strings, byte_hist = bytes, "
                   "meta = metadata.")
    sel = run.csv("selection.csv")
    if sel is not None:
        st.subheader("Feature selection and RE review (FR-04, FR-05)")
        counts = sel.groupby(["re_decision", "selected"]).size().reset_index(name="features")
        st.dataframe(counts, hide_index=True)
        with st.expander("Full selection table"):
            st.dataframe(sel, hide_index=True, use_container_width=True)


def _cv(run) -> None:
    cv = run.results.get("cross_validation")
    if not cv:
        st.info("This run has no cross-validation. Re-run with `pemd run ... --cv`.")
        return
    rows = [{"model": MODEL_LABELS.get(m, m), "metric": k, "mean": v[0], "std": v[1]}
            for m, d in cv.items() for k, v in d.items()]
    df = pd.DataFrame(rows)
    folds = get_config()["evaluation"]["cv_folds"]
    st.subheader(f"Stratified {folds}-fold cross-validation on the training split (FR-13)")
    df["low"], df["high"] = df["mean"] - df["std"], df["mean"] + df["std"]
    base = alt.Chart(df).encode(x=alt.X("model:N", title=None), color="model:N")
    st.altair_chart(alt.layer(
        base.mark_point(filled=True, size=80).encode(y=alt.Y("mean:Q", title=None)),
        base.mark_errorbar().encode(y="low:Q", y2="high:Q"),
    ).properties(width=160, height=200).facet(column=alt.Column("metric:N", title=None))
     .resolve_scale(y="independent"))
    st.dataframe(df.pivot(index="model", columns="metric", values="mean"),
                 use_container_width=True)


def _files(run) -> None:
    report = run.text("report.md")
    if report:
        st.download_button("Download report.md", report, file_name=f"{run.name}_report.md")
        with st.expander("report.md", expanded=True):
            st.markdown(report)
    env = run.text("environment.json")
    if env:
        with st.expander("environment.json (reproducibility record, NFR-04)"):
            st.code(env, language="json")
    cfg = run.text("config.yaml")
    if cfg:
        with st.expander("config.yaml used for this run"):
            st.code(cfg, language="yaml")
    st.caption(f"Folder: `{run.path}`")
