"""Compare runs side by side, e.g. with vs without the RE review (RQ2) or oracle vs static."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from pemd.dashboard.common import MODEL_LABELS, list_runs, load_run, no_runs_message

COLS = ["accuracy", "f1", "roc_auc", "mcc", "fpr", "fnr"]


def render() -> None:
    st.title("⚖️ Compare runs")
    st.caption("Typical uses: `raw_with_re` vs `raw_without_re` for RQ2, the `oracle` vs `static` "
               "escalation policies, or EMBER vs raw-file results.")
    runs = list_runs()
    if not runs:
        no_runs_message()
        return
    chosen = st.multiselect("Runs", runs, default=runs[: min(2, len(runs))],
                            format_func=lambda p: load_run(p).name)
    if not chosen:
        return
    model_choice = st.radio("Model", ["best model of each run", *MODEL_LABELS], horizontal=True,
                            format_func=lambda m: MODEL_LABELS.get(m, m))

    rows = []
    for p in chosen:
        run = load_run(p)
        r = run.results
        model = run.best_model if model_choice.startswith("best") else model_choice
        m = r.get("models", {}).get(model)
        if m is None:
            continue
        h = r.get("hybrid", {})
        rows.append({
            "run": run.name, "model": MODEL_LABELS.get(model, model),
            **{c: m["test"].get(c) for c in COLS},
            "hybrid FPR": h.get("hybrid", {}).get("fpr"),
            "hybrid FNR": h.get("hybrid", {}).get("fnr"),
            "resolved statically": h.get("routing", {}).get("static_resolution_rate"),
            "policy": h.get("policy"),
            "features kept": r.get("selection", {}).get("n_selected"),
            "split": r.get("dataset", {}).get("split", {}).get("method"),
            "demo": run.is_demo,
        })
    if not rows:
        st.warning("The chosen model is not in these runs.")
        return
    df = pd.DataFrame(rows)
    num = [*COLS, "hybrid FPR", "hybrid FNR", "resolved statically"]
    st.dataframe(df, hide_index=True, use_container_width=True,
                 column_config={c: st.column_config.NumberColumn(format="%.4f") for c in num})
    long = df.melt(id_vars="run", value_vars=num, var_name="metric")
    st.altair_chart(alt.Chart(long).mark_bar().encode(
        x=alt.X("run:N", title=None, axis=alt.Axis(labels=False)), y=alt.Y("value:Q", title=None),
        color=alt.Color("run:N", legend=alt.Legend(orient="bottom", columns=1)),
        column=alt.Column("metric:N", title=None),
        tooltip=["run", "metric", alt.Tooltip("value:Q", format=".4f")],
    ).properties(width=90, height=200))
    if len(df) >= 2:
        a, b = df.iloc[0], df.iloc[1]
        diff = {c: (b[c] - a[c]) for c in num if pd.notna(a[c]) and pd.notna(b[c])}
        st.subheader(f"Difference: {b['run']} − {a['run']}")
        st.dataframe(pd.DataFrame([diff]), hide_index=True,
                     column_config={c: st.column_config.NumberColumn(format="%+.4f")
                                    for c in diff})
