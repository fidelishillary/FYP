"""Monitoring: live triage statistics from the scan history (FR-12, NFR-05)."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from pemd.dashboard.common import (
    ROUTE_LABELS,
    fmt_pct,
    get_config,
    get_history,
    route_scale,
    score_histogram,
    selected_run,
)


def render() -> None:
    st.title("📊 Monitoring")
    st.caption("Live view of every file scanned through the dashboard or `pemd scan --log`. "
               "Shows how much of the workload the static path settles without the sandbox.")
    auto = st.toggle("Auto-refresh (5 s)", value=False)
    _live(auto)

    with st.expander("Manage history"):
        st.caption(f"Database: `{get_history().db_path}` (metadata only, no file contents)")
        if st.checkbox("I want to delete all scan history"):
            if st.button("Clear history", type="primary"):
                get_history().clear()
                st.success("History cleared.")
                st.rerun()


def _live(auto: bool) -> None:
    @st.fragment(run_every=5 if auto else None)
    def body() -> None:
        hist = get_history()
        df = hist.dataframe()
        if df.empty:
            st.info("No scans recorded yet. Go to **Scan files** and scan something, "
                    "or run `pemd demo`, which logs a few demo scans.")
            return
        s = hist.stats()
        target = 0.85  # NFR-05 design expectation: 85-90 % resolved statically
        k = st.columns(6)
        k[0].metric("Files scanned", s["n_scans"])
        k[1].metric("Malware reported", s["malware_reported"])
        k[2].metric("Escalated to sandbox", s["escalated"])
        k[3].metric("Benign cleared", s["benign_cleared"])
        rate = s["static_resolution_rate"]
        k[4].metric("Resolved statically", fmt_pct(rate),
                    delta=None if rate is None else f"{(rate - target) * 100:+.1f} pts vs 85%",
                    help="Share of valid files the gate settled without dynamic analysis "
                         "(NFR-05 design expectation 85-90%). Equals the workload reduction "
                         "versus sandboxing every file.")
        ms = s["mean_static_seconds"]
        k[5].metric("Mean static time", "-" if ms is None else f"{ms * 1000:.1f} ms",
                    help=f"Configured sandbox estimate: "
                         f"{get_config()['evaluation']['dynamic_seconds_estimate']} s per file")

        valid = df[df["error"].isna()].copy()
        valid["route"] = valid["route"].fillna("rejected")
        left, right = st.columns([3, 2])
        with left:
            st.subheader("Activity")
            span = (df["ts"].max() - df["ts"].min()).total_seconds()
            unit = "yearmonthdatehoursminutes" if span < 6 * 3600 else "yearmonthdatehours"
            act = df.assign(route=df["route"].fillna("rejected"))
            st.altair_chart(alt.Chart(act).mark_bar().encode(
                x=alt.X(f"{unit}(ts):T", title="time (UTC)"),
                y=alt.Y("count():Q", title="files"),
                color=alt.Color("route:N", scale=route_scale(), title="route"),
                tooltip=["route:N", alt.Tooltip("count():Q", title="files")],
            ).properties(height=260), use_container_width=True)
        with right:
            st.subheader("Routing")
            counts = (df.assign(route=df["route"].fillna("rejected"))["route"]
                      .value_counts().rename_axis("route").reset_index(name="n"))
            counts["label"] = counts["route"].map(ROUTE_LABELS)
            st.altair_chart(alt.Chart(counts).mark_arc(innerRadius=55).encode(
                theta="n:Q", color=alt.Color("route:N", scale=route_scale(), legend=None),
                tooltip=["label:N", "n:Q"],
            ).properties(height=260), use_container_width=True)

        run = selected_run()
        if run is not None and run.gate and not valid.empty:
            st.subheader("Confidence distribution")
            st.caption("p(malware) of scanned files, coloured by the static decision. Shaded "
                       "bands are the active run's gate: benign | escalate | malware.")
            valid["class"] = valid["p_malware"].ge(0.5).map({True: "malware", False: "benign"})
            st.altair_chart(score_histogram(valid, "p_malware", run.gate["t_benign"],
                                            run.gate["t_malware"]), use_container_width=True)

        st.subheader("Needs attention")
        alerts = df[df["route"].isin(["malware", "escalate"])].head(15)
        if alerts.empty:
            st.success("No malware or escalated files in the history.")
        else:
            st.dataframe(_table(alerts), hide_index=True, use_container_width=True,
                         column_config=_column_config())

        st.subheader("Recent scans")
        st.dataframe(_table(df.head(200)), hide_index=True, use_container_width=True,
                     column_config=_column_config())

    body()


def _table(df: pd.DataFrame) -> pd.DataFrame:
    out = df[["ts", "file", "verdict", "route", "p_malware", "static_seconds", "model",
              "source", "sha256", "error"]].copy()
    out["file"] = out["file"].map(lambda f: str(f).replace("\\", "/").rsplit("/", 1)[-1])
    out["route"] = out["route"].map(lambda r: _dot(r) + " " + str(r) if r else "")
    out["static_seconds"] = out["static_seconds"] * 1000
    out["error"] = out["error"].fillna("")
    return out


def _dot(route) -> str:
    return {"benign": "🟢", "malware": "🔴", "escalate": "🟠"}.get(route, "⚪")


def _column_config() -> dict:
    return {
        "ts": st.column_config.DatetimeColumn("time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
        "p_malware": st.column_config.ProgressColumn("p(malware)", min_value=0.0, max_value=1.0,
                                                     format="%.3f"),
        "static_seconds": st.column_config.NumberColumn("static ms", format="%.1f"),
        "sha256": st.column_config.TextColumn("SHA-256", width="small"),
    }

