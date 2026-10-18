"""Scan files: upload or point at a folder; verdict, confidence and influential features (FR-15)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from pemd.dashboard.common import (
    demo_banner,
    get_config,
    get_history,
    get_scanner,
    list_runs,
    load_run,
    no_runs_message,
    run_can_scan,
    run_label,
    score_gauge,
    verdict_badge,
)

MAX_FOLDER_FILES = 5000


def render() -> None:
    st.title("🔍 Scan files")
    st.caption("Static analysis only: each file is parsed, never executed. Uncertain files are "
               "routed to the dynamic-analysis fallback.")
    runs = [r for r in list_runs() if run_can_scan(r)]
    if not runs:
        if list_runs():
            st.warning("None of the runs can scan raw files. EMBER runs use a different feature "
                       "layout; train on raw files with `pemd extract` + `pemd run`, "
                       "or create the demo run with `pemd demo`.")
        else:
            no_runs_message()
        return
    active = st.session_state.get("run_path")
    run_path = st.selectbox("Detection model (scan-ready runs)", runs,
                            index=runs.index(active) if active in runs else 0,
                            format_func=run_label)
    run = load_run(run_path)
    demo_banner(run)
    scanner = get_scanner(run_path)
    st.caption(f"Model **{scanner.model_name}** · gate: benign if p < "
               f"**{scanner.gate.t_benign:.2f}**, malware if p ≥ **{scanner.gate.t_malware:.2f}**,"
               " otherwise escalate.")

    tab_up, tab_dir = st.tabs(["Upload files", "Scan a folder"])
    with tab_up:
        files = st.file_uploader("Windows PE files (.exe, .dll, .sys, ...)",
                                 accept_multiple_files=True)
        if st.button("Scan uploaded files", type="primary", disabled=not files):
            results = []
            with st.spinner("Extracting static features..."):
                for f in files:
                    data = f.getvalue()
                    res = scanner.scan_bytes(data, name=f.name)
                    res["_bytes_key"] = f.name
                    get_history().add(res, run=run.name, source="upload")
                    results.append(res)
                    st.session_state.setdefault("upload_bytes", {})[f.name] = data
            st.session_state["scan_results"] = results
    with tab_dir:
        st.caption("Scans every file in a folder on this machine (triage). Use this for real "
                   "samples **only inside the isolated VM**.")
        folder = st.text_input("Folder path", placeholder="data/demo/samples")
        recursive = st.checkbox("Include sub-folders", value=True)
        if st.button("Scan folder", type="primary", disabled=not folder):
            root = Path(folder)
            if not root.is_dir():
                st.error(f"Not a folder: {root}")
            else:
                paths = [p for p in (root.rglob("*") if recursive else root.glob("*"))
                         if p.is_file()][:MAX_FOLDER_FILES]
                bar = st.progress(0.0, text=f"0 / {len(paths)}")
                results = []
                for i, p in enumerate(paths, 1):
                    res = scanner.scan_file(p)
                    get_history().add(res, run=run.name, source="folder")
                    results.append(res)
                    bar.progress(i / len(paths), text=f"{i} / {len(paths)}  {p.name}")
                st.session_state["scan_results"] = results

    results = st.session_state.get("scan_results")
    if results:
        _show_results(results, scanner)


def _show_results(results: list[dict], scanner) -> None:
    st.divider()
    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]
    k = st.columns(4)
    k[0].metric("Scanned", len(results))
    k[1].metric("Malware", sum(r["route"] == "malware" for r in ok))
    k[2].metric("Escalated", sum(r["route"] == "escalate" for r in ok))
    k[3].metric("Rejected (not valid PE)", len(bad))

    if ok:
        table = pd.DataFrame([{
            "file": Path(r["file"]).name, "verdict": r["verdict"], "p_malware": r["p_malware"],
            "route": r["route"], "static ms": r["static_seconds"] * 1000, "sha256": r["sha256"],
        } for r in ok]).sort_values("p_malware", ascending=False)
        st.dataframe(table, hide_index=True, use_container_width=True, column_config={
            "p_malware": st.column_config.ProgressColumn("p(malware)", min_value=0.0,
                                                         max_value=1.0, format="%.3f"),
            "static ms": st.column_config.NumberColumn(format="%.1f"),
        })
        st.download_button("Download results (JSON)",
                           json.dumps([_clean(r) for r in results], indent=2),
                           file_name="scan_results.json", mime="application/json")
    for r in bad:
        st.error(f"**{Path(r['file']).name}**: {r['error']}")

    st.subheader("Per-file explanation")
    for r in sorted(ok, key=lambda r: -r["p_malware"])[:50]:
        with st.expander(f"{Path(r['file']).name}  ·  {r['verdict']}  ·  p={r['p_malware']:.3f}",
                         expanded=len(ok) == 1):
            _detail(r, scanner)


def _detail(r: dict, scanner) -> None:
    st.markdown(verdict_badge(r["verdict"], r["route"]), unsafe_allow_html=True)
    c1, c2 = st.columns([2, 3])
    with c1:
        st.markdown(f"**SHA-256** `{r['sha256']}`  \n**Model** {r['model']}  \n"
                    f"**Static time** {r['static_seconds'] * 1000:.1f} ms")
        st.altair_chart(score_gauge(r["p_malware"], r["t_benign"], r["t_malware"]),
                        use_container_width=True)
        st.caption("green = cleared · orange = escalate · red = malware")
        if "dynamic" in r:
            d = r["dynamic"]
            st.success(f"Sandbox verdict: **{r['verdict']}** (malscore {d['malscore']}, "
                       f"task {d['task_id']}, {d['seconds']} s)")
        elif r["route"] == "escalate":
            _escalate_button(r, scanner)
    with c2:
        feats = pd.DataFrame(r["influential_features"])
        if feats.empty:
            st.caption("No per-feature explanation for this model.")
        else:
            feats["label"] = feats.apply(
                lambda f: f["feature"] + (f"  ({', '.join(f['tokens'][:2])})"
                                          if f["tokens"] else ""), axis=1)
            feats["pushes towards"] = feats["contribution"].map(
                lambda c: "malware" if c > 0 else "benign")
            st.altair_chart(alt.Chart(feats).mark_bar().encode(
                x=alt.X("contribution:Q"), y=alt.Y("label:N", sort="-x", title=None),
                color=alt.Color("pushes towards:N", scale=alt.Scale(
                    domain=["benign", "malware"], range=["#1a9850", "#d73027"])),
                tooltip=["feature", "value", "contribution"],
            ).properties(height=30 * len(feats) + 40), use_container_width=True)
            st.caption(f"Influential features: {r['explanation_method']}.")


def _escalate_button(r: dict, scanner) -> None:
    cfg = get_config()
    if not cfg["dynamic"].get("enabled"):
        st.warning("Uncertain: this file would go to the CAPE sandbox. Dynamic analysis is "
                   "disabled (`dynamic.enabled: false`).")
        return
    if st.button("Send to CAPE sandbox", key=f"cape_{r['sha256']}"):
        data = st.session_state.get("upload_bytes", {}).get(r.get("_bytes_key"))
        try:
            with st.spinner("Waiting for the sandbox report..."):
                if data is not None:
                    with tempfile.TemporaryDirectory() as tmp:
                        p = Path(tmp) / "sample.bin"
                        p.write_bytes(data)
                        new = scanner.escalate(p, r)
                else:
                    new = scanner.escalate(r["file"], r)
        except Exception as exc:  # noqa: BLE001 - surface any sandbox error in the UI
            st.error(f"Sandbox analysis failed: {exc}")
            return
        get_history().add(new, source="sandbox")
        st.session_state["scan_results"] = [new if x is r else x
                                            for x in st.session_state["scan_results"]]
        st.rerun()


def _clean(r: dict) -> dict:
    return {k: v for k, v in r.items() if not k.startswith("_")}
