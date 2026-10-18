"""System: configuration, environment, sandbox status and safety (NFR-01, NFR-04)."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st
import yaml

from pemd.config import environment_info
from pemd.dashboard.common import get_config, get_history, selected_run


def render() -> None:
    st.title("⚙️ System")
    cfg = get_config()
    run = selected_run()

    st.subheader("Pipeline")
    st.markdown(
        "```\n"
        "PE file ─► Static Analysis Module ─► ML classifier ─► Decision gate\n"
        "           (pefile, LIEF, capstone)   (RF / XGBoost /    p < t_benign  ─► BENIGN\n"
        "           never executed             SVM: p(malware))   p ≥ t_malware ─► MALWARE\n"
        "                                                         otherwise     ─► CAPE sandbox\n"
        "```")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.subheader("Active run")
        if run is None:
            st.caption("none")
        else:
            st.markdown(f"`{run.name}`  \nbest model **{run.best_model}**  \n"
                        f"t_benign **{run.gate.get('t_benign')}**, "
                        f"t_malware **{run.gate.get('t_malware')}**  \n"
                        f"tuning constraints met: "
                        f"**{run.gate.get('tuning', {}).get('constraints_met')}**")
    with c2:
        st.subheader("Dynamic fallback (FR-14)")
        d = cfg["dynamic"]
        if not d.get("enabled"):
            st.info("Disabled (`dynamic.enabled: false`). Escalated files are reported as "
                    "uncertain.")
        else:
            st.markdown(f"CAPE URL `{d['cape_url']}`")
            from pemd.dynamic.cape import SandboxSafetyError, assert_isolated

            try:
                assert_isolated(d["cape_url"])
                st.success("Address is private / host-only.")
            except SandboxSafetyError as exc:
                st.error(str(exc))
            if st.button("Check connection"):
                import requests

                try:
                    r = requests.get(d["cape_url"].rstrip("/") + "/apiv2/cuckoo/status/",
                                     timeout=5)
                    st.success(f"CAPE answered HTTP {r.status_code}")
                except requests.RequestException as exc:
                    st.error(f"Not reachable: {exc}")
    with c3:
        st.subheader("Scan history")
        db = get_history().db_path
        size = db.stat().st_size / 1024 if db.exists() else 0
        st.markdown(f"`{db}`  \n{get_history().stats()['n_scans']} scans, {size:.0f} KB")

    st.subheader("Safety rules (NFR-01, NFR-08)")
    st.markdown(
        "- Files are **parsed only**; nothing is executed by this dashboard.\n"
        "- Real malware is handled **only inside the isolated Ubuntu VM** (host-only network, "
        "snapshots). On the Windows host use EMBER features, benign files and the synthetic "
        "demo corpus.\n"
        "- The dashboard listens on `127.0.0.1` only; it is not reachable from other machines.\n"
        "- The CAPE client refuses any sandbox address that is not private or loopback.\n"
        "- The history stores names, hashes and scores, never file contents.")

    with st.expander("Configuration in use (configs/default.yaml + overrides)"):
        st.code(yaml.safe_dump(cfg, sort_keys=False), language="yaml")
    with st.expander("PRD targets"):
        st.code(yaml.safe_dump(cfg["targets"], sort_keys=False), language="yaml")
    with st.expander("Environment of this dashboard process"):
        env = environment_info()
        st.dataframe(pd.DataFrame(env["packages"].items(), columns=["package", "version"]),
                     hide_index=True)
        st.code(json.dumps({k: v for k, v in env.items() if k != "packages"}, indent=2),
                language="json")
