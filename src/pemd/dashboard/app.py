"""Dashboard entry point. Run with ``pemd dashboard`` (or ``streamlit run`` on this file).

Pages
-----
Monitoring          live triage statistics from the scan history (FR-12, NFR-05)
Scan files          upload files or scan a folder: verdict, confidence, features (FR-15)
Experiment results  metrics, targets, hybrid/efficiency, features, CV of one run (FR-10-13)
Compare runs        side-by-side runs, e.g. with vs without the RE review (RQ2)
Gate lab            what-if analysis of the decision-gate thresholds (FR-08)
System              configuration, environment, sandbox status and safety (NFR-01, NFR-04)
"""

from __future__ import annotations

import streamlit as st

from pemd import __version__
from pemd.dashboard.common import list_runs, run_label
from pemd.dashboard.views import compare, gate_lab, monitoring, results, scan, system

st.set_page_config(page_title="PEMD - Static-first PE malware detection", page_icon="🛡️",
                   layout="wide")

pages = st.navigation({
    "Operations": [
        st.Page(monitoring.render, title="Monitoring", icon="📊", url_path="monitoring",
                default=True),
        st.Page(scan.render, title="Scan files", icon="🔍", url_path="scan"),
    ],
    "Research": [
        st.Page(results.render, title="Experiment results", icon="📈", url_path="results"),
        st.Page(compare.render, title="Compare runs", icon="⚖️", url_path="compare"),
        st.Page(gate_lab.render, title="Gate lab", icon="🎚️", url_path="gate-lab"),
    ],
    "Admin": [st.Page(system.render, title="System", icon="⚙️", url_path="system")],
})

with st.sidebar:
    st.markdown("### 🛡️ PEMD dashboard")
    st.caption("Static-first hybrid Windows PE malware detection · FYP prototype "
               f"v{__version__}")
    runs = list_runs()
    if runs:
        current = st.session_state.get("run_path")
        index = runs.index(current) if current in runs else 0
        st.session_state["run_path"] = st.selectbox(
            "Active experiment run", runs, index=index, format_func=run_label,
            help="Models, thresholds and results come from this run "
                 "(experiments/<timestamp>_<name>).")
    else:
        st.session_state["run_path"] = None
        st.warning("No runs yet - run `pemd demo` or `pemd run`.")
    st.divider()
    st.caption("Files are parsed statically and never executed. Only analyse real "
               "malware inside the isolated VM (NFR-01).")

pages.run()
