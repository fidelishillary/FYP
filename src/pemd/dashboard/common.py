"""Shared helpers for the dashboard pages: config, experiment runs, scanner, charts."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import yaml

from pemd.config import load_config
from pemd.history import DEFAULT_DB, ScanHistory

ROUTE_COLORS = {"benign": "#1a9850", "malware": "#d73027", "escalate": "#f39c12",
                "rejected": "#7f8c8d"}
ROUTE_LABELS = {"benign": "Benign (cleared)", "malware": "Malware (reported)",
                "escalate": "Escalated (uncertain)", "rejected": "Rejected (not PE)"}
MODEL_LABELS = {"random_forest": "Random Forest", "xgboost": "XGBoost", "svm": "SVM"}
METRICS = ["accuracy", "precision", "recall", "f1", "roc_auc", "mcc", "fpr", "fnr"]


# ------------------------------------------------------------------ config/state
@st.cache_resource
def get_config() -> dict:
    return load_config(os.environ.get("PEMD_CONFIG") or None)


@st.cache_resource
def get_history() -> ScanHistory:
    return ScanHistory(os.environ.get("PEMD_DB") or DEFAULT_DB)


def experiments_dir() -> Path:
    return Path(get_config()["paths"]["experiments"])


# ------------------------------------------------------------------------ runs
@dataclass
class Run:
    path: Path
    results: dict = field(default_factory=dict)
    gate: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def is_demo(self) -> bool:
        return bool(self.config.get("demo"))

    @property
    def best_model(self) -> str | None:
        return self.results.get("best_model")

    def csv(self, name: str) -> pd.DataFrame | None:
        p = self.path / name
        return pd.read_csv(p) if p.exists() else None

    def text(self, name: str) -> str | None:
        p = self.path / name
        return p.read_text(encoding="utf-8") if p.exists() else None


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


@st.cache_data(ttl=10)
def list_runs() -> list[str]:
    """Completed runs (they have results.json), newest first."""
    root = experiments_dir()
    if not root.exists():
        return []
    runs = [p for p in root.iterdir() if p.is_dir() and (p / "results.json").exists()]
    return [str(p) for p in sorted(runs, key=lambda p: p.name, reverse=True)]


@st.cache_data(ttl=30)
def _load_run(path: str) -> tuple[dict, dict, dict]:
    p = Path(path)
    cfg_path = p / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    return _read_json(p / "results.json"), _read_json(p / "gate.json"), cfg or {}


def load_run(path: str | Path) -> Run:
    results, gate, cfg = _load_run(str(path))
    return Run(Path(path), results, gate, cfg)


@st.cache_data(ttl=60)
def run_can_scan(path: str) -> bool:
    from pemd.scanner import Scanner

    return Scanner.can_scan(path, get_config())


def run_label(path: str) -> str:
    run = load_run(path)
    tags = []
    if run.is_demo:
        tags.append("demo")
    tags.append("scan-ready" if run_can_scan(path) else "results only")
    return f"{run.name}  [{', '.join(tags)}]"


@st.cache_resource(max_entries=4)
def get_scanner(path: str):
    from pemd.scanner import Scanner

    return Scanner(path, get_config())


def selected_run() -> Run | None:
    path = st.session_state.get("run_path")
    return load_run(path) if path else None


# ----------------------------------------------------------------------- ui bits
def fmt_pct(v: float | None, digits: int = 1) -> str:
    return "-" if v is None else f"{v * 100:.{digits}f}%"


def fmt_num(v, digits: int = 4) -> str:
    if v is None:
        return "-"
    return f"{v:.{digits}f}" if isinstance(v, float) else str(v)


def demo_banner(run: Run | None) -> None:
    if run is not None and run.is_demo:
        st.info("This run uses the **synthetic demo corpus**: harmless generated files, "
                "not malware. Use it to learn the system; never report its numbers as results.",
                icon="🧪")


def verdict_badge(verdict: str, route: str) -> str:
    color = ROUTE_COLORS.get(route, "#7f8c8d")
    text = {"escalate": "UNCERTAIN → ESCALATE"}.get(route, verdict.upper())
    return (f"<span style='background:{color};color:white;padding:3px 10px;"
            f"border-radius:6px;font-weight:600;font-size:0.9rem'>{text}</span>")


def no_runs_message() -> None:
    st.warning("No experiment runs found yet. Create one first:")
    st.code("pemd demo", language="bash")
    st.caption("This builds a harmless synthetic dataset, trains the models and fills the "
               "dashboard. Then refresh this page.")


# ------------------------------------------------------------------------ charts
def route_scale() -> alt.Scale:
    return alt.Scale(domain=list(ROUTE_COLORS), range=list(ROUTE_COLORS.values()))


def gate_bands(t_benign: float, t_malware: float) -> alt.Chart:
    bands = pd.DataFrame({
        "start": [0.0, t_benign, t_malware], "end": [t_benign, t_malware, 1.0],
        "route": ["benign", "escalate", "malware"],
    })
    return alt.Chart(bands).mark_rect(opacity=0.2).encode(
        x=alt.X("start:Q", scale=alt.Scale(domain=[0, 1])), x2="end:Q",
        color=alt.Color("route:N", scale=route_scale(), legend=None),
    )


def score_gauge(p: float, t_benign: float, t_malware: float) -> alt.Chart:
    """Horizontal 0-1 bar split into the gate bands, with a marker at p(malware)."""
    bands = pd.DataFrame({
        "start": [0.0, t_benign, t_malware], "end": [t_benign, t_malware, 1.0],
        "route": ["benign", "escalate", "malware"],
    })
    x = alt.X("start:Q", scale=alt.Scale(domain=[0, 1]), title="p(malware)")
    base = alt.Chart(bands).mark_rect(opacity=0.55, height=26).encode(
        x=x, x2="end:Q", color=alt.Color("route:N", scale=route_scale(), legend=None),
        tooltip=["route:N", "start:Q", "end:Q"])
    marker = pd.DataFrame({"p": [p], "label": [f"p = {p:.3f}"]})
    tick = alt.Chart(marker).mark_tick(color="#2563eb", thickness=5, size=40).encode(
        x=alt.X("p:Q", scale=alt.Scale(domain=[0, 1])))
    text = alt.Chart(marker).mark_text(dy=-24, fontWeight="bold", color="#2563eb").encode(
        x="p:Q", text="label:N")
    return (base + tick + text).properties(height=80)


def score_histogram(df: pd.DataFrame, score_col: str, t_benign: float, t_malware: float,
                    color_col: str = "class", height: int = 260) -> alt.Chart:
    """Histogram of p(malware) with the gate bands shaded behind it."""
    bars = alt.Chart(df).mark_bar(opacity=0.85).encode(
        x=alt.X(f"{score_col}:Q", bin=alt.Bin(extent=[0, 1], step=0.025),
                title="p(malware)", scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("count():Q", title="files", stack=True),
        color=alt.Color(f"{color_col}:N", title=None,
                        scale=alt.Scale(domain=["benign", "malware"],
                                        range=[ROUTE_COLORS["benign"], ROUTE_COLORS["malware"]])),
        tooltip=[alt.Tooltip("count():Q", title="files")],
    )
    rules = alt.Chart(pd.DataFrame({"t": [t_benign, t_malware]})).mark_rule(
        strokeDash=[4, 3], color="#555").encode(x="t:Q")
    return (gate_bands(t_benign, t_malware) + bars + rules).properties(height=height)
