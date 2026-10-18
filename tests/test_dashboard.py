"""Scanner, scan history, synthetic demo corpus and dashboard smoke tests."""

import importlib.util
import json
from pathlib import Path

import pytest

from pemd.cli import main
from pemd.data.dataset import build_from_directories
from pemd.history import ScanHistory
from pemd.pipeline import run_experiment
from pemd.scanner import Scanner
from pemd.synthetic import generate_corpus


@pytest.fixture
def trained_run(cfg, pe_corpus, tmp_path):
    mal_dir, ben_dir = pe_corpus
    ds = build_from_directories(cfg, mal_dir, ben_dir)
    ds.save(tmp_path / "ds.npz")
    return run_experiment(cfg, tmp_path / "ds.npz", name="t")


def test_scanner_bytes_and_rejects(cfg, pe_corpus, trained_run):
    mal_dir, _ = pe_corpus
    sc = Scanner(trained_run, cfg)
    res = sc.scan_bytes(next(mal_dir.glob("m*.bin")).read_bytes(), name="m.bin")
    assert res["route"] in ("benign", "malware", "escalate")
    assert res["t_benign"] <= res["t_malware"]
    assert "error" in sc.scan_bytes(b"not a pe at all", name="x.txt")
    assert Scanner.can_scan(trained_run, cfg)


def test_predictions_have_every_model(trained_run):
    import pandas as pd

    for name in ("predictions.csv", "predictions_val.csv"):
        df = pd.read_csv(trained_run / name)
        assert {"p_random_forest", "p_xgboost", "p_svm", "label", "route"} <= set(df.columns)


def test_history_roundtrip(tmp_path):
    h = ScanHistory(tmp_path / "h.db")
    h.add({"file": "a.exe", "sha256": "aa", "p_malware": 0.9, "route": "malware",
           "verdict": "malware", "static_seconds": 0.01, "model": "xgboost"})
    h.add({"file": "b.exe", "sha256": "bb", "p_malware": 0.5, "route": "escalate",
           "verdict": "uncertain", "static_seconds": 0.02, "model": "xgboost"})
    h.add({"file": "c.txt", "error": "rejected: missing MZ header"})
    s = h.stats()
    assert s["n_scans"] == 3 and s["n_valid"] == 2 and s["n_rejected"] == 1
    assert s["static_resolution_rate"] == 0.5
    h.clear()
    assert h.stats()["n_scans"] == 0


def test_synthetic_corpus_is_valid_pe(cfg, tmp_path):
    paths = generate_corpus(tmp_path / "demo", n_per_class=15, n_holdout=4)
    ds = build_from_directories(cfg, paths["malware"], paths["benign"], dates_csv=paths["dates"])
    assert len(ds) == 30 and ds.summary()["n_dated"] == 30
    assert len(list(paths["samples"].iterdir())) == 4


def test_demo_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / "fast.yaml"
    cfg_file.write_text(
        "paths: {experiments: experiments}\nselection: {k: 60}\n"
        "models: {random_forest: {n_estimators: 20}, xgboost: {n_estimators: 20}}\n",
        encoding="utf-8")
    assert main(["--config", str(cfg_file), "demo", "--n", "40", "--no-cv"]) == 0
    run = next((tmp_path / "experiments").glob("*_demo"))
    assert json.loads((run / "results.json").read_text())["best_model"]
    assert ScanHistory(tmp_path / "data" / "scan_history.db").stats()["n_scans"] == 20


def test_dashboard_pages_render(cfg, trained_run, tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    app_path = Path(importlib.util.find_spec("pemd.dashboard").origin).parent / "app.py"
    exp = tmp_path / "exp.yaml"
    exp.write_text(f"paths: {{experiments: '{trained_run.parent.as_posix()}'}}\n",
                   encoding="utf-8")
    monkeypatch.setenv("PEMD_CONFIG", str(exp))
    monkeypatch.setenv("PEMD_DB", str(tmp_path / "h.db"))
    ScanHistory(tmp_path / "h.db").add(
        {"file": "a.exe", "sha256": "aa", "p_malware": 0.9, "route": "malware",
         "verdict": "malware", "static_seconds": 0.01, "model": "xgboost"})

    at = AppTest.from_file(str(app_path), default_timeout=120)
    at.run()
    assert not at.exception, at.exception

    for view in ("monitoring", "scan", "results", "compare", "gate_lab", "system"):
        at = AppTest.from_string(PAGE_SCRIPT.format(view=view), default_timeout=120)
        at.run()
        assert not at.exception, f"{view}: {at.exception}"


PAGE_SCRIPT = """
import importlib
import streamlit as st
from pemd.dashboard.common import list_runs
st.session_state["run_path"] = list_runs()[0]
importlib.import_module("pemd.dashboard.views.{view}").render()
"""
