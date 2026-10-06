from pathlib import Path

import numpy as np
import pytest

from pemd.baseline.signature import HashSignatureBaseline, YaraBaseline
from pemd.data.dataset import Dataset, balance, split
from pemd.dynamic.cape import SandboxSafetyError, assert_isolated
from pemd.evaluation.hybrid import evaluate_hybrid
from pemd.evaluation.metrics import compare_to_targets, detection_metrics
from pemd.gate.prioritisation import BENIGN, ESCALATE, MALWARE, DecisionGate, tune_thresholds
from pemd.selection.selector import FeatureSelector
from tests.conftest import make_pe


def _toy(n=200, d=20, seed=0, dates=False):
    rng = np.random.default_rng(seed)
    y = np.array([0, 1] * (n // 2))
    X = rng.normal(size=(n, d)).astype(np.float32)
    X[:, 0] += 3 * y  # informative
    X[:, 1] = 0  # constant
    fs = None
    if dates:
        fs = np.array([f"2020-01-{(i % 28) + 1:02d}" for i in range(n)], dtype=object)
    return Dataset(X=X, y=y, feature_names=[f"f:{i}" for i in range(d)],
                   sha256=np.array([f"h{i}" for i in range(n)], dtype=object), first_seen=fs)


def test_split_stratified(cfg):
    ds = _toy()
    s = split(ds, cfg)
    assert s.method == "stratified"
    assert len(s.train) + len(s.val) + len(s.test) == len(ds)
    assert not set(s.train) & set(s.test)
    assert ds.y[s.test].mean() == pytest.approx(0.5, abs=0.05)


def test_split_time_based(cfg):
    ds = _toy(dates=True)
    s = split(ds, cfg)
    assert s.method == "time"
    assert max(ds.first_seen[s.train]) <= min(ds.first_seen[s.test])


def test_balance(cfg):
    ds = balance(_toy(), 30, seed=1)
    assert (ds.y == 0).sum() == 30 and (ds.y == 1).sum() == 30


def test_dataset_roundtrip(tmp_path):
    ds = _toy()
    ds.save(tmp_path / "d.npz")
    back = Dataset.load(tmp_path / "d.npz")
    assert np.array_equal(back.X, ds.X) and np.array_equal(back.y, ds.y)
    assert back.feature_names == ds.feature_names


def test_selector_respects_re_review():
    ds = _toy()
    sel = FeatureSelector(k=3, prioritise=("f:7",), discard=("f:0",)).fit(
        ds.X, ds.y, ds.feature_names)
    names = sel.selected_names
    assert "f:7" in names and "f:0" not in names and "f:1" not in names
    assert len(names) == 3


def test_gate_routing():
    g = DecisionGate(0.2, 0.8)
    assert list(g.route(np.array([0.1, 0.5, 0.9]))) == [BENIGN, ESCALATE, MALWARE]
    with pytest.raises(ValueError):
        DecisionGate(0.9, 0.1)


def test_tune_thresholds_meets_constraints():
    rng = np.random.default_rng(0)
    y = np.array([0] * 500 + [1] * 500)
    p = np.clip(np.where(y == 1, rng.normal(0.75, 0.25, 1000), rng.normal(0.25, 0.25, 1000)), 0, 1)
    gate, info = tune_thresholds(y, p, 0.05, 0.03)
    assert info["constraints_met"]
    assert info["fpr_resolved"] <= 0.05 and info["fnr_resolved"] <= 0.03
    assert 0 < info["coverage"] < 1


def test_metrics_and_targets():
    m = detection_metrics([0, 0, 1, 1], [0, 1, 1, 1], [0.1, 0.6, 0.7, 0.9])
    assert m["fpr"] == 0.5 and m["fnr"] == 0.0 and m["roc_auc"] == 1.0
    assert m["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 0, "tp": 2}
    t = compare_to_targets("xgboost", m, {"fpr_max": 0.05, "models": {"xgboost": {"f1": 0.95}}})
    assert t["fpr"]["met"] is False


def test_hybrid_policies():
    y = np.array([0, 0, 1, 1])
    p = np.array([0.05, 0.55, 0.45, 0.95])
    g = DecisionGate(0.2, 0.8)
    sha = np.array(["a", "b", "c", "d"])
    oracle = evaluate_hybrid(y, p, g, sha, policy="oracle", static_seconds=np.ones(4),
                             dynamic_seconds_estimate=100)
    assert oracle["routing"]["escalated"] == 2
    assert oracle["hybrid"]["accuracy"] == 1.0
    assert oracle["routing"]["workload_reduction_vs_fully_dynamic"] == 0.5
    static = evaluate_hybrid(y, p, g, sha, policy="static")
    assert static["hybrid"]["accuracy"] == 0.5
    v = evaluate_hybrid(y, p, g, sha, policy="verdicts", verdicts={"b": (0, 120.0), "c": (1, 90.0)})
    assert v["hybrid"]["accuracy"] == 1.0
    assert v["timing"]["dynamic_seconds_source"] == "measured"


def test_hash_baseline():
    b = HashSignatureBaseline().fit(np.array(["a", "b", "c"]), np.array([1, 0, 1]))
    assert list(b.predict(np.array(["a", "b", "z"]))) == [1, 0, 0]


def test_yara_baseline(tmp_path):
    pytest.importorskip("yara")
    good = tmp_path / "good.bin"
    bad = tmp_path / "bad.bin"
    good.write_bytes(make_pe())
    bad.write_bytes(make_pe(text_name=b"UPX0"))
    yb = YaraBaseline(Path(__file__).resolve().parents[1] / "rules" / "yara")
    pred, secs, hits = yb.predict(np.array([str(good), str(bad), ""]))
    assert list(pred) == [0, 1, -1]
    assert "Packer_UPX_Sections" in hits[1]


def test_sandbox_must_be_isolated():
    assert_isolated("http://192.168.56.10:8000")
    assert_isolated("http://127.0.0.1:8000")
    with pytest.raises(SandboxSafetyError):
        assert_isolated("http://8.8.8.8:8000")
