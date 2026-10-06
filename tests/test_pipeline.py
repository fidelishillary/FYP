import json

from pemd.cli import main
from pemd.data.dataset import build_from_directories
from pemd.pipeline import run_experiment


def test_end_to_end(cfg, pe_corpus, tmp_path, capsys):
    mal_dir, ben_dir = pe_corpus
    ds = build_from_directories(cfg, mal_dir, ben_dir, rejected_log=tmp_path / "rej.csv")
    assert len(ds) == 60  # invalid file and duplicate dropped
    rejected = (tmp_path / "rej.csv").read_text()
    assert "not_a_pe.txt" in rejected and "duplicate" in rejected
    ds_path = tmp_path / "ds.npz"
    ds.save(ds_path)

    run = run_experiment(cfg, ds_path, name="test", do_cv=True)
    results = json.loads((run / "results.json").read_text())
    for m in ("random_forest", "xgboost", "svm"):
        assert results["models"][m]["test"]["accuracy"] >= 0.9
    assert "hash" in results["baselines"] and "yara" in results["baselines"]
    splits = json.loads((run / "splits.json").read_text())
    routing = results["hybrid"]["routing"]
    assert routing["n"] == splits["test"]["n"]
    routed = routing["benign_cleared"] + routing["malware_reported"] + routing["escalated"]
    assert routed == routing["n"]
    assert (run / "report.md").exists() and (run / "environment.json").exists()
    assert results["top_features"]["features"]

    # FR-15 scan interface on one file
    sample = next(mal_dir.glob("m*.bin"))
    code = main(["scan", str(sample), "--run-dir", str(run)])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["route"] in ("malware", "benign", "escalate")
    assert 0.0 <= out["p_malware"] <= 1.0
