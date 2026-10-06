# Requirements traceability

This table maps each PRD requirement to its implementation, its automated test, and the dissertation evidence it produces. Update the **Status** column as FYP II progresses. PRD Section 10.5 counts the project as done when FR-01 to FR-12 are implemented and tested and every Must item traces to a result.

Status key: ✅ implemented and tested · 🟡 implemented, still needs real data or a lab run · ⬜ not started

## Functional requirements

| ID | Priority | Implementation | Test | Evidence in dissertation | Status |
|---|---|---|---|---|---|
| FR-01 Accept PE, reject or log invalid/corrupted | Must | `features/extractor.py` `_parse`, `InvalidPEError`; `data/dataset.py` writes `*.rejected.csv` | `test_rejects_non_pe`, `test_rejects_truncated_pe`, `test_end_to_end` | Dataset composition and rejection counts | ✅ |
| FR-02 Static features (header, imports/exports, opcode n-grams, sections/entropy, strings/bytes, metadata), no execution | Must | `features/extractor.py` (feature groups `hdr`, `sec`, `imp`, `api_cat`, `exp`, `op`, `byte_hist`, `str`, `meta`) | `test_header_and_section_features`, `test_imports_and_api_categories`, `test_strings_and_entropy` | Feature table (report Table 3.1) | ✅ |
| FR-03 Python + pefile + LIEF, labelled vectors written to a dataset | Must | `FeatureExtractor`, `Dataset.save` (`.npz`) | `test_dataset_roundtrip`, `test_metadata_flags_reflect_empty_directories` | Appendix A | ✅ |
| FR-04 Chi-square + mutual-information ranking | Must | `selection/selector.py` | `test_selector_respects_re_review` | `selection.csv`, feature selection results | ✅ |
| FR-05 RE case study: retain / prioritise / discard | Must | `configs/re_feature_review.yaml`, consumed by the selector; `docs/re_case_study/` | `test_selector_respects_re_review` | RE case study chapter, Appendix B | 🟡 needs the Ghidra study |
| FR-06 RF + XGBoost primary, SVM secondary | Must | `models/classifiers.py` | `test_end_to_end` | Classification metrics table | ✅ |
| FR-07 Label + confidence score | Must | `malware_proba`; `predictions.csv` | `test_end_to_end` | — | ✅ |
| FR-08 Configurable thresholds tuned on validation | Must | `gate/prioritisation.py` `DecisionGate`, `tune_thresholds`; `gate.json` | `test_gate_routing`, `test_tune_thresholds_meets_constraints` | Gate design and thresholds | ✅ |
| FR-09 Signature (YARA-style) baseline on same test data | Must | `baseline/signature.py` (hash + YARA), `rules/yara/` | `test_hash_baseline`, `test_yara_baseline` | Baseline comparison (RQ4) | 🟡 swap in a published rule set |
| FR-10 Accuracy, precision, recall, F1, ROC-AUC, MCC, FPR, FNR, confusion matrix | Must | `evaluation/metrics.py`, `report.md` | `test_metrics_and_targets` | Table 4.1 | ✅ |
| FR-11 Feature importance of best tree model | Must | `pipeline.py` → `feature_importance.csv` (group totals + hashed-bucket tokens) | `test_end_to_end` | RQ1 answer | ✅ |
| FR-12 Static vs escalated proportion, per-path time | Must | `evaluation/hybrid.py` | `test_hybrid_policies` | Table 4.2, efficiency analysis | ✅ (dynamic time measured once CAPE runs) |
| FR-13 k-fold CV + time-based split | Should | `pipeline.cross_validate`, `data/dataset.split` | `test_split_time_based`, `test_end_to_end` | Validation design | ✅ |
| FR-14 Dynamic fallback in CAPE/Cuckoo | Should | `dynamic/cape.py`, `pemd scan --dynamic`, `evaluation.dynamic_verdicts` CSV | `test_sandbox_must_be_isolated` | Dynamic case study | 🟡 needs the lab sandbox |
| FR-15 Scan interface: verdict, confidence, influential features | Could | `pemd scan` (`cli.py`) | `test_end_to_end` | Interface demo | ✅ CLI (web UI: see open items) |
| FR-16 LSTM / sequence model | Could | — | — | — | ⬜ |
| FR-17 Polymorphic-family robustness check | Could | — (reuse `pemd run` on a family-held-out dataset) | — | — | ⬜ |

## Non-functional requirements

| ID | How it is addressed |
|---|---|
| NFR-01 Isolated lab | `docs/safety_lab_setup.md`; `dynamic/cape.py` refuses any sandbox URL that does not resolve to a private or loopback address; dynamic analysis is off by default |
| NFR-02 Prefer feature datasets | `pemd import-ember`; raw extraction is documented as VM-only |
| NFR-03 VM snapshots | `docs/safety_lab_setup.md` snapshot procedure |
| NFR-04 Reproducibility | Fixed `seed`; pinned `requirements.txt`; each run stores `config.yaml` and `environment.json` (versions, git commit) |
| NFR-05 Efficiency | `routing.static_resolution_rate`, `workload_reduction_vs_fully_dynamic` and timing in every report |
| NFR-06 Interpretability | Global importances, group totals, hashed-bucket vocabulary, TreeSHAP contributions in `pemd scan` |
| NFR-07 Data quality | SHA-256 de-duplication (incl. conflicting labels), invalid-file rejection, `class_weight: balanced`, `--balance` |
| NFR-08 Legal/ethical | `.gitignore` blocks binaries/archives; safety doc; no offensive functionality |

## Research questions

| RQ | Produced by |
|---|---|
| RQ1 most useful static features | `feature_importance.csv`, the feature group totals in `report.md`, `selection.csv` |
| RQ2 RE-guided stable features | `configs/re_feature_review.yaml` plus the case study notes. Compare runs with and without the review (point `selection.re_review` at an empty file) |
| RQ3 best model | Test metrics plus CV mean ± std per model |
| RQ4 hybrid vs signature baseline | "Static-first hybrid vs baselines" table and routing/efficiency table |
