# FYP II milestones and build plan

FYP II runs for 14 weeks from 7 September 2026 (Week 1). The week-commencing dates below are calculated from that start date; **check them against the official academic calendar**.

| Week | Week commencing | Official milestone |
|---|---|---|
| 6 | 12 Oct 2026 | Progress Assessment 1 |
| 9 | 2 Nov 2026 | Draft Dissertation and Draft Technical Paper |
| 10 | 9 Nov 2026 | Dissertation soft bound and Revised Technical Paper |
| 12 | 23 Nov 2026 | Project Presentation and Progress Assessment 2 |
| 14 | 7 Dec 2026 | Project Dissertation hard bound |

## Build checklist

The order follows report Section 3.7. Tick items as they are completed.

### By Progress Assessment 1 (Week 6): pipeline and first model
- [x] Repository, configuration, reproducibility logging
- [x] Static feature extractor + tests (FR-01–03)
- [x] Download EMBER 2018 and vectorise it; `pemd import-ember --balance 6000`
- [x] First `pemd run` on EMBER: RF / XGBoost / SVM metrics table
- [x] Analysis VM built and snapshotted (`clean-isolated`)

### Weeks 6–8: RE study, raw track, baselines
- [x] Collect raw case-study samples + benign set inside the VM; `pemd extract`
- [x] Ghidra case study notes (5–10 samples) → `configs/re_feature_review.yaml` (FR-05)
- [x] Run with vs without the RE review (RQ2)
- [x] Replace the example YARA rules with a published rule set; run the baseline (FR-09)
- [x] Cross-validation and time-based split results (FR-13)
- [ ] ~~Optional: CAPE sandbox on the escalated subset (FR-14)~~ not done; reported as a limitation with oracle/static bounds

### Additional work completed (beyond the original plan)
- [x] EMBER learning curve (12k / 50k / 100k) and all-features ablation
- [x] Validity check: raw track without build artefacts (`raw_no_artifacts`)
- [x] Readable EMBER feature groups for RQ1
- [x] Web dashboard: monitoring, scan, results, compare, gate lab, system

### Week 9: draft dissertation
- [ ] Final runs frozen (record the run directories and git commit in the dissertation)
- [ ] RQ1–RQ4 answered with tables/figures from `report.md`
- [ ] Gap analysis for every target that was not met (PRD Section 10)

### Weeks 10–12: polish and presentation
- [x] `pemd scan` demo (FR-15) + web dashboard (`pemd dashboard`); still to do: record a demo video
- [x] Polymorphic-family check (FR-17): leave-one-family-out, `scripts/family_holdout.py`
- [ ] ~~LSTM (FR-16)~~ dropped (Could); future work
