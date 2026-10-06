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
- [ ] Download EMBER 2018 and vectorise it; `pemd import-ember --balance 6000`
- [ ] First `pemd run` on EMBER: RF / XGBoost / SVM metrics table
- [ ] Analysis VM built and snapshotted (`clean-isolated`)

### Weeks 6–8: RE study, raw track, baselines
- [ ] Collect raw case-study samples + benign set inside the VM; `pemd extract`
- [ ] Ghidra case study notes (5–10 samples) → `configs/re_feature_review.yaml` (FR-05)
- [ ] Run with vs without the RE review (RQ2)
- [ ] Replace the example YARA rules with a published rule set; run the baseline (FR-09)
- [ ] Cross-validation and time-based split results (FR-13)
- [ ] Optional: CAPE sandbox on the escalated subset → `dynamic_verdicts.csv` (FR-14)

### Week 9: draft dissertation
- [ ] Final runs frozen (record the run directories and git commit in the dissertation)
- [ ] RQ1–RQ4 answered with tables/figures from `report.md`
- [ ] Gap analysis for every target that was not met (PRD Section 10)

### Weeks 10–12: polish and presentation
- [ ] `pemd scan` demo (FR-15), or a small web front-end if one is decided
- [ ] Could-haves if time allows: LSTM (FR-16), polymorphic-family check (FR-17)
