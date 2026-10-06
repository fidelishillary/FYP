# Evaluation protocol

This document fixes the evaluation choices in advance, so that results can be checked against PRD Section 10 and the threats to validity are stated up front.

## Data

- **Target corpus:** 12,000 samples, 6,000 malware and 6,000 benign (`--balance 6000`). See [open items](open_items.md) on the sample count.
- **Cleaning:** files that are not PE or are corrupted/truncated are rejected and logged (`*.rejected.csv`). Exact duplicates (same SHA-256) are dropped. A file that appears under both labels is dropped as a label conflict.
- **Two tracks:**
  1. *EMBER track:* EMBER's 2,381-dimensional vectors through `pemd import-ember`. This gives the main metrics at scale without handling binaries.
  2. *Raw track:* the in-house extractor (`pemd extract`) on raw samples inside the VM. This is needed for the RE-guided features, the YARA baseline, timing measurements and `pemd scan`.
  The two tracks have different feature spaces, so a model from one track cannot score data from the other.

## Splits (FR-13)

- With `time_based: auto`, a split is time-ordered (oldest 70% train, next 15% validation, newest 15% test) when **every** sample has a `first_seen` date. Otherwise the split is stratified at random 70/15/15 with the fixed seed. Time ordering is the stronger test against temporal leakage.
- Feature selection, model fitting and threshold tuning use **only** training and validation data. The test split is used once per final configuration.
- `pemd run --cv` adds stratified k-fold (k = 5) on the training split and reports mean ± std.

## Metrics (FR-10)

Accuracy, precision, recall, F1, ROC-AUC, MCC, FPR = FP/(FP+TN) and FNR = FN/(FN+TP), plus the confusion matrix. Malware is the positive class. Static-only predictions use a 0.5 threshold on p(malware).

## Decision gate (FR-08)

`tune_thresholds` searches `t_benign ≤ 0.5 ≤ t_malware` on the validation split. It keeps the pairs where the **statically resolved** samples meet FPR ≤ 5% and FNR ≤ 3%, and of those picks the pair that escalates the fewest samples. If no pair meets the constraints, the run logs a warning and `gate.json` records `constraints_met: false`. Report that case; do not hide it.

## Escalated samples (FR-12, FR-14)

The hybrid verdict depends on what happens to escalated samples. Always state which policy was used:

| Policy | Meaning | Use for |
|---|---|---|
| `oracle` | Sandbox assumed correct | Upper bound of the hybrid design |
| `static` | Sandbox adds nothing (static label kept) | Lower bound |
| `verdicts` | Measured CAPE verdicts from CSV, falling back to `static` | The real result for the escalated subset that was sandboxed |

Report the `oracle` and `static` bounds together, and `verdicts` for the sandboxed case study. The PRD's anticipated 12.4% → 4.1% FPR improvement is a projection to be tested, not an expected output.

## Efficiency (NFR-05, PRD 10.4)

- *Workload reduction vs fully dynamic* = 1 − escalation rate, because a fully dynamic pipeline sandboxes every sample. The design expectation is 85–90% resolved statically.
- *Time*: mean static time is measured per sample (extraction). Mean dynamic time comes from measured CAPE runs, or from `dynamic_seconds_estimate` when nothing has been measured; the report says which.

## Baselines (FR-09, RQ4)

- **Hash signatures:** SHA-256 of training malware. This shows how exact-match signatures fail on unseen samples. It is available on both tracks.
- **YARA:** rules in `rules/yara/` scanned over raw test files (raw track only). For the dissertation, use a published rule set dated before the test samples, and record its name, version and date.

## Threats to validity

- Label noise in public feeds, and temporal leakage when only random splits are possible.
- Pre-extracted datasets limit which features exist (EMBER has no opcode n-grams).
- The benign set may differ from malware in ways the model learns as shortcuts (compiler, age, size). Check the top features for such artefacts.
- Dynamic analysis is limited to a small set, so evasive behaviour is under-sampled.
