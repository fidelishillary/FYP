# Static-First Hybrid Windows PE Malware Detection

**A Static-First Hybrid Framework for Windows PE Malware Detection Using Reverse Engineering-Guided Feature Extraction and Machine Learning**

Final Year Project, Bachelor of Information Technology (Hons), Universiti Teknologi PETRONAS
Student: Fidelis Hillary bin Leanad (22007169) · Supervisor: Dr. Abdullateef Oluwagbemiga Balogun

> **Defensive research prototype.** The framework parses Windows PE files without executing them. It is a proof of concept and does not claim production-ready antivirus performance. No malware is created, modified or redistributed, and this repository contains **no samples**. See [docs/safety_lab_setup.md](docs/safety_lab_setup.md).

The requirements are in the [PRD](docs/PRD_PE_Malware_Detection_FYP.docx). Each requirement is mapped to code in [docs/requirements_traceability.md](docs/requirements_traceability.md).

## How it works

```
PE file ──► Static Analysis Module ──► ML classifier ──► Prioritisation Engine (decision gate)
            (pefile, LIEF, capstone)   (RF / XGBoost /     p < t_benign         ─► BENIGN
            no execution               SVM, p(malware))    p ≥ t_malware        ─► MALWARE
                                                           otherwise            ─► Dynamic fallback (CAPE, optional)
```

| Module | Package | PRD |
|---|---|---|
| Static feature extraction: header, sections/entropy, imports/exports, opcode n-grams, strings/bytes, metadata | `pemd.features` | FR-01–03 |
| Dataset building, de-duplication, stratified 70/15/15 or time-based split, EMBER import | `pemd.data` | FR-03, FR-13, NFR-07 |
| Chi-square + mutual-information ranking, combined with the RE review decisions | `pemd.selection` | FR-04, FR-05 |
| Random Forest, XGBoost (primary), SVM (comparison) | `pemd.models` | FR-06, FR-07 |
| Decision gate with thresholds tuned on validation | `pemd.gate` | FR-08 |
| Hash-signature and YARA baselines | `pemd.baseline` | FR-09 |
| Metrics, hybrid/efficiency analysis, cross-validation, report | `pemd.evaluation`, `pemd.pipeline` | FR-10–13 |
| CAPE sandbox client, restricted to private/host-only addresses | `pemd.dynamic` | FR-14 |
| `pemd scan` proof-of-concept interface | `pemd.cli` | FR-15 |

## Setup

Use Python 3.11 in the Ubuntu 22.04 analysis VM (PRD Section 11):

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # pinned versions (NFR-04)
pip install -e .
make test                         # the tests use synthetic, harmless PE files
```

## Usage

```bash
pemd features                                   # feature groups and vector size

# Option A: pre-extracted EMBER features (preferred, NFR-02). This works outside the VM.
pemd import-ember --ember-dir data/external/ember2018 --balance 6000 --out data/processed/ember.npz
pemd run --dataset data/processed/ember.npz --name ember --cv

# Option B: raw PE files. Do this ONLY inside the isolated VM (NFR-01).
pemd extract --malware-dir data/raw/malware --benign-dir data/raw/benign \
             --dates data/raw/first_seen.csv --balance 6000
pemd run --name raw --cv
pemd scan suspicious.exe --run-dir experiments/<run>      # verdict, confidence, top features
pemd scan suspicious.exe --run-dir experiments/<run> --dynamic   # escalate to CAPE (if enabled)
```

Each `run` writes `experiments/<timestamp>_<name>/`. The directory holds the config used, library versions, the git commit, the splits, the feature ranking, the models, the tuned gate, per-sample predictions, `results.json` and a `report.md` laid out like report Tables 4.1 and 4.2, with every PRD Section 10 target marked met or not met.

The settings are in [configs/default.yaml](configs/default.yaml). To change them, pass `--config my.yaml` with only the keys you want to override. Record the reverse engineering decisions in [configs/re_feature_review.yaml](configs/re_feature_review.yaml).

## Repository layout

```
configs/            default.yaml (all parameters + PRD targets), re_feature_review.yaml (FR-05)
data/               raw/ processed/ external/  (git-ignored; never commit samples)
docs/               PRD, traceability, safety/lab setup, evaluation protocol, RE case study, milestones
experiments/        run outputs (git-ignored)
notebooks/          exploratory analysis
rules/yara/         signature baseline rules
src/pemd/           the framework
tests/              unit + end-to-end tests on synthetic PE files
```

## Documentation

- [Requirements traceability](docs/requirements_traceability.md): FR/NFR → code → test → dissertation evidence
- [Safety and lab setup](docs/safety_lab_setup.md): isolated VM, snapshots, sample handling (NFR-01–03, NFR-08)
- [Evaluation protocol](docs/evaluation_protocol.md): splits, metrics, gate tuning, escalation policies, RQ1–RQ4
- [Reverse engineering case study](docs/re_case_study/README.md): Ghidra workflow and note template (FR-05, RQ2)
- [Milestones](docs/milestones.md): FYP II timeline and build checklist
- [Open items](docs/open_items.md): inconsistencies between the source documents to settle with the supervisor

## References

- Anderson, H.S. and Roth, P., 2018. *EMBER: An open dataset for training static PE malware machine learning models.* arXiv:1804.04637.
- Harang, R. and Rudd, E.M., 2020. *SOREL-20M: A large scale benchmark dataset for malicious PE detection.* arXiv:2012.07634.
