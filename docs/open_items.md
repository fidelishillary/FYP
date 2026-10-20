# Open items to confirm with the supervisor

These come from PRD Section 16: inconsistencies between the source documents that examiners may notice. Record the decision and the date once each one is settled.

| # | Item | Options / note | Decision |
|---|---|---|---|
| 1 | **Data sources:** the slides and Form 07 list VirusTotal, MalwareBazaar and CAPE; the report lists EMBER, VirusShare and MalwareBazaar | The code supports EMBER (features) plus any raw source. Align the wording across documents | **Proposed (2026-10-20):** EMBER 2018 (main evaluation) + MalwareBazaar (raw track, 671 recent samples) + 600 benign files from a clean Windows 11 install. VirusTotal, VirusShare and CAPE were not used; remove them from the slides. *Confirm with supervisor.* |
| 2 | **Sample count:** "10,000+" (slides) vs 12,000 = 6,000 + 6,000 (report) | `data.balance_to` / `--balance` sets it | **Proposed:** 12,000 EMBER samples (6,000 + 6,000) as in the report, plus a learning curve at 50,000 and 100,000; raw track 1,200 (600 + 600). *Confirm with supervisor.* |
| 3 | **Statistics presented as findings:** the family split (42/28/15/10/5), 12.4% vs 4.1% FPR and the 10–15% gain are stated as results in the slides but are projections | Replace them with measured values from `report.md` | **Measured:** EMBER static-only XGBoost FPR 15.5% → hybrid 4.5% (upper bound, oracle sandbox). Raw-track family mix from MalwareBazaar signatures (NanoCore 79, Formbook 56, …) replaces the 42/28/15/10/5 projection. *Update the slides.* |
| 4 | **Workload reduction wording:** "half or more" (3.4) vs "roughly 60%" (4.4) vs "up to 60%" (slides) | Code measures 1 − escalation rate; `targets.workload_reduction: 0.60` | **Proposed wording:** "about 60% reduction in dynamic-analysis workload (target), measured as the share of files resolved statically"; measured 69.1% on EMBER. *Use this sentence everywhere.* |
| 5 | **Interface technology:** CLI or web? | `pemd scan` (CLI, JSON output) is implemented. A small web front-end could wrap it if required | **Done:** both a CLI (`pemd scan`) and a local web dashboard (`pemd dashboard`, Streamlit, 127.0.0.1 only). |
| 6 | **Survey form** (Form 07): its purpose is unclear | Clarify whether it feeds any requirement | **Open:** ask the supervisor whether a survey is still expected; no requirement depends on it. |
