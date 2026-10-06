# Open items to confirm with the supervisor

These come from PRD Section 16: inconsistencies between the source documents that examiners may notice. Record the decision and the date once each one is settled.

| # | Item | Options / note | Decision |
|---|---|---|---|
| 1 | **Data sources:** the slides and Form 07 list VirusTotal, MalwareBazaar and CAPE; the report lists EMBER, VirusShare and MalwareBazaar | The code supports EMBER (features) plus any raw source. Align the wording across documents | |
| 2 | **Sample count:** "10,000+" (slides) vs 12,000 = 6,000 + 6,000 (report) | `data.balance_to` / `--balance` sets it | |
| 3 | **Statistics presented as findings:** the family split (42/28/15/10/5), 12.4% vs 4.1% FPR and the 10–15% gain are stated as results in the slides but are projections | Replace them with measured values from `report.md` | |
| 4 | **Workload reduction wording:** "half or more" (3.4) vs "roughly 60%" (4.4) vs "up to 60%" (slides) | Code measures 1 − escalation rate; `targets.workload_reduction: 0.60` | |
| 5 | **Interface technology:** CLI or web? | `pemd scan` (CLI, JSON output) is implemented. A small web front-end could wrap it if required | |
| 6 | **Survey form** (Form 07): its purpose is unclear | Clarify whether it feeds any requirement | |
