# Counting incidents, not reports

Code and results for "Counting Incidents, Not Reports: Duplicate-Coverage Bias in ATT&CK Technique Statistics".

Threat-report statistics count each report. Heavily covered incidents are counted many times. This repository clusters
reports into incidents with a validated, constrained rule and compares per-report with per-incident technique rankings
on MITRE ATT&CK v20.1 citations, TIE/OpenCTI, and public report texts. CPU only; no labelling, no language model.

## Run

    pip install -r requirements.txt
    ./run_all.sh

ATT&CK results need only the ATT&CK v20.1 Enterprise STIX bundle at `data/attack_stix/enterprise-attack.json`.
Paths can be moved with `RB_ROOT`, `RB_DATA` and `RB_TEXTS` (see `scripts/paths.py`).

## Method (main setting)

- Link two reports if they share a subject actor, campaign or malware within 60 days, or share 3+ rare indicators (seen in 2-20 reports).
- Software used by 4+ ATT&CK groups never links. Only a report's subject entities link. Year-only dates link only via indicators.
- Constrained single linkage: an incident may span at most 60 days.
- Per-incident counting counts a technique once per incident. Share ratio rho = per-report share / per-incident share, with a 1,000-replicate cluster bootstrap.

## Results (`results/`)

| File | Content |
|---|---|
| `attack_main_tech.csv`, `corpus_main_tech.csv`, `tie_main_tech.csv` | every technique: counts, shares and ranks per report and per incident |
| `*_share_shift.json` | share ratio with 95% CI and over/under flag |
| `*_sensitivity.json` | all clustering settings, with validation precision/recall |
| `producer_vs_duplicate.json` | vendor-balanced (producer) ratio next to the duplicate ratio |
| `attack_yearly_top10.json` | yearly top-10, per report vs per incident |
| `attack_clusters_main.json`, `corpus_clusters_main.json` | incident id of every report |
| `gold_candidates.csv`, `gold_eval.json` | 205 tool-labelled pairs, used only for error analysis (not ground truth) |

## Data and licences

Report texts are vendor-copyrighted and are not redistributed; `results/corpus_reports.jsonl` holds only derived features
(technique IDs, entity matches, indicators, dates). Sources: MITRE ATT&CK (attack.mitre.org), TIE (MITRE CTID),
APT & CyberCriminal Campaign Collections (github.com/CyberMonitor), CISA advisories (cisa.gov), vendor blogs.
