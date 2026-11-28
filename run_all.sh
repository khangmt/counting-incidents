#!/usr/bin/env bash
# Rebuild every result and figure. Needs: data/attack_stix/enterprise-attack.json (ATT&CK v20.1 STIX),
# data/tie/combined_dataset_full_frequency.json (TIE), and for the text corpus the extracted texts under texts/.
set -euo pipefail
cd "$(dirname "$0")/scripts"
python3 run_logged.py attack_citations.py          # ATT&CK citations -> results/attack_reports.jsonl
python3 run_logged.py run_attack.py                # ATT&CK: sweep, validation, main results
if [ -d "${RB_TEXTS:-../texts}" ]; then
  python3 run_logged.py corpus_features.py         # report texts -> results/corpus_reports.jsonl
  python3 run_logged.py cisa_features.py           # CISA advisories -> results/cisa_reports.jsonl
fi
python3 run_logged.py run_corpus.py                # report texts: sweep, validation, main results (uses results/*.jsonl)
python3 run_logged.py run_tie.py                   # TIE/OpenCTI (fetch_otx.py first for OTX dates; slow, rate-limited)
python3 run_logged.py paper_extra.py               # producer vs duplicate; yearly top-10
python3 run_logged.py reviewer_checks.py           # prior-work rule, span stability, permutation null
python3 run_logged.py enrich_checks.py            # temporal hold-out of the span cap; text counting threshold
python3 run_logged.py make_figures.py              # paper figures
python3 make_raw_samples.py                        # gate G2 sheet: audit/raw_samples.md
python3 check_claims.py                            # evidence gate: audit/claims.md, fails if a paper number does not match results/
