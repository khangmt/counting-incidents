#!/usr/bin/env bash
# Rebuild every result and figure. Needs: data/attack_stix/enterprise-attack.json (ATT&CK v20.1 STIX),
# data/tie/combined_dataset_full_frequency.json (TIE), and for the text corpus the extracted texts under texts/.
set -euo pipefail
cd "$(dirname "$0")/scripts"
python3 attack_citations.py          # ATT&CK citations -> results/attack_reports.jsonl
python3 run_attack.py                # ATT&CK: sweep, validation, main results
if [ -d "${RB_TEXTS:-../texts}" ]; then
  python3 corpus_features.py         # report texts -> results/corpus_reports.jsonl
  python3 cisa_features.py           # CISA advisories -> results/cisa_reports.jsonl
fi
python3 run_corpus.py                # report texts: sweep, validation, main results (uses results/*.jsonl)
python3 run_tie.py                   # TIE/OpenCTI (fetch_otx.py first for OTX dates; slow, rate-limited)
python3 paper_extra.py               # producer vs duplicate; yearly top-10
python3 make_figures.py              # paper figures
