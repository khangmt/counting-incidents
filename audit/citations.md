# Citation check (G4)

Checked 2026-11-17 by Claude (agent). Each reference was resolved through DOI/arXiv/publisher page and the sentence it supports was compared with the source text. **Kenta must confirm this table before submission (gate G4).**

| Key | Resolved via | Sentence it supports in main.tex | Source text checked | Status |
|---|---|---|---|---|
| rahman2024arsenal | arXiv 2401.01865 (arXiv API: title, 4 authors) | merge rule "common group or malware" + tau = 2 months; 920 -> 667 citations; ATT&CK v12; threshold set from sampled pairs, no accuracy reported for the merge | arXiv HTML: "at least one common cybercrime group or malware", "we identify tau=2", "920 citations", "667 citations", "Version 12" | verified; paper sentence corrected (they did check sampled pairs for the threshold) |
| suarezroman2026echo | arXiv 2602.17458 (arXiv API: title, 4 authors) | 13,308 reports, LLM structuring, removes exact and title/year/vendor duplicates, no incident clustering, no technique-frequency test | arXiv HTML: "13,308 unique files", "prompt o3-2025-04-16", hash + (title, year, vendor) dedup; no incident clustering | verified |
| cyentia2023multisource | publisher page | 22 public sources; about a third of techniques never mentioned | "Over a third (36%) of the 193 ATT&CK techniques weren't reported by any of the 22 sources" | verified |
| ctid2021sightings | GitHub README of center-for-threat-informed-defense/sightings_ecosystem | sightings are observations of technique use contributed by defenders | README: contributors share "when they see adversaries use specific behaviors against real production systems" | verified for that claim only; report PDF host blocked from this session, so no number from it is used |
| ctid2022top | GitHub README of center-for-threat-informed-defense/top-attack-techniques | calculator weights technique prevalence | README: methodology "considers technique prevalence, common attack choke points, and actionability" | verified; citation now points to the repository |
| cisa2023mapping | cisa.gov PDF (text extracted) | names novelty, visibility and producer bias in reporting | "Novelty bias...", "Visibility bias...", "Producer bias. Some organizations publish much more reporting" | verified |
| strom2020attack | attack.mitre.org PDF (text extracted) | most incidents are never reported publicly | Sect. 4.1.2.3: "The vast majority of incidents discovered are not reported publicly"; authors Strom, Applebaum, Miller, Nickels, Pennington, Thomas; revised March 2020 | verified; paper no longer cites it for "bias" names |
| redcanary2026tdr | redcanary.com methodology page (HTML) | prevalence derived from detection analytics behind confirmed threats | "Because we know which ATT&CK techniques an analytic aims to detect ... determine technique prevalence" | verified; the earlier claim about counting threats per environment was removed (not on the current page) |
| maschmeyer2021tale | Crossref DOI 10.1080/19331681.2020.1776658 | commercial reporting focuses on high-end threats to well-resourced targets, under-represents civil society | Crossref metadata (title, 3 authors, JITP 18(1) 1-20); abstract via Munk School page | verified |
| furumoto2025survey | Crossref DOI 10.1145/3772280; TUNI portal abstract | 200+ studies; evaluation results depend on which vendors are in the dataset | "over 200 studies ... 2001 and 2025"; "evaluation results depending on which vendors are included in the dataset" | verified; paper sentence narrowed to match |
| li2019tealeaves | USENIX proceedings page | limited coverage and accuracy of indicator feeds | "significant limitations and challenges in using existing threat intelligence data"; 7 authors incl. Kirill Levchenko; pp. 851-867 | verified; bib was missing Levchenko (fixed) |
| bouwman2020cup | USENIX proceedings page | almost no overlap between commercial and open feeds | "There is almost no overlap between them, nor with four large open threat intelligence feeds"; pp. 433-450 | verified |
| turner2025tie | arXiv 2503.04819 (arXiv API: title, 5 authors) | TIE dataset used as a corpus | dataset release (data used directly) | verified |
| cybermonitor2024apt | git ls-remote github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections (HEAD cbf136e2) | report collection filed in dated folders | repository layout used directly | verified (exists) |

## Novelty search log (backs "has not been measured")

| Date | Where | Query | Relevant hits |
|---|---|---|---|
| 2026-11-15 | web search, arXiv | ATT&CK technique frequency CTI reports deduplication | Rahman et al. 2024; Cyentia 2023 |
| 2026-11-15 | web search, arXiv | CTI echo chamber vendor overlap | Suarez-Roman et al. 2026 |
| 2026-11-17 | web search (extended) | MITRE ATT&CK technique prevalence threat reports bias measurement paper | Cyentia 2023, CTID Sightings, MITRE slides, Rahman 2024, Picus Red Report (prevalence ranking, not bias) |
| 2026-11-17 | web search (extended) | cyber threat intelligence reports duplicate coverage same incident clustering deduplication research | arXiv 2509.23571 (MinHash dedup of security events for a benchmark), arXiv 2210.14067 (clustering CERT reports), arXiv 2604.09104 (incident dedup, not CTI); none measures effect on technique statistics |
| 2026-11-17 | web search (extended) | "threat intelligence" reporting bias vendor bias APT reports measurement study RAID ACSAC EuroS&P | Furumoto 2025, Suarez-Roman 2026, Maschmeyer 2021, ETH Zurich CSS project (ongoing, dataset of commercial reporting) |
| 2026-11-17 | web search | Red Canary / CTID Top ATT&CK Techniques methodology | counting units of detection-based statistics |

Not searched: ACM DL and IEEE Xplore full-text search (blocked from this session), Google Scholar. Kenta should run one Scholar search for "ATT&CK" + "deduplication" OR "same incident" before submission. The ETH Zurich CSS project on bias in commercial threat reporting is ongoing; check for a 2026-27 publication.
