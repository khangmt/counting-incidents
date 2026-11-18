# External review 1: OpenAI ChatGPT (Think mode, free plan), 18 Nov 2026

Input: `paper/main.tex` at commit 28cfcf7 (LaTeX only, no figures, no .bib), with a prompt asking for a SecureComm 2027 short-paper PC review.
Conversation: chatgpt.com, in Kenta's browser ("Review paper methodology").
Verdict: **Weak reject**, confidence 4/5. Fit with SecureComm: good (CTI and incident response are listed topics).
Novelty: "moderate, incremental"; frame it as quantifying the effect of the counting unit, not as a new dedup algorithm.

This file summarises the review. It is not a verbatim copy. The right-hand column is our assessment, not the reviewer's.

| # | Reviewer point (severity) | Our assessment | Proposed action |
|---|---|---|---|
| W1 | Critical. The clusters are campaign waves, not individual incidents: same actor within 60 days can join separate victims. | Valid. Our Discussion already says "closest to campaign waves", but the title, abstract and RQs say "incident". | Reframe as "incident clusters (campaign waves)". Define the unit early and use it everywhere. Decision for Kenta. |
| W2 | Critical. Validation is weak: campaign labels are not incident labels, recall 0.39, folder precision 0.25, and "independent ground truth" is too strong. | Partly valid. The labels come from others, but they are campaign-level proxies. | Rename to "external campaign groupings". Report tp/fp/fn and pair counts. Define pairwise P and R. No new human labelling (Kenta ruled that out earlier). |
| W3 | Major. The bootstrap p-value, the CI method and the permutation algorithm are under-specified. | Valid and cheap to fix. | Add 3 to 4 sentences: percentile CI; p = 2·min tail share; the null keeps each incident's size and year, and cross-year incidents stay singletons. Optionally raise B to 10,000 for the headline six. |
| W3c | Major. Hypothesis family unclear; span-cap repeats are not independent confirmations. | Valid. | State that the primary family is the 215 ATT&CK tests at S=60. Present span caps as robustness, not confirmation. Release the full p/q columns (already in `results/`). |
| W4a | Major. TIE: 6,025 entries vs 5,596 distinct reports; which is the unit? | Valid. Table 3 uses entries. | Either rerun TIE with the 5,596 distinct reports as units or state it explicitly. Recommend the rerun (cheap). |
| W4b | Major. Why ≥3 technique IDs? Do the other texts cluster? | They do cluster (all 3,775); only counting uses the 532. | State this. Add a ≥1-ID sensitivity row if cheap. |
| W4c | Minor. S=45 folder P 0.29 lies outside its interval 0.17–0.28. | Real artefact of the percentile bootstrap of a ratio estimator. | Name the interval method in the caption, or switch to a BCa / basic interval. |
| W5 | Major. Overstated generality: "top-10 lists are safe to use"; the TIE "lower bound"; "under-merging is conservative" ignores false merges. | Valid. | Soften all three: "robust to this correction within these corpora"; "likely conservative if undated entries mainly hide true links"; acknowledge false merges can bias either way. |
| W6 | Major. Tuning and validation are not independent; the folder documents are also in the text corpus. | Valid. Already disclosed, but not in these words. | Say plainly in Analysis history that the validation is development-set, not held-out. |
| W7 | Moderate. Spearman ≈ 0 does not prove the effects are distinct. | Valid. | Add a bootstrap CI for Spearman. Reword to "show little correlation". |
| Minor | Fig. 1 caption should separate the BH and null criteria; Fig. 2 should say rank 1 = top; state the ATT&CK version and retrieval date; check alt text. | Valid. | Text-only fixes. |

Reviewer's stated path to acceptance: reframe the unit (W1), add incident-level checks of cluster merges (W2), and clarify the statistics and accounting (W3, W4).

Reviewer's citations: it named only works already in our bibliography and found no missing prior work. It confirmed that Rahman et al. use a two-month connected-component rule.
