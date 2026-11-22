# External review 2: Google Gemini ("Deeper analysis" model), 22 Nov 2026

Input: `paper/main.tex` at commit 91c5e6b (LaTeX only), same prompt as the ChatGPT review (SecureComm 2027 short-paper PC review). Gemini did not see the ChatGPT review.
Account: the author's university (Edu) Gemini account; the page states these chats are not used to improve Google's models.
Verdict: **Weak accept**, confidence 4/5. It says the paper fits SecureComm and its novelty is "incremental but solid", and it found no missing prior work.

This is a summary, not a verbatim copy. The last column records what we did.

| # | Reviewer point (severity) | Action taken |
|---|---|---|
| 1 | High. No permutation null on the report texts, so the generic text techniques may be false positives. | **Done.** Ran the same null on the 532 texts (`reviewer_checks.json`, `texts_permutation_*`). Domain Trust Discovery and Spearphishing Link pass both corrected tests; SMB shares and Process Injection pass the null but are nominal in the bootstrap; PowerShell is explained by the null (q = 0.14) and is now dropped from Fig. 1b. |
| 2 | High. Text-corpus precision is only a lower bound (0.25), and validation is development-set; suggests a manual audit of 50–100 cross-folder merges. | Not done: the author ruled out human or model labels as evidence. The limitation is stated in the Validation and Analysis-history paragraphs. |
| 3 | Medium. URL-less texts count as their own vendor and are up-weighted in RQ3. | **Done.** 177 of 188 text producer units are URL-less. Without them (355 texts, 11 vendors) the Spearman correlation is 0.085 (CI −0.09 to 0.26), so the conclusion holds. Stated in RQ3. |
| 4 | Medium-low. TIE is framed as an equal third corpus but adds little signal. | **Done.** Sect. 3 now calls TIE a stress test of sparse metadata. |
| 5 | Low-medium. The provenance of the text corpus is underspecified. | **Done.** Counts per source are in Sect. 3, with AnnoCTR and Attack Flow now cited (both resolved via arXiv/Crossref and GitHub). |
| Stats | The Spearman CI resamples techniques, which are not independent. | Stated as approximate in RQ3. |
| Minor | Table 2 "--" unexplained; Fig. 2 caption should give 67/26 and note the partial year; Fig. 1 caption. | **Done.** |

While doing this, we found that the Spearman bootstrap depended on Python's set ordering, so the interval changed slightly between runs. It now sorts first and is deterministic; the ATT&CK interval is −0.17 to 0.11.
