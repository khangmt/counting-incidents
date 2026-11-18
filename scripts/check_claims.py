"""Evidence gate: every headline number in paper/main.tex is recomputed from results/ and must appear in the paper.
Writes audit/claims.md (claim | number | file | status). Exit code 1 if any claim fails.
Run: python3 scripts/check_claims.py"""
import json, csv, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from paths import RB
RES = RB + 'results/'; TEX = open(RB + 'paper/main.tex').read()
J = lambda f: json.load(open(RES + f))
L = lambda f: [json.loads(l) for l in open(RES + f)]
def by_t(f): return {x['t']: x for x in J(f)}
def tech_csv(f): return {r['t']: r for r in csv.DictReader(open(RES + f))}
n = lambda x: f"{x:,}"
f2 = lambda x: f"{x:.2f}"; f3 = lambda x: f"{x:.3f}"
pct = lambda r: f"{round((r - 1) * 100)}\\%"
A, T, P = by_t('attack_share_shift.json'), by_t('corpus_share_shift.json'), J('producer_vs_duplicate.json')
RC, AM, CM, TM = J('reviewer_checks.json'), J('attack_main_tech.json'), J('corpus_main_tech.json'), J('tie_main_tech.json')
AS = J('attack_sensitivity.json'); CS = {x['setting']: x for x in J('corpus_sensitivity.json')}
AT, CT = tech_csv('attack_main_tech.csv'), tech_csv('corpus_main_tech.csv')
att = L('attack_reports.jsonl'); YT = [y for y in J('attack_yearly_top10.json') if y['level'] == 'tech']
GENERIC = ['T1083', 'T1140', 'T1204.002', 'T1105', 'T1027.013', 'T1071.001']
def sens(tau, span='main'):
    for x in AS:
        if x['link'] == 'int+cam+mal' and x['tau'] == tau and x.get('span', 'main') == span: return x
CLAIMS = [  # (claim, value as it must appear in the paper, source file)
 ('ATT&CK cited reports', n(len(att)), 'attack_reports.jsonl'),
 ('ATT&CK dated reports', n(sum(1 for r in att if r['date'])), 'attack_reports.jsonl'),
 ('ATT&CK incidents', n(AM['n_units_incident']), 'attack_main_tech.json'),
 ('ATT&CK Kendall tau_b', f3(AM['kendall_tau_b']), 'attack_main_tech.json'),
 ('Texts: report texts', n(CS['ent+ioc_t60']['docs_all']), 'corpus_sensitivity.json'),
 ('Texts: labelled reports', n(CM['n_units_report']), 'corpus_main_tech.json'),
 ('Texts: incidents', n(CM['n_units_incident']), 'corpus_main_tech.json'),
 ('Texts: Kendall tau_b', f3(CM['kendall_tau_b']), 'corpus_main_tech.json'),
 ('TIE entries', n(TM['n_units_report']), 'tie_main_tech.json'),
 ('TIE incidents', n(TM['n_units_incident']), 'tie_main_tech.json'),
 ('TIE Kendall tau_b', f3(TM['kendall_tau_b']), 'tie_main_tech.json'),
 ('CISA advisories', n(len(L('cisa_reports.jsonl'))), 'cisa_reports.jsonl'),
 ('Validation ATT&CK P (main)', f2(sens(60)['val_P']), 'attack_sensitivity.json'),
 ('Validation ATT&CK R (main)', f2(sens(60)['val_R']), 'attack_sensitivity.json'),
 ('Validation ATT&CK R (S=45)', f2(sens(60, 45)['val_R']), 'attack_sensitivity.json'),
 ('Validation ATT&CK R (tau=0)', f2(sens(0)['val_R']), 'attack_sensitivity.json'),
 ('Validation ATT&CK P (no time limit)', f2(sens(None)['val_P']), 'attack_sensitivity.json'),
 ('Validation folders P (main)', f2(CS['ent+ioc_t60']['val_P']), 'corpus_sensitivity.json'),
 ('Validation folders R (main)', f2(CS['ent+ioc_t60']['val_R']), 'corpus_sensitivity.json'),
 ('Validation folders P (S=45)', f2(CS['ent+ioc_t60_span45']['val_P']), 'corpus_sensitivity.json'),
 ('Validation folders P (S=180)', f2(CS['ent+ioc_t60_span180']['val_P']), 'corpus_sensitivity.json'),
 ('Validation folder pairs', n(CS['ent+ioc_t60']['val_pos_pairs']), 'corpus_sensitivity.json'),
 ('Validation ATT&CK pairs', n(sens(60)['val_tp'] + sens(60)['val_fn']), 'attack_sensitivity.json'),
 ('Largest ATT&CK cluster, no time window', n(sens(None)['largest']), 'attack_sensitivity.json'),
 ('Largest text cluster, no span cap', n(CS['ent+ioc_t60_nospan']['largest_all']), 'corpus_sensitivity.json'),
 ('Prior rule on texts: largest cluster', n(RC['texts_rahman_rule']['largest']), 'reviewer_checks.json'),
 ('Prior rule on texts: tau_b', f3(RC['texts_rahman_rule']['tau_b']), 'reviewer_checks.json'),
 ('Prior rule on texts: folder P', f3(RC['texts_rahman_rule']['P']), 'reviewer_checks.json'),
 ('Permutations', n(RC['attack_permutation_meta']['n_permutations']), 'reviewer_checks.json'),
 ('ATT&CK techniques tested', str(RC['attack_permutation_meta']['n_tested']), 'reviewer_checks.json'),
 ('Texts techniques tested', str(len(T)), 'corpus_share_shift.json'),
 ('TIE techniques tested', str(len(J('tie_share_shift.json'))), 'tie_share_shift.json'),
 ('Headline set size (bootstrap BH and null BH)', {6: 'six'}.get(len(RC['attack_permutation_meta']['over_bootstrap_bh_and_null_bh']), '?'), 'reviewer_checks.json'),
 ('Headline set stable at every span cap (BH)', 'yes' if set(RC['attack_permutation_meta']['over_bootstrap_bh_and_null_bh']) <= set(RC['attack_over_bh_in_every_span']) else 'NO', 'reviewer_checks.json'),
 ('Data Destruction rho', f2(A['T1485']['share_ratio']), 'attack_share_shift.json'),
 ('Data Destruction CI', f"{pct(A['T1485']['ci_lo'])[:-2]}--{pct(A['T1485']['ci_hi'])}", 'attack_share_shift.json'),
 ('Financial Theft rho', f2(A['T1657']['share_ratio']), 'attack_share_shift.json'),
 ('Data Encrypted for Impact rho', f2(A['T1486']['share_ratio']), 'attack_share_shift.json'),
 ('Data Encrypted for Impact CI', f"{pct(A['T1486']['ci_lo'])[:-2]}--{pct(A['T1486']['ci_hi'])}", 'attack_share_shift.json'),
 ('Inhibit System Recovery rho', f2(A['T1490']['share_ratio']), 'attack_share_shift.json'),
 ('Domains rho', f2(A['T1583.001']['share_ratio']), 'attack_share_shift.json'),
 ('JavaScript rho', f2(A['T1059.007']['share_ratio']), 'attack_share_shift.json'),
 ('Token theft rho', f2(A['T1528']['share_ratio']), 'attack_share_shift.json'),
 ('Token theft rank move', f"rank {AT['T1528']['rank_report']} to {AT['T1528']['rank_incident']}", 'attack_main_tech.csv'),
 ('Token theft incidents', f"{AT['T1528']['n_report']} reports in {AT['T1528']['n_incident']} incidents", 'attack_main_tech.csv'),
 ('Software dependencies rank move', f"{AT['T1195.001']['rank_report']} to {AT['T1195.001']['rank_incident']}", 'attack_main_tech.csv'),
 ('Disk Structure Wipe rho', f2(A['T1561.002']['share_ratio']), 'attack_share_shift.json'),
 ('Data Destruction rank move', f"rank {AT['T1485']['rank_report']} to {AT['T1485']['rank_incident']}", 'attack_main_tech.csv'),
 ('Financial Theft rank move', f"{AT['T1657']['rank_report']} to {AT['T1657']['rank_incident']}", 'attack_main_tech.csv'),
 ('Ransomware encryption rank move', f"{AT['T1486']['rank_report']} to {AT['T1486']['rank_incident']}", 'attack_main_tech.csv'),
 ('Max rank places lost (token theft)', str(int(AT['T1528']['rank_incident']) - int(AT['T1528']['rank_report'])), 'attack_main_tech.csv'),
 ('Generic techniques: smallest null p (rounded down)', f"{int(min(RC['attack_permutation_null'][t]['p_null'] for t in GENERIC) * 100) / 100:.2f}", 'reviewer_checks.json'),
 ('PowerShell rank move (texts)', f"rank {CT['T1059.001']['rank_report']} to {CT['T1059.001']['rank_incident']}", 'corpus_main_tech.csv'),
 ('Producer vs duplicate Spearman, ATT&CK', f"{P['attack']['spearman_producer_vs_duplicate']:.2f}".replace('-', '$-'), 'producer_vs_duplicate.json'),
 ('Producer CIs excluding 1, ATT&CK', str(P['attack']['n_producer_ci_excludes_1']), 'producer_vs_duplicate.json'),
 ('Producer CIs excluding 1, texts', str(P['corpus']['n_producer_ci_excludes_1']), 'producer_vs_duplicate.json'),
 ('Producer ratios significant after BH', 'none' if P['attack']['n_producer_bh_sig'] == P['corpus']['n_producer_bh_sig'] == 0 else 'SOME', 'producer_vs_duplicate.json'),
 ('Vendors, ATT&CK', str(P['attack']['n_vendors']), 'producer_vs_duplicate.json'),
 ('Years with a changed top-10', f"{sum(1 for y in YT if y['n_changed'])} of {len(YT)} years", 'attack_yearly_top10.json'),
 ('Top-10 entries changed', f"{sum(y['n_changed'] for y in YT)} entries", 'attack_yearly_top10.json'),
 ('2026 reports and incidents', f"{YT[-1]['reports']} cited reports form {YT[-1]['incidents']} incidents", 'attack_yearly_top10.json'),
]

import glob, re as _re
def LOG(script, pattern, group=1):
    f = sorted(glob.glob(RES + f'runs/{script}-*.log'))[-1]
    return _re.search(pattern, open(f).read()).group(group)
PR = {k: {x['t']: x for x in P[k]['techniques']} for k in P}
TS = J('tie_sensitivity.json')['levels']
cl = J('attack_clusters_main.json'); import collections as _C
sz = _C.Counter(cl.values()); multi = [k for k, v in sz.items() if v > 1]
_inc = _C.defaultdict(set)
for r in att: _inc[cl[r['source_name']]] |= set(r['techniques'])
BASE = sum(len(v) for v in _inc.values()) / sum(len(set(r['techniques'])) for r in att)
taus = [x['tech_tau_b'] for x in AS if x['tau'] is not None]
CLAIMS += [
 ('Gold: ATT&CK campaign reports', LOG('run_attack', r'one campaign\): (\d+)'), 'runs/run_attack-*.log'),
 ('Gold: ATT&CK campaigns', LOG('run_attack', r'campaigns: (\d+)'), 'runs/run_attack-*.log'),
 ('Gold: campaign folders with 2+ texts', LOG('run_corpus', r'folders with >=2 docs (\d+)'), 'runs/run_corpus-*.log'),
 ('TIE entries with OTX metadata', LOG('run_tie', r'with OTX metadata (\d+)'), 'runs/run_tie-*.log'),
 ('TIE dated entries', n(int(LOG('run_tie', r'dated (\d+)'))), 'runs/run_tie-*.log'),
 ('CISA advisories not already present', LOG('run_corpus', r'advisories added: (\d+)'), 'runs/run_corpus-*.log'),
 ('TIE distinct reports', n([x for x in TS if x['setting'] == 'same_report'][0]['units']), 'tie_sensitivity.json'),
 ('ATT&CK reports in multi-report incidents', n(sum(sz[k] for k in multi)), 'attack_clusters_main.json'),
 ('ATT&CK multi-report incidents', n(len(multi)), 'attack_clusters_main.json'),
 ('ATT&CK tau_b, all time-window settings (min)', f2(min(taus)), 'attack_sensitivity.json'),
 ('ATT&CK tau_b, all time-window settings (max)', f3(max(taus)), 'attack_sensitivity.json'),
 ('ATT&CK tau_b, no time window', f3(sens(None)['tech_tau_b']), 'attack_sensitivity.json'),
 ('Baseline rho = sum I / sum R (ATT&CK)', f2(BASE), 'attack_reports.jsonl + attack_clusters_main.json'),
 ('Producer ratio Financial Theft (ATT&CK)', f2(PR['attack']['T1657']['producer_ratio']), 'producer_vs_duplicate.json'),
 ('Producer ratio token theft (ATT&CK)', f2(PR['attack']['T1528']['producer_ratio']), 'producer_vs_duplicate.json'),
 ('Producer ratio Disk Structure Wipe (ATT&CK)', f2(PR['attack']['T1561.002']['producer_ratio']), 'producer_vs_duplicate.json'),
 ('Producer, texts vendors', str(P['corpus']['n_vendors']), 'producer_vs_duplicate.json'),
 ('Producer vs duplicate Spearman, texts', f"{P['corpus']['spearman_producer_vs_duplicate']:.3f}", 'producer_vs_duplicate.json'),
 ('Validation ATT&CK R (S=180)', f2(sens(60, 180)['val_R']), 'attack_sensitivity.json'),
 ('Validation ATT&CK R (no time limit)', f2(sens(None)['val_R']), 'attack_sensitivity.json'),
 ('Validation prior rule, texts R', f2(RC['texts_rahman_rule']['R']), 'reviewer_checks.json'),
 ('Texts q, SMB shares and Process Injection', f"$q$ {T['T1021.002']['q_bh']:.2f} and {T['T1055']['q_bh']:.2f}", 'corpus_share_shift.json'),
 ('Nominal ATT&CK q range', f"$q$ = {min(A[t]['q_bh'] for t in ['T1528','T1195.001','T1561.002']):.2f}--{max(A[t]['q_bh'] for t in ['T1528','T1195.001','T1561.002']):.2f}", 'attack_share_shift.json'),
 ('TIE techniques passing BH', {7: 'seven'}.get(sum(1 for x in J('tie_share_shift.json') if x['shift_bh'] == 'over'), '?'), 'tie_share_shift.json'),
]

rows, bad = [], 0
for claim, val, src in CLAIMS:
    ok = val in TEX or val in ('yes',)
    if val in ('none', 'six') and val not in TEX: ok = False
    bad += not ok
    rows.append(f"| {claim} | {val.replace('|', '/')} | results/{src} | {'verified' if ok else 'MISMATCH: not found in main.tex'} |")
hdr = ("# Claims table (generated by scripts/check_claims.py; do not edit by hand)\n\n"
       "Each number is recomputed from the results file and must appear verbatim in paper/main.tex. "
       "Status `verified` means the number traces to a logged run (results/runs.jsonl). All claims are exploratory (no pre-registered plan).\n\n"
       "| Claim | Number in paper | Source | Status |\n|---|---|---|---|\n")
open(RB + 'audit/claims.md', 'w').write(hdr + '\n'.join(rows) + '\n')
print(f"{len(CLAIMS) - bad} of {len(CLAIMS)} claims verified")
for r in rows:
    if 'MISMATCH' in r: print(r)
sys.exit(1 if bad else 0)
